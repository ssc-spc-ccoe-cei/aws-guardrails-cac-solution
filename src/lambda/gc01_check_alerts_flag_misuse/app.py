""" GC01 - Check Root MFA
    https://canada-ca.github.io/cloud-guardrails/EN/01_Protect-Root-Account.html
"""
import json
import logging
import time

import boto3
import botocore
import botocore.exceptions

# Logging setup
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Set to True to get the lambda to assume the Role attached on the Config Service
ASSUME_ROLE_MODE = True
DEFAULT_RESOURCE_TYPE = "AWS::::Account"


# This gets the client after assuming the Config service role
# either in the same AWS account or cross-account.
def get_client(service, event):
    """Return the service boto client. It should be used instead of directly calling the client.
    Keyword arguments:
    service -- the service name used for calling the boto.client()
    event -- the event variable given in the lambda handler
    """
    if not ASSUME_ROLE_MODE:
        return boto3.client(service)
    execution_role_arn = f"arn:aws:iam::{AWS_ACCOUNT_ID}:role/{EXECUTION_ROLE_NAME}"
    credentials = get_assume_role_credentials(execution_role_arn)
    return boto3.client(
        service,
        aws_access_key_id=credentials["AccessKeyId"],
        aws_secret_access_key=credentials["SecretAccessKey"],
        aws_session_token=credentials["SessionToken"],
    )


def get_assume_role_credentials(role_arn):
    """Returns the temporary credentials from ASSUME_ROLE_MODE role.
    Keyword arguments:
    role_arn -- the ARN of the role to assume
    """
    sts_client = boto3.client("sts")
    try:
        assume_role_response = sts_client.assume_role(
            RoleArn=role_arn,
            RoleSessionName="configLambdaExecution"
        )
        return assume_role_response["Credentials"]
    except botocore.exceptions.ClientError as ex:
        # Scrub error message for any internal account info leaks
        if "AccessDenied" in ex.response["Error"]["Code"]:
            ex.response["Error"]["Message"] = "AWS Config does not have permission to assume the IAM role."
        else:
            ex.response["Error"]["Message"] = "InternalError"
            ex.response["Error"]["Code"] = "InternalError"
        raise ex


def is_scheduled_notification(message_type):
    """Check whether the message is a ScheduledNotification or not.
    Keyword arguments:
    message_type -- the message type
    """
    return message_type == "ScheduledNotification"


def evaluate_parameters(rule_parameters):
    """Evaluate the rule parameters dictionary.
    Keyword arguments:
    rule_parameters -- the Key/Value dictionary of the Config rule parameters
    """
    return rule_parameters


# This generate an evaluation for config
def build_evaluation(
    resource_id,
    compliance_type,
    event,
    resource_type=DEFAULT_RESOURCE_TYPE,
    annotation=None,
):
    """Form an evaluation as a dictionary. Usually suited to report on scheduled rules.
    Keyword arguments:
    resource_id -- the unique id of the resource to report
    compliance_type -- either COMPLIANT, NON_COMPLIANT or NOT_APPLICABLE
    event -- the event variable given in the lambda handler
    resource_type -- the CloudFormation resource type (or AWS::::Account)
    to report on the rule (default DEFAULT_RESOURCE_TYPE)
    annotation -- an annotation to be added to the evaluation (default None)
    """
    eval_cc = {}
    if annotation:
        eval_cc["Annotation"] = annotation
    eval_cc["ComplianceResourceType"] = resource_type
    eval_cc["ComplianceResourceId"] = resource_id
    eval_cc["ComplianceType"] = compliance_type
    eval_cc["OrderingTimestamp"] = str(
        json.loads(event["invokingEvent"])["notificationCreationTime"]
    )
    return eval_cc

def get_guard_duty_enabled():
    try:
        response = AWS_GUARD_DUTY_CLIENT.list_detectors()
        detectorIds = response.get("DetectorIds", [])
        return len(detectorIds) > 0
    except botocore.exceptions.ClientError as ex:
        if "BadRequest" in ex.response['Error']['Code']:
            ex.response['Error']['Message'] = "Failed to fetch detector ids for GuardDuty. Bad Request."
        else:
            ex.response["Error"]["Message"] = "InternalError"
            ex.response["Error"]["Code"] = "InternalError"
            
        raise ex
    
def get_event_bridge_rules(naming_convention):
    rules = []
    try:
        # Assuming we only need to check the default event bus
        response = AWS_EVENT_BRIDGE_CLIENT.list_rules(naming_convention)
        rules = rules + response.get("Rules")
        next_token = response.get("NextToken")
        
        while next_token != None:
            response = AWS_EVENT_BRIDGE_CLIENT.list_rules(naming_convention, next_token)
            rules = rules + response.get("Rules")
            next_token = response.get("NextToken")
            
        return rules
    except botocore.exceptions.ClientError as ex:
        if "ResourceNotFound" in ex.response['Error']['Code']:
            ex.response['Error']['Message'] = "Failed to list rules for EventBridge. Resource not found."
        else:
            ex.response["Error"]["Message"] = "InternalError"
            ex.response["Error"]["Code"] = "InternalError"
        raise ex

def check_rules_sns_target_is_setup(rule_name):
    try:
        response = AWS_EVENT_BRIDGE_CLIENT.list_targets_by_rule(rule_name)
        targets = response.get("Targets", [])
        next_token = response.get("NextToken")
        
        while next_token != None:
            response = AWS_EVENT_BRIDGE_CLIENT.list_targets_by_rule(rule_name, NextToken=next_token)
            targets = targets + response.get("Targets", [])
            next_token = response.get("NextToken")

        for target in targets:
            if target.get("InputTransformer") != None:
                # get sns topic via target ARN
                # then list subscriptions for topic
                # then search topic for a subscription with "email" protocol and is confirmed
                logger.info("not done yet")
                
    except botocore.exceptions.ClientError as ex:
        raise ex
        
def lambda_handler(event, context):
    """This function is the main entry point for Lambda.
    Keyword arguments:
    event -- the event variable given in the lambda handler
    context -- the context variable given in the lambda handler
    """
    logger.debug("Received event: %s", event)

    global AWS_CONFIG_CLIENT
    global AWS_GUARD_DUTY_CLIENT
    global AWS_EVENT_BRIDGE_CLIENT
    global AWS_SNS_CLIENT
    global AWS_ACCOUNT_ID
    global EXECUTION_ROLE_NAME
    global AUDIT_ACCOUNT_ID

    evaluations = []
    rule_parameters = {}
    invoking_event = json.loads(event["invokingEvent"])
    logger.info("Received Event: %s", json.dumps(event, indent=2))

    # parse parameters
    AWS_ACCOUNT_ID = event["accountId"]

    if "ruleParameters" in event:
        rule_parameters = json.loads(event["ruleParameters"])

    valid_rule_parameters = evaluate_parameters(rule_parameters)

    if "ExecutionRoleName" in valid_rule_parameters:
        EXECUTION_ROLE_NAME = valid_rule_parameters["ExecutionRoleName"]
    else:
        EXECUTION_ROLE_NAME = "AWSA-GCLambdaExecutionRole"

    if "AuditAccountID" in valid_rule_parameters:
        AUDIT_ACCOUNT_ID = valid_rule_parameters["AuditAccountID"]
    else:
        AUDIT_ACCOUNT_ID = ""

    AWS_CONFIG_CLIENT = get_client("config", event)
    AWS_GUARD_DUTY_CLIENT = get_client("guardduty", event)
    AWS_EVENT_BRIDGE_CLIENT = get_client("events", event)
    AWS_SNS_CLIENT = get_client("sns", event)
    
    # is this a scheduled invokation?
    if is_scheduled_notification(invoking_event["messageType"]):
        # yes, proceed with checking GuardDuty
        # check if GuardDuty is enabled
        logger.info("Root Account MFA check in account %s", AWS_ACCOUNT_ID)
        if get_guard_duty_enabled():
            # yes, check that an EventBridge rule is setup to alert authorized user
            logger.info("not done yet")
        else:
            # no, check for EventBridge rules with naming convention
            # Assuming RuleNamingConvention is always going to be a prefix convention
            rule_naming_convention = valid_rule_parameters.get("RuleNamingConvention")
            rules = get_event_bridge_rules(rule_naming_convention)
            
            if len(rules) > 0:
                evaluations.append(
                    build_evaluation(
                        event["accountId"],
                        "NON_COMPLIANT",
                        event,
                        resource_type=DEFAULT_RESOURCE_TYPE,
                        annotation="GuardDuty is not enabled and there are no EventBridge rules. ",
                    )
                )
            else:
                evaluations.append(
                    build_evaluation(
                        event["accountId"],
                        "NON_COMPLIANT",
                        event,
                        resource_type=DEFAULT_RESOURCE_TYPE,
                        annotation="GuardDuty is not enabled and there are no EventBridge rules. ",
                    )
                )
            
            
            
        # Update AWS Config with the evaluation result
        AWS_CONFIG_CLIENT.put_evaluations(
            Evaluations=evaluations,
            ResultToken=event["resultToken"]
        )
