""" GC01 - Check Root MFA
    https://canada-ca.github.io/cloud-guardrails/EN/01_Protect-Root-Account.html
"""
import json
import logging
import time
import re

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

def check_s3_object_exists(object_path):
    """Check if the S3 object exists
    Keyword arguments:
    object_path -- the S3 object path
    """
    # parse the S3 path
    bucket_name, key_name = extract_bucket_name_and_key(object_path)
    try:
        AWS_S3_CLIENT.head_object(Bucket=bucket_name, Key=key_name)
    except botocore.exceptions.ClientError as err:
        if err.response["Error"]["Code"] == "404":
            # The object does not exist.
            logger.info("Object %s not found in bucket %s", key_name, bucket_name)
            return False
        elif err.response["Error"]["Code"] == "403":
            # AccessDenied
            logger.info("Access denied to bucket %s", bucket_name)
            return False
        else:
            # Something else has gone wrong.
            logger.error("Error trying to find object %s in bucket %s", key_name, bucket_name)
            raise ValueError(f"Error trying to find object {key_name} in bucket {bucket_name}") from err
    else:
        # The object does exist.
        return True

def extract_bucket_name_and_key(object_path):
    match = re.match(r"s3:\/\/([^/]+)\/((?:[^/]*/)*.*)", object_path)
    if match:
        bucket_name = match.group(1)
        key_name = match.group(2)
    else:
        logger.error("Unable to parse S3 object path %s", object_path)
        raise ValueError(f"Unable to parse S3 object path {object_path}")
    return bucket_name,key_name


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
    
def get_event_bridge_rules():
    rules = []
    try:
        # Assuming we only need to check the default event bus
        response = AWS_EVENT_BRIDGE_CLIENT.list_rules()
        rules = rules + response.get("Rules")
        next_token = response.get("NextToken")
        
        while next_token != None:
            response = AWS_EVENT_BRIDGE_CLIENT.list_rules(NextToken=next_token)
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

def get_topic_subscriptions(topic_arn):
    try:
        response = AWS_SNS_CLIENT.list_subscriptions_by_topic(TopicArn=topic_arn)
        subscriptions = response.get("Subscriptions", [])
        next_token = response.get("NextToken")

        while next_token != None:
            response = AWS_SNS_CLIENT.list_subscriptions_by_topic(TopicArn=topic_arn, NextToken=next_token)
            subscriptions = subscriptions + response.get("Subscriptions", [])
            next_token = response.get("NextToken")
        
        return subscriptions
    except botocore.exceptions.ClientError as ex:
        if "NotFound" in ex.response['Error']['Code']:
            ex.response['Error']['Message'] = "Failed to get topic subscriptions. Resource not found."
        elif "InvalidParameter" in ex.response['Error']['Code']:
            ex.response['Error']['Message'] = "Failed to get topic subscriptions. Invalid parameter."
        elif "AuthorizationError" in ex.response['Error']['Code']:
            ex.response['Error']['Message'] = "Faled to get topic subscriptions. User is unauthorized."
        else:
            ex.response["Error"]["Message"] = "InternalError"
            ex.response["Error"]["Code"] = "InternalError"
        raise ex
    
def subscription_is_confirmed(subscription_arn):
    try:
        response = AWS_SNS_CLIENT.get_subscription_attributes(SubscriptionArn=subscription_arn)
        attributes = response.get("Attributes")
        logger.info("Subscription attributes: %s", attributes)
        
        if attributes == None:
            return False
        
        return attributes.get("PendingConfirmation") == "false"
    except botocore.exceptions.ClientError as ex:
        if "NotFound" in ex.response['Error']['Code']:
            ex.response['Error']['Message'] = "Failed to get subscription attributes. Resource not found."
        elif "InvalidParameter" in ex.response['Error']['Code']:
            ex.response['Error']['Message'] = "Failed to get subscription attributes. Invalid parameter."
        elif "AuthorizationError" in ex.response['Error']['Code']:
            ex.response['Error']['Message'] = "Faled to get subscription attributes. User is unauthorized."
        else:
            ex.response["Error"]["Message"] = "InternalError"
            ex.response["Error"]["Code"] = "InternalError"
        raise ex

def fetch_rule_targets(rule_name):
    try:
        response = AWS_EVENT_BRIDGE_CLIENT.list_targets_by_rule(Rule=rule_name)
        targets = response.get("Targets", [])
        next_token = response.get("NextToken")
            
        while next_token != None:
            response = AWS_EVENT_BRIDGE_CLIENT.list_targets_by_rule(Rule=rule_name, NextToken=next_token)
            targets = targets + response.get("Targets", [])
            next_token = response.get("NextToken")
        return targets   
    except botocore.exceptions.ClientError as ex:
        if "NotFound" in ex.response['Error']['Code']:
            ex.response['Error']['Message'] = "Failed to fetch all targets for a rule. Resource not found."
        else:
            ex.response["Error"]["Message"] = "InternalError"
            ex.response["Error"]["Code"] = "InternalError"
        raise ex

def rule_event_pattern_matches_guard_duty_findings(rule_event_pattern:str | None):
    if rule_event_pattern == None:
        return False
    logger.info("rule_event_pattern: %s", rule_event_pattern)
    
    event_pattern_dict = json.loads(rule_event_pattern)
    logger.info("event_pattern_dict: %s", event_pattern_dict)
    return "aws.guardduty" in event_pattern_dict.get("source", []) and "GuardDuty Finding" in event_pattern_dict.get("detail-type", [])

def check_rules_sns_target_is_setup(rules, event):
    for rule in rules:
        logger.info("Checking rule: %s", rule)
        if rule.get("State") == "DISABLED":
            return build_evaluation(
                event["accountId"],
                "NON_COMPLIANT",
                event,
                resource_type="AWS::Events::Rule",
                annotation="Rule is disabled.",
            )   
        
        rule_name = rule.get("Name")          
        targets = fetch_rule_targets(rule_name)

        for target in targets:
            logger.info("Checking rule target: %s", target)
            # is target an SNS input transformer?
            target_arn: str = target.get("Arn")
            if target_arn.startswith("arn:aws:sns:") :
                # yes, get a list of topic subscriptions
                subscriptions =  get_topic_subscriptions(target_arn)
                # then search topic for a subscription with "email" protocol and is confirmed
                for subscription in subscriptions:
                    logger.info("Checking target subscriptions: %s", subscription)
                    if subscription.get("Protocol") == "email":
                        subscription_arn = subscription.get("SubscriptionArn")
                        if subscription_is_confirmed(subscription_arn):
                            return build_evaluation(
                                event["accountId"],
                                "COMPLIANT",
                                event,
                                resource_type=DEFAULT_RESOURCE_TYPE,
                                annotation="An Event rule that has a SNS topic and subscription to send notification emails setup and confirmed.",
                            )
    
    return build_evaluation(
        event["accountId"],
        "NON_COMPLIANT",
        event,
        resource_type=DEFAULT_RESOURCE_TYPE,
        annotation="An Event rule that has a SNS topic and subscription to send notification emails is not setup or confirmed.",
    )         

def get_rule_naming_convention(rule_naming_convention_file_path):
    bucket, key = extract_bucket_name_and_key(rule_naming_convention_file_path)
    response = AWS_S3_CLIENT.get_object(Bucket=bucket, Key=key)
    rule_naming_convention = response.get("Body").read().decode("utf-8")
    return rule_naming_convention
        
def lambda_handler(event, context):
    """This function is the main entry point for Lambda.
    Keyword arguments:
    event -- the event variable given in the lambda handler
    context -- the context variable given in the lambda handler
    """
    logger.debug("Received event: %s", event)

    global AWS_CONFIG_CLIENT
    global AWS_GUARD_DUTY_CLIENT
    global AWS_S3_CLIENT
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
    AWS_S3_CLIENT = boto3.client("s3")
    AWS_GUARD_DUTY_CLIENT = get_client("guardduty", event)
    AWS_EVENT_BRIDGE_CLIENT = get_client("events", event)
    AWS_SNS_CLIENT = get_client("sns", event)
    
    # is this a scheduled invokation?
    if is_scheduled_notification(invoking_event["messageType"]):
        # yes, proceed with checking GuardDuty
        rules = get_event_bridge_rules()
        
        guard_duty_evaluation = None
        # is Guardduty enabled?
        if get_guard_duty_enabled():
            # yes, filter for rules that target GuardDuty findings
            logger.info("GuardDuty is enabled.")
            guardduty_rules = [ r for r in rules if rule_event_pattern_matches_guard_duty_findings(r.get("EventPattern")) ]
            logger.info("GuardDuty rules count: %d", len(guardduty_rules))
            # are there any rules that target GuardDuty findings
            if len(guardduty_rules) > 0:
                # yes, check that an SNS target is setup that sends an email notification to authorized personnel
                guard_duty_evaluation = check_rules_sns_target_is_setup(guardduty_rules, event)
                logger.info("GuardDuty Evaluation: %s", guard_duty_evaluation)
                evaluations.append(guard_duty_evaluation)
        
        # are the GuardDuty rules found to be NON_COMPLIANT?
        if guard_duty_evaluation == None or guard_duty_evaluation.get("ComplianceType") == "NON_COMPLIANT":
            # yes, check for EventBridge rules with naming convention
            rule_naming_convention_file_path = valid_rule_parameters.get("RuleNamingConventionFilePath", "")
            if check_s3_object_exists(rule_naming_convention_file_path) == False:
                evaluations.append(
                    build_evaluation(
                        event["accountId"],
                        "NON_COMPLIANT",
                        event,
                        resource_type=DEFAULT_RESOURCE_TYPE,
                        annotation="No RuleNamingConventionFilePath input provided.",
                    )
                ) 
            else:
                rule_naming_convention = get_rule_naming_convention(rule_naming_convention_file_path)
                reg = re.compile(rule_naming_convention)
                logger.info("Filtering rules by rule_naming_convention: %s", rule_naming_convention)
                filtered_rules = [ r for r in rules if reg.match(r.get("Name", "")) ]
                
                # are there any rules matching the naming convention?
                if len(filtered_rules) > 0:
                    # yes, check that an SNS target is setup that sends an email notification to authorized personnel 
                    rule_evaluation = check_rules_sns_target_is_setup(rules, event)
                    # are the filtered event rules found to be COMPLIANT
                    if rule_evaluation.get("ComplianceType") == "COMPLIANT":
                        # yes, set evaluation results to rule_evaluation because the validation should be found compliant
                        evaluations = [rule_evaluation]
                    else:
                        # no, append to evaluation results
                        evaluations.append(rule_evaluation)
                else:
                    # no, append to evaluation results
                    evaluations.append(
                        build_evaluation(
                            event["accountId"],
                            "NON_COMPLIANT",
                            event,
                            resource_type=DEFAULT_RESOURCE_TYPE,
                            annotation="GuardDuty is not enabled and there are no EventBridge rules.",
                        )
                    ) 
            
        # Update AWS Config with the evaluation result
        logging.info("AWES Config updating evaluations: %s", evaluations)
        AWS_CONFIG_CLIENT.put_evaluations(
            Evaluations=evaluations,
            ResultToken=event["resultToken"]
        )
