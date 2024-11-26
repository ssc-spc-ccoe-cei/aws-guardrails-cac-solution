""" GC04 - Check Alerts Flag Misuse
    https://canada-ca.github.io/cloud-guardrails/EN/04_Enterprise-Monitoring-Accounts.html
"""
import json
import logging
import time

import boto3
import botocore

logger = logging.getLogger()
logger.setLevel(logging.INFO)
ASSUME_ROLE_MODE = True
DEFAULT_RESOURCE_TYPE = "AWS::::Account"


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
    """Return the service boto client. It should be used instead of directly calling the client.
    Keyword arguments:
    service -- the service name used for calling the boto.client()
    event -- the event variable given in the lambda handler
    """
    sts_client = boto3.client("sts")
    try:
        assume_role_response = sts_client.assume_role(
            RoleArn=role_arn,
            RoleSessionName="configLambdaExecution"
        )
        return assume_role_response["Credentials"]
    except botocore.exceptions.ClientError as ex:
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
    if "IAM_Role_Name" not in rule_parameters:
        raise ValueError('The parameter with "IAM_Role_Name" as key must be defined.')
    if not rule_parameters["IAM_Role_Name"]:
        raise ValueError('The parameter "IAM_Role_Name" must have a defined value.')
    if "IAM_Trusted_Principal" not in rule_parameters:
        raise ValueError('The parameter with "IAM_Trusted_Principal" as key must be defined.')
    if not rule_parameters["IAM_Trusted_Principal"]:
        raise ValueError('The parameter "IAM_Trusted_Principal" must have a defined value.')
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
    annotation -- an annotation to be added to the evaluation (default None).
    It will be truncated to 255 if longer.
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
            ex.response['Error']['Message'] = "Failed to get topic subscriptions. User is unauthorized."
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
            ex.response['Error']['Message'] = "Failed to get subscription attributes. User is unauthorized."
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

def rule_matches_against_cb_role_identity(rule):
    if rule_event_pattern == None:
        return False
    logger.info("rule_event_pattern: %s", rule_event_pattern)
    
    event_pattern_dict = json.loads(rule_event_pattern)
    logger.info("event_pattern_dict: %s", event_pattern_dict)
    return "aws.guardduty" in event_pattern_dict.get("source", []) and "GuardDuty Finding" in event_pattern_dict.get("detail-type", [])

def check_rule_sns_target_is_setup(rule, event):
    
    logger.info("Checking rule: %s", rule)
    if rule.get("State") == "DISABLED":
        return build_evaluation(
            rule.get("Name"),
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
                            rule.get("Name"),
                            "COMPLIANT",
                            event,
                            resource_type="AWS::Events::Rule",
                            annotation="An Event rule that has a SNS topic and subscription to send notification emails is setup and confirmed.",
                        )
    
    return build_evaluation(
        rule.get("Name"),
        "NON_COMPLIANT",
        event,
        resource_type="AWS::Events::Rule",
        annotation="An Event rule that has a SNS topic and subscription to send notification emails is not setup or confirmed.",
    )

def lambda_handler(event, context):
    """Lambda handler to check CloudTrail trails are logging.
    Keyword arguments:
    event -- the event variable given in the lambda handler
    context -- the context variable given in the lambda handler
    """
    global AWS_CONFIG_CLIENT
    global AWS_SNS_CLIENT
    global AWS_EVENT_BRIDGE_CLIENT
    global AWS_ACCOUNT_ID
    global EXECUTION_ROLE_NAME
    global AUDIT_ACCOUNT_ID
    

    evaluations = []
    rule_parameters = {}

    invoking_event = json.loads(event["invokingEvent"])

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
    AWS_EVENT_BRIDGE_CLIENT = get_client("events", event)
    AWS_SNS_CLIENT = get_client("sns", event)

    # is this a scheduled invokation?
    if is_scheduled_notification(invoking_event["messageType"]):
        