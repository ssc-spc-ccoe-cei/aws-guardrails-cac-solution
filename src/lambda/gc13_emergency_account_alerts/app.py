""" GC13 - Check Emergency Account Alerts Lambda Function
    Checking for the existence of EventBridge alerts as evidence to support the Guardrails
"""
import json
import logging
import re

import boto3
import botocore

# Logging setup
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Set to True to get the lambda to assume the Role attached on the Config Service
ASSUME_ROLE_MODE = True
DEFAULT_RESOURCE_TYPE = "AWS::::Account"
RULE_RESOURCE_TYPE = "AWS::Events::Rule"


# This gets the client after assuming the Config service role
# either in the same AWS account or cross-account.
def get_client(service, event):
    """Return the service boto client. It should be used instead of directly calling the client.
    Keyword arguments:
    service -- the service name used for calling the boto.client()
    event -- the event variable given in the lambda handler
    """
    if not ASSUME_ROLE_MODE or (AWS_ACCOUNT_ID == AUDIT_ACCOUNT_ID):
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
    """Returns the credentials required to assume the passed role
    Keyword arguments:
    role_arn -- the arn of the role to assume"""
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
        logger.error("ERROR assuming role. %s", ex.response["Error"])
        raise ex


# Check whether the message is a ScheduledNotification or not.
def is_scheduled_notification(message_type):
    """Check whether the message is a ScheduledNotification or not.
    Keyword arguments:
    message_type -- the message type
    """
    return message_type == "ScheduledNotification"


def evaluate_parameters(rule_parameters):
    """Evaluate the rule parameters dictionary validity. Raise a Exception for invalid parameters.
    Keyword arguments:
    rule_parameters -- the Key/Value dictionary of the Config Rule parameters
    """
    if "s3ObjectPath" not in rule_parameters:
        logger.error('The parameter with "s3ObjectPath" as key must be defined.')
        raise ValueError('The parameter with "s3ObjectPath" as key must be defined.')
    if not rule_parameters["s3ObjectPath"]:
        logger.error('The parameter "s3ObjectPath" must have a defined value.')
        raise ValueError('The parameter "s3ObjectPath" must have a defined value.')
    return rule_parameters


# This generate an evaluation for config
def build_evaluation(resource_id, compliance_type, event, resource_type=DEFAULT_RESOURCE_TYPE, annotation=None):
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
    eval_cc["OrderingTimestamp"] = str(json.loads(event["invokingEvent"])["notificationCreationTime"])
    return eval_cc


def check_s3_object_exists(object_path: str) -> bool:
    """Check if the S3 object exists
    Keyword arguments:
    object_path -- the S3 object path
    """
    # parse the S3 path
    match = re.match(r"s3:\/\/([^/]+)\/((?:[^/]*/)*.*)", object_path)
    if match:
        bucket_name = match.group(1)
        key_name = match.group(2)
    else:
        logger.error("Unable to parse S3 object path %s", object_path)
        raise ValueError(f"Unable to parse S3 object path {object_path}")
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


def extract_bucket_name_and_key(object_path: str) -> tuple[str, str]:
    match = re.match(r"s3:\/\/([^/]+)\/((?:[^/]*/)*.*)", object_path)
    if match:
        bucket_name = match.group(1)
        key_name = match.group(2)
    else:
        logger.error("Unable to parse S3 object path %s", object_path)
        raise ValueError(f"Unable to parse S3 object path {object_path}")
    return bucket_name, key_name


def get_event_bridge_rules() -> list[dict]:
    try:
        rules = []
        next_token = None
        while True:
            # Assuming we only need to check the default event bus
            response = AWS_EVENT_BRIDGE_CLIENT.list_rules() if not next_token else AWS_EVENT_BRIDGE_CLIENT.list_rules(NextToken=next_token)
            rules = rules + response.get("Rules")
            next_token = response.get("NextToken")
            if not next_token:
                break
        return rules
    except botocore.exceptions.ClientError as ex:
        if "ResourceNotFound" in ex.response['Error']['Code']:
            ex.response['Error']['Message'] = "Failed to list rules for EventBridge. Resource not found."
        else:
            ex.response["Error"]["Message"] = "InternalError"
            ex.response["Error"]["Code"] = "InternalError"
        raise ex


def get_topic_subscriptions(topic_arn: str) -> list[dict]:
    try:
        subscriptions = []
        next_token = None
        while True:
            response = AWS_SNS_CLIENT.list_subscriptions_by_topic(TopicArn=topic_arn) if not next_token else AWS_SNS_CLIENT.list_subscriptions_by_topic(TopicArn=topic_arn, NextToken=next_token)
            subscriptions = subscriptions + response.get("Subscriptions", [])
            next_token = response.get("NextToken")
            if not next_token:
                break
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


def fetch_rule_targets(rule_name: str) -> list[dict]:
    try:
        targets = []
        next_token = None
        while True:
            response = AWS_EVENT_BRIDGE_CLIENT.list_targets_by_rule(Rule=rule_name) if not next_token else AWS_EVENT_BRIDGE_CLIENT.list_targets_by_rule(Rule=rule_name, NextToken=next_token)
            targets = targets + response.get("Targets", [])
            next_token = response.get("NextToken")
            if not next_token:
                break
        return targets   
    except botocore.exceptions.ClientError as ex:
        if "NotFound" in ex.response['Error']['Code']:
            ex.response['Error']['Message'] = "Failed to fetch all targets for a rule. Resource not found."
        else:
            ex.response["Error"]["Message"] = "InternalError"
            ex.response["Error"]["Code"] = "InternalError"
        raise ex


def subscription_is_confirmed(subscription_arn: str) -> bool:
    try:
        response = AWS_SNS_CLIENT.get_subscription_attributes(SubscriptionArn=subscription_arn)
        attributes = response.get("Attributes")
        logger.info("Subscription attributes: %s", attributes)
        return attributes != None and attributes.get("PendingConfirmation") == "false"
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


def rule_is_configured_to_notify_authorized_personnel(rule_name: str) -> bool:
    targets = fetch_rule_targets(rule_name)

    for target in targets:
        logger.info("Checking rule target: %s", target)
        # is target an SNS input transformer?
        target_arn: str = target.get("Arn", "")
        if target_arn.startswith("arn:aws:sns:"):
            # yes, get a list of topic subscriptions
            subscriptions = get_topic_subscriptions(target_arn)
            # then search topic for a subscription with "email" protocol and is confirmed
            for subscription in subscriptions:
                logger.info("Checking target subscriptions: %s", subscription)
                if subscription.get("Protocol") == "email" and subscription_is_confirmed(subscription.get("SubscriptionArn")):
                    return True

    return False


def get_rule_names(rule_names_file_path: str) -> list[str]:
    bucket, key = extract_bucket_name_and_key(rule_names_file_path)
    response = AWS_S3_CLIENT.get_object(Bucket=bucket, Key=key)
    rule_names = response.get("Body").read().decode("utf-8").splitlines()
    return rule_names


def lambda_handler(event, context):
    """
    This function is the main handler for the Lambda function.
    It will call the appropriate functions based on the event type. Keyword arguments:
    event -- the event variable given in the lambda handler
    context -- the context variable given in the lambda handler
    """

    global AWS_CONFIG_CLIENT
    global AWS_S3_CLIENT
    global AWS_SNS_CLIENT
    global AWS_EVENT_BRIDGE_CLIENT
    global AWS_ACCOUNT_ID
    global EXECUTION_ROLE_NAME
    global AUDIT_ACCOUNT_ID

    evaluations = []
    rule_parameters = {}
    invoking_event = json.loads(event["invokingEvent"])
    logger.info("Received Event: %s", json.dumps(event, indent=2))

    # is this a scheduled invocation?
    if not is_scheduled_notification(invoking_event["messageType"]):
        # no, do not proceed
        return

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
    AWS_EVENT_BRIDGE_CLIENT = get_client("events", event)
    AWS_SNS_CLIENT = get_client("sns", event)

    file_param_name = "s3ObjectPath"
    rule_names_file_path = valid_rule_parameters.get(file_param_name, "")

    if not check_s3_object_exists(rule_names_file_path):
        logger.info(f"No {file_param_name} input provided.")
        evaluations.append(
            build_evaluation(
                event["accountId"],
                "NON_COMPLIANT",
                event,
                resource_type=DEFAULT_RESOURCE_TYPE,
                annotation=f"No {file_param_name} input provided.",
            )
        )

    else:
        rule_names = get_rule_names(rule_names_file_path)
        logger.info("rule_names from the file in s3: %s", rule_names)

        if not rule_names:
            logger.info("No rule names found in input file.")
            evaluations.append(
                build_evaluation(
                    event["accountId"],
                    "NON_COMPLIANT",
                    event,
                    resource_type=DEFAULT_RESOURCE_TYPE,
                    annotation=f"No rule names provided. The input file for {file_param_name} is empty.",
                )
            )

        else:
            event_bridge_rules = get_event_bridge_rules()
            num_compliant_rules = 0

            # TODO: Remove after testing is complete
            # for rule in event_bridge_rules:
            #     logger.info("rule_is_configured_to_notify_authorized_personnel: %s", rule_is_configured_to_notify_authorized_personnel(rule.get("Name", "")))

            for rule_name in rule_names:
                rule = next((r for r in event_bridge_rules if r.get("Name", "") == rule_name), None)
                logger.info("Processing EventBridge rule with name '%s': %s", rule_name, rule)

                if not rule:
                    evaluations.append(
                        build_evaluation(
                            event["accountId"],
                            "NON_COMPLIANT",
                            event,
                            resource_type=RULE_RESOURCE_TYPE,
                            annotation=f"Rule with name '{rule_name}' was not found in the EventBridge rule set.",
                        )
                    )
                elif rule.get("State") == "DISABLED":
                    evaluations.append(
                        build_evaluation(
                            event["accountId"],
                            "NON_COMPLIANT",
                            event,
                            resource_type=RULE_RESOURCE_TYPE,
                            annotation=f"Rule with name '{rule_name}' is 'DISABLED' in the EventBridge rule set.",
                        )
                    )
                elif not rule_is_configured_to_notify_authorized_personnel(rule_name):
                    evaluations.append(
                        build_evaluation(
                            event["accountId"],
                            "NON_COMPLIANT",
                            event,
                            resource_type=RULE_RESOURCE_TYPE,
                            annotation=f"Rule with name '{rule_name}' is NOT configured to send notifications.",
                        )
                    )
                else:
                    num_compliant_rules = num_compliant_rules + 1
                    evaluations.append(
                        build_evaluation(
                            event["accountId"],
                            "COMPLIANT",
                            event,
                            resource_type=RULE_RESOURCE_TYPE,
                            annotation=f"Rule with name '{rule_name}' is enabled and configured to send notifications.",
                        )
                    )

            if len(rule_names) == num_compliant_rules:
                evaluations.append(
                    build_evaluation(
                        event["accountId"],
                        "COMPLIANT",
                        event,
                        resource_type=DEFAULT_RESOURCE_TYPE,
                        annotation="All required rules are enabled and configured with an SNS topic and subscription to send notification",
                    )
                )
            else:
                evaluations.append(
                    build_evaluation(
                        event["accountId"],
                        "NON_COMPLIANT",
                        event,
                        resource_type=DEFAULT_RESOURCE_TYPE,
                        annotation="NOT all required rules are enabled and configured with an SNS topic and subscription to send notification",
                    )
                )

    AWS_CONFIG_CLIENT.put_evaluations(
        Evaluations=evaluations,
        ResultToken=event["resultToken"]
    )
