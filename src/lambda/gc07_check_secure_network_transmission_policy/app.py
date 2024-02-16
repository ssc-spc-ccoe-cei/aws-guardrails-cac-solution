""" GC07 - Check Secure Network Transmission Policy
    https://canada-ca.github.io/cloud-guardrails/EN/07_Protect-Data-in-Transit.html
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
    """Returns the credentials required to assume the provided role.
    Keyword arguments:
    role_arn -- the arn of the role to assume
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
        logger.error("ERROR assuming role.\n%s", ex.response["Error"])
        raise ex


def is_scheduled_notification(message_type):
    """Return True if the message is a ScheduledNotification, False otherwise."""
    return message_type == "ScheduledNotification"


def evaluate_parameters(rule_parameters):
    """Evaluate the rule parameters dictionary validity. Raise a ValueError for invalid parameters.
    Keyword arguments:
    rule_parameters -- the Key/Value dictionary of the Config rule parameters
    """
    if "s3ObjectPath" not in rule_parameters:
        logger.error('The parameter with "s3ObjectPath" as key must be defined.')
        raise ValueError('The parameter with "s3ObjectPath" as key must be defined.')
    if not rule_parameters["s3ObjectPath"]:
        logger.error('The parameter "s3ObjectPath" must have a defined value.')
        raise ValueError('The parameter "s3ObjectPath" must have a defined value.')
    return rule_parameters


def check_s3_object_exists(object_path):
    """Check if the S3 object exists.
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
            raise
    else:
        # The object does exist.
        return True


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


def lambda_handler(event, context):
    """This function is the main entry point for Lambda.
    Keyword arguments:
    event -- the event variable given in the lambda handler
    context -- the context variable given in the lambda handler
    """
    global AWS_CONFIG_CLIENT
    global AWS_S3_CLIENT
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

    if "EXECUTION_ROLE_NAME" in valid_rule_parameters:
        EXECUTION_ROLE_NAME = valid_rule_parameters["ExecutionRoleName"]
    else:
        EXECUTION_ROLE_NAME = "AWSA-GCLambdaExecutionRole"

    if "AuditAccountID" in valid_rule_parameters:
        AUDIT_ACCOUNT_ID = valid_rule_parameters["AuditAccountID"]
    else:
        AUDIT_ACCOUNT_ID = ""

    compliance_value = "NOT_APPLICABLE"
    custom_annotation = "Guardrail only applicable in the Audit Account"

    # is this a scheduled invokation?
    if is_scheduled_notification(invoking_event["messageType"]):
        # yes, proceed
        # is this being executed against the Audit Account -
        # (this check only applies to the audit account)
        if AWS_ACCOUNT_ID == AUDIT_ACCOUNT_ID:
            # yes, we're in the Audit account
            AWS_CONFIG_CLIENT = get_client("config", event)
            AWS_S3_CLIENT = get_client("s3", event)

            # check if object exists in S3
            if check_s3_object_exists(valid_rule_parameters["s3ObjectPath"]):
                compliance_value = "COMPLIANT"
                custom_annotation = "Secure Network Transmission Policy found."
                logger.info('COMPLIANT - Secure Network Transmission Policy found in S3 at "%s"', valid_rule_parameters["s3ObjectPath"])
            else:
                compliance_value = "NON_COMPLIANT"
                custom_annotation = "Secure Network Transmission Policy NOT found"
                logger.info("NON_COMPLIANT - Secure Network Transmission Policy not found in S3")

            # Update AWS Config with the evaluation result
            evaluations.append(
                build_evaluation(
                    event["accountId"],
                    compliance_value,
                    event,
                    resource_type=DEFAULT_RESOURCE_TYPE,
                    annotation=custom_annotation,
                )
            )
            AWS_CONFIG_CLIENT.put_evaluations(
                Evaluations=evaluations,
                ResultToken=event["resultToken"]
            )
        else:
            logger.info("Secure network transmission policy not checked in account %s - not the Audit account", AWS_ACCOUNT_ID)
