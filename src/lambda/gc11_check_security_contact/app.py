""" GC11 - Check Security Contact
    https://canada-ca.github.io/cloud-guardrails/EN/12_Cloud-Marketplace-Config.html
"""

import json
import logging

import boto3
import botocore

# Logging setup
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Set to True to get the lambda to assume the Role attached on the Config Service
ASSUME_ROLE_MODE = True
ACCOUNT_RESOURCE_TYPE = "AWS::::Account"


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
    """Returns the temporary credentials for the service account.
    Keyword arguments:
    role_arn -- the ARN of the service account
    """
    sts_client = boto3.client("sts")
    try:
        assume_role_response = sts_client.assume_role(RoleArn=role_arn, RoleSessionName="configLambdaExecution")
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
    """Check whether the message is a ScheduledNotification or not"""
    return message_type == "ScheduledNotification"


def evaluate_parameters(rule_parameters):
    """Evaluate the rule parameters dictionary.
    Keyword arguments:
    rule_parameters -- the Key/Value dictionary of the Config rule parameters
    """
    return rule_parameters


def check_security_contact(aws_account_client):
    """Check if the account has a security contact.
    Returns:
    True if the account has a security contact, False otherwise.
    """
    try:
        response = aws_account_client.get_alternate_contact(AlternateContactType="SECURITY")
    except botocore.exceptions.ClientError as err:
        if "ResourceNotFound" in err.response["Error"]["Code"]:
            return False
        else:
            raise ValueError(f"Unexpected error: {err}") from err
    else:
        if response:
            alternate_contact = response.get("AlternateContact", {})
            if (
                alternate_contact.get("AlternateContactType", "") == "SECURITY"
                and alternate_contact.get("EmailAddress", None)
                and alternate_contact.get("Name", None)
                and alternate_contact.get("PhoneNumber", None)
            ):
                return True
        else:
            raise ValueError("No response returned from get_alternate_contact.")
    return False


# This generates an evaluation for config
def build_evaluation(
    resource_id,
    compliance_type,
    event,
    resource_type=ACCOUNT_RESOURCE_TYPE,
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
    eval_cc["OrderingTimestamp"] = str(json.loads(event["invokingEvent"])["notificationCreationTime"])
    return eval_cc


def lambda_handler(event, context):
    """This function is the main entry point for Lambda.
    Keyword arguments:
    event -- the event variable given in the lambda handler
    context -- the context variable given in the lambda handler
    """
    global AWS_ACCOUNT_ID
    global EXECUTION_ROLE_NAME
    global AUDIT_ACCOUNT_ID

    rule_parameters = json.loads(event.get("ruleParameters", "{}"))
    invoking_event = json.loads(event["invokingEvent"])
    logger.info("Received Event: %s", json.dumps(event, indent=2))

    # parse parameters
    AWS_ACCOUNT_ID = event["accountId"]
    logger.info("Assessing account %s", AWS_ACCOUNT_ID)

    if not is_scheduled_notification(invoking_event["messageType"]):
        logger.error("Skipping assessments as this is not a scheduled invocation")
        return

    valid_rule_parameters = evaluate_parameters(rule_parameters)
    EXECUTION_ROLE_NAME = valid_rule_parameters.get("ExecutionRoleName", "AWSA-GCLambdaExecutionRole")
    AUDIT_ACCOUNT_ID = valid_rule_parameters.get("AuditAccountID", "")

    aws_config_client = get_client("config", event)
    aws_account_client = get_client("account", event)

    if check_security_contact(aws_account_client):
        compliance_type = "COMPLIANT"
        annotation = "Security contact registered"
    else:
        compliance_type = "NON_COMPLIANT"
        annotation = "Security contact NOT registered"

    logger.info(f"{compliance_type}: {annotation}")
    evaluations = [build_evaluation(AWS_ACCOUNT_ID, compliance_type, event, ACCOUNT_RESOURCE_TYPE, annotation)]

    aws_config_client.put_evaluations(Evaluations=evaluations, ResultToken=event["resultToken"])
