""" GC09 - Check Non Public Storage Accounts
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
S3_BUCKET_RESOURCE_TYPE = "AWS::S3::Bucket"


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
    """Returns the temporary credentials from ASSUME_ROLE_MODE
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
    """Checks whether the message is a ScheduledNotification or not.
    Keyword arguments:
    message_type -- the message type
    """
    return message_type == "ScheduledNotification"


def evaluate_parameters(rule_parameters):
    """Evaluate the rule parameters dictionary validity. Raise a ValueError for invalid parameters.
    Keyword arguments:
    rule_parameters -- the Key/Value dictionary of the Config Rules parameters
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

def get_buckets():
    buckets = []
    response = AWS_S3_CLIENT.list_buckets()
    while True:
        buckets = buckets + response.get('Buckets', [])
        continuationToken = response.get('ContinuationToken')
        if not continuationToken:
            break
        response = AWS_S3_CLIENT.list_buckets(ContinuationToken=continuationToken)
    
    return buckets

def check_bucket_acls(bucket_name, event):
    response = AWS_S3_CLIENT.get_public_access_block(Bucket=bucket_name)
    configuration = response.get("PublicAccessBlockConfiguration", {})
    if configuration.get("BlockPublicAcls", False) and configuration.get("IgnorePublicAcls", False) and configuration.get("BlockPublicPolicy", False) and configuration.get("RestrictPublicBuckets", False):
        return build_evaluation(
            bucket_name,
            "COMPLIANT",
            event,
            S3_BUCKET_RESOURCE_TYPE
        )
    else:
         return build_evaluation(
            bucket_name,
            "NON_COMPLIANT",
            event,
            S3_BUCKET_RESOURCE_TYPE,
            "S3 bucket has misconfigured public access block. Ensure that 'BlockPublicAcls', 'IgnorePublicAcls', 'BlockPublicPolicy', and 'RestrictPublicBuckets' are all enabled."
        )

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

    compliance_value = "COMPLIANT"
    custom_annotation = ""

    # is this a scheduled invokation?
    if is_scheduled_notification(invoking_event["messageType"]):
        AWS_CONFIG_CLIENT = get_client("config", event)
        AWS_S3_CLIENT = get_client("s3", event)
        
        
        buckets = get_buckets()
        for b in buckets:
            b_eval = check_bucket_acls(b.get("Name", ""), event)
            evaluations.append(b_eval)
            if b_eval.get("ComplianceType", "NON_COMPLIANT") == "NON_COMPLIANT":
                compliance_value = "NON_COMPLIANT"
                custom_annotation = "One or more S3 buckets have misconfigured public access blocks."
        
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
