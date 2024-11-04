""" GC01 - Check Monitoring And Logging
    https://github.com/canada-ca/cloud-guardrails/blob/master/EN/01_Protect-user-accounts-and-identities.md
"""
import json
import logging
import time

import boto3
import botocore

# Logging setup
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Set to True to get the lambda to assume the Role attached on the Config Service
ASSUME_ROLE_MODE = True
DEFAULT_RESOURCE_TYPE = "AWS::CloudTrail::Trail"


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

def list_cloudtrails():
    """Fetches a list of all trails in the account"""
    try:
        response = AWS_CLOUDTRAIL_CLIENT.list_trails()
        trails = response.get("Trails")
        next_token = response.get("NextToken")
        while next_token == None:
            response = AWS_CLOUDTRAIL_CLIENT.list_trails()
            trails = trails + response.get("Trails")
            next_token = response.get("NextToken")
        return trails
    except botocore.exceptions.ClientError as ex:
        if "UnsupportedOperationException" in ex.response['Error']['Code']:
            ex.response["Error"]["Message"] = "list_trails operation not supported by CloudTrails."
        elif "OperationNotPermittedException" in ex.response['Error']['Code']:
            ex.response["Error"]["Message"] = "list_trails operation not permitted."
        else:
            ex.response["Error"]["Message"] = "InternalError"
            ex.response["Error"]["Code"] = "InternalError"
            
        raise ex

def check_trail_status(trails, event):
    """Checks the status of the fetched trails"""    
    evaluations = []
    for t in trails:
        try:
            trail_name = t.get("Name", "")
            status = AWS_CLOUDTRAIL_CLIENT.get_trail_status(trail_name)
            if status.get("IsLogging", False):
                evaluations.append(
                    build_evaluation(
                        t.get("TrailARN", trail_name),
                        "COMPLIANT",
                        event,
                        resource_type=DEFAULT_RESOURCE_TYPE,
                        annotation="CloudTrail is logging"
                    )
                )
            else:
                evaluations.append(
                    build_evaluation(
                        t.get("TrailARN", trail_name),
                        "NON_COMPLIANT",
                        event,
                        resource_type=DEFAULT_RESOURCE_TYPE,
                        annotation="CloudTrail is not logging"
                    )
                )
        except botocore.exceptions.ClientError as ex:
            logger.error("Error while trying to fetch cloudtrail status.")
            logger.error(ex)
            raise ex
    return evaluations

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
    logger.debug("Received event: %s", event)

    global AWS_CONFIG_CLIENT
    global AWS_CLOUDTRAIL_CLIENT
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
    AWS_CLOUDTRAIL_CLIENT = get_client("cloudtrail", event)

    # is this a scheduled invokation?
    if is_scheduled_notification(invoking_event["messageType"]):
        # yes, proceed with checking CloudTrails
        # fetch all CloudTrails
        logger.info("Monitoring and logging check in account %s", AWS_ACCOUNT_ID)
        trails = list_cloudtrails()
        
        # doesl the account have any CloudTrails?
        if len(trails) < 0:
            # no, add NON_COMPLIANT results to evaluations
            evaluations.append(
                build_evaluation(
                    event["accountId"],
                    "NON_COMPLIANT",
                    event,
                    resource_type="AWS::::Account",
                    annotation="No CloudTrails found in account",
                )
            )
        else:
            # yes, check the status of all the trails and get evaluations results
            evaluations = evaluations + check_trail_status(trails, event)
            
        # Update AWS Config with the evaluation results
        AWS_CONFIG_CLIENT.put_evaluations(
            Evaluations=evaluations,
            ResultToken=event["resultToken"]
        )
