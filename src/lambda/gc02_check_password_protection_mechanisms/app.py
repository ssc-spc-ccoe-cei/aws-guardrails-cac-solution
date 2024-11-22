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


def is_guard_duty_enabled():
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
    
def list_cloudtrails():
    """Fetches a list of all trails in the account"""
    try:
        response = AWS_CLOUDTRAIL_CLIENT.list_trails()
        trails = response.get("Trails")
        next_token = response.get("NextToken")
        while next_token != None:
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

def trails_are_logging(trails):
    """Checks the status of the fetched trails"""    
    for t in trails:
        try:
            trail_arn = t.get("TrailARN")
            status = AWS_CLOUDTRAIL_CLIENT.get_trail_status(Name=trail_arn)
            if status.get("IsLogging", False):
                return False
        except botocore.exceptions.ClientError as ex:
            logger.error("Error while trying to fetch cloudtrail status.")
            logger.error(ex)
            raise ex
    return True    
    
def trails_configured_for_iam_events(trails):
    """Checks for a trails with the configuration required to capture IAM events and returns a filtered list"""    
    filtered_trails = []
    for t in trails:
        try:
            trail_arn = t.get("TrailARN")
            configuration = AWS_CLOUDTRAIL_CLIENT.get_trail(Name=trail_arn)
            if configuration.get("IncludeGlobalServiceEvents", False) and configuration.get("IsMultiRegionTrail", False) and configuration.get("IsOrganizationTrail", False):
                filtered_trails.append(t)
        except botocore.exceptions.ClientError as ex:
            logger.error("Error while trying to fetch cloudtrail configuration.")
            logger.error(ex)
            raise ex
    return True  

def is_cloudtrail_enabled():
    """Checks if cloudtrail is enabled to watch for iam login events"""
    trails = trails_configured_for_iam_events(list_cloudtrails())
    return len(trails) > 0 and trails_are_logging(trails)

def has_federated_idp():
    return True
        
def lambda_handler(event, context):
    """This function is the main entry point for Lambda.
    Keyword arguments:
    event -- the event variable given in the lambda handler
    context -- the context variable given in the lambda handler
    """
    logger.debug("Received event: %s", event)

    global AWS_CONFIG_CLIENT
    global AWS_GUARD_DUTY_CLIENT
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
    AWS_GUARD_DUTY_CLIENT = get_client("guardduty", event)
    AWS_CLOUDTRAIL_CLIENT = get_client("cloudtrail", event)
    
    # is this a scheduled invokation?
    if is_scheduled_notification(invoking_event["messageType"]):
        # is Guardduty enabled?
        if is_guard_duty_enabled() or is_cloudtrail_enabled():
            # yes, check if federated idp exists and add compliant evaluation
            annotation = ""
            if has_federated_idp():
                annotation="Dependent on the compliance of Federated IdP"
                
            evaluations.append(
                AWS_ACCOUNT_ID,
                "COMPLIANT",
                event,
                DEFAULT_RESOURCE_TYPE,
                annotation
            )
        else:
            # no, add non compliant evaluation
            evaluations.append(
                build_evaluation(
                    AWS_ACCOUNT_ID,
                    "NON_COMPLIANT",
                    event,
                    DEFAULT_RESOURCE_TYPE
                )
            )
            
        # Update AWS Config with the evaluation result
        logging.info("AWES Config updating evaluations: %s", evaluations)
        AWS_CONFIG_CLIENT.put_evaluations(
            Evaluations=evaluations,
            ResultToken=event["resultToken"]
        )