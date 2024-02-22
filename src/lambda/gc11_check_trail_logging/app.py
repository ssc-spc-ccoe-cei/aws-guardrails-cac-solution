""" GC11 - Check Trail Logging
    https://canada-ca.github.io/cloud-guardrails/EN/11_Logging-and-Monitoring.html
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


def get_assume_role_credentials(role_arn, region="ca-central-1"):
    """Returns the temporary credentials for the service account.
    Keyword arguments:
    role_arn -- the ARN of the service account
    region -- the region where the service account exists
    """
    sts_client = boto3.client("sts", region_name=region)
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
    # if 's3ObjectPath' not in rule_parameters:
    #     raise ValueError('The parameter with "s3ObjectPath" as key must be defined.')
    # if not rule_parameters['s3ObjectPath']:
    #     raise ValueError('The parameter "s3ObjectPath" must have a defined value.')
    return rule_parameters


def check_trail_logging():
    """Check whether all trails are logging."""
    traill_ist = []
    processed_trail_list = []
    b_all_trails_compliant = True
    try:
        response = AWS_CLOUDTRAIL_CLIENT.list_trails()
        next_token = response.get("NextToken")
        if response:
            for trail in response.get("Trails"):
                traill_ist.append(
                    {
                        "TrailName": trail.get("Name"),
                        "TrailARN": trail.get("TrailARN")
                    }
                )
        else:
            # return -1 indicating we were unable to query the trails
            return -1
        while next_token:
            response = AWS_CLOUDTRAIL_CLIENT.list_trails(NextToken=next_token)
            next_token = response.get("NextToken")
            if response:
                for trail in response.get("Trails"):
                    traill_ist.append(
                        {
                            "TrailName": trail.get("Name"),
                            "TrailARN": trail.get("TrailARN"),
                            "IsLogging": False,
                        }
                    )
            else:
                # return -1 indicating we were unable to query the trails
                return -1
    except botocore.exceptions.ClientError as err:
        # something has gone wrong
        raise ValueError(err) from err
    else:
        # do we have at least 1 trail?
        if len(traill_ist) > 0:
            # yes, check each trail we found
            for trail in traill_ist:
                b_logging = False
                try:
                    response = AWS_CLOUDTRAIL_CLIENT.get_trail_status(
                        Name=trail.get("TrailARN")
                    )
                except botocore.exceptions.ClientError as err:
                    # something has gone wrong
                    raise ValueError(err) from err
                else:
                    # do we have a response
                    if response:
                        # yes, check if logging
                        if response.get("IsLogging"):
                            # this trail is logging
                            b_logging = True
                        else:
                            b_all_trails_compliant = False
                    else:
                        # return -1 indicating we were unable to query the trails
                        return -1
                processed_trail_list.append(
                    {
                        "TrailName": trail.get("Name"),
                        "TrailARN": trail.get("TrailARN"),
                        "IsLogging": b_logging,
                    }
                )
        else:
            # we have no trails, return -1 indicating we were unable to query the trails
            return -1
    # return our result
    if b_all_trails_compliant:
        return 1
    else:
        return 0


# This generates an evaluation for config
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
    """Lambda handler to check CloudTrail trails are logging.
    Keyword arguments:
    event -- the event variable given in the lambda handler
    context -- the context variable given in the lambda handler
    """
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

    compliance_value = "NOT_APPLICABLE"
    custom_annotation = ""

    AWS_CONFIG_CLIENT = get_client("config", event)
    AWS_CLOUDTRAIL_CLIENT = get_client("cloudtrail", event)

    # is this a scheduled invokation?
    if is_scheduled_notification(invoking_event["messageType"]):
        # yes, proceed with checking the cloud trails
        result = check_trail_logging()
        if result == 1:
            # all trails are logging
            compliance_value = "COMPLIANT"
            custom_annotation = "All identified trails are logging"
        elif result == 0:
            compliance_value = "NON_COMPLIANT"
            custom_annotation = "Found trail(s) that are not logging"
        else:
            compliance_value = "NON_COMPLIANT"
            custom_annotation = "Unable to validate CloudTrail trails are logging"
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
        AWS_CONFIG_CLIENT.put_evaluations(Evaluations=evaluations, ResultToken=event["resultToken"])