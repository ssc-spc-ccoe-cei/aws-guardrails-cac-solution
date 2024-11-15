""" GC13 - Check Emergency Account Alerts Lambda Function
    Confirm that administrative access to cloud environments is from approved and trusted locations and devices
"""

import json
import logging
import re
import ipaddress

import boto3
import botocore

# Logging setup
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Set to True to get the lambda to assume the Role attached on the Config Service
ASSUME_ROLE_MODE = True
DEFAULT_RESOURCE_TYPE = "AWS::::Account"
TRAIL_RESOURCE_TYPE = "AWS::CloudTrail::Trail"


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
    """Returns the credentials required to assume the passed role
    Keyword arguments:
    role_arn -- the arn of the role to assume"""
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


def get_console_login_cloud_trail_events() -> list[dict]:
    """Fetches a list of all cloud trail events in the account"""
    lookup_attributes = [{"AttributeKey": "EventName", "AttributeValue": "ConsoleLogin"}]
    try:
        values = []
        next_token = None
        while True:
            response = (
                AWS_CLOUDTRAIL_CLIENT.lookup_events(LookupAttributes=lookup_attributes)
                if not next_token
                else AWS_CLOUDTRAIL_CLIENT.lookup_events(LookupAttributes=lookup_attributes, NextToken=next_token)
            )
            values = values + response.get("Events", [])
            next_token = response.get("NextToken")
            if not next_token:
                break
        return values
    except botocore.exceptions.ClientError as ex:
        if "InvalidLookupAttributes" in ex.response["Error"]["Code"]:
            ex.response["Error"]["Message"] = "Invalid lookup attributes provided."
        elif "InvalidTimeRange" in ex.response["Error"]["Code"]:
            ex.response["Error"]["Message"] = "Invalid time range provided."
        elif "InvalidMaxResults" in ex.response["Error"]["Code"]:
            ex.response["Error"]["Message"] = "Invalid max results value provided."
        elif "InvalidNextToken" in ex.response["Error"]["Code"]:
            ex.response["Error"]["Message"] = "Invalid next token provided."
        elif "InvalidEventCategory" in ex.response["Error"]["Code"]:
            ex.response["Error"]["Message"] = "Invalid event category provided."
        elif "UnsupportedOperation" in ex.response["Error"]["Code"]:
            ex.response["Error"]["Message"] = "lookup_events operation not supported by CloudTrails."
        elif "OperationNotPermitted" in ex.response["Error"]["Code"]:
            ex.response["Error"]["Message"] = "lookup_events operation not permitted."
        else:
            ex.response["Error"]["Message"] = "InternalError"
            ex.response["Error"]["Code"] = "InternalError"
        raise ex


def get_lines_from_s3_file(s3_file_path: str) -> list[str]:
    bucket, key = extract_bucket_name_and_key(s3_file_path)
    response = AWS_S3_CLIENT.get_object(Bucket=bucket, Key=key)
    return response.get("Body").read().decode("utf-8").splitlines()


def ip_is_within_ranges(ip_addr: str, ip_cidr_ranges: list[str]) -> bool:
    """Return true if the given IP Address is within the at least one of the given CIDR ranges, otherwise returns false"""
    for ip_range in ip_cidr_ranges:
        ip_network = ipaddress.ip_network(ip_range)
        if ipaddress.ip_address(ip_addr) in ip_network:
            return True
    return False


def account_has_federated_entra_id_users(user_name: str) -> bool:
    return True


def lambda_handler(event, context):
    """
    This function is the main handler for the Lambda function.
    It will call the appropriate functions based on the event type. Keyword arguments:
    event -- the event variable given in the lambda handler
    context -- the context variable given in the lambda handler
    """

    global AWS_CONFIG_CLIENT
    global AWS_S3_CLIENT
    global AWS_CLOUDTRAIL_CLIENT
    global AWS_ACCOUNT_ID
    global EXECUTION_ROLE_NAME
    global AUDIT_ACCOUNT_ID

    evaluations = []
    invoking_event = json.loads(event["invokingEvent"])
    logger.info("Received Event: %s", json.dumps(event, indent=2))

    # is this a scheduled invocation?
    if not is_scheduled_notification(invoking_event["messageType"]):
        # no, do not proceed
        return

    # parse parameters
    AWS_ACCOUNT_ID = event["accountId"]
    rule_parameters = json.loads(event["ruleParameters"]) if "ruleParameters" in event else {}
    valid_rule_parameters = evaluate_parameters(rule_parameters)

    EXECUTION_ROLE_NAME = valid_rule_parameters.get("ExecutionRoleName", "AWSA-GCLambdaExecutionRole")
    AUDIT_ACCOUNT_ID = valid_rule_parameters.get("AuditAccountID", "")

    AWS_CONFIG_CLIENT = get_client("config", event)
    AWS_S3_CLIENT = boto3.client("s3")
    AWS_CLOUDTRAIL_CLIENT = get_client("cloudtrail", event)

    file_param_name = "s3ObjectPath"
    vpn_ip_ranges_file_path = valid_rule_parameters.get(file_param_name, "")

    if not check_s3_object_exists(vpn_ip_ranges_file_path):
        annotation = f"No file found for s3 path '{vpn_ip_ranges_file_path}' via '{file_param_name}' input parameter."
        logger.info(annotation)
        evaluations.append(build_evaluation(AWS_ACCOUNT_ID, "NON_COMPLIANT", event, DEFAULT_RESOURCE_TYPE, annotation))
        AWS_CONFIG_CLIENT.put_evaluations(Evaluations=evaluations, ResultToken=event["resultToken"])
        return

    vpn_ip_ranges = get_lines_from_s3_file(vpn_ip_ranges_file_path)
    logger.info("vpn_ip_ranges from the file in s3: %s", vpn_ip_ranges)

    if not vpn_ip_ranges:
        annotation = "No ip ranges found in input file."
        logger.info(annotation)
        evaluations.append(build_evaluation(AWS_ACCOUNT_ID, "NON_COMPLIANT", event, DEFAULT_RESOURCE_TYPE, annotation))
        AWS_CONFIG_CLIENT.put_evaluations(Evaluations=evaluations, ResultToken=event["resultToken"])
        return

    bg_account_names = [valid_rule_parameters["BgUser1"], valid_rule_parameters["BgUser2"]]
    console_login_cloud_trail_events = get_console_login_cloud_trail_events()
    cloud_trail_events = [e for e in console_login_cloud_trail_events if e.get("Username") not in bg_account_names]
    num_compliant_rules = 0
    logger.info("Number of events found: %s", len(cloud_trail_events))

    for lookup_event in cloud_trail_events:
        ct_event = json.loads(lookup_event.get("CloudTrailEvent", "{}"))
        # logger.info("lookup_event: %s", lookup_event)
        # logger.info("ct_event: %s", ct_event)

        if not ip_is_within_ranges(ct_event["sourceIPAddress"], vpn_ip_ranges):
            annotation = f"Cloud Trail Event has a source IP address outside of the allowed ranges."
            # evaluations.append(
            #     build_evaluation(ct_event.get("EventId"), "NON_COMPLIANT", event, TRAIL_RESOURCE_TYPE, annotation)
            # )
        else:
            num_compliant_rules = num_compliant_rules + 1
            annotation = f"Cloud Trail Event has a source IP address inside of the allowed ranges."
            if account_has_federated_entra_id_users(lookup_event["Username"]):
                annotation = f"{annotation} Dependent on the compliance of the Federated IdP."
            # evaluations.append(
            #     build_evaluation(ct_event.get("EventId"), "COMPLIANT", event, TRAIL_RESOURCE_TYPE, annotation)
            # )
        logger.info(annotation)

    if len(cloud_trail_events) == num_compliant_rules:
        annotation = "All Cloud Trail Events are within the allowed source IP address ranges or are dependant on the federated identity provider."
        evaluations.append(build_evaluation(AWS_ACCOUNT_ID, "COMPLIANT", event, DEFAULT_RESOURCE_TYPE, annotation))
    else:
        annotation = "NOT all Cloud Trail Events are within the allowed source IP address ranges."
        evaluations.append(build_evaluation(AWS_ACCOUNT_ID, "NON_COMPLIANT", event, DEFAULT_RESOURCE_TYPE, annotation))
    logger.info(annotation)

    AWS_CONFIG_CLIENT.put_evaluations(Evaluations=evaluations, ResultToken=event["resultToken"])
