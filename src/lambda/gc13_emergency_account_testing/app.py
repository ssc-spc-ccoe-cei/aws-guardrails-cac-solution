""" GC13 - Emergency Account Testing Lambda Function
    Verifies that testing of emergency accounts took place and that periodic testing is included
"""
import json
import logging
import re
from datetime import datetime, timedelta

import boto3
import botocore

# Logging setup
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Set to True to get the lambda to assume the Role attached on the Config Service
ASSUME_ROLE_MODE = True
DEFAULT_RESOURCE_TYPE = "AWS::::Account"
IAM_USER_RESOURCE_TYPE = "AWS::IAM::User"


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


def get_iam_users_in_bg_list(bg_accounts: list[str]) -> list[dict]:
    """Get a list of IAM users in the account."""
    result_iam_users = []
    try:
        response = AWS_IAM_CLIENT.list_users()
        b_more_data = True
        while b_more_data:
            if response:
                logger.info("Found %s IAM users in account %s", len(response.get("Users")), AWS_ACCOUNT_ID)
                users = response.get("Users")
                if users:
                    for user in users:
                        if user.get("UserName") in bg_accounts:
                            result_iam_users.append({
                                "UserName": user.get("UserName"),
                                "UserId": user.get("UserId"),
                                "Arn": user.get("Arn"),
                                "PasswordLastUsed": user.get("PasswordLastUsed", None),
                            })
                    if response.get("IsTruncated"):
                        marker = response.get("Marker")
                        response = AWS_IAM_CLIENT.list_users(Marker=marker)
                    else:
                        b_more_data = False
                else:
                    logger.info("No IAM users found in account %s", AWS_ACCOUNT_ID)
                    b_more_data = False
            else:
                logger.error("Empty response while trying to list_users in account %s", AWS_ACCOUNT_ID)
                b_more_data = False
    except botocore.exceptions.ClientError as ex:
        logger.error("Error while trying to list_users. %s", ex)
        raise ex
    return result_iam_users


def get_lines_in_s3_file(s3_file_path: str) -> list[str]:
    bucket, key = extract_bucket_name_and_key(s3_file_path)
    response = AWS_S3_CLIENT.get_object(Bucket=bucket, Key=key)
    lines = response.get("Body").read().decode("utf-8").splitlines()
    return lines


def last_use_of_password_is_within_one_year(password_last_used_date: str | None) -> bool:
    if not password_last_used_date:
        return False
    last_used_date = datetime.fromisoformat(password_last_used_date)
    one_year_ago = datetime.now() - timedelta(days=365)
    return last_used_date > one_year_ago


def lambda_handler(event, context):
    """
    This function is the main handler for the Lambda function.
    It will call the appropriate functions based on the event type. Keyword arguments:
    event -- the event variable given in the lambda handler
    context -- the context variable given in the lambda handler
    """

    global AWS_CONFIG_CLIENT
    global AWS_S3_CLIENT
    global AWS_IAM_CLIENT
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
    AWS_IAM_CLIENT = get_client("iam", event)

    file_param_name = "s3ObjectPath"
    account_names_file_path = valid_rule_parameters.get(file_param_name, "")

    if not check_s3_object_exists(account_names_file_path):
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
        bg_account_names = get_lines_in_s3_file(account_names_file_path)
        logger.info("bg_account_names from the file in s3: %s", bg_account_names)

        if not bg_account_names:
            logger.info("No account names found in input file.")
            evaluations.append(
                build_evaluation(
                    event["accountId"],
                    "NON_COMPLIANT",
                    event,
                    resource_type=DEFAULT_RESOURCE_TYPE,
                    annotation=f"No account names provided. The input file for {file_param_name} is empty.",
                )
            )

        else:
            iam_users = get_iam_users_in_bg_list(bg_account_names)
            num_compliant = 0

            for account_name in bg_account_names:
                iam_account = next((r for r in iam_users if r.get("Name", "") == account_name), None)
                logger.info("Processing account with name '%s': %s", account_name, iam_account)

                if not iam_account:
                    evaluations.append(
                        build_evaluation(
                            event["accountId"],
                            "NON_COMPLIANT",
                            event,
                            resource_type=IAM_USER_RESOURCE_TYPE,
                            annotation=f"Account with name '{account_name}' was NOT found in the IAM account set.",
                        )
                    )
                elif not last_use_of_password_is_within_one_year(iam_account.get("PasswordLastUsed")):
                    evaluations.append(
                        build_evaluation(
                            event["accountId"],
                            "NON_COMPLIANT",
                            event,
                            resource_type=IAM_USER_RESOURCE_TYPE,
                            annotation=f"Account with name '{account_name}' has NOT used it's password within 1 year.",
                        )
                    )
                else:
                    num_compliant = num_compliant + 1
                    evaluations.append(
                        build_evaluation(
                            event["accountId"],
                            "COMPLIANT",
                            event,
                            resource_type=IAM_USER_RESOURCE_TYPE,
                            annotation=f"Account with name '{account_name}' exists and has used it's password within 1 year.",
                        )
                    )

            if len(bg_account_names) == num_compliant:
                evaluations.append(
                    build_evaluation(
                        event["accountId"],
                        "COMPLIANT",
                        event,
                        resource_type=DEFAULT_RESOURCE_TYPE,
                        annotation="All break-glass accounts exist and have used their password within 1 year.",
                    )
                )
            else:
                evaluations.append(
                    build_evaluation(
                        event["accountId"],
                        "NON_COMPLIANT",
                        event,
                        resource_type=DEFAULT_RESOURCE_TYPE,
                        annotation="NOT all break-glass accounts exist and have used their password within 1 year.",
                    )
                )

    AWS_CONFIG_CLIENT.put_evaluations(
        Evaluations=evaluations,
        ResultToken=event["resultToken"]
    )
