""" GC10 - check Cyber Center Sensors
"""

import json
import logging
import re
import time

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


def get_client_for_account(service: str, account_id: str | int, execution_role_name: str):
    execution_role_arn = f"arn:aws:iam::{account_id}:role/{execution_role_name}"
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
    if role_arn is None:
        logger.info("Role ARN is None")
        return {}
    role_session_name = "config-lambda-execution"
    sts_client = boto3.client("sts")
    try:
        assume_role_response = sts_client.assume_role(RoleArn=role_arn, RoleSessionName=role_session_name)
        return assume_role_response["Credentials"]
    except botocore.exceptions.ClientError as ex:
        # Scrub error message for any internal account info leaks
        if "AccessDenied" in ex.response["Error"]["Code"]:
            ex.response["Error"]["Message"] = "AWS Config does not have permission to assume the IAM role."
        else:
            ex.response["Error"]["Message"] = "InternalError"
            ex.response["Error"]["Code"] = "InternalError"
        raise ex


# Check whether the message is a ScheduledNotification or not.
def is_scheduled_notification(message_type):
    """Check whether the message is a ScheduledNotification or not.
    Keyword arguments:
    message_type -- the message type string
    """
    return message_type == "ScheduledNotification"


def evaluate_parameters(rule_parameters):
    """Evaluate the rule parameters dictionary validity. Raise a ValueError for invalid parameters.
    Keyword arguments:
    rule_parameters -- the Key/Value dictionary of the Config Rules parameters
    """
    if "S3LogBucketsPath" not in rule_parameters:
        logger.error('The parameter with "S3LogBucketsPath" as key must be defined.')
        raise ValueError('The parameter with "S3LogBucketsPath" as key must be defined.')
    if not rule_parameters["S3LogBucketsPath"]:
        logger.error('The parameter "S3LogBucketsPath" must have a defined value.')
        raise ValueError('The parameter "S3LogBucketsPath" must have a defined value.')
    if "LogArchiveAccountName" not in rule_parameters:
        logger.error('The parameter with "LogArchiveAccountName" as key must be defined.')
        raise ValueError('The parameter with "LogArchiveAccountName" as key must be defined.')
    if not rule_parameters["LogArchiveAccountName"]:
        logger.error('The parameter "LogArchiveAccountName" must have a defined value.')
        raise ValueError('The parameter "LogArchiveAccountName" must have a defined value.')
    return rule_parameters


def check_s3_object_exists(aws_s3_client, object_path: str) -> bool:
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
        aws_s3_client.head_object(Bucket=bucket_name, Key=key_name)
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


def get_lines_from_s3_file(aws_s3_client, s3_file_path: str) -> list[str]:
    bucket, key = extract_bucket_name_and_key(s3_file_path)
    response = aws_s3_client.get_object(Bucket=bucket, Key=key)
    return response.get("Body").read().decode("utf-8").splitlines()


# This generate an evaluation for config
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


def get_organizations_mgmt_account_id(aws_organizations_client):
    """Calls the AWS Organizations API to obtain the Management Account ID"""
    management_account_id = ""
    i_retry_limit = 10
    i_retries = 0
    b_completed = False
    b_retry = True
    while (b_retry and (not b_completed)) and (i_retries < i_retry_limit):
        try:
            response = aws_organizations_client.describe_organization()
            if response:
                organization = response.get("Organization", None)
                if organization:
                    management_account_id = organization.get("MasterAccountId", "")
                else:
                    logger.error("Unable to read the Organization from the dict")
            else:
                logger.error("Invalid response.")
            b_completed = True
        except botocore.exceptions.ClientError as ex:
            if "AccessDenied" in ex.response["Error"]["Code"]:
                logger.error("ACCESS DENIED when trying to describe_organization")
                management_account_id = "ERROR"
                b_retry = False
            elif "AWSOrganizationsNotInUse" in ex.response["Error"]["Code"]:
                logger.error("AWS Organizations not in use")
                management_account_id = "ERROR"
                b_retry = False
            elif "ServiceException" in ex.response["Error"]["Code"]:
                logger.error("AWS Organizations Service Exception")
                management_account_id = "ERROR"
                b_retry = False
            elif ("ConcurrentModification" in ex.response["Error"]["Code"]) or (
                "TooManyRequests" in ex.response["Error"]["Code"]
            ):
                # throttling
                logger.info("AWS Organizations API is throttling requests or going through a modification. Will retry.")
                time.sleep(2)
                if i_retries >= i_retry_limit:
                    logger.error("Retry limit reached. Returning an error")
                    management_account_id = "ERROR"
                    b_retry = False
                else:
                    i_retries += 1
        except ValueError:
            logger.error("Unknown exception - get_organizations_mgmt_account_id.")
            management_account_id = "ERROR"
    return management_account_id


def organizations_list_all_accounts(
    organizations_client, interval_between_calls: float = 0.25
) -> list[dict]:
    """
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/organizations/paginator/ListAccounts.html
    """
    resources: list[dict] = []
    paginator = organizations_client.get_paginator("list_accounts")
    page_iterator = paginator.paginate()
    for page in page_iterator:
        resources.extend(page.get("Accounts", []))
        time.sleep(interval_between_calls)
    return resources


def iam_list_all_roles(iam_client, page_size: int = 100, interval_between_calls: float = 0.25) -> list[dict]:
    """
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/iam/paginator/ListRoles.html
    """
    resources: list[dict] = []
    paginator = iam_client.get_paginator("list_roles")
    page_iterator = paginator.paginate(PaginationConfig={"PageSize": page_size})
    for page in page_iterator:
        resources.extend(page.get("Roles", []))
        time.sleep(interval_between_calls)
    return resources


def s3_get_bucket_replication(s3_client, bucket_name) -> tuple[dict, None] | tuple[None, dict]:
    try:
        response = s3_client.get_bucket_replication(Bucket=bucket_name)
        return response["ReplicationConfiguration"], None
    except botocore.exceptions.ClientError as e:
        return None, e.response["Error"]["Message"]


def replication_config_exists_for_cyber_centre(config: dict) -> bool:
    # TODO: Implement this
    raise Exception("replication_config_exists_for_cyber_centre Not Implemented")


def assess_bucket_replication_policies(s3_client, log_buckets: list[str], event: dict) -> tuple[list, bool]:
    resource_type = "AWS::S3::Bucket"
    evaluations = []
    all_resources_are_compliant = True

    for bucket_name in log_buckets:
        replication_config, error = s3_get_bucket_replication(s3_client, bucket_name)
        if error:
            compliance_type = "NON_COMPLIANT"
            annotation = f"An error occurred when querying the replication configuration for bucket '{bucket_name}' in the log archive account '{log_archive_account_name}'."
        elif replication_config_exists_for_cyber_centre(replication_config):
            compliance_type = "COMPLIANT"
            annotation = f"The replication configuration for bucket '{bucket_name}' was found."
        else:
            compliance_type = "NON_COMPLIANT"
            annotation = f"The replication configuration for bucket '{bucket_name}' was NOT found."

        logger.info(f"{compliance_type}: {annotation}. Error: %s", error)
        evaluations.append(build_evaluation(bucket_name, compliance_type, event, resource_type, annotation))
        if compliance_type == "NON_COMPLIANT":
            all_resources_are_compliant = False

    return evaluations, all_resources_are_compliant


def submit_evaluations(
    aws_config_client, result_token: str, evaluations: list[dict], interval_between_calls: float = 0.25
):
    max_evaluations_per_call = 100
    while evaluations:
        batch_of_evaluations, evaluations = (
            evaluations[:max_evaluations_per_call],
            evaluations[max_evaluations_per_call:],
        )
        aws_config_client.put_evaluations(Evaluations=batch_of_evaluations, ResultToken=result_token)
        if evaluations:
            time.sleep(interval_between_calls)


def lambda_handler(event, context):
    """
    Keyword arguments:
    event -- the event variable given in the lambda handler
    context -- the context variable given in the lambda handler
    """
    global AWS_ACCOUNT_ID
    global EXECUTION_ROLE_NAME
    global AUDIT_ACCOUNT_ID

    rule_parameters = json.loads(event.get("ruleParameters", "{}"))
    invoking_event = json.loads(event["invokingEvent"])
    logger.info("Received event: %s", json.dumps(event, indent=2))

    AWS_ACCOUNT_ID = event["accountId"]
    logger.info("Assessing account %s", AWS_ACCOUNT_ID)

    if not is_scheduled_notification(invoking_event["messageType"]):
        logger.error("Skipping assessments as this is not a scheduled invocation")
        return

    valid_rule_parameters = evaluate_parameters(rule_parameters)
    target_role_name = "cbs-global-reader"
    file_param_name = "S3LogBucketsPath"
    log_buckets_file_path = valid_rule_parameters.get(file_param_name, "")
    log_archive_account_name = valid_rule_parameters["LogArchiveAccountName"]
    EXECUTION_ROLE_NAME = valid_rule_parameters.get("ExecutionRoleName", "AWSA-GCLambdaExecutionRole")
    AUDIT_ACCOUNT_ID = valid_rule_parameters.get("AuditAccountID", "")

    aws_organizations_client = get_client("organizations", event)

    if AWS_ACCOUNT_ID != get_organizations_mgmt_account_id(aws_organizations_client):
        # We're not in the Management Account
        logger.info(
            "Cyber Center Sensors not checked in account %s as this is not the Management Account", AWS_ACCOUNT_ID
        )
        return

    aws_config_client = get_client("config", event)
    # Not using get_client to get S3 client for the Audit account
    aws_s3_client_for_audit_account = boto3.client("s3")

    if not check_s3_object_exists(aws_s3_client_for_audit_account, log_buckets_file_path):
        annotation = f"No file found for s3 path '{log_buckets_file_path}' via '{file_param_name}' input parameter."
        logger.info(f"NON_COMPLIANT: {annotation}")
        evaluations = [build_evaluation(AWS_ACCOUNT_ID, "NON_COMPLIANT", event, ACCOUNT_RESOURCE_TYPE, annotation)]
        submit_evaluations(aws_config_client, event["resultToken"], evaluations)
        return

    accounts = organizations_list_all_accounts(aws_organizations_client)
    log_archive_account = next((x for x in accounts if x.get("Name", "") == log_archive_account_name), None)

    if not log_archive_account:
        annotation = f"A log archive account with name '{log_archive_account_name}' does not exist in the organization."
        logger.info(f"NON_COMPLIANT: {annotation}")
        evaluations = [build_evaluation(AWS_ACCOUNT_ID, "NON_COMPLIANT", event, ACCOUNT_RESOURCE_TYPE, annotation)]
        submit_evaluations(aws_config_client, event["resultToken"], evaluations)
        return

    logger.info("A log archive account with name '%s' was found: %s", log_archive_account_name, log_archive_account)

    aws_iam_client_for_log_archive_account = get_client_for_account(
        "iam", log_archive_account["Id"], EXECUTION_ROLE_NAME
    )
    roles = iam_list_all_roles(aws_iam_client_for_log_archive_account)

    target_role = next((x for x in roles if x.get("RoleName", "") == target_role_name), None)

    if not target_role:
        annotation = f"A role with name '{target_role_name}' was not found in the log archive account '{log_archive_account_name}'."
        logger.info(f"NON_COMPLIANT: {annotation}")
        evaluations = [build_evaluation(AWS_ACCOUNT_ID, "NON_COMPLIANT", event, ACCOUNT_RESOURCE_TYPE, annotation)]
        submit_evaluations(aws_config_client, event["resultToken"], evaluations)
        return

    log_buckets = set(get_lines_from_s3_file(aws_s3_client_for_audit_account, log_buckets_file_path))
    logger.info("log_buckets from the file in s3: %s", log_buckets)

    aws_s3_client_for_log_archive_account = get_client_for_account("s3", log_archive_account["Id"], EXECUTION_ROLE_NAME)

    evaluations, all_s3_resources_are_compliant = assess_bucket_replication_policies(
        aws_s3_client_for_log_archive_account, log_buckets, event
    )

    if all_s3_resources_are_compliant:
        compliance_type = "COMPLIANT"
        annotation = "All resources found are compliant."
    else:
        compliance_type = "NON_COMPLIANT"
        annotation = "Non-compliant resources found in scope."

    logger.info(f"{compliance_type}: {annotation}")
    evaluations.append(build_evaluation(AWS_ACCOUNT_ID, compliance_type, event, ACCOUNT_RESOURCE_TYPE, annotation))
    submit_evaluations(aws_config_client, event["resultToken"], evaluations)
