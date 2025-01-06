""" GC10 - check Cyber Center Sensors
"""

import json
import logging

import botocore.exceptions

from utils import is_scheduled_notification, check_required_parameters
from boto_util.client import get_client
from boto_util.config import build_evaluation, submit_evaluations
from boto_util.organizations import get_organizations_mgmt_account_id, organizations_list_all_accounts
from boto_util.s3 import list_all_s3_buckets, get_lines_from_s3_file, check_s3_object_exists
from boto_util.iam import list_all_iam_roles

# Logging setup
logger = logging.getLogger()
logger.setLevel(logging.INFO)


def s3_get_bucket_replication(s3_client, bucket_name) -> tuple[dict, None] | tuple[None, dict]:
    try:
        response = s3_client.get_bucket_replication(Bucket=bucket_name)
        return response["ReplicationConfiguration"], None
    except botocore.exceptions.ClientError as e:
        return None, e.response["Error"]["Message"]


def replication_config_exists(config: dict) -> bool:
    rules: list[dict] = config.get("Rules", [])
    for rule in rules:
        if rule.get("Status", "") == "Enabled" and not rule.get("Filter", None) and not rule.get("Prefix", None):
            return True
    return False


def assess_bucket_replication_policies(s3_client, log_buckets: list[str], event: dict) -> tuple[list, bool]:
    resource_type = "AWS::S3::Bucket"
    evaluations = []
    all_resources_are_compliant = True

    all_buckets = [x.get("Name") for x in list_all_s3_buckets(s3_client)]
    logger.info("All Buckets: %s", all_buckets)

    for bucket_name in log_buckets:
        if bucket_name not in all_buckets:
            error = None
            compliance_type = "NON_COMPLIANT"
            annotation = f"Bucket '{bucket_name}' does not exist in the log archive account."
        else:
            replication_config, error = s3_get_bucket_replication(s3_client, bucket_name)
            if error:
                compliance_type = "NON_COMPLIANT"
                annotation = f"An error occurred when querying the replication configuration for bucket '{bucket_name}' in the log archive account."
            elif replication_config_exists(replication_config):
                compliance_type = "COMPLIANT"
                annotation = f"The replication configuration for bucket '{bucket_name}' was found."
            else:
                compliance_type = "NON_COMPLIANT"
                annotation = f"The replication configuration for bucket '{bucket_name}' was NOT found."

        if error:
            logger.info(f"{compliance_type}: {annotation} Error: %s", error)
        else:
            logger.info(f"{compliance_type}: {annotation}")
        evaluations.append(build_evaluation(bucket_name, compliance_type, event, resource_type, annotation))
        if compliance_type == "NON_COMPLIANT":
            all_resources_are_compliant = False

    return evaluations, all_resources_are_compliant


def lambda_handler(event, context):
    """
    This function is the main entry point for Lambda.

    Keyword arguments:

    event -- the event variable given in the lambda handler

    context -- the context variable given in the lambda handler
    """
    logger.info("Received Event: %s", json.dumps(event, indent=2))

    invoking_event = json.loads(event["invokingEvent"])
    if not is_scheduled_notification(invoking_event["messageType"]):
        logger.error("Skipping assessments as this is not a scheduled invocation")
        return

    rule_parameters = check_required_parameters(
        json.loads(event.get("ruleParameters", "{}")),
        ["ExecutionRoleName", "S3LogBucketsPath", "LogArchiveAccountName"],
    )
    execution_role_name = rule_parameters.get("ExecutionRoleName")
    audit_account_id = rule_parameters.get("AuditAccountID", "")
    aws_account_id = event["accountId"]
    is_not_audit_account = aws_account_id != audit_account_id

    target_role_name = "cbs-global-reader"
    file_param_name = "S3LogBucketsPath"
    log_buckets_s3_path = rule_parameters.get(file_param_name, "")
    log_archive_account_name = rule_parameters["LogArchiveAccountName"]

    aws_organizations_client = get_client("organizations", aws_account_id, execution_role_name, is_not_audit_account)

    if aws_account_id != get_organizations_mgmt_account_id(aws_organizations_client):
        # We're not in the Management Account
        logger.info(
            "Cyber Center Sensors not checked in account %s as this is not the Management Account", aws_account_id
        )
        return

    aws_config_client = get_client("config", aws_account_id, execution_role_name, is_not_audit_account)
    # Get the S3 client for the current (Audit) account where this lambda runs from
    aws_s3_client_for_audit_account = get_client("s3")

    if not check_s3_object_exists(aws_s3_client_for_audit_account, log_buckets_s3_path):
        annotation = f"No file found for s3 path '{log_buckets_s3_path}' via '{file_param_name}' input parameter."
        logger.info(f"NON_COMPLIANT: {annotation}")
        evaluations = [build_evaluation(aws_account_id, "NON_COMPLIANT", event, annotation=annotation)]
        submit_evaluations(aws_config_client, event["resultToken"], evaluations)
        return

    ###
    # Assert that the log archive account exists
    ###
    accounts = organizations_list_all_accounts(aws_organizations_client)
    log_archive_account = next((x for x in accounts if x.get("Name", "") == log_archive_account_name), None)

    if not log_archive_account:
        annotation = f"A log archive account with name '{log_archive_account_name}' does not exist in the organization."
        logger.info(f"NON_COMPLIANT: {annotation}")
        evaluations = [build_evaluation(aws_account_id, "NON_COMPLIANT", event, annotation=annotation)]
        submit_evaluations(aws_config_client, event["resultToken"], evaluations)
        return

    logger.info("A log archive account with name '%s' was found: %s", log_archive_account_name, log_archive_account)

    ###
    # Assert that the target_role_name role exists
    ###
    aws_iam_client_for_log_archive_account = get_client("iam", log_archive_account["Id"], execution_role_name)

    roles = list_all_iam_roles(aws_iam_client_for_log_archive_account)
    target_role = next((x for x in roles if x.get("RoleName", "") == target_role_name), None)

    if not target_role:
        annotation = f"A role with name '{target_role_name}' was not found in the log archive account '{log_archive_account_name}'."
        logger.info(f"NON_COMPLIANT: {annotation}")
        evaluations = [build_evaluation(aws_account_id, "NON_COMPLIANT", event, annotation=annotation)]
        submit_evaluations(aws_config_client, event["resultToken"], evaluations)
        return

    ###
    # Assert that buckets have the replication policy configured
    ###
    log_buckets = set(get_lines_from_s3_file(aws_s3_client_for_audit_account, log_buckets_s3_path))
    logger.info("log_buckets from the file in s3: %s", log_buckets)

    aws_s3_client_for_log_archive_account = get_client("s3", log_archive_account["Id"], execution_role_name)

    evaluations, all_s3_resources_are_compliant = assess_bucket_replication_policies(
        aws_s3_client_for_log_archive_account, log_buckets, event
    )

    ###
    # Create account evaluation and submit evaluations
    ###
    if all_s3_resources_are_compliant:
        compliance_type = "COMPLIANT"
        annotation = "All resources found are compliant."
    else:
        compliance_type = "NON_COMPLIANT"
        annotation = "Non-compliant resources found in scope."

    logger.info(f"{compliance_type}: {annotation}")
    evaluations.append(build_evaluation(aws_account_id, compliance_type, event, annotation=annotation))
    submit_evaluations(aws_config_client, event["resultToken"], evaluations)
