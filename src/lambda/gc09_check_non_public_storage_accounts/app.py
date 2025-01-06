""" GC09 - Check Non Public Storage Accounts
"""

import json
import logging

# Logging setup
logger = logging.getLogger()
logger.setLevel(logging.INFO)

from utils import is_scheduled_notification, check_required_parameters
from boto_util.client import get_client
from boto_util.config import build_evaluation, submit_evaluations
from boto_util.s3 import list_all_s3_buckets


def check_bucket_acls(s3_client, bucket_name, event):
    resource_type = "AWS::S3::Bucket"
    response = s3_client.get_public_access_block(Bucket=bucket_name)
    configuration = response.get("PublicAccessBlockConfiguration", {})
    if (
        configuration.get("BlockPublicAcls", False)
        and configuration.get("IgnorePublicAcls", False)
        and configuration.get("BlockPublicPolicy", False)
        and configuration.get("RestrictPublicBuckets", False)
    ):
        return build_evaluation(bucket_name, "COMPLIANT", event, resource_type)
    else:
        return build_evaluation(
            bucket_name,
            "NON_COMPLIANT",
            event,
            resource_type,
            "S3 bucket has misconfigured public access block. Ensure that 'BlockPublicAcls', 'IgnorePublicAcls', 'BlockPublicPolicy', and 'RestrictPublicBuckets' are all enabled.",
        )


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
        json.loads(event.get("ruleParameters", "{}")), ["ExecutionRoleName"]
    )
    execution_role_name = rule_parameters.get("ExecutionRoleName")
    audit_account_id = rule_parameters.get("AuditAccountID", "")
    aws_account_id = event["accountId"]
    is_not_audit_account = aws_account_id != audit_account_id

    evaluations = []

    compliance_type = "COMPLIANT"
    annotation = "All S3 buckets have properly configured public access blocks."

    aws_config_client = get_client("config", aws_account_id, execution_role_name)
    aws_s3_client = get_client("s3", aws_account_id, execution_role_name)

    buckets = list_all_s3_buckets(aws_s3_client)
    for b in buckets:
        b_eval = check_bucket_acls(aws_s3_client, b.get("Name", ""), event)
        evaluations.append(b_eval)
        if b_eval.get("ComplianceType", "NON_COMPLIANT") == "NON_COMPLIANT":
            compliance_type = "NON_COMPLIANT"
            annotation = "One or more S3 buckets have misconfigured public access blocks."

    logger.info(f"{compliance_type}: {annotation}")
    evaluations.append(build_evaluation(aws_account_id, compliance_type, event, annotation=annotation))
    submit_evaluations(aws_config_client, event["resultToken"], evaluations)
