""" GC13 - Check Emergency Account Management Procedure Approvals Lambda Function
    Providing documents as evidence to support the Guardrails
"""

import json
import logging

from utils import is_scheduled_notification, check_required_parameters
from boto_util.client import get_client
from boto_util.config import build_evaluation, submit_evaluations
from boto_util.s3 import check_s3_object_exists

# Logging setup
logger = logging.getLogger()
logger.setLevel(logging.INFO)


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
        json.loads(event.get("ruleParameters", "{}")), ["ExecutionRoleName", "s3ObjectPath"]
    )
    execution_role_name = rule_parameters.get("ExecutionRoleName")
    audit_account_id = rule_parameters.get("AuditAccountID", "")
    aws_account_id = event["accountId"]
    is_not_audit_account = aws_account_id != audit_account_id

    evaluations = []

    # This check only applies to the audit account
    if is_not_audit_account:
        logger.info(
            "Emergency Account Management Procedure Approval not checked in account %s - not the Audit account",
            aws_account_id,
        )
        return

    aws_config_client = get_client("config")
    aws_s3_client = get_client("s3")

    if check_s3_object_exists(aws_s3_client, rule_parameters["s3ObjectPath"]):
        compliance_type = "COMPLIANT"
        annotation = "Emergency Account Management Procedure Approval found"
    else:
        compliance_type = "NON_COMPLIANT"
        annotation = "Emergency Account Management Procedure Approval NOT found"

    logger.info(f"{compliance_type}: {annotation}")
    evaluations.append(build_evaluation(aws_account_id, compliance_type, event, annotation=annotation))
    submit_evaluations(aws_config_client, event["resultToken"], evaluations)
