""" GC01 - Check MFA Digital Policy
"""

import json
import logging

from utils import is_scheduled_notification, check_required_parameters
from boto_util.client import get_client
from boto_util.config import build_evaluation, submit_evaluations
from boto_util.iam import account_has_federated_users

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

    rule_parameters = json.loads(event.get("ruleParameters", "{}"))
    valid_rule_parameters = check_required_parameters(rule_parameters, [])
    execution_role_name = valid_rule_parameters.get("ExecutionRoleName", "AWSA-GCLambdaExecutionRole")
    audit_account_id = valid_rule_parameters.get("AuditAccountID", "")
    aws_account_id = event["accountId"]
    is_not_audit_account = aws_account_id != audit_account_id
    evaluations = []

    aws_config_client = get_client("config", aws_account_id, execution_role_name)
    aws_iam_client = get_client("iam", aws_account_id, execution_role_name)

    compliance_type = "COMPLIANT"
    annotation = (
        "Dependent on the compliance of the Federated IdP."
        if account_has_federated_users(aws_iam_client)
        else "No federated IdP found."
    )

    logger.info(f"{compliance_type}: {annotation}")
    evaluations.append(build_evaluation(aws_account_id, compliance_type, event, annotation=annotation))
    submit_evaluations(aws_config_client, event["resultToken"], evaluations)
