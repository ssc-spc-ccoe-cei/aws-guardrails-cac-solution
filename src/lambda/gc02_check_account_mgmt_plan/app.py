""" GC02 - Check Account Management Plan
    https://canada-ca.github.io/cloud-guardrails/EN/02_Management-Admin-Privileges.html
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
    Keyword arguments:

    event -- the event variable given in the lambda handler

    context -- the context variable given in the lambda handler
    """
    logger.info("Received Event: %s", json.dumps(event, indent=2))

    rule_parameters = json.loads(event.get("ruleParameters", "{}"))
    valid_rule_parameters = check_required_parameters(rule_parameters, ["s3ObjectPath"], logger)
    execution_role_name = valid_rule_parameters.get("ExecutionRoleName", "AWSA-GCLambdaExecutionRole")
    audit_account_id = valid_rule_parameters.get("AuditAccountID", "")
    invoking_event = json.loads(event["invokingEvent"])
    aws_account_id = event["accountId"]
    evaluations = []

    compliance_type = "NOT_APPLICABLE"
    annotation = "Guardrail only applicable in the Audit Account"

    if not is_scheduled_notification(invoking_event["messageType"]):
        logger.error("Skipping assessments as this is not a scheduled invocation")
        return

    if aws_account_id != audit_account_id:
        logger.info(
            "Account management plan document not checked in account %s - not the Audit account", aws_account_id
        )
        return

    aws_config_client = get_client("config", aws_account_id, execution_role_name)
    aws_s3_client = get_client("s3", aws_account_id, execution_role_name)

    if check_s3_object_exists(aws_s3_client, valid_rule_parameters["s3ObjectPath"]):
        compliance_type = "COMPLIANT"
        annotation = "Account management plan document found"
    else:
        compliance_type = "NON_COMPLIANT"
        annotation = "Account management plan document NOT found"

    logger.info(f"{compliance_type}: {annotation}")
    evaluations.append(build_evaluation(aws_account_id, compliance_type, event, annotation=annotation))
    submit_evaluations(aws_config_client, event["resultToken"], evaluations)
