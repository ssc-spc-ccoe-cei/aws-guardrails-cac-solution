""" GC08 - check Cloud Segmentation Design
    https://canada-ca.github.io/cloud-guardrails/EN/08_Segmentation.html
"""

import json
import logging

from utils import is_scheduled_notification, check_required_parameters, check_guardrail_requirement_by_cloud_usage_profile, get_cloud_profile_from_tags, GuardrailType, GuardrailRequirementType
from boto_util.organizations import get_account_tags
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
            "Target Cloud Segmentation Design document not checked in account %s - not the Audit account",
            aws_account_id,
        )
        return

    aws_config_client = get_client("config")
    aws_s3_client = get_client("s3")
    aws_organizations_client = get_client("organizations", aws_account_id, execution_role_name)
    
    # Check cloud profile
    tags = get_account_tags(aws_organizations_client, aws_account_id)
    cloud_profile = get_cloud_profile_from_tags(tags)
    gr_requirement_type = check_guardrail_requirement_by_cloud_usage_profile(GuardrailType.Guardrail8, cloud_profile)
    
    # If the guardrail is recommended
    if gr_requirement_type == GuardrailRequirementType.Recommended:
        return submit_evaluations(aws_config_client, [build_evaluation(
            aws_account_id,
            "COMPLIANT",
            event,
            gr_requirement_type=gr_requirement_type
        )])
    # If the guardrail is not required
    elif gr_requirement_type == GuardrailRequirementType.Not_Required:
        return submit_evaluations(aws_config_client, [build_evaluation(
            aws_account_id,
            "NOT_APPLICABLE",
            event,
            gr_requirement_type=gr_requirement_type
        )])
        
    if check_s3_object_exists(aws_s3_client, rule_parameters["s3ObjectPath"]):
        compliance_type = "COMPLIANT"
        annotation = "Target Cloud Segmentation Design document found"
    else:
        compliance_type = "NON_COMPLIANT"
        annotation = "Target Cloud Segmentation Design document NOT found"

    logger.info(f"{compliance_type}: {annotation}")
    evaluations.append(build_evaluation(aws_account_id, compliance_type, event, annotation=annotation))
    submit_evaluations(aws_config_client, event["resultToken"], evaluations)
