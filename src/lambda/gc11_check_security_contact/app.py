""" GC11 - Check Security Contact
    https://canada-ca.github.io/cloud-guardrails/EN/12_Cloud-Marketplace-Config.html
"""

import json
import logging

import botocore.exceptions

from utils import is_scheduled_notification, check_required_parameters, check_guardrail_requirement_by_cloud_usage_profile, get_cloud_profile_from_tags, GuardrailType, GuardrailRequirementType
from boto_util.organizations import get_account_tags
from boto_util.client import get_client
from boto_util.config import build_evaluation, submit_evaluations

# Logging setup
logger = logging.getLogger()
logger.setLevel(logging.INFO)

def check_security_contact(aws_account_client):
    """Check if the account has a security contact.
    Returns:
    True if the account has a security contact, False otherwise.
    """
    try:
        response = aws_account_client.get_alternate_contact(AlternateContactType="SECURITY")
    except botocore.exceptions.ClientError as err:
        if "ResourceNotFound" in err.response["Error"]["Code"]:
            return False
        else:
            raise ValueError(f"Unexpected error: {err}") from err
    else:
        if response:
            alternate_contact = response.get("AlternateContact", {})
            if (
                alternate_contact.get("AlternateContactType", "") == "SECURITY"
                and alternate_contact.get("EmailAddress", None)
                and alternate_contact.get("Name", None)
                and alternate_contact.get("PhoneNumber", None)
            ):
                return True
        else:
            raise ValueError("No response returned from get_alternate_contact.")
    return False


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

    rule_parameters = check_required_parameters(json.loads(event.get("ruleParameters", "{}")), ["ExecutionRoleName"])
    execution_role_name = rule_parameters.get("ExecutionRoleName")
    audit_account_id = rule_parameters.get("AuditAccountID", "")
    aws_account_id = event["accountId"]
    is_not_audit_account = aws_account_id != audit_account_id

    aws_config_client = get_client("config", aws_account_id, execution_role_name, is_not_audit_account)
    aws_account_client = get_client("account", aws_account_id, execution_role_name, is_not_audit_account)
    
    # Check cloud profile
    tags = get_account_tags(get_client("organizations", assume_role=False), aws_account_id)
    cloud_profile = get_cloud_profile_from_tags(tags)
    gr_requirement_type = check_guardrail_requirement_by_cloud_usage_profile(GuardrailType.Guardrail11, cloud_profile)
    
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
        
    if check_security_contact(aws_account_client):
        compliance_type = "COMPLIANT"
        annotation = "Security contact registered"
    else:
        compliance_type = "NON_COMPLIANT"
        annotation = "Security contact NOT registered"

    logger.info(f"{compliance_type}: {annotation}")
    evaluations = [build_evaluation(aws_account_id, compliance_type, event, annotation=annotation)]
    submit_evaluations(aws_config_client, event["resultToken"], evaluations)
