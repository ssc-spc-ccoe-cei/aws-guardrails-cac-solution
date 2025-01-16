""" GC11 - Confirms whether monitoring and auditing is implemented for all users
"""

import json
import logging
import re

import botocore.exceptions

from utils import is_scheduled_notification, check_required_parameters, check_guardrail_requirement_by_cloud_usage_profile, get_cloud_profile_from_tags, GuardrailType, GuardrailRequirementType
from boto_util.organizations import get_account_tags
from boto_util.client import get_client
from boto_util.config import build_evaluation, submit_evaluations

# Logging setup
logger = logging.getLogger()
logger.setLevel(logging.INFO)


def extract_conformance_pack_id(config_rule_name: str) -> str:
    search = re.search("^.*-conformance-pack-(.*)$", config_rule_name)
    if not search:
        raise Exception("Unable to extract the conformance pack ID from the current config rule name")
    return search.group(1)


def lambda_handler(event: dict, context):
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

    evaluations = []

    aws_config_client = get_client("config", aws_account_id, execution_role_name, is_not_audit_account)
    
    # Check cloud profile
    tags = get_account_tags(get_client("organizations", assume_role=False), aws_account_id)
    cloud_profile = get_cloud_profile_from_tags(tags)
    gr_requirement_type = check_guardrail_requirement_by_cloud_usage_profile(GuardrailType.Guardrail11, cloud_profile)
    
    # If the guardrail is recommended
    if gr_requirement_type == GuardrailRequirementType.Recommended:
        return submit_evaluations(aws_config_client, event["resultToken"], [build_evaluation(
            aws_account_id,
            "COMPLIANT",
            event,
            gr_requirement_type=gr_requirement_type
        )])
    # If the guardrail is not required
    elif gr_requirement_type == GuardrailRequirementType.Not_Required:
        return submit_evaluations(aws_config_client, event["resultToken"], [build_evaluation(
            aws_account_id,
            "NOT_APPLICABLE",
            event,
            gr_requirement_type=gr_requirement_type
        )])
        
    conformance_pack_id = extract_conformance_pack_id(event.get("configRuleName", ""))
    config_rule_name = f"gc01_check_monitoring_and_logging-conformance-pack-{conformance_pack_id}"

    logger.info("Querying validation results for GR1.4 using config rule name '%s'", config_rule_name)

    try:
        response = aws_config_client.describe_compliance_by_config_rule(ConfigRuleNames=[config_rule_name])
    except botocore.exceptions.ClientError as ex:
        response = None
        logger.error("%s Config rule name queried: '%s'", ex, config_rule_name)

    if not response:
        compliance_type = "NON_COMPLIANT"
        annotation = f"Compliance results not found for config rule '{config_rule_name}'"
    else:
        rule = response.get("ComplianceByConfigRules")[0]
        gc01_compliance_type = rule.get("Compliance", {}).get("ComplianceType")
        logger.info("rule = %s", rule)

        if not gc01_compliance_type == "COMPLIANT":
            compliance_type = "NON_COMPLIANT"
            annotation = "Validation results for GR 1.4 are NON_COMPLIANT"
        else:
            compliance_type = "COMPLIANT"
            annotation = "Validation results for GR 1.4 are COMPLIANT"

    logger.info(f"{compliance_type}: {annotation}")
    evaluations = [build_evaluation(aws_account_id, compliance_type, event, annotation=annotation)]
    submit_evaluations(aws_config_client, event["resultToken"], evaluations)
