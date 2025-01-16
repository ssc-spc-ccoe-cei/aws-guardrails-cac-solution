""" GC11 - Confirms that the policy for event logging is implemented
"""

import json
import logging

from utils import is_scheduled_notification, check_required_parameters, check_guardrail_requirement_by_cloud_usage_profile, get_cloud_profile_from_tags, GuardrailType, GuardrailRequirementType
from boto_util.organizations import get_account_tags
from boto_util.client import get_client
from boto_util.config import build_evaluation, submit_evaluations, describe_all_config_rules

# Logging setup
logger = logging.getLogger()
logger.setLevel(logging.INFO)


def assess_aws_managed_rules(config_client, event: dict) -> tuple[list[dict], bool]:
    evaluations = []
    all_resources_are_compliant = True

    config_rules = describe_all_config_rules(config_client)

    required_aws_managed_rules = {
        "AWSAccelerator-cloudtrail-s3-dataevents-enabled": {},
        "AWSAccelerator-cloudtrail-enabled": {},
        "AWSAccelerator-cloudtrail-security-trail-enabled": {},
    }

    for rule in config_rules:
        name = rule.get("ConfigRuleName")
        if name in required_aws_managed_rules:
            required_aws_managed_rules[name] = rule

    for rule in required_aws_managed_rules.values():
        name = rule.get("ConfigRuleName")
        resource_id = rule.get("ConfigRuleArn", name)

        if rule.get("ConfigRuleState") != "ACTIVE":
            compliance_type = "NON_COMPLIANT"
            annotation = f"Required Config Rule is NOT enabled: '{name}'"
        else:
            compliance_type = "COMPLIANT"
            annotation = f"Required Config Rule is enabled: '{name}'"

        logger.info(f"{compliance_type}: {annotation}")
        # There is no available resource type for the config rules, fallback to the account type
        evaluations.append(build_evaluation(resource_id, compliance_type, event, annotation=annotation))
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

    rule_parameters = check_required_parameters(json.loads(event.get("ruleParameters", "{}")), ["ExecutionRoleName"])
    execution_role_name = rule_parameters.get("ExecutionRoleName")
    audit_account_id = rule_parameters.get("AuditAccountID", "")
    aws_account_id = event["accountId"]
    is_not_audit_account = aws_account_id != audit_account_id

    aws_config_client = get_client("config", aws_account_id, execution_role_name, is_not_audit_account)
    
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
        
    evaluations, all_aws_managed_rules_are_compliant = assess_aws_managed_rules(aws_config_client, event)

    if not all_aws_managed_rules_are_compliant:
        compliance_type = "NON_COMPLIANT"
        annotation = "Non-compliant resources found in scope."
    else:
        compliance_type = "COMPLIANT"
        annotation = "All resources found are compliant and AWS Config is enabled."

    logger.info(f"{compliance_type}: {annotation}")
    evaluations.append(build_evaluation(aws_account_id, compliance_type, event, annotation=annotation))
    submit_evaluations(aws_config_client, event["resultToken"], evaluations)
