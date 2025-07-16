""" GC01 - Check Root MFA
    https://canada-ca.github.io/cloud-guardrails/EN/01_Protect-Root-Account.html
"""

import json
import logging

import botocore.exceptions

from utils import is_scheduled_notification, check_required_parameters, check_guardrail_requirement_by_cloud_usage_profile, get_cloud_profile_from_tags, GuardrailType, GuardrailRequirementType
from boto_util.organizations import get_account_tags
from boto_util.client import get_client
from boto_util.config import build_evaluation, submit_evaluations
from boto_util.iam import account_has_federated_users
from boto_util.guard_duty import guard_duty_is_enabled
from boto_util.cloud_trail import trails_are_logging, list_all_cloud_trails


# Logging setup
logger = logging.getLogger()
logger.setLevel(logging.INFO)


def filter_trails_configured_for_iam_events(cloudtrail_client, trails):
    """Checks for a trails with the configuration required to capture IAM events and returns a filtered list"""
    filtered_trails = []
    for t in trails:
        try:
            trail_arn = t.get("TrailARN")
            configuration = cloudtrail_client.get_trail(Name=trail_arn)
            if (
                configuration.get("IncludeGlobalServiceEvents", False)
                and configuration.get("IsMultiRegionTrail", False)
                and configuration.get("IsOrganizationTrail", False)
            ):
                filtered_trails.append(t)
        except botocore.exceptions.ClientError as ex:
            logger.error("Error while trying to fetch cloudtrail configuration.")
            logger.error(ex)
            raise ex
    return filtered_trails


def is_cloudtrail_enabled(cloudtrail_client):
    """Checks if cloudtrail is enabled to watch for iam login events"""
    trails = filter_trails_configured_for_iam_events(cloudtrail_client, list_all_cloud_trails(cloudtrail_client))
    return len(trails) > 0 and trails_are_logging(cloudtrail_client, trails)


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

    evaluations = []

    aws_config_client = get_client("config", aws_account_id, execution_role_name)
    aws_iam_client = get_client("iam", aws_account_id, execution_role_name)
    aws_guard_duty_client = get_client("guardduty", aws_account_id, execution_role_name)
    aws_cloudtrail_client = get_client("cloudtrail", aws_account_id, execution_role_name)
    
    # Check cloud profile
    tags = get_account_tags(get_client("organizations", assume_role=False), aws_account_id)
    cloud_profile = get_cloud_profile_from_tags(tags)
    gr_requirement_type = check_guardrail_requirement_by_cloud_usage_profile(GuardrailType.Guardrail2, cloud_profile)
    
    # If the guardrail is recommended
    if gr_requirement_type == GuardrailRequirementType.Recommended:
        return submit_evaluations(aws_config_client, event, [build_evaluation(
            aws_account_id,
            "COMPLIANT",
            event,
            gr_requirement_type=gr_requirement_type
        )])
    # If the guardrail is not required
    elif gr_requirement_type == GuardrailRequirementType.Not_Required:
        return submit_evaluations(aws_config_client, event, [build_evaluation(
            aws_account_id,
            "NOT_APPLICABLE",
            event,
            gr_requirement_type=gr_requirement_type
        )])
        
    if guard_duty_is_enabled(aws_guard_duty_client) or is_cloudtrail_enabled(aws_cloudtrail_client):
        compliance_type = "COMPLIANT"
        annotation = (
            "Dependent on the compliance of Federated IdP" if account_has_federated_users(aws_iam_client) else ""
        )
    else:
        compliance_type = "NON_COMPLIANT"
        annotation = "Neither Guard Duty nor Cloud Trail are enabled."

    logger.info(f"{compliance_type}: {annotation}")
    evaluations.append(build_evaluation(aws_account_id, compliance_type, event, annotation=annotation))
    submit_evaluations(aws_config_client, event, evaluations)
