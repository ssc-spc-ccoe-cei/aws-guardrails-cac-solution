""" GC01 - Check Monitoring And Logging
    https://github.com/canada-ca/cloud-guardrails/blob/master/EN/01_Protect-user-accounts-and-identities.md
"""

import json
import logging

from utils import is_scheduled_notification, check_required_parameters, check_guardrail_requirement_by_cloud_usage_profile, get_cloud_profile_from_tags, GuardrailType, GuardrailRequirementType
from boto_util.organizations import get_account_tags
from boto_util.client import get_client
from boto_util.config import build_evaluation, submit_evaluations
from boto_util.cloud_trail import list_all_cloud_trails

import botocore.exceptions

# Logging setup
logger = logging.getLogger()
logger.setLevel(logging.INFO)


def check_trail_status(cloudtrail_client, trails, event):
    resource_type = "AWS::CloudTrail::Trail"
    evaluations = []

    for t in trails:
        try:
            trail_arn = t.get("TrailARN")
            status = cloudtrail_client.get_trail_status(Name=trail_arn)

            if status.get("IsLogging", False):
                compliance_type = "COMPLIANT"
                annotation = "CloudTrail is logging"
            else:
                compliance_type = "NON_COMPLIANT"
                annotation = "CloudTrail is not logging"

            evaluations.append(build_evaluation(trail_arn, compliance_type, event, resource_type, annotation))
        except botocore.exceptions.ClientError as ex:
            logger.error("Error while trying to fetch cloudtrail status.")
            logger.error(ex)
            raise ex

    return evaluations


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
    aws_cloudtrail_client = get_client("cloudtrail", aws_account_id, execution_role_name)
    
    # Check cloud profile
    tags = get_account_tags(get_client("organizations", assume_role=False), aws_account_id)
    cloud_profile = get_cloud_profile_from_tags(tags)
    gr_requirement_type = check_guardrail_requirement_by_cloud_usage_profile(GuardrailType.Guardrail1, cloud_profile)
    
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
    
    trails = list_all_cloud_trails(aws_cloudtrail_client)

    if trails:
        evaluations.extend(check_trail_status(aws_cloudtrail_client, trails, event))
    else:
        evaluations.append(
            build_evaluation(aws_account_id, "NON_COMPLIANT", event, annotation="No CloudTrails found in account")
        )

    logger.info("AWS Config updating evaluations: %s", evaluations)
    submit_evaluations(aws_config_client, event, evaluations)
