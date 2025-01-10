""" GC11 - Check Trail Logging
    https://canada-ca.github.io/cloud-guardrails/EN/11_Logging-and-Monitoring.html
"""

import json
import logging

from utils import is_scheduled_notification, check_required_parameters
from boto_util.client import get_client
from boto_util.config import build_evaluation, submit_evaluations, aws_config_is_enabled
from boto_util.cloud_trail import list_all_cloud_trails

# Logging setup
logger = logging.getLogger()
logger.setLevel(logging.INFO)


def event_selectors_are_configured_correctly(event_selectors):
    for selector in event_selectors:
        if selector.get("IncludeManagementEvents", None) != True or selector.get("ReadWriteType", "") != "All":
            logger.info("Improperly Configured Event Selector found: %s", selector)
            return False
    return True


def assess_cloudtrail_configurations(cloudtrail_client, event: dict) -> tuple[list[dict], bool]:
    resource_type = "AWS::CloudTrail::Trail"
    evaluations = []
    all_resources_are_compliant = True

    trail_list = list_all_cloud_trails(cloudtrail_client)

    if not trail_list:
        return [], False

    response = cloudtrail_client.describe_trails(
        trailNameList=[x.get("TrailARN") for x in trail_list], includeShadowTrails=True
    )
    trails_descriptions = response.get("trailList", [])

    for trail in trails_descriptions:
        trail_name = trail.get("Name", "")
        resource_id = trail.get("TrailARN", trail_name)
        trail_status = cloudtrail_client.get_trail_status(Name=trail_name)

        if not trail_status.get("IsLogging", False):
            compliance_type = "NON_COMPLIANT"
            annotation = f"Cloud Trail '{trail_name}' is NOT logging."
        elif not trail.get("IncludeGlobalServiceEvents", False):
            compliance_type = "NON_COMPLIANT"
            annotation = f"Cloud Trail '{trail_name}' does NOT have IncludeGlobalServiceEvents set to True."
        else:
            response = cloudtrail_client.get_event_selectors(TrailName=trail_name)
            event_selectors = response.get("EventSelectors", [])
            if not event_selectors:
                compliance_type = "NON_COMPLIANT"
                annotation = f"Cloud Trail '{trail_name}' does have any event selectors."
            elif not event_selectors_are_configured_correctly(event_selectors):
                compliance_type = "NON_COMPLIANT"
                annotation = f"Cloud Trail '{trail_name}' has an improperly configured event selector."
            else:
                compliance_type = "COMPLIANT"
                annotation = f"Cloud Trail '{trail_name}' has the required configuration."

        logger.info(f"{compliance_type}: {annotation}")
        evaluations.append(build_evaluation(resource_id, compliance_type, event, resource_type, annotation))
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
    aws_cloudtrail_client = get_client("cloudtrail", aws_account_id, execution_role_name, is_not_audit_account)

    evaluations, all_cloudtrail_resources_are_compliant = assess_cloudtrail_configurations(aws_cloudtrail_client, event)

    if not evaluations:
        compliance_type = "NON_COMPLIANT"
        annotation = f"No trails found. Cloud Trail is not enabled."
    elif not all_cloudtrail_resources_are_compliant:
        compliance_type = "NON_COMPLIANT"
        annotation = "Non-compliant resources found in scope."
    elif not aws_config_is_enabled(aws_config_client):
        compliance_type = "NON_COMPLIANT"
        annotation = "AWS Config is NOT enabled."
    else:
        compliance_type = "COMPLIANT"
        annotation = "All resources found are compliant and AWS Config is enabled."

    logger.info(f"{compliance_type}: {annotation}")
    evaluations.append(build_evaluation(aws_account_id, compliance_type, event, annotation=annotation))
    submit_evaluations(aws_config_client, event["resultToken"], evaluations)
