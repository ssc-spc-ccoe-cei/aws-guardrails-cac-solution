""" GC03 - Check trusted devices admin access
    Confirm that administrative access to cloud environments is from approved and trusted locations and devices
"""

import json
import logging
import ipaddress

from utils import is_scheduled_notification, check_required_parameters, check_guardrail_requirement_by_cloud_usage_profile, get_cloud_profile_from_tags, GuardrailType, GuardrailRequirementType
from boto_util.organizations import get_account_tags, get_organizations_mgmt_account_id
from boto_util.client import get_client
from boto_util.config import build_evaluation, submit_evaluations
from boto_util.iam import account_has_federated_users
from boto_util.s3 import check_s3_object_exists, get_lines_from_s3_file
from boto_util.cloud_trail import lookup_cloud_trail_events

# Logging setup
logger = logging.getLogger()
logger.setLevel(logging.INFO)


def ip_is_within_ranges(ip_addr: str, ip_cidr_ranges: list[str]) -> bool:
    """Return true if the given IP Address is within the at least one of the given CIDR ranges, otherwise returns false"""
    for ip_range in ip_cidr_ranges:
        ip_network = ipaddress.ip_network(ip_range)
        if ipaddress.ip_address(ip_addr) in ip_network:
            return True
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

    rule_parameters = check_required_parameters(
        json.loads(event.get("ruleParameters", "{}")), ["ExecutionRoleName", "s3ObjectPath"]
    )
    execution_role_name = rule_parameters.get("ExecutionRoleName")
    audit_account_id = rule_parameters.get("AuditAccountID", "")
    aws_account_id = event["accountId"]
    is_not_audit_account = aws_account_id != audit_account_id

    evaluations = []

    aws_organizations_client = get_client("organizations", aws_account_id, execution_role_name)

    if aws_account_id != get_organizations_mgmt_account_id(aws_organizations_client):
        logger.info(
            "Cloud Trail events not checked in account %s as this is not the Management Account", aws_account_id
        )
        return

    aws_config_client = get_client("config", aws_account_id, execution_role_name)
    aws_s3_client = get_client("s3")
    aws_cloudtrail_client = get_client("cloudtrail", aws_account_id, execution_role_name)
    aws_iam_client = get_client("iam", aws_account_id, execution_role_name)

    # Check cloud profile
    tags = get_account_tags(get_client("organizations", assume_role=False), aws_account_id)
    cloud_profile = get_cloud_profile_from_tags(tags)
    gr_requirement_type = check_guardrail_requirement_by_cloud_usage_profile(GuardrailType.Guardrail3, cloud_profile)
    
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
        
    file_param_name = "s3ObjectPath"
    vpn_ip_ranges_file_path = rule_parameters.get(file_param_name, "")

    if not check_s3_object_exists(aws_s3_client, vpn_ip_ranges_file_path):
        annotation = f"No file found for s3 path '{vpn_ip_ranges_file_path}' via '{file_param_name}' input parameter."
        logger.info(annotation)
        evaluations.append(build_evaluation(aws_account_id, "NON_COMPLIANT", event, annotation=annotation))
        submit_evaluations(aws_config_client, event["resultToken"], evaluations)
        return

    vpn_ip_ranges = get_lines_from_s3_file(aws_s3_client, vpn_ip_ranges_file_path)
    logger.info("vpn_ip_ranges from the file in s3: %s", vpn_ip_ranges)

    if not vpn_ip_ranges:
        annotation = "No ip ranges found in input file."
        logger.info(annotation)
        evaluations.append(build_evaluation(aws_account_id, "NON_COMPLIANT", event, annotation=annotation))
        submit_evaluations(aws_config_client, event["resultToken"], evaluations)
        return

    bg_account_names = [rule_parameters["BgUser1"], rule_parameters["BgUser2"]]
    lookup_attributes = [{"AttributeKey": "EventName", "AttributeValue": "ConsoleLogin"}]
    console_login_cloud_trail_events = lookup_cloud_trail_events(aws_cloudtrail_client, lookup_attributes)
    cloud_trail_events = [e for e in console_login_cloud_trail_events if e.get("Username") not in bg_account_names]
    num_compliant_rules = 0
    logger.info("Number of events found: %s", len(cloud_trail_events))

    for lookup_event in cloud_trail_events:
        ct_event = json.loads(lookup_event.get("CloudTrailEvent", "{}"))
        ct_event_id = ct_event.get("eventID", "")

        if not ip_is_within_ranges(ct_event["sourceIPAddress"], vpn_ip_ranges):
            compliance_type = "NON_COMPLIANT"
            annotation = f"Cloud Trail Event '{ct_event_id}' has a source IP address OUTSIDE of the allowed ranges."
        else:
            num_compliant_rules = num_compliant_rules + 1
            compliance_type = "COMPLIANT"
            annotation = f"Cloud Trail Event '{ct_event_id}' has a source IP address inside of the allowed ranges."
            if account_has_federated_users(aws_iam_client):
                annotation = f"{annotation} Dependent on the compliance of the Federated IdP."

        logger.info(f"{compliance_type}: {annotation}")
        evaluations.append(build_evaluation(ct_event_id, compliance_type, event, "AWS::CloudTrail::Trail", annotation))

    if len(cloud_trail_events) == num_compliant_rules:
        compliance_type = "COMPLIANT"
        annotation = "All Cloud Trail Events are within the allowed source IP address ranges."
        if account_has_federated_users(aws_iam_client):
            annotation = f"All Cloud Trail Events are within the allowed source IP address ranges or are dependant on the federated identity provider."
    else:
        compliance_type = "NON_COMPLIANT"
        annotation = "NOT all Cloud Trail Events are within the allowed source IP address ranges."

    logger.info(f"{compliance_type}: {annotation}")
    evaluations.append(build_evaluation(aws_account_id, compliance_type, event, annotation=annotation))
    submit_evaluations(aws_config_client, event["resultToken"], evaluations)
