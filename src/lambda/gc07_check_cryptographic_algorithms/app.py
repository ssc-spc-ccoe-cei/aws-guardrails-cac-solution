""" GC07 - Check Cryptographic Algorithms
"""

import json
import logging

from utils import is_scheduled_notification, check_required_parameters, flat, check_guardrail_requirement_by_cloud_usage_profile, get_cloud_profile_from_tags, GuardrailType, GuardrailRequirementType
from boto_util.organizations import get_account_tags
from boto_util.client import get_client
from boto_util.config import build_evaluation, submit_evaluations
from boto_util.elb import describe_elb_load_balancer_policies, describe_all_elb_load_balancers


# Logging setup
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# See https://www.cyber.gc.ca/en/guidance/guidance-securely-configuring-network-protocols-itsp40062
#   section 3.1 TLS Cipher suites (Table 2 and Table 3)
ITSP_40_062_ALLOWED_SUITES = {
    "TLSv1.2": [
        "ECDHE-ECDSA-AES256-GCM-SHA384",
        "ECDHE-ECDSA-AES256-CCM",
        "ECDHE-ECDSA-AES128-GCM-SHA256",
        "ECDHE-ECDSA-AES128-CCM",
        "ECDHE-RSA-AES256-GCM-SHA384",
        "ECDHE-RSA-AES128-GCM-SHA256",
        "DHE-RSA-AES256-GCM-SHA384",
        "DHE-DSS-AES256-GCM-SHA384",
        "DHE-RSA-AES256-CCM",
        "DHE-RSA-AES128-GCM-SHA256",
        "DHE-DSS-AES128-GCM-SHA256",
        "DHE-RSA-AES128-CCM",
        "ECDHE-ECDSA-AES256-CCM-8",
        "ECDHE-ECDSA-AES128-CCM-8",
        "ECDHE-ECDSA-AES256-CBC-SHA384",
        "ECDHE-ECDSA-AES128-CBC-SHA256",
        "ECDHE-RSA-AES256-CBC-SHA384",
        "ECDHE-RSA-AES128-CBC-SHA256",
        "DHE-RSA-AES256-CBC-SHA256",
        "DHE-RSA-AES128-CBC-SHA256",
    ],
    "TLSv1.3": [
        "AES256-GCM-SHA384",
        "AES128-GCM-SHA256",
        "AES128-CCM-SHA256",
        "AES128-CCM-8-SHA256",
    ],
}


def extract_custom_policies(policies: list[dict]) -> list[dict]:
    return [
        policy
        for policy in policies
        if not policy.get("PolicyName", "").startswith("ELBSecurityPolicy")
        and not policy.get("PolicyName", "").startswith("ELBSample")
    ]


def policy_protocols_and_cipher_suites_meet_recommendations(lb_name: str, policies: list[dict]) -> bool:
    all_meet_recommendations = True
    for policy in policies:
        # Example: attributes = [
        #   {"AttributeName": "Protocol-TLSv1.2", "AttributeValue": "true"},
        #   {"AttributeName": "AES128-SHA", "AttributeValue": "false"}
        # ]
        attributes = policy.get("PolicyAttributeDescriptions", [])
        policy_name = policy.get("PolicyName", "")

        ### Section: Verify that all policies are only using recommended protocols
        # Example: enabled_protocols = ["TLSv1.3"]
        enabled_protocols = [
            attr.get("AttributeName", "").lstrip("Protocol-")
            for attr in attributes
            if attr.get("AttributeName", "").startswith("Protocol") and attr.get("AttributeValue", "") == "true"
        ]
        disallowed_and_enabled_protocols = [x for x in enabled_protocols if x not in ITSP_40_062_ALLOWED_SUITES.keys()]
        if disallowed_and_enabled_protocols:
            logger.info(
                f"Invalid protocol(s) '{ "', '".join(disallowed_and_enabled_protocols) }' enabled for Policy '{policy_name}' in Load Balancer '{lb_name}'."
            )
            all_meet_recommendations = False

        ### Section: Verify that all policies are only using recommended cipher suites
        # Merge the lists of allowed suites for all the protocols that are enabled
        allowed_suites = flat([v for k, v in ITSP_40_062_ALLOWED_SUITES.items() if k in enabled_protocols])
        enabled_suites = [
            attr.get("AttributeName", "")
            for attr in attributes
            if (
                not attr.get("AttributeName", "").startswith("Protocol")
                and not attr.get("AttributeName", "") == "Server-Defined-Cipher-Order"
                and attr.get("AttributeValue", "") == "true"
            )
        ]
        disallowed_and_enabled_suites = [x for x in enabled_suites if x not in allowed_suites]
        if disallowed_and_enabled_suites:
            logger.info(
                f"Invalid cipher suite(s) '{ "', '".join(disallowed_and_enabled_suites) }' enabled for Policy '{policy_name}' in Load Balancer '{lb_name}'."
            )
            all_meet_recommendations = False

    return all_meet_recommendations


def assess_load_balancer_enforcement(load_balancers_details: list[dict], event) -> list[dict]:
    resource_type = "AWS::ElasticLoadBalancing::LoadBalancer"
    evaluations = []
    all_resources_are_compliant = True

    for load_balancer_details in load_balancers_details:
        lb_name: str = load_balancer_details["Description"]["LoadBalancerName"]
        resource_id = lb_name
        custom_policies = extract_custom_policies(load_balancer_details.get("Policies", []))
        logger.info("Custom Policies found for Load Balancer '%s': %s", lb_name, custom_policies)

        if not custom_policies:
            compliance_type = "COMPLIANT"
            annotation = "The load balancer is NOT using a custom policy."
        elif policy_protocols_and_cipher_suites_meet_recommendations(lb_name, custom_policies):
            compliance_type = "COMPLIANT"
            annotation = (
                "The load balancer is using a custom policy and the protocol and cipher suite meet recommendations."
            )
        else:
            compliance_type = "NON_COMPLIANT"
            annotation = "The load balancer is using a custom policy, but the protocol and/or cipher suite do NOT meet recommendations."

        logger.info(f"{annotation} LoadBalancerName: '{lb_name}'")
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

    page_size = 100
    interval_between_api_calls = 0.1

    aws_config_client = get_client("config", aws_account_id, execution_role_name, is_not_audit_account)
    # Using older 'elb' api instead of 'elbv2' so that we get the 'Classic' load balancers
    aws_elb_client = get_client("elb", aws_account_id, execution_role_name, is_not_audit_account)
    
    # Check cloud profile
    tags = get_account_tags(get_client("organizations", assume_role=False), aws_account_id)
    cloud_profile = get_cloud_profile_from_tags(tags)
    gr_requirement_type = check_guardrail_requirement_by_cloud_usage_profile(GuardrailType.Guardrail7, cloud_profile)
    
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
        
    load_balancers_details = [
        {
            "Description": x,
            "Policies": describe_elb_load_balancer_policies(
                aws_elb_client, x.get("LoadBalancerName"), x.get("Policies", {}).get("OtherPolicies", [])
            ),
        }
        for x in describe_all_elb_load_balancers(aws_elb_client, page_size, interval_between_api_calls)
    ]

    evaluations, all_resources_are_compliant = assess_load_balancer_enforcement(load_balancers_details, event)

    if all_resources_are_compliant:
        compliance_type = "COMPLIANT"
        annotation = "All resources found are compliant."
    else:
        compliance_type = "NON_COMPLIANT"
        annotation = "Non-compliant resources found in scope."

    logger.info(f"{compliance_type}: {annotation}")
    evaluations.append(build_evaluation(aws_account_id, compliance_type, event, annotation=annotation))
    submit_evaluations(aws_config_client, event["resultToken"], evaluations, interval_between_api_calls)
