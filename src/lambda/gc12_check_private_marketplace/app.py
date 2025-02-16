""" GC12 - Check Marketplace Configuration
    https://canada-ca.github.io/cloud-guardrails/EN/12_Cloud-Marketplace-Config.html
"""

import logging
import json
import time

import botocore

from utils import (
    is_scheduled_notification,
    check_required_parameters,
    check_guardrail_requirement_by_cloud_usage_profile,
    get_cloud_profile_from_tags,
    GuardrailType,
    GuardrailRequirementType,
)
from boto_util.client import get_client
from boto_util.config import build_evaluation, submit_evaluations
from boto_util.organizations import (
    organizations_list_all_service_control_policies,
    get_organizations_mgmt_account_id,
    organizations_list_all_policies_for_target,
    organizations_list_all_organizational_units,
    get_account_tags,
)

logger = logging.getLogger()
logger.setLevel(logging.INFO)


def private_marketplace_is_configured(marketplace_catalog_client) -> bool:
    try:
        response = marketplace_catalog_client.list_entities(
            Catalog="AWSMarketplace",
            EntityType="Experience",
            FilterList=[{"Name": "Scope", "ValueList": ["SharedWithMe"]}],
        )
    except botocore.exceptions.ClientError as err:
        raise ValueError(f"Error in AWS Marketplace Catalog: {err}") from err
    if not response:
        raise ValueError("No response from AWS Marketplace Catalog")
    entity_summary_list = response.get("EntitySummaryList") or []
    for entity in entity_summary_list:
        if entity.get("EntityType") == "Experience":
            return True
    return False


def policy_restricts_marketplace_access(iam_client, policy_content: str, interval_between_calls: float = "0.1") -> bool:
    args = {
        "PolicyInputList": [policy_content],
        "ActionNames": ["aws-marketplace-management:*", "aws-marketplace:*"],
    }
    resources: list[dict] = []
    while True:
        response = iam_client.simulate_custom_policy(**args)
        if response:
            resources.extend(response.get("EvaluationResults", []))
            args["Marker"] = response.get("Marker")
        else:
            args["Marker"] = None
        if not args.get("Marker"):
            break
        else:
            time.sleep(interval_between_calls)
    for eval_result in resources:
        if eval_result.get("EvalDecision") == "allowed":
            return False
    return True


def get_policies_that_restrict_marketplace_access(
    organizations_client, iam_client, interval_between_calls: float = "0.1"
):
    policies = organizations_list_all_service_control_policies(organizations_client, interval_between_calls)
    selected_policy_summaries = []
    for policy_summary in policies:
        policy_id = policy_summary.get("Id")
        if not policy_id:
            continue
        response = organizations_client.describe_policy(PolicyId=policy_id)
        policy = response.get("Policy", {})
        policy_content = policy.get("Content") or ""
        if not policy_content:
            continue
        if policy_restricts_marketplace_access(iam_client, policy_content, interval_between_calls):
            selected_policy_summaries.append(policy_summary)
    logger.info("Marketplace restriction policies found: %s", selected_policy_summaries)
    return selected_policy_summaries


def policy_is_attached(
    organizations_client, target_id: str, policy_ids: list[str], interval_between_calls: float = "0.1"
) -> bool:
    policies = organizations_list_all_policies_for_target(
        organizations_client, target_id, interval_between_calls=interval_between_calls
    )
    logger.info("Policies found for target '%s': %s", target_id, policies)
    return any(x.get("Id") in policy_ids for x in policies)


def is_policy_attached_in_ancestry(organizations_client, child_id: str, policy_ids: list[str]) -> bool:
    current_id = child_id
    while True:
        if policy_is_attached(organizations_client, current_id, policy_ids):
            return True
        parents = organizations_client.list_parents(ChildId=current_id).get("Parents", [])
        if not parents:
            break
        parent_id = parents[0].get("Id")
        parent_type = parents[0].get("Type")
        if parent_type == "ROOT":
            if policy_is_attached(organizations_client, parent_id, policy_ids):
                return True
            return False
        else:
            current_id = parent_id
    return False


def assess_policy_attachment(
    organizations_client, policy_summaries: list[dict], current_account_id: str, interval_between_calls: float = "0.1"
) -> tuple[str, str]:
    policy_ids = [x.get("Id") for x in policy_summaries]
    mgmt_account_id = get_organizations_mgmt_account_id(organizations_client)
    if current_account_id == mgmt_account_id:
        if policy_is_attached(organizations_client, mgmt_account_id, policy_ids, interval_between_calls):
            return (
                "NON_COMPLIANT",
                "The restricting policy is attached to the Management Account, which is not allowed.",
            )
        parents = organizations_client.list_parents(ChildId=current_account_id).get("Parents")
        if not parents:
            return False
        parent_id = parents[0["Id"]]
        ou_list = organizations_list_all_organizational_units(organizations_client, parent_id, interval_between_calls,)
        missing_ous = []
        for ou in ou_list:
            ou_id = ou["Id"]
            if not policy_is_attached(organizations_client, ou_id, policy_ids, interval_between_calls):
                missing_ous.append(ou_id)
        if missing_ous:
            return ("NON_COMPLIANT", f"The restricting policy is NOT attached to OUs: {', '.join(missing_ous)}.")
        return ("COMPLIANT", "All OUs have the restricting policy, and management account is not attached.")
    else:
        if is_policy_attached_in_ancestry(organizations_client, current_account_id, policy_ids):
            return ("COMPLIANT", "The account effectively inherits the restricting SCP.")
        else:
            return ("NON_COMPLIANT", "The account (and its parents) do NOT have the restricting policy attached.")


def lambda_handler(event, context):
    logger.info("Received Event: %s", json.dumps(event, indent=2))
    invoking_event = json.loads(event["invokingEvent"])
    if not is_scheduled_notification(invoking_event.get("messageType", "")):
        logger.error("Skipping assessments as this is not a scheduled invocation")
        return
    rule_parameters = check_required_parameters(json.loads(event.get("ruleParameters", "{}")), ["ExecutionRoleName"])
    execution_role_name = rule_parameters["ExecutionRoleName"]
    audit_account_id = rule_parameters.get("AuditAccountID", "")
    aws_account_id = event["accountId"]
    is_not_audit_account = aws_account_id != audit_account_id
    interval_between_calls = float("0.1")
    aws_config_client = get_client("config", aws_account_id, execution_role_name, is_not_audit_account)
    aws_iam_client = get_client("iam", aws_account_id, execution_role_name, is_not_audit_account)
    aws_orgs_client = get_client("organizations", aws_account_id, execution_role_name, is_not_audit_account)
    tags = get_account_tags(get_client("organizations", assume_role=False), aws_account_id)
    cloud_profile = get_cloud_profile_from_tags(tags)
    gr_requirement_type = check_guardrail_requirement_by_cloud_usage_profile(GuardrailType.Guardrail12, cloud_profile)
    if gr_requirement_type == GuardrailRequirementType.Recommended:
        evaluation = build_evaluation(aws_account_id, "COMPLIANT", event, gr_requirement_type=gr_requirement_type)
        return submit_evaluations(aws_config_client, event, [evaluation])
    if gr_requirement_type == GuardrailRequirementType.Not_Required:
        evaluation = build_evaluation(aws_account_id, "NOT_APPLICABLE", event, gr_requirement_type=gr_requirement_type)
        return submit_evaluations(aws_config_client, event, [evaluation])
    restricting_policies = get_policies_that_restrict_marketplace_access(
        aws_orgs_client, aws_iam_client, float(interval_between_calls)
    )
    if not restricting_policies:
        compliance_type = "NON_COMPLIANT"
        annotation = "No restricting SCP found that denies Marketplace usage."
        logger.info(f"{compliance_type}: {annotation}")
        eval_ = build_evaluation(aws_account_id, compliance_type, event, annotation=annotation)
        return submit_evaluations(aws_config_client, event, [eval_])
    compliance_type, annotation = assess_policy_attachment(
        aws_orgs_client, restricting_policies, aws_account_id, interval_between_calls
    )
    if compliance_type == "COMPLIANT":
        aws_marketplace_catalog_client = get_client(
            "marketplace-catalog", aws_account_id, execution_role_name, is_not_audit_account, region="us-east-1"
        )
        if not private_marketplace_is_configured(aws_marketplace_catalog_client):
            compliance_type = "NON_COMPLIANT"
            annotation = "Private Marketplace NOT found."
        else:
            annotation = f"Private Marketplace found. {annotation}"
    logger.info(f"{compliance_type}: {annotation}")
    final_eval = build_evaluation(aws_account_id, compliance_type, event, annotation=annotation)
    submit_evaluations(aws_config_client, event, [final_eval])

