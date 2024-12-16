""" GC12 - Check Marketplace Configuration
    https://canada-ca.github.io/cloud-guardrails/EN/12_Cloud-Marketplace-Config.html
"""

import logging
import json
import time

import botocore

from utils import is_scheduled_notification, check_required_parameters
from boto_util.client import get_client
from boto_util.config import build_evaluation, submit_evaluations
from boto_util.organizations import (
    organizations_list_all_service_control_policies,
    get_organizations_mgmt_account_id,
    organizations_list_all_policies_for_target,
    organizations_list_all_organizational_units,
)

# Logging setup
logger = logging.getLogger()
logger.setLevel(logging.INFO)


def private_marketplace_is_configured(marketplace_catalog_client):
    """Check whether the account is using a private marketplace.
    Returns:
    True if the account is using a private marketplace, False otherwise.
    Raises:
    ValueError if the Marketplace Catalog is not available.
    ValueError if the Marketplace Catalog returns an error.
    """
    try:
        response = marketplace_catalog_client.list_entities(
            Catalog="AWSMarketplace",
            EntityType="Experience",
            FilterList=[{"Name": "Scope", "ValueList": ["SharedWithMe"]}],
        )
    except botocore.exceptions.ClientError as err:
        raise ValueError(f"Error in AWS Marketplace Catalog: {err}") from err
    else:
        if response:
            entity_summary_list = response.get("EntitySummaryList")
            for entity in entity_summary_list:
                if entity.get("EntityType") == "Experience":
                    # found a private marketplace
                    return True
        else:
            raise ValueError("No response from AWS Marketplace Catalog")
    # if we got here we have not found a private marketplace
    return False


def policy_restricts_marketplace_access(iam_client, policy_content: str, interval_between_calls: float = 0.1) -> bool:
    args = {"PolicyInputList": [policy_content], "ActionNames": ["aws-marketplace-management:*", "aws-marketplace:*"]}
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
    organizations_client, iam_client, interval_between_calls: float = 0.1
):
    policies = organizations_list_all_service_control_policies(organizations_client, interval_between_calls)
    selected_policy_summaries: list[dict] = []

    for policy_summary in policies:
        response = organizations_client.describe_policy(PolicyId=policy_summary.get("Id"))
        policy = response.get("Policy", {})
        policy_content = policy.get("Content")

        if not policy_content:
            break

        if policy_restricts_marketplace_access(iam_client, policy_content, interval_between_calls):
            selected_policy_summaries.append(policy_summary)
            break

    logger.info("Marketplace restriction policies found: %s", selected_policy_summaries)
    return selected_policy_summaries


def policy_is_attached(
    organizations_client, target_id: str, policy_ids: list[str], interval_between_calls: int = 0.1
) -> bool:
    policies = organizations_list_all_policies_for_target(
        organizations_client, target_id, interval_between_calls=interval_between_calls
    )
    logger.info("Policies found for target '%s': %s", target_id, policies)
    return next((True for x in policies if x.get("Id", "") in policy_ids), False)


def assess_policy_attachment(
    organizations_client, policy_summaries: list[dict], current_account_id: str, interval_between_calls: float = 0.1
) -> tuple[str, str]:
    policy_ids = [x.get("Id") for x in policy_summaries]
    policy_is_attached_to_account = policy_is_attached(
        organizations_client, current_account_id, policy_ids, interval_between_calls
    )
    management_account_id = get_organizations_mgmt_account_id(organizations_client)
    is_management_account = current_account_id == management_account_id

    if is_management_account:
        # Only Check OUs when in the management account since they are global for the organization
        ou_list = organizations_list_all_organizational_units(
            organizations_client, interval_between_calls=interval_between_calls
        )
        ou_ids_missing_policy = [
            x.get("Id")
            for x in ou_list
            if not policy_is_attached(organizations_client, x.get("Id"), policy_ids, interval_between_calls)
        ]

        compliance_type = "NON_COMPLIANT" if policy_is_attached_to_account or ou_ids_missing_policy else "COMPLIANT"

        if ou_ids_missing_policy:
            annotation = f"The marketplace restriction policy is NOT attached to the OUs '{ "', '".join(ou_ids_missing_policy) }'."
        else:
            annotation = "The marketplace restriction policy is attached to all the OUs."

        if policy_is_attached_to_account:
            annotation = (
                f"A marketplace restriction policy should not be attached to the Management Account. {annotation}"
            )

    elif not policy_is_attached_to_account:
        compliance_type = "NON_COMPLIANT"
        annotation = "The account does NOT have a marketplace restriction policy attached."
    else:
        compliance_type = "COMPLIANT"
        annotation = "The account has a marketplace restriction policy attached."

    return compliance_type, annotation


def lambda_handler(event, context):
    """
    This function is the main entry point for Lambda.

    Keyword arguments:

    event -- the event variable given in the lambda handler

    context -- the context variable given in the lambda handler
    """
    logger.info("Received Event: %s", json.dumps(event, indent=2))

    invoking_event = json.loads(event["invokingEvent"])
    rule_parameters = json.loads(event.get("ruleParameters", "{}"))
    valid_rule_parameters = check_required_parameters(rule_parameters, [])
    execution_role_name = valid_rule_parameters.get("ExecutionRoleName", "AWSA-GCLambdaExecutionRole")
    audit_account_id = valid_rule_parameters.get("AuditAccountID", "")
    aws_account_id = event["accountId"]
    is_not_audit_account = aws_account_id != audit_account_id

    evaluations = []
    interval_between_calls = 0.1

    if not is_scheduled_notification(invoking_event["messageType"]):
        logger.error("Skipping assessments as this is not a scheduled invocation")
        return

    aws_config_client = get_client("config", aws_account_id, execution_role_name, is_not_audit_account)
    aws_iam_client = get_client("iam", aws_account_id, execution_role_name, is_not_audit_account)
    aws_organizations_client = get_client("organizations", aws_account_id, execution_role_name, is_not_audit_account)

    selected_policy_summaries = get_policies_that_restrict_marketplace_access(
        aws_organizations_client, aws_iam_client, interval_between_calls
    )

    if not selected_policy_summaries:
        compliance_type = "NON_COMPLIANT"
        annotation = "A policy that restricts marketplace access was NOT found."
        logger.info(f"{compliance_type}: {annotation}")
        evaluations = [build_evaluation(aws_account_id, compliance_type, event, annotation=annotation)]
        submit_evaluations(aws_config_client, event["resultToken"], evaluations)
        return

    compliance_type, annotation = assess_policy_attachment(
        aws_organizations_client, selected_policy_summaries, aws_account_id, interval_between_calls
    )

    if compliance_type == "COMPLIANT":
        aws_marketplace_catalog_client = get_client(
            "marketplace-catalog", aws_account_id, execution_role_name, is_not_audit_account, region="us-east-1"
        )
        if not private_marketplace_is_configured(aws_marketplace_catalog_client):
            compliance_type = "NON_COMPLIANT"
            annotation = "Private Marketplace NOT found."
        else:
            compliance_type = "COMPLIANT"
            annotation = f"Private Marketplace found. {annotation}"

    # Update AWS Config with the evaluation result
    logger.info(f"{compliance_type}: {annotation}")
    evaluations = [build_evaluation(aws_account_id, compliance_type, event, annotation=annotation)]
    submit_evaluations(aws_config_client, event["resultToken"], evaluations)
