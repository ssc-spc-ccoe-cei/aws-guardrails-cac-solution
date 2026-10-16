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


def private_marketplace_is_configured(mgmt_account_id,execution_role_name,is_not_audit_account):
    """
    Wrapper
    """
    import os
    import logging
    import boto3
    import botocore.exceptions
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    os.environ["AWS_DEFAULT_REGION"] = "us-east-1"
    # This gets the client after assuming the Config service role
    # either in the same AWS account or cross-account.
    def get_clientt(
        service: str,
        account_id: str | None = None,
        role_name: str | None = None,
        assume_role: bool = True,
        region: str | None = None,
    ):
        """
        Return the service boto client. It should be used instead of directly calling the client.
        This gets the client after assuming the Config service role for the provided account.
        If no account_id or role_name is provided, the client is configured for the current credentials and account.
        Keyword arguments:
        service -- the service name used for calling the boto.client(service)
        account_id -- the id of the account for the assumed role
        role_name -- the name of the role to assume when creating the client
        """
        # if not role_name or not account_id or not assume_role:
        #     return boto3.client(service)
        credentials = get_assume_role_credentials(f"arn:aws:iam::{account_id}:role/{role_name}")

        return boto3.client(
            service,
            region_name="us-east-1",
            aws_access_key_id=credentials["AccessKeyId"],
            aws_secret_access_key=credentials["SecretAccessKey"],
            aws_session_token=credentials["SessionToken"],
        )
    def get_assume_role_credentials(role_arn: str) -> dict:
        """
        Returns the credentials required to assume the passed role.
        Keyword arguments:
        role_arn -- the arn of the role to assume
        """
        sts_client = boto3.client("sts", region_name="us-east-1")
        try:
            assume_role_response = sts_client.assume_role(RoleArn=role_arn, RoleSessionName="configLambdaExecution")
            return assume_role_response["Credentials"]
        except botocore.exceptions.ClientError as ex:
            # Scrub error message for any internal account info leaks
            if "AccessDenied" in ex.response["Error"]["Code"]:
                ex.response["Error"]["Message"] = "AWS Config does not have permission to assume the IAM role."
            else:
                ex.response["Error"]["Message"] = "InternalError"
                ex.response["Error"]["Code"] = "InternalError"
            logger.error("ERROR assuming role. %s", ex.response["Error"])
            raise ex
    def is_throttling_exception(e):
        """Returns True if the exception code is one of the throttling exception codes we have"""
        b_is_throttling = False
        throttling_exception_codes = [
            "ConcurrentModificationException",
            "InsufficientDeliveryPolicyException",
            "NoAvailableDeliveryChannelException",
            "ConcurrentModifications",
            "LimitExceededException",
            "OperationNotPermittedException",
            "TooManyRequestsException",
            "Throttling",
            "ThrottlingException",
            "InternalErrorException",
            "InternalException",
            "ECONNRESET",
            "EPIPE",
            "ETIMEDOUT",
        ]
        for throttling_code in throttling_exception_codes:
            if throttling_code in e.response["Error"]["Code"]:
                b_is_throttling = True
                break
        return b_is_throttling
    """
    Wrapper
    """
    marketplace_catalog_client = get_clientt(
            "marketplace-catalog",
            mgmt_account_id,
            execution_role_name,
            is_not_audit_account,
            region="us-east-1"
        )
    logger.info(marketplace_catalog_client.meta.region_name)
    sts_client = get_client(
        "sts",
        mgmt_account_id,
        execution_role_name,
        is_not_audit_account,
        region="us-east-1"
    )
    identity = sts_client.get_caller_identity()
    logger.info(identity)
    try:
        response = marketplace_catalog_client.list_entities(
            Catalog="AWSMarketplace",
            EntityType="Experience"
        )
    except botocore.exceptions.ClientError as err:
        raise ValueError(f"Error in AWS Marketplace Catalog: {err}") from err
    if not response:
        raise ValueError("No response from AWS Marketplace Catalog")
    logger.info("Entities Returned: %s", response)
    entity_summary_list = response.get("EntitySummaryList") or []
    for entity in entity_summary_list:
        if entity.get("EntityType") == "Experience":
            return True
    return False


def policy_restricts_marketplace_access(iam_client, policy_content: str, interval_between_calls: str = "0.1") -> bool:
    args = {
        "PolicyInputList": [policy_content],
        "ActionNames": ["aws-marketplace:As*",
                        "aws-marketplace:CreateP*",
                        "aws-marketplace:DescribePri*",
                        "aws-marketplace:Di*",
                        "aws-marketplace:ListP*",
                        "aws-marketplace:Start*"],
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
            time.sleep(float(interval_between_calls))
    for eval_result in resources:
        if eval_result.get("EvalDecision") == "allowed":
            return False
    return True


def get_policies_that_restrict_marketplace_access(
    organizations_client, iam_client, interval_between_calls: str = "0.1"
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
    organizations_client, target_id: str, policy_ids: list[str], interval_between_calls: float = 0.1
) -> bool:
    policies = organizations_list_all_policies_for_target(
        organizations_client, target_id, interval_between_calls=float(interval_between_calls)
    )
    logger.info("Policies found for target '%s': %s", target_id, policies)
    return any(x.get("Id") in policy_ids for x in policies)


def is_policy_attached_in_ancestry(organizations_client, child_id: str, policy_ids: list[str]) -> bool:
    current_id = child_id
    while True:
        if policy_is_attached(organizations_client, current_id, policy_ids):
            return True
        parents = organizations_client.list_parents(ChildId=str(current_id)).get("Parents", [])
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
    organizations_client, policy_summaries: list[dict], current_account_id: str, interval_between_calls: float = 0.1
) -> tuple[str, str]:
    policy_ids = [x.get("Id") for x in policy_summaries]
    mgmt_account_id = get_organizations_mgmt_account_id(organizations_client)
    if current_account_id == mgmt_account_id:
        if policy_is_attached(organizations_client, mgmt_account_id, policy_ids, interval_between_calls):
            return (
                "NON_COMPLIANT",
                "The restricting policy is attached to the Management Account, which is not allowed.",
            )
        parents = organizations_client.list_parents(ChildId=str(current_account_id)).get("Parents")
        if not parents:
            return False
        parent_id = parents[0]["Id"]
        ou_list = organizations_list_all_organizational_units(organizations_client, parent_id, interval_between_calls)
        missing_ous = []
        for ou in ou_list:
            ou_id = str(ou["Id"])
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
    interval_between_calls = 0.1
    aws_config_client = get_client("config", aws_account_id, execution_role_name, is_not_audit_account)
    aws_iam_client = get_client("iam", aws_account_id, execution_role_name, is_not_audit_account)
    aws_orgs_client = get_client("organizations", aws_account_id, execution_role_name, is_not_audit_account)
    tags = get_account_tags(get_client("organizations", assume_role=False), aws_account_id)
    cloud_profile = get_cloud_profile_from_tags(tags)

    # perform the check only for management account - issue 196

    if aws_account_id != get_organizations_mgmt_account_id(aws_orgs_client):
        logger.info("Not checked in account %s as this is not the Management Account", aws_account_id)
        return

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
        aws_orgs_client, restricting_policies, aws_account_id, float(interval_between_calls)
    )
    if compliance_type == "COMPLIANT":
        # aws_marketplace_catalog_client = get_client(
        #     "marketplace-catalog", aws_account_id, execution_role_name, is_not_audit_account, region='us-east-1'
        # )

        mgmt_account_id = get_organizations_mgmt_account_id(aws_orgs_client)

        if not private_marketplace_is_configured(mgmt_account_id,execution_role_name,is_not_audit_account):
        # if not private_marketplace_is_configured(aws_marketplace_catalog_client):

            compliance_type = "NON_COMPLIANT"
            annotation = "Private Marketplace NOT found."
        else:
            annotation = f"Private Marketplace found. {annotation}"
    logger.info(f"{compliance_type}: {annotation}")
    final_eval = build_evaluation(aws_account_id, compliance_type, event, annotation=annotation)
    submit_evaluations(aws_config_client, event, [final_eval])