""" GC12 - Check Marketplace Configuration
    https://canada-ca.github.io/cloud-guardrails/EN/12_Cloud-Marketplace-Config.html
"""

import logging
import json
import re
import time

import boto3
import botocore
import botocore.exceptions

from utils import (
    is_scheduled_notification,
    check_required_parameters,
    check_guardrail_requirement_by_cloud_usage_profile,
    get_cloud_profile_from_tags,
    GuardrailType,
    GuardrailRequirementType,
)
from boto_util.client import get_client, get_assume_role_credentials
from boto_util.config import build_evaluation, submit_evaluations
from boto_util.organizations import (
    organizations_list_all_service_control_policies,
    get_organizations_mgmt_account_id,
    organizations_list_all_policies_for_target,
    organizations_list_all_roots,
    get_account_tags,
)

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# The AWS Marketplace Catalog API for the "Experience" (Private Marketplace) entity type is
# only available in us-east-1, regardless of the region this lambda executes in.
MARKETPLACE_CATALOG_REGION = "us-east-1"
MARKETPLACE_CATALOG = "AWSMarketplace"

# The AWS managed SCP that is attached to every target by default. It never restricts anything.
FULL_AWS_ACCESS_POLICY_ID = "p-FullAWSAccess"

# The private marketplace administration actions that a restricting SCP must deny.
PRIVATE_MARKETPLACE_ADMIN_ACTIONS = [
    "aws-marketplace:StartChangeSet",
    "aws-marketplace:CancelChangeSet",
    "aws-marketplace:CreatePrivateMarketplace",
    "aws-marketplace:StartPrivateMarketplace",
    "aws-marketplace:StopPrivateMarketplace",
    "aws-marketplace:UpdatePrivateMarketplaceSettings",
    "aws-marketplace:AssociateProductsWithPrivateMarketplace",
    "aws-marketplace:DisassociateProductsFromPrivateMarketplace",
    "aws-marketplace:CreatePrivateMarketplaceProfile",
    "aws-marketplace:UpdatePrivateMarketplaceProfile"
]


def get_regional_client(
    service: str,
    account_id: str | None = None,
    role_name: str | None = None,
    assume_role: bool = True,
    region: str | None = None,
):
    """
    Return a boto client pinned to a specific region for the (optionally assumed) role.

    The shared `boto_util.client.get_client` helper only uses the `region` argument when
    creating the STS client, so the resulting service client still lands in the lambda's
    own region. The Marketplace Catalog API is only available in us-east-1, so this check
    needs a client that is explicitly bound to that region.
    """
    if not role_name or not account_id or not assume_role:
        return boto3.client(service, region_name=region)

    credentials = get_assume_role_credentials(f"arn:aws:iam::{account_id}:role/{role_name}", region)
    return boto3.client(
        service,
        region_name=region,
        aws_access_key_id=credentials["AccessKeyId"],
        aws_secret_access_key=credentials["SecretAccessKey"],
        aws_session_token=credentials["SessionToken"],
    )


def _entity_details(entity_response: dict) -> dict:
    """
    DescribeEntity returns the entity details as a JSON object in `DetailsDocument` and the
    same payload as a JSON string in the legacy `Details` field. Accept either.
    """
    details = entity_response.get("DetailsDocument")
    if isinstance(details, dict):
        return details

    raw = entity_response.get("Details")
    if isinstance(raw, str) and raw:
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            return {}
        return parsed if isinstance(parsed, dict) else {}
    return {}


def marketplace_list_all_entities(
    marketplace_catalog_client, entity_type: str, interval_between_calls: float = 0.1
) -> list[dict]:
    """
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/marketplace-catalog/client/list_entities.html
    """
    resources: list[dict] = []
    next_token = None
    while True:
        args = {"Catalog": MARKETPLACE_CATALOG, "EntityType": entity_type}
        if next_token:
            args["NextToken"] = next_token
        response = marketplace_catalog_client.list_entities(**args)
        if not response:
            raise ValueError("No response from AWS Marketplace Catalog")
        resources.extend(response.get("EntitySummaryList") or [])
        next_token = response.get("NextToken")
        if not next_token:
            break
        time.sleep(interval_between_calls)
    return resources


def get_enabled_experience_ids(marketplace_catalog_client, interval_between_calls: float = 0.1) -> list[str]:
    """
    Return the ids of the Private Marketplace experiences whose Status is Enabled.

    A disabled or archived experience has no effect: "If there are no private marketplace
    experiences enabled for an account, then all restrictions are removed, and users are able
    to procure any products in the public AWS Marketplace."
    """
    enabled: list[str] = []
    for entity in marketplace_list_all_entities(marketplace_catalog_client, "Experience", interval_between_calls):
        entity_id = entity.get("EntityId")
        if not entity_id:
            continue
        response = marketplace_catalog_client.describe_entity(Catalog=MARKETPLACE_CATALOG, EntityId=entity_id)
        details = _entity_details(response)
        status = str(details.get("Status", "")).lower()
        logger.info("Private Marketplace experience %s has status '%s'.", entity_id, details.get("Status"))
        if status == "enabled":
            enabled.append(entity_id)
        time.sleep(interval_between_calls)
    return enabled


def get_audience_principals(marketplace_catalog_client, interval_between_calls: float = 0.1) -> set[str]:
    """
    Return the set of principals (account ids, OU ids, or the organization id) that are
    associated with a Private Marketplace experience via an Audience entity.
    """
    principals: set[str] = set()
    for entity in marketplace_list_all_entities(marketplace_catalog_client, "Audience", interval_between_calls):
        entity_id = entity.get("EntityId")
        if not entity_id:
            continue
        response = marketplace_catalog_client.describe_entity(Catalog=MARKETPLACE_CATALOG, EntityId=entity_id)
        details = _entity_details(response)
        for principal in details.get("Principals") or []:
            principals.add(str(principal))
        time.sleep(interval_between_calls)
    logger.info("Private Marketplace audience principals: %s", sorted(principals))
    return principals


def assess_private_marketplace(
    organizations_client,
    mgmt_account_id: str,
    execution_role_name: str,
    is_not_audit_account: bool,
    interval_between_calls: float = 0.1,
) -> tuple[str, str]:
    """
    Verify that an enabled Private Marketplace experience exists AND that its audience covers
    every OU and account in the organization.

    Audience principals may be an account id, an OU id, or the organization id. Associating
    the organization is the default for every account; associating an OU covers the accounts
    beneath it. The organization root (r-...) is NOT a valid principal, so accounts sitting
    directly in the root container must be covered by the organization id or individually.
    """
    marketplace_catalog_client = get_regional_client(
        "marketplace-catalog",
        mgmt_account_id,
        execution_role_name,
        is_not_audit_account,
        region=MARKETPLACE_CATALOG_REGION,
    )

    try:
        enabled_experiences = get_enabled_experience_ids(marketplace_catalog_client, interval_between_calls)
        if not enabled_experiences:
            return ("NON_COMPLIANT", "No enabled Private Marketplace experience found.")
        principals = get_audience_principals(marketplace_catalog_client, interval_between_calls)
    except botocore.exceptions.ClientError as err:
        raise ValueError(f"Error in AWS Marketplace Catalog: {err}") from err

    if not principals:
        return ("NON_COMPLIANT", "The Private Marketplace experience is not associated with any accounts or OUs.")

    organization_id = str(organizations_client.describe_organization()["Organization"]["Id"])
    if organization_id in principals:
        # The experience associated with the organization is the default for every account.
        return ("COMPLIANT", "Private Marketplace found and applied to the entire organization.")

    uncovered = find_uncovered_targets(
        organizations_client,
        lambda target_id: target_id in principals,
        interval_between_calls,
    )
    if uncovered:
        return (
            "NON_COMPLIANT",
            f"The Private Marketplace experience does NOT apply to: {', '.join(uncovered)}.",
        )
    return ("COMPLIANT", "Private Marketplace found and applied to all OUs and accounts.")


def _as_list(value) -> list:
    """Policy elements such as Action/Resource may be a single string or a list."""
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def iam_pattern_matches(pattern: str, action: str) -> bool:
    """
    Match an IAM policy action pattern against a concrete action name.

    IAM wildcards are `*` (any sequence) and `?` (any single character), and matching is
    case-insensitive. `fnmatch` is deliberately not used because it also treats `[...]` as a
    character class, which IAM does not.
    """
    regex = "".join(
        ".*" if char == "*" else "." if char == "?" else re.escape(char)
        for char in str(pattern)
    )
    return re.fullmatch(regex, str(action), flags=re.IGNORECASE) is not None


def statement_denies_all_resources(statement: dict) -> bool:
    """The private marketplace admin actions are not resource-scoped, so the Deny must be on `*`."""
    return "*" in _as_list(statement.get("Resource"))


def actions_denied_by_statement(statement: dict, candidate_actions: set[str]) -> set[str]:
    """
    Return the subset of `candidate_actions` that the given Deny statement blocks.

    Handles both `Action` (deny what matches) and `NotAction` (deny what does NOT match).
    """
    if "NotAction" in statement:
        not_actions = _as_list(statement.get("NotAction"))
        return {
            action
            for action in candidate_actions
            if not any(iam_pattern_matches(pattern, action) for pattern in not_actions)
        }

    actions = _as_list(statement.get("Action"))
    return {
        action
        for action in candidate_actions
        if any(iam_pattern_matches(pattern, action) for pattern in actions)
    }


def policy_restricts_marketplace_access(policy_doc) -> bool:
    """
    Return True when the policy denies *every* private marketplace administration action.

    The policy document is evaluated statically rather than with `iam:SimulateCustomPolicy`.
    Simulating an SCP on its own always reports every action as `implicitDeny`, because an
    SCP contains no Allow statements, so the simulation returned "restricted" for any
    Deny-only policy regardless of its content.

    Conditional Deny statements are ignored: a deny that only applies under certain
    conditions (a region, a principal, ...) does not unconditionally restrict the action.
    """
    # Handle both string and dictionary inputs
    if isinstance(policy_doc, str):
        try:
            document_dict = json.loads(policy_doc)
        except json.JSONDecodeError:
            # if the string is not valid, return False
            return False
    else:
        document_dict = policy_doc

    if not isinstance(document_dict, dict):
        return False

    statements = document_dict.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]

    remaining = set(PRIVATE_MARKETPLACE_ADMIN_ACTIONS)
    for statement_component in statements:
        if not isinstance(statement_component, dict):
            continue
        if statement_component.get("Effect", "") != "Deny":
            continue
        if statement_component.get("Condition"):
            # A conditional deny is not a guaranteed restriction.
            continue
        if not statement_denies_all_resources(statement_component):
            continue

        remaining -= actions_denied_by_statement(statement_component, remaining)
        if not remaining:
            return True

    logger.debug("Policy does not deny the following marketplace actions: %s", sorted(remaining))
    return False


def get_policies_that_restrict_marketplace_access(
    organizations_client, interval_between_calls: float = 0.1
):
    """
    Return the SCPs in the organization that deny every private marketplace admin action.
    """
    policies = organizations_list_all_service_control_policies(organizations_client, interval_between_calls)
    selected_policy_summaries = []
    for policy_summary in policies:
        policy_id = policy_summary.get("Id")
        if not policy_id or policy_id == FULL_AWS_ACCESS_POLICY_ID:
            # The AWS managed FullAWSAccess policy never restricts anything, skip the API call.
            continue
        response = organizations_client.describe_policy(PolicyId=policy_id)
        policy = response.get("Policy", {})
        policy_content = policy.get("Content") or ""
        if not policy_content:
            continue
        if policy_restricts_marketplace_access(policy_content):
            selected_policy_summaries.append(policy_summary)
        time.sleep(interval_between_calls)
    logger.info("Marketplace restriction policies found: %s", selected_policy_summaries)
    return selected_policy_summaries


def organizations_list_all_accounts_for_parent(
    organizations_client, parent_id: str, interval_between_calls: float = 0.1
) -> list[dict]:
    """
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/organizations/paginator/ListAccountsForParent.html

    Not available in the shared boto_util.organizations layer module, which only exposes
    `organizations_list_all_accounts` (every account in the org, without its parent).
    """
    resources: list[dict] = []
    paginator = organizations_client.get_paginator("list_accounts_for_parent")
    for page in paginator.paginate(ParentId=parent_id):
        resources.extend(page.get("Accounts", []))
        time.sleep(interval_between_calls)
    return resources


def organizations_list_child_organizational_units(
    organizations_client, parent_id: str, interval_between_calls: float = 0.1
) -> list[dict]:
    """
    Direct child OUs of a parent. The shared `organizations_list_all_organizational_units`
    helper recurses through the whole subtree, which we do not want here because the
    traversal below prunes entire branches once they are covered.
    """
    resources: list[dict] = []
    paginator = organizations_client.get_paginator("list_organizational_units_for_parent")
    for page in paginator.paginate(ParentId=parent_id):
        resources.extend(page.get("OrganizationalUnits", []))
        time.sleep(interval_between_calls)
    return resources


def get_organization_root_id(organizations_client, interval_between_calls: float = 0.1) -> str:
    roots = organizations_list_all_roots(organizations_client, interval_between_calls)
    if not roots:
        raise ValueError("Unable to determine the organization root.")
    return str(roots[0]["Id"])


def find_uncovered_targets(
    organizations_client,
    is_covered,
    interval_between_calls: float = 0.1,
    skip_account_ids: set[str] | None = None,
) -> list[str]:
    """
    Walk the organization tree from the root and return the ids of any targets that are not
    covered by `is_covered`.

    Coverage is inherited: once a target is covered, its whole subtree is covered and is not
    descended into. This correctly handles both of the things we need to verify:

      * an SCP attached to the root or to an OU applies to every account beneath it;
      * a private marketplace audience principal set to an OU applies to its child accounts.

    Accounts that sit directly in the root container (i.e. not in any OU) are visited as
    children of the root, so they are never silently skipped.

    `skip_account_ids` is used to exclude the management account, which is exempt from SCPs.
    """
    skip_account_ids = skip_account_ids or set()
    root_id = get_organization_root_id(organizations_client, interval_between_calls)

    uncovered: list[str] = []
    # Targets still to inspect. The root is checked first; if it is covered the entire
    # organization is covered and no further API calls are made.
    pending = [root_id]

    while pending:
        target_id = pending.pop()
        if is_covered(target_id):
            continue

        # Not covered at this level, so each child must be covered on its own.
        for account in organizations_list_all_accounts_for_parent(
            organizations_client, target_id, interval_between_calls
        ):
            account_id = str(account["Id"])
            if account_id in skip_account_ids:
                continue
            if not is_covered(account_id):
                uncovered.append(account_id)

        for ou in organizations_list_child_organizational_units(
            organizations_client, target_id, interval_between_calls
        ):
            pending.append(str(ou["Id"]))

    return uncovered


def policy_is_attached(
    organizations_client,
    target_id: str,
    policy_ids: list[str],
    interval_between_calls: float = 0.1,
    policies_by_target: dict[str, list[dict]] | None = None,
) -> bool:
    if policies_by_target is None:
        policies_by_target = {}
    if target_id not in policies_by_target:
        policies_by_target[target_id] = organizations_list_all_policies_for_target(
            organizations_client, target_id, interval_between_calls=float(interval_between_calls)
        )
    policies = policies_by_target[target_id]
    logger.debug("Policies found for target '%s': %s", target_id, policies)
    return any(x.get("Id") in policy_ids for x in policies)


def assess_policy_attachment(
    organizations_client,
    policy_summaries: list[dict],
    mgmt_account_id: str,
    interval_between_calls: float = 0.1,
) -> tuple[str, str]:
    """
    Verify the restricting SCP applies to every account and OU in the organization (whether
    attached directly or inherited from the root / an ancestor OU) and is NOT attached to the
    management account itself.

    This is only ever called from the management account (see `assess_guardrail_12`), which
    is also the only account able to read the organization's policy attachments.
    """
    policy_ids = [x.get("Id") for x in policy_summaries]
    # Cache of target_id -> attached SCPs, so each target is only queried once.
    policies_by_target: dict[str, list[dict]] = {}

    if policy_is_attached(
        organizations_client,
        mgmt_account_id,
        policy_ids,
        interval_between_calls,
        policies_by_target=policies_by_target,
    ):
        return (
            "NON_COMPLIANT",
            "The restricting policy is attached to the Management Account, which is not allowed.",
        )

    def is_covered(target_id: str) -> bool:
        return policy_is_attached(
            organizations_client,
            target_id,
            policy_ids,
            interval_between_calls,
            policies_by_target=policies_by_target,
        )

    uncovered = find_uncovered_targets(
        organizations_client,
        is_covered,
        interval_between_calls,
        # SCPs never apply to the management account, and it must not be attached directly.
        skip_account_ids={str(mgmt_account_id)},
    )

    if uncovered:
        return (
            "NON_COMPLIANT",
            f"The restricting policy does NOT apply to: {', '.join(uncovered)}.",
        )
    return (
        "COMPLIANT",
        "The restricting policy applies to all OUs and accounts, and is not attached to the management account.",
    )


def lambda_handler(event, context):
    """
    Entry point. Any unexpected failure is still reported to AWS Config so that the account
    is never silently missing from the daily evidence / CSV report.
    """
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
    aws_config_client = get_client("config", aws_account_id, execution_role_name, is_not_audit_account)

    try:
        return assess_guardrail_12(event, aws_config_client, rule_parameters)
    except Exception as ex:  # noqa: BLE001 - deliberately broad, see docstring
        logger.exception("Unexpected error while evaluating Guardrail 12 in account %s", aws_account_id)
        evaluation = build_evaluation(
            aws_account_id,
            "NON_COMPLIANT",
            event,
            annotation=f"The evaluation could not be completed due to an error: {type(ex).__name__}.",
        )
        return submit_evaluations(aws_config_client, event, [evaluation])


def assess_guardrail_12(event, aws_config_client, rule_parameters):
    execution_role_name = rule_parameters["ExecutionRoleName"]
    audit_account_id = rule_parameters.get("AuditAccountID", "")
    aws_account_id = event["accountId"]
    is_not_audit_account = aws_account_id != audit_account_id
    interval_between_calls = 0.1
    aws_orgs_client = get_client("organizations", aws_account_id, execution_role_name, is_not_audit_account)

    # Perform the check only for the management account - issue 196.
    # Workload accounts are typically denied organizations:ListPolicies, which produced a
    # large amount of AccessDeniedException noise in the logs, and the management account
    # assessment already covers every OU in the organization.
    mgmt_account_id = get_organizations_mgmt_account_id(aws_orgs_client)
    if aws_account_id != mgmt_account_id:
        logger.info("Not checked in account %s as this is not the Management Account", aws_account_id)
        # Report NOT_APPLICABLE rather than returning without an evaluation, so that any
        # previous result for this account is overwritten and the account still appears in
        # the compliance report.
        evaluation = build_evaluation(
            aws_account_id,
            "NOT_APPLICABLE",
            event,
            annotation="Guardrail 12 is only assessed in the Management Account.",
        )
        return submit_evaluations(aws_config_client, event, [evaluation])

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
        aws_orgs_client, float(interval_between_calls)
    )
    if not restricting_policies:
        compliance_type = "NON_COMPLIANT"
        annotation = "No restricting SCP found that denies Marketplace usage."
        logger.info(f"{compliance_type}: {annotation}")
        eval_ = build_evaluation(aws_account_id, compliance_type, event, annotation=annotation)
        return submit_evaluations(aws_config_client, event, [eval_])

    compliance_type, annotation = assess_policy_attachment(
        aws_orgs_client, restricting_policies, mgmt_account_id, float(interval_between_calls)
    )
    if compliance_type == "COMPLIANT":
        compliance_type, marketplace_annotation = assess_private_marketplace(
            aws_orgs_client,
            mgmt_account_id,
            execution_role_name,
            is_not_audit_account,
            float(interval_between_calls),
        )
        annotation = f"{marketplace_annotation} {annotation}" if compliance_type == "COMPLIANT" else marketplace_annotation

    logger.info(f"{compliance_type}: {annotation}")
    final_eval = build_evaluation(aws_account_id, compliance_type, event, annotation=annotation)
    return submit_evaluations(aws_config_client, event, [final_eval])
