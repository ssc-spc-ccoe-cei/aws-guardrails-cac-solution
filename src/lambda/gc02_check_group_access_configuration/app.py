""" GC02 - Check Group Access Configuration
    https://canada-ca.github.io/cloud-guardrails/EN/02_Management-Admin-Privileges.html
"""

import json
import logging
from enum import Enum

import botocore.exceptions

from utils import (
    is_scheduled_notification,
    check_required_parameters,
    check_guardrail_requirement_by_cloud_usage_profile,
    get_cloud_profile_from_tags,
    GuardrailType,
    GuardrailRequirementType,
)
from boto_util.organizations import get_account_tags, get_organizations_mgmt_account_id
from boto_util.client import get_client
from boto_util.config import build_evaluation, submit_evaluations
from boto_util.s3 import check_s3_object_exists, get_lines_from_s3_file
from boto_util.iam import (
    list_all_iam_users,
    list_all_iam_groups,
    list_all_iam_attached_group_policies,
    get_all_iam_group_members,
    fetch_inline_user_policies,
    fetch_aws_managed_user_policies,
    policies_grant_admin_access,
)
from boto_util.sso_admin import list_all_sso_admin_instances
from boto_util.identity_store import list_all_identity_store_groups


# Logging setup
logger = logging.getLogger()
logger.setLevel(logging.INFO)


class PermissionSetPolicyComposition(Enum):
    ADMIN = 1
    NON_ADMIN = 2
    MIX = 3


def only_admin_policies(managed_policies, inline_policies):
    # Returns True if both managed policies and inline_policies only give admin access
    return next((False for p in managed_policies if p.get("PolicyName", "") != "AdministratorAccess"), True) and next(
        (False for p in inline_policies if not policy_doc_gives_admin_access(p.get("PolicyDocument", "{}"))), True
    )


def only_non_admin_policies(managed_policies, inline_policies):
    # Returns True if both managed policies and inline_policies only give non admin access
    return next((False for p in managed_policies if p.get("PolicyName", "") == "AdministratorAccess"), True) and next(
        (False for p in inline_policies if policy_doc_gives_admin_access(p.get("PolicyDocument", "{}"))), True
    )


def fetch_customer_managed_policy_documents_for_permission_set(iam_client, customer_managed_policies):
    policy_docs = []
    try:
        marker = None
        while True:
            response = (
                iam_client.list_policies(Scope="Local", Marker=marker)
                if marker
                else iam_client.list_policies(Scope="Local")
            )
            policies = response.get("Policies")
            for p in policies:
                if p.get("PolicyName") in customer_managed_policies:
                    p_doc_response = iam_client.get_policy_version(
                        PolicyArn=p.get("Arn"), VersionId=p.get("DefaultVersionId")
                    )
                    policy_docs.append(p_doc_response.get("PolicyVersion").get("Document"))
            marker = response.get("Marker")
            if not marker:
                break
    except botocore.exceptions.ClientError as ex:
        ex.response["Error"]["Message"] = "InternalError"
        ex.response["Error"]["Code"] = "InternalError"
        raise ex

    return policy_docs


def permission_set_only_has_admin_or_non_admin_policies(
    iam_client, sso_admin_client, instance_arn, permission_set_arn
) -> PermissionSetPolicyComposition:
    managed_policies = []
    inline_policies = []

    next_token = None
    try:
        # Fetch all AWS Managed policies for the permission set and add them to the list of managed policies
        while True:
            response = (
                sso_admin_client.list_managed_policies_in_permission_set(
                    InstanceArn=instance_arn, NextToken=next_token, PermissionSetArn=permission_set_arn
                )
                if next_token
                else sso_admin_client.list_managed_policies_in_permission_set(
                    InstanceArn=instance_arn, PermissionSetArn=permission_set_arn
                )
            )
            managed_policies = managed_policies + response.get("AttachedManagedPolicies")
            next_token = response.get("NextToken")
            if not next_token:
                break
        # Fetch the inline document for the permission set if any exists. If none exists the response will still be valid, just an empty policy doc.
        response = sso_admin_client.get_inline_policy_for_permission_set(
            InstanceArn=instance_arn, PermissionSetArn=permission_set_arn
        )
        # If length is less than or equal to 1 then the policy doc is empty because there is no inline policy.The API specifies a min length of 1, but is a bit vague on what an empty policy doc would look like so we are covering the case of empty string
        if len(response.get("InlinePolicy")) > 1:
            inline_policies.append({"PolicyDocument": response.get("InlinePolicy")})
        # Fetch all customer managed policy references, convert the references into their policy document on the account, and add them to the list of inline policies.
        while True:
            response = (
                sso_admin_client.list_customer_managed_policy_references_in_permission_set(
                    InstanceArn=instance_arn, NextToken=next_token, PermissionSetArn=permission_set_arn
                )
                if next_token
                else sso_admin_client.list_customer_managed_policy_references_in_permission_set(
                    InstanceArn=instance_arn, PermissionSetArn=permission_set_arn
                )
            )
            for policy_doc in fetch_customer_managed_policy_documents_for_permission_set(
                iam_client, [p.get("Name") for p in response.get("CustomerManagedPolicyReferences")]
            ):
                inline_policies.append({"PolicyDocument": policy_doc})
            next_token = response.get("NextToken")
            if not next_token:
                break

        if only_admin_policies(managed_policies, inline_policies):
            return "ADMIN"
        elif only_non_admin_policies(managed_policies, inline_policies):
            return "NON_ADMIN"
        else:
            return "MIX"

    except botocore.exceptions.ClientError as ex:
        ex.response["Error"]["Message"] = "InternalError"
        ex.response["Error"]["Code"] = "InternalError"
        raise ex


def get_permission_sets_for_group(sso_admin_client, instance_arn, group_id):
    permission_sets = set()
    next_token = None
    try:
        while True:
            response = (
                sso_admin_client.list_account_assignments_for_principal(
                    InstanceArn=instance_arn, PrincipalId=group_id, PrincipalType="GROUP", NextToken=next_token
                )
                if next_token
                else sso_admin_client.list_account_assignments_for_principal(
                    InstanceArn=instance_arn, PrincipalId=group_id, PrincipalType="GROUP"
                )
            )

            for acc_assignment in response.get("AccountAssignments"):
                p_set_arn = acc_assignment.get("PermissionSetArn")
                if p_set_arn not in permission_sets:
                    permission_sets.add(p_set_arn)

            next_token = response.get("NextToken")
            if not next_token:
                break
    except botocore.exceptions.ClientError as ex:
        ex.response["Error"]["Message"] = "InternalError"
        ex.response["Error"]["Code"] = "InternalError"
        raise ex

    return permission_sets


def fetch_identity_center_group_members(identity_store_client, instance_id, group_id):
    members = set()
    next_token = None
    try:
        while True:
            response = (
                identity_store_client.list_group_memberships(
                    IdentityStoreId=instance_id, GroupId=group_id, NextToken=next_token
                )
                if next_token
                else identity_store_client.list_group_memberships(IdentityStoreId=instance_id, GroupId=group_id)
            )
            for membership in response.get("GroupMemberships", []):
                user_id = membership.get("MemberId", {}).get("UserId", "")
                user_description = identity_store_client.describe_user(IdentityStoreId=instance_id, UserId=user_id)

                if user_description not in members:
                    members.append(user_description)

            next_token = response.get("NextToken")
            if not next_token:
                break
    except botocore.exceptions.ClientError as ex:
        ex.response["Error"]["Message"] = "InternalError"
        ex.response["Error"]["Code"] = "InternalError"
        raise ex

    return members


def check_iam_group_policies(iam_client, group_name, admin_accounts, event):
    resource_type = "AWS::IAM::Group"
    # Checks all group policies to ensure that there is not mixture of admin and non-admin roles.

    # Fetch aws managed and inline group policies
    managed_policies = list_all_iam_attached_group_policies(iam_client, group_name)
    inline_policies = fetch_inline_group_policies(iam_client, group_name)

    # Checks for the aws managed policy AdministratorAccess or an inline policy that gives the same access.
    has_admin_policy = next(
        (True for p in managed_policies if p.get("PolicyName", "") == "AdministratorAccess"), False
    ) or next((True for p in inline_policies if policy_doc_gives_admin_access(p.get("PolicyDocument", "{}"))), False)
    has_non_admin_policy = next(
        (True for p in managed_policies if p.get("PolicyName", "") != "AdministratorAccess"), False
    ) or next(
        (True for p in inline_policies if not policy_doc_gives_admin_access(p.get("PolicyDocument", "{}"))), False
    )

    # Does the group have admin policies and non admin policies?
    if has_admin_policy and has_non_admin_policy:
        # yes, there is a mixture of admin and non-admin roles attached to the group. Return NON_COMPLIANT evaluation for group
        annotation = f"Group '{group_name}' has attached policies that contain both admin and non-admin roles."
        return build_evaluation(group_name, "NON_COMPLIANT", event, resource_type, annotation)

    # Is the group an admin group?
    if has_admin_policy:
        # yes, fetch group members and check against admin_accounts
        group_members = get_all_iam_group_members(iam_client, group_name)
        has_non_admin_member = next((m for m in group_members if m.get("UserName", "") not in admin_accounts), False)
        if has_non_admin_member:
            annotation = f"Group '{group_name}' is an admin group that contains non-admin members."
            return build_evaluation(group_name, "NON_COMPLIANT", event, resource_type, annotation)

    annotation = (
        f"Group '{group_name}' has policies that only provides admin roles and only has admin members."
        if has_admin_policy
        else f"Group '{group_name}' has policies that only provides non-admin roles."
    )

    return build_evaluation(group_name, "COMPLIANT", event, resource_type, annotation)


def is_admin_group(iam_client, sso_admin_client, instance_arn, p_set_arns) -> bool:
    for arn in p_set_arns:
        p_set_type = permission_set_only_has_admin_or_non_admin_policies(
            iam_client, sso_admin_client, instance_arn, arn
        )
        if p_set_type == PermissionSetPolicyComposition.ADMIN and p_set_type == PermissionSetPolicyComposition.MIX:
            return True
    return False


def check_identity_center_admin_group(
    identity_store_client, instance_id, instance_arn, group_id, group_name, admin_accounts, event
):
    resource_type = "AWS::IAM::Group"
    # Checks all group policies to ensure that there is not mixture of admin and non-admin roles.
    group_members = fetch_identity_center_group_members(identity_store_client, instance_id, group_id)
    has_non_admin_member = next((m for m in group_members if m.get("UserName", "") not in admin_accounts), False)

    if has_non_admin_member:
        annotation = f"Group '{group_name}' has permission set(s) that applies an admin access policy but also contains non-admin members."
        return build_evaluation(group_name, "NON_COMPLIANT", event, resource_type, annotation)

    annotation = (
        f"Group '{group_name}' has permission set(s) that applies an admin access policy and only has admin members."
    )
    return build_evaluation(group_name, "COMPLIANT", event, resource_type, annotation=annotation)


def policy_doc_gives_admin_access(policy_doc: str) -> bool:

    document_dict = json.loads(policy_doc)
    statements = document_dict.get("Statement", [])

    for statement_component in statements:
        if statement_component.get("Effect", "") == "Allow":

            actions = statement_component.get("Action", [])
            if isinstance(actions, str):
                actions = [actions]

            # Check if any action is exact "*" AND Resource == "*".
            if "*" in actions and statement_component.get("Resource", "") == "*":
                return True

    return False


def fetch_inline_group_policies(iam_client, group_name):
    policies = []
    marker = None
    try:
        while True:
            response = (
                iam_client.list_group_policies(GroupName=group_name, Marker=marker)
                if marker
                else iam_client.list_group_policies(GroupName=group_name)
            )
            policies = policies + response.get("PolicyNames", [])
            marker = response.get("Marker")
            if not marker:
                break
    except botocore.exceptions.ClientError as ex:
        if "NoSuchEntity" in ex.response["Error"]["Code"]:
            ex.response["Error"][
                "Message"
            ] = f"Unable to fetch policies for group '{group_name}'. No such entity found."
        elif "InvalidInput" in ex.response["Error"]["Code"]:
            ex.response["Error"]["Message"] = f"Invalid group name '{group_name}' or marker '{marker}' input received."
        else:
            ex.response["Error"]["Message"] = "InternalError"
            ex.response["Error"]["Code"] = "InternalError"
        raise ex

    try:
        for i in range(len(policies)):
            policies[i] = iam_client.get_group_policy(group_name, policies[i])
    except botocore.exceptions.ClientError as ex:
        if "NoSuchEntity" in ex.response["Error"]["Code"]:
            ex.response["Error"]["Message"] = "Unable to fetch inline policy information. No such entity found."
        elif "InvalidInput" in ex.response["Error"]["Code"]:
            ex.response["Error"]["Message"] = "Failed to fetch inline policy information. Invalid input."
        else:
            ex.response["Error"]["Message"] = "InternalError"
            ex.response["Error"]["Code"] = "InternalError"

    return policies


def iam_user_has_administrator_access(iam_client, user):
    user_name = user.get("UserName", "")
    inline_policies = fetch_inline_user_policies(iam_client, user_name)
    aws_managed_policies = fetch_aws_managed_user_policies(iam_client, user_name)
    return policies_grant_admin_access(aws_managed_policies, inline_policies)


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

    aws_config_client = get_client("config", aws_account_id, execution_role_name, is_not_audit_account)
    aws_iam_client = get_client("iam", aws_account_id, execution_role_name, is_not_audit_account)
    aws_identity_store_client = get_client("identitystore", aws_account_id, execution_role_name, is_not_audit_account)
    aws_sso_admin_client = get_client("sso-admin", aws_account_id, execution_role_name, is_not_audit_account)
    aws_s3_client = get_client("s3")
    aws_organizations_client = get_client("organizations", aws_account_id, execution_role_name, is_not_audit_account)

    # Check cloud profile
    tags = get_account_tags(get_client("organizations", assume_role=False), aws_account_id)
    cloud_profile = get_cloud_profile_from_tags(tags)
    gr_requirement_type = check_guardrail_requirement_by_cloud_usage_profile(GuardrailType.Guardrail2, cloud_profile)

    # If the guardrail is recommended
    if gr_requirement_type == GuardrailRequirementType.Recommended:
        return submit_evaluations(
            aws_config_client,
            event,
            [build_evaluation(aws_account_id, "COMPLIANT", event, gr_requirement_type=gr_requirement_type)],
        )
    # If the guardrail is not required
    elif gr_requirement_type == GuardrailRequirementType.Not_Required:
        return submit_evaluations(
            aws_config_client,
            event,
            [build_evaluation(aws_account_id, "NOT_APPLICABLE", event, gr_requirement_type=gr_requirement_type)],
        )

    admin_accounts_s3_path = rule_parameters.get("s3ObjectPath", "")
    if not check_s3_object_exists(aws_s3_client, admin_accounts_s3_path):
        evaluations.append(
            build_evaluation(
                aws_account_id, "NON_COMPLIANT", event, annotation="No AdminAccountsFilePath input provided."
            )
        )
        submit_evaluations(aws_config_client, event, evaluations)
        return

    is_compliant = True
    annotation = ""
    management_account_id = get_organizations_mgmt_account_id(aws_organizations_client)
    admin_accounts = get_lines_from_s3_file(aws_s3_client, admin_accounts_s3_path)
    if not admin_accounts:
        evaluations.append(build_evaluation(aws_account_id,"NON_COMPLIANT",event,annotation="Admin accounts file is empty.",gr_requirement_type=gr_requirement_type))
        submit_evaluations(aws_config_client, event, evaluations)
        return
    instances = list_all_sso_admin_instances(aws_sso_admin_client)
    identity_center_enabled = len([i for i in instances if i.get("Status", "") == "ACTIVE"]) > 0

    # Identity Center Check
    if identity_center_enabled:
        if aws_account_id != management_account_id:
            logger.info("Not a management account, Identity center check not applicable for account %s", aws_account_id)
            return submit_evaluations(
            aws_config_client,
            event,
            [build_evaluation(aws_account_id, "NOT_APPLICABLE", event, annotation="NOT applicable in this account")])

        for i in instances:
            has_non_admin_group = False
            i_id = i.get("IdentityStoreId")
            i_arn = i.get("InstanceArn")
            identity_center_groups = list_all_identity_store_groups(aws_identity_store_client, i_id)

            for g in identity_center_groups:
                g_id = g.get("GroupId")
                g_name = g.get("DisplayName")
                p_sets = get_permission_sets_for_group(aws_sso_admin_client, i_arn, g_id)
                if is_admin_group(aws_iam_client, aws_sso_admin_client, i_arn, p_sets):
                    eval = check_identity_center_admin_group(
                        aws_identity_store_client,
                        i_id,
                        i_arn,
                        g_id,
                        g_name,
                        admin_accounts,
                        event,
                    )
                    if eval.get("ComplianceType", "NON_COMPLIANT") == "NON_COMPLIANT":
                        is_compliant = False
                        annotation = "Group has a permission set that provides administrator access and members that are not admin members."

                    evaluations.append(eval)
                else:
                    has_non_admin_group = True

            if not has_non_admin_group:
                is_compliant = False
                annotation = (
                    "Account does not have an Identity Center group that does not provide administrator access."
                )

        # Append Account evaluation
        evaluations.append(
            build_evaluation(
                aws_account_id,
                "COMPLIANT" if is_compliant else "NON_COMPLIANT",
                event,
                annotation=annotation,
                gr_requirement_type=gr_requirement_type,
            )
        )
    else:
        # IAM
        groups = list_all_iam_groups(aws_iam_client)
        has_non_admin_group = False
        has_non_compliant_iam_group = False

        for g in groups:
            group_name = g.get("GroupName")
            inline_policies = fetch_inline_group_policies(aws_iam_client, group_name)
            aws_managed_policies = list_all_iam_attached_group_policies(aws_iam_client, group_name)
            # Does the group's policies grant administrator access?
            if policies_grant_admin_access(aws_managed_policies, inline_policies):
                # Yes, check to make sure all group members are in the admin user list
                group_members = get_all_iam_group_members(aws_iam_client, group_name)
                non_admin_members = [
                    u.get("UserName") for u in group_members if u.get("UserName", "") not in admin_accounts
                ]
                if len(non_admin_members) > 0:
                    has_non_compliant_iam_group = True
                    evaluations.append(
                        build_evaluation(
                            g.get("Arn"),
                            "NON_COMPLIANT",
                            event,
                            "AWS::IAM::Group",
                            annotation=f"Group {group_name} gives administrator access to non-admin users: {", ".join(non_admin_members)}",
                        ),
                        gr_requirement_type=gr_requirement_type,
                    )
                else:
                    evaluations.append(
                        build_evaluation(
                            g.get("Arn"), "COMPLIANT", event, "AWS::IAM::Group", gr_requirement_type=gr_requirement_type
                        )
                    )
            else:
                has_non_admin_group = True
                evaluations.append(build_evaluation(g.get("Arn"), "COMPLIANT", event, "AWS::IAM::Group"))

        # Append Account evaluation
        annotation = " and ".join(
            filter(
                lambda x: x != None,
                [
                    (
                        "Account does not have an IAM group that doesn't provide admin access."
                        if not has_non_admin_group
                        else None
                    ),
                    (
                        "One or more IAM groups gives administrator access to a non-admin user."
                        if has_non_compliant_iam_group
                        else None
                    ),
                ],
            )
        )
        compliance_type = "COMPLIANT" if has_non_admin_group and not has_non_compliant_iam_group else "NON_COMPLIANT"
        evaluations.append(
            build_evaluation(
                aws_account_id, compliance_type, event, annotation=annotation, gr_requirement_type=gr_requirement_type
            )
        )

    logger.info(f"Put evaluations: {evaluations}")
    submit_evaluations(aws_config_client, event, evaluations)
