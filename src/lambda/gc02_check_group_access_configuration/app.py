""" GC02 - Check Group Access Configuration
    https://canada-ca.github.io/cloud-guardrails/EN/02_Management-Admin-Privileges.html
"""

import json
import logging
from enum import Enum

import botocore.exceptions

from utils import is_scheduled_notification, check_required_parameters, check_guardrail_rquirement_by_cloud_usage_profile, get_cloud_profile_from_tags, GuardrailType, GuardrailRequirementType
from boto_util.organizations import get_account_tags
from boto_util.client import get_client
from boto_util.config import build_evaluation, submit_evaluations
from boto_util.s3 import check_s3_object_exists, get_lines_from_s3_file
from boto_util.iam import list_all_iam_groups, list_all_iam_attached_group_policies, get_all_iam_group_members
from boto_util.sso_admin import list_all_sso_admin_instances
from boto_util.identity_store import list_all_identity_store_groups


# Logging setup
logger = logging.getLogger()
logger.setLevel(logging.INFO)


class GroupPermissionAssignment(Enum):
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
) -> GroupPermissionAssignment:
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

            for acc_assignment in response.get("PermissionSets"):
                p_set_arn = acc_assignment.get("PermissionSetArn")
                if p_set_arn not in permission_sets:
                    permission_sets.append(p_set_arn)

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


def check_identity_center_group_policies(
    iam_client, sso_admin_client, identity_store_client, instance_id, instance_arn, group, admin_accounts, event
):
    resource_type = "AWS::IAM::Group"
    # Checks all group policies to ensure that there is not mixture of admin and non-admin roles.

    group_id = group.get("GroupId")
    group_name = group.get("DisplayName")
    permission_set_arns = get_permission_sets_for_group(sso_admin_client, instance_id, group_id)
    group_members = fetch_identity_center_group_members(identity_store_client, instance_id, group_id)
    has_non_admin_member = next((m for m in group_members if m.get("UserName", "") not in admin_accounts), False)
    has_admin_pset = False
    has_non_admin_pset = False

    for p_set_arn in permission_set_arns:
        p_set_type = permission_set_only_has_admin_or_non_admin_policies(
            iam_client, sso_admin_client, instance_arn, p_set_arn
        )  # Is the group an admin group?
        if p_set_type == GroupPermissionAssignment.ADMIN:
            # yes, fetch group members and check against admin_accounts
            has_admin_pset = True
            if has_non_admin_member:
                annotation = f"Group '{group_name}' is a group containing non-admin members that has been assigned an admin permission set."
                return build_evaluation(group_name, "NON_COMPLIANT", event, resource_type, annotation)
        elif p_set_type == GroupPermissionAssignment.NON_ADMIN:
            has_non_admin_pset = True
        # Does the group have admin policies and non admin policies?
        elif p_set_type == GroupPermissionAssignment.MIX:
            # yes, there is a mixture of admin and non-admin roles attached to the group. Return NON_COMPLIANT evaluation for group
            annotation = (
                f"Group '{group_name}' has an assigned permission set that contain both admin and non-admin roles."
            )
            return build_evaluation(group_name, "NON_COMPLIANT", event, resource_type, annotation)

        if has_admin_pset and has_non_admin_pset:
            annotation = (
                f"Group '{group_name}' has been assigned admin only and non admin only permission sets. Groups should only contain admin only permission sets or non admin only permission sets.",
            )
            return build_evaluation(group_name, "NON_COMPLIANT", event, resource_type, annotation)

    annotation = (
        f"Group '{group_name}' has permission sets that apply policies granting only admin roles and only has admin members."
        if has_admin_pset
        else f"Group '{group_name}' permission sets that apply policies granting only non-admin roles."
    )

    return build_evaluation(group_name, "COMPLIANT", event, resource_type, annotation=annotation)


def policy_doc_gives_admin_access(policy_doc: str):
    document_dict = json.loads(policy_doc)
    statement = document_dict.get("Statement", [])
    for statement_component in statement:
        if (
            statement_component.get("Effect", "") == "Allow"
            and statement_component.get("Action", "") == "*"
            and statement_component.get("Resource", "") == "*"
        ):
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
    aws_organizations_client = get_client("organizations", aws_account_id, execution_role_name)
    
    # Check cloud profile
    tags = get_account_tags(aws_organizations_client, aws_account_id)
    cloud_profile = get_cloud_profile_from_tags(tags)
    gr_requirement_type = check_guardrail_rquirement_by_cloud_usage_profile(GuardrailType.Guardrail1, cloud_profile)
    
    # If the guardrail is recommended
    if gr_requirement_type == GuardrailRequirementType.Recommended:
        return submit_evaluations(aws_config_client, [build_evaluation(
            aws_account_id,
            "COMPLIANT",
            event,
            gr_requirement_type=gr_requirement_type
        )])
    # If the guardrail is not required
    elif gr_requirement_type == GuardrailRequirementType.Not_Required:
        return submit_evaluations(aws_config_client, [build_evaluation(
            aws_account_id,
            "NOT_APPLICABLE",
            event,
            gr_requirement_type=gr_requirement_type
        )])
    
    admin_accounts_s3_path = rule_parameters.get("s3ObjectPath", "")
    if not check_s3_object_exists(aws_s3_client, admin_accounts_s3_path):
        compliance_type = "NON_COMPLIANT"
        annotation = "No AdminAccountsFilePath input provided."

    else:
        is_compliant = True
        admin_accounts = get_lines_from_s3_file(aws_s3_client, admin_accounts_s3_path)

        # IAM
        iam_groups = list_all_iam_groups(aws_iam_client)
        for g in iam_groups:
            eval = check_iam_group_policies(aws_iam_client, g.get("GroupName", ""), admin_accounts, event)
            if eval.get("ComplianceType", "NON_COMPLIANT") == "NON_COMPLIANT":
                is_compliant = False
            evaluations.append(eval)

        # Identity Center
        instances = list_all_sso_admin_instances(aws_sso_admin_client)
        for i in instances:
            i_id = i.get("IdentityStoreId")
            i_arn = i.get("InstanceArn")
            identity_center_groups = list_all_identity_store_groups(aws_identity_store_client, i_id)
            for g in identity_center_groups:
                eval = check_identity_center_group_policies(
                    aws_iam_client,
                    aws_sso_admin_client,
                    aws_identity_store_client,
                    i_id,
                    i_arn,
                    g,
                    admin_accounts,
                    event,
                )
                if eval.get("ComplianceType", "NON_COMPLIANT") == "NON_COMPLIANT":
                    is_compliant = False
                evaluations.append(eval)

        if is_compliant:
            compliance_type = "COMPLIANT"
            annotation = (
                "Account groups only have admin or only have non-admin roles, and admin groups only have admin members."
            )
        else:
            compliance_type = "NON_COMPLIANT"
            annotation = "Account groups do not only have admin or only have non-admin roles, and admin groups only have admin members."

    logger.info(f"{compliance_type}: {annotation}")
    evaluations.append(build_evaluation(aws_account_id, compliance_type, event, annotation=annotation))
    submit_evaluations(aws_config_client, event["resultToken"], evaluations)
