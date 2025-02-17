""" GC02 - Check IAM Password Policy
    https://canada-ca.github.io/cloud-guardrails/EN/02_Management-Admin-Privileges.html
"""

import json
import logging

import botocore.exceptions

from utils import (
    is_scheduled_notification,
    check_required_parameters,
    check_guardrail_requirement_by_cloud_usage_profile,
    get_cloud_profile_from_tags,
    GuardrailType,
    GuardrailRequirementType,
)
from boto_util.organizations import get_account_tags, get_organizations_mgmt_account_id, organizations_list_all_accounts
from boto_util.client import get_client
from boto_util.config import build_evaluation, submit_evaluations
from boto_util.s3 import check_s3_object_exists, get_lines_from_s3_file
from boto_util.iam import list_all_iam_users
from boto_util.sso_admin import list_all_sso_admin_instances

# Logging setup
logger = logging.getLogger()
logger.setLevel(logging.INFO)


def fetch_sso_users(sso_admin_client, identity_store_client):
    """
    Return two dictionaries:
      1) users_by_instance: { instance_arn: [ { "UserName", "UserId", ... }, ... ] }
      2) instance_id_by_arn: { instance_arn: identity_store_id }
    """
    instances = list_all_sso_admin_instances(sso_admin_client)
    users_by_instance = {}
    instance_id_by_arn = {}

    for i in instances:
        if i.get("Status") != "ACTIVE":
            continue

        instance_id = i.get("IdentityStoreId")
        instance_arn = i.get("InstanceArn")
        instance_id_by_arn[instance_arn] = instance_id
        users_by_instance[instance_arn] = []
        next_token = None

        try:
            while True:
                response = (
                    identity_store_client.list_users(IdentityStoreId=instance_id, NextToken=next_token)
                    if next_token
                    else identity_store_client.list_users(IdentityStoreId=instance_id)
                )
                users_by_instance[instance_arn].extend(response.get("Users", []))
                next_token = response.get("NextToken")
                if not next_token:
                    break
        except botocore.exceptions.ClientError as ex:
            ex.response["Error"]["Message"] = "InternalError"
            ex.response["Error"]["Code"] = "InternalError"
            raise ex

    return users_by_instance, instance_id_by_arn


def fetch_sso_group_ids_for_user(identity_store_client, identity_store_id, user_id): 
    """
    Return the list of group IDs for which the specified user is a member.
    """
    group_ids = []
    # First, list all groups in the identity store.
    groups = []
    next_token = None
    while True:
        response = (
            identity_store_client.list_groups(IdentityStoreId=identity_store_id, NextToken=next_token)
            if next_token
            else identity_store_client.list_groups(IdentityStoreId=identity_store_id)
        )
        groups.extend(response.get("Groups", []))
        next_token = response.get("NextToken")
        if not next_token:
            break

    # Now, for each group, check if the user is a member.
    for group in groups:
        group_id = group.get("GroupId")
        membership_next_token = None
        while True:
            response = (
                identity_store_client.list_group_memberships(
                    IdentityStoreId=identity_store_id,
                    GroupId=group_id,
                    NextToken=membership_next_token,
                )
                if membership_next_token
                else identity_store_client.list_group_memberships(
                    IdentityStoreId=identity_store_id,
                    GroupId=group_id,
                )
            )
            for membership in response.get("GroupMemberships", []):
                if membership.get("MemberId", {}).get("UserId") == user_id:
                    group_ids.append(group_id)
                    break  # Found the user in this group; move on to the next group.
            membership_next_token = response.get("NextToken")
            if not membership_next_token:
                break

    return group_ids


def policy_doc_gives_admin_access(policy_doc: str) -> bool:
    """
    Check if the given JSON policy document has Effect=Allow, Action=*, Resource=*
    """
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


def fetch_inline_user_policies(iam_client, user_name):
    """
    Returns a list of inline policy documents (dicts with 'PolicyDocument') 
    for the specified user, including those inherited from any IAM groups.
    """
    inline_policy_docs = []
    marker = None

    # 1) Inline policies directly attached to the user
    user_inline_policies = []
    try:
        while True:
            response = (
                iam_client.list_user_policies(UserName=user_name, Marker=marker)
                if marker
                else iam_client.list_user_policies(UserName=user_name)
            )
            user_inline_policies.extend(response.get("PolicyNames", []))
            marker = response.get("Marker")
            if not marker:
                break

        for policy_name in user_inline_policies:
            try:
                pol_resp = iam_client.get_user_policy(UserName=user_name, PolicyName=policy_name)
                inline_policy_docs.append({"PolicyDocument": pol_resp["PolicyDocument"]})
            except botocore.exceptions.ClientError as ex:
                if "NoSuchEntity" in ex.response["Error"]["Code"]:
                    ex.response["Error"]["Message"] = (
                        f"Unable to fetch inline policy '{policy_name}' for user '{user_name}'. No such entity found."
                    )
                elif "InvalidInput" in ex.response["Error"]["Code"]:
                    ex.response["Error"]["Message"] = (
                        f"Invalid username '{user_name}' or policy '{policy_name}' input received."
                    )
                else:
                    ex.response["Error"]["Message"] = "InternalError"
                    ex.response["Error"]["Code"] = "InternalError"
                raise ex
    except botocore.exceptions.ClientError as ex:
        if "NoSuchEntity" in ex.response["Error"]["Code"]:
            ex.response["Error"]["Message"] = (
                f"Unable to fetch policies for user '{user_name}'. No such entity found."
            )
        elif "InvalidInput" in ex.response["Error"]["Code"]:
            ex.response["Error"]["Message"] = (
                f"Invalid username '{user_name}' or marker '{marker}' input received."
            )
        else:
            ex.response["Error"]["Message"] = "InternalError"
            ex.response["Error"]["Code"] = "InternalError"
        raise ex

    # 2) Inline policies from any IAM groups the user is in
    groups = []
    marker = None
    try:
        while True:
            response = (
                iam_client.list_groups_for_user(UserName=user_name, Marker=marker)
                if marker
                else iam_client.list_groups_for_user(UserName=user_name)
            )
            groups.extend(response.get("Groups", []))
            marker = response.get("Marker")
            if not marker:
                break

        for g in groups:
            group_name = g["GroupName"]
            group_marker = None
            while True:
                grp_resp = (
                    iam_client.list_group_policies(GroupName=group_name, Marker=group_marker)
                    if group_marker
                    else iam_client.list_group_policies(GroupName=group_name)
                )
                group_policy_names = grp_resp.get("PolicyNames", [])
                group_marker = grp_resp.get("Marker")

                for gp_name in group_policy_names:
                    try:
                        gp_resp = iam_client.get_group_policy(GroupName=group_name, PolicyName=gp_name)
                        inline_policy_docs.append({"PolicyDocument": gp_resp["PolicyDocument"]})
                    except botocore.exceptions.ClientError as ex:
                        if "NoSuchEntity" in ex.response["Error"]["Code"]:
                            ex.response["Error"]["Message"] = (
                                f"Unable to fetch inline policy '{gp_name}' from group '{group_name}'."
                            )
                        elif "InvalidInput" in ex.response["Error"]["Code"]:
                            ex.response["Error"]["Message"] = (
                                f"Invalid group name '{group_name}' or policy '{gp_name}' input received."
                            )
                        else:
                            ex.response["Error"]["Message"] = "InternalError"
                            ex.response["Error"]["Code"] = "InternalError"
                        raise ex

                if not group_marker:
                    break
    except botocore.exceptions.ClientError as ex:
        if "NoSuchEntity" in ex.response["Error"]["Code"]:
            ex.response["Error"]["Message"] = (
                f"Unable to fetch group policies for user '{user_name}'. No such entity found."
            )
        elif "InvalidInput" in ex.response["Error"]["Code"]:
            ex.response["Error"]["Message"] = (
                f"Invalid user name '{user_name}' or marker '{marker}' input received."
            )
        else:
            ex.response["Error"]["Message"] = "InternalError"
            ex.response["Error"]["Code"] = "InternalError"
        raise ex

    return inline_policy_docs


def fetch_aws_managed_user_policies(iam_client, user_name):
    """
    Returns a list of AWS-managed or customer-managed policies that are 
    attached directly to the user or inherited through IAM groups.
    """
    policies = []
    marker = None

    try:
        # 1) Fetch policies attached directly to the user
        while True:
            response = (
                iam_client.list_attached_user_policies(UserName=user_name, Marker=marker)
                if marker
                else iam_client.list_attached_user_policies(UserName=user_name)
            )
            policies += response.get("AttachedPolicies", [])
            marker = response.get("Marker")
            if not marker:
                break

        # 2) Fetch policies inherited from groups
        groups = []
        marker = None
        while True:
            response = (
                iam_client.list_groups_for_user(UserName=user_name, Marker=marker)
                if marker
                else iam_client.list_groups_for_user(UserName=user_name)
            )
            groups += response.get("Groups", [])
            marker = response.get("Marker")
            if not marker:
                break

        for g in groups:
            group_marker = None
            while True:
                grp_resp = (
                    iam_client.list_attached_group_policies(GroupName=g.get("GroupName"), Marker=group_marker)
                    if group_marker
                    else iam_client.list_attached_group_policies(GroupName=g.get("GroupName"))
                )
                policies += grp_resp.get("AttachedPolicies", [])
                group_marker = grp_resp.get("Marker")
                if not group_marker:
                    break

        return policies
    except botocore.exceptions.ClientError as ex:
        if "NoSuchEntity" in ex.response["Error"]["Code"]:
            ex.response["Error"]["Message"] = (
                f"Unable to fetch policies for user '{user_name}'. No such entity found."
            )
        elif "InvalidInput" in ex.response["Error"]["Code"]:
            ex.response["Error"]["Message"] = (
                f"Invalid user name '{user_name}' or marker '{marker}' input received."
            )
        else:
            ex.response["Error"]["Message"] = "InternalError"
            ex.response["Error"]["Code"] = "InternalError"
        raise ex


def fetch_customer_managed_policy_documents_for_permission_set(iam_client, customer_managed_policies):
    """
    Given a list of policy names, fetch the local (customer-managed) policy 
    documents from IAM for each.
    """
    policy_docs = []

    try:
        marker = None
        while True:
            response = (
                iam_client.list_policies(Scope="Local", Marker=marker)
                if marker
                else iam_client.list_policies(Scope="Local")
            )
            for p in response.get("Policies", []):
                if p.get("PolicyName") in customer_managed_policies:
                    p_doc_response = iam_client.get_policy_version(
                        PolicyArn=p.get("Arn"), VersionId=p.get("DefaultVersionId")
                    )
                    policy_docs.append(p_doc_response.get("PolicyVersion", {}).get("Document"))
            marker = response.get("Marker")
            if not marker:
                break
    except botocore.exceptions.ClientError as ex:
        ex.response["Error"]["Message"] = "InternalError"
        ex.response["Error"]["Code"] = "InternalError"
        raise ex

    return policy_docs


def permission_set_has_admin_policies(iam_client, sso_admin_client, instance_arn, permission_set_arn):
    """
    Determine if a given permission set includes Administrator privileges 
    (AWS-managed 'AdministratorAccess' or inline doc with * permissions).
    """
    managed_policies = []
    inline_policies = []
    next_token = None

    try:
        # 1) AWS-managed policies attached to this Permission Set
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
            managed_policies += response.get("AttachedManagedPolicies", [])
            next_token = response.get("NextToken")
            if not next_token:
                break

        # 2) Inline policies defined directly in the Permission Set
        response = sso_admin_client.get_inline_policy_for_permission_set(
            InstanceArn=instance_arn, PermissionSetArn=permission_set_arn
        )
        if len(response.get("InlinePolicy", "")) > 1:
            inline_policies.append({"PolicyDocument": response["InlinePolicy"]})

        # 3) Customer-managed policies attached to the Permission Set
        next_token = None
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
            customer_policy_names = [p.get("Name") for p in response.get("CustomerManagedPolicyReferences", [])]
            for policy_doc in fetch_customer_managed_policy_documents_for_permission_set(iam_client, customer_policy_names):
                inline_policies.append({"PolicyDocument": policy_doc})

            next_token = response.get("NextToken")
            if not next_token:
                break

        return policies_grant_admin_access(managed_policies, inline_policies)
    except botocore.exceptions.ClientError as ex:
        ex.response["Error"]["Message"] = "InternalError"
        ex.response["Error"]["Code"] = "InternalError"
        raise ex


def get_admin_permission_sets_for_instance_by_account(iam_client, sso_admin_client, instance_arn, organizations_client):
    """
    For the given SSO instance, enumerate all accounts and figure out 
    which permission sets on each account have admin-level privileges.
    """
    permission_sets = {}
    try:
        accounts = organizations_list_all_accounts(organizations_client)
        for a in accounts:
            account_id = a.get("Id")
            permission_sets[account_id] = []
            next_token = None
            while True:
                response = (
                    sso_admin_client.list_permission_sets_provisioned_to_account(
                        AccountId=account_id, InstanceArn=instance_arn, NextToken=next_token
                    )
                    if next_token
                    else sso_admin_client.list_permission_sets_provisioned_to_account(
                        AccountId=account_id, InstanceArn=instance_arn
                    )
                )
                for p_set in response.get("PermissionSets", []):
                    if permission_set_has_admin_policies(iam_client, sso_admin_client, instance_arn, p_set):
                        permission_sets[account_id].append(p_set)
                next_token = response.get("NextToken")
                if not next_token:
                    break
    except botocore.exceptions.ClientError as ex:
        ex.response["Error"]["Message"] = "InternalError"
        ex.response["Error"]["Code"] = "InternalError"
        raise ex

    return permission_sets


def user_assigned_to_permission_set(sso_admin_client, user_id, user_group_ids, instance_arn, account_id, permission_set_arn):
    """
    Check if the user is assigned to the given permission set either directly 
    (PrincipalType == 'USER') or via a group membership (PrincipalType == 'GROUP').
    """
    try:
        next_token = None
        while True:
            response = (
                sso_admin_client.list_account_assignments(
                    AccountId=account_id,
                    InstanceArn=instance_arn,
                    PermissionSetArn=permission_set_arn,
                    NextToken=next_token,
                )
                if next_token
                else sso_admin_client.list_account_assignments(
                    AccountId=account_id,
                    InstanceArn=instance_arn,
                    PermissionSetArn=permission_set_arn,
                )
            )
            for assignment in response.get("AccountAssignments", []):
                principal_id = assignment.get("PrincipalId")
                principal_type = assignment.get("PrincipalType")

                # Direct user assignment
                if principal_type == "USER" and principal_id == user_id:
                    return True
                # Group-based assignment
                if principal_type == "GROUP" and principal_id in user_group_ids:
                    return True

            next_token = response.get("NextToken")
            if not next_token:
                break
        return False
    except botocore.exceptions.ClientError as ex:
        ex.response["Error"]["Message"] = "InternalError"
        ex.response["Error"]["Code"] = "InternalError"
        raise ex


def check_users(
    organizations_client,
    sso_admin_client,
    iam_client,
    identity_store_client,
    privileged_user_list,
    non_privileged_user_list,
    event,
    aws_account_id,
    sso_users_by_instance,
    sso_instance_id_by_arn,
):
    """
    1) Check all IAM users (direct inline & attached policies, plus group memberships).
    2) Check all SSO users (direct assignment & group-based assignment to Permission Sets).
    """
    evaluations = []
    at_least_one_privileged_user_has_admin_access = False
    non_privileged_user_with_admin_access = []

    # === IAM Checks ===
    iam_users = list_all_iam_users(iam_client)
    for u in iam_users:
        user_name = u.get("UserName")
        logger.info(f"Checking IAM user: {user_name}")

        managed_policies = fetch_aws_managed_user_policies(iam_client, user_name)
        inline_policies = fetch_inline_user_policies(iam_client, user_name)

        if user_name in privileged_user_list:
            # If we haven't yet found a privileged user with admin access, check now
            if not at_least_one_privileged_user_has_admin_access:
                if policies_grant_admin_access(managed_policies, inline_policies):
                    at_least_one_privileged_user_has_admin_access = True
        elif user_name in non_privileged_user_list:
            if policies_grant_admin_access(managed_policies, inline_policies):
                non_privileged_user_with_admin_access.append(user_name)

    # === SSO (Identity Center) Checks ===
    for instance_arn, sso_users in sso_users_by_instance.items():
        admin_permission_sets_by_account = get_admin_permission_sets_for_instance_by_account(
            iam_client, sso_admin_client, instance_arn, organizations_client
        )
        instance_id = sso_instance_id_by_arn[instance_arn]

        for user in sso_users:
            user_name = user.get("UserName")
            user_id = user.get("UserId")
            # Get this user's SSO group memberships
            user_group_ids = fetch_sso_group_ids_for_user(identity_store_client, instance_id, user_id)

            logger.info(f"Checking SSO user: {user_name}")
            if user_name in privileged_user_list:
                if at_least_one_privileged_user_has_admin_access:
                    continue

                # Check if user or user's groups is assigned to an admin permission set
                for a_id, perm_sets in admin_permission_sets_by_account.items():
                    for p_arn in perm_sets:
                        if user_assigned_to_permission_set(sso_admin_client, user_id, user_group_ids, instance_arn, a_id, p_arn):
                            at_least_one_privileged_user_has_admin_access = True
                            break
                    if at_least_one_privileged_user_has_admin_access:
                        break

            elif user_name in non_privileged_user_list:
                # Check if user or user's groups is assigned to an admin permission set
                for a_id, perm_sets in admin_permission_sets_by_account.items():
                    for p_arn in perm_sets:
                        if user_assigned_to_permission_set(sso_admin_client, user_id, user_group_ids, instance_arn, a_id, p_arn):
                            non_privileged_user_with_admin_access.append(user_name)
                            break

    # === Final evaluations ===
    if at_least_one_privileged_user_has_admin_access and len(non_privileged_user_with_admin_access) == 0:
        evaluations.append(build_evaluation(aws_account_id, "COMPLIANT", event))
    else:
        failed_check_strings = []
        if not at_least_one_privileged_user_has_admin_access:
            failed_check_strings.append("no privileged user with admin access was found")
        if len(non_privileged_user_with_admin_access) > 0:
            failed_check_strings.append(
                f"non_privileged users {non_privileged_user_with_admin_access} have admin access"
            )

        annotation = " and ".join([e for e in failed_check_strings if e]).capitalize()
        evaluations.append(build_evaluation(aws_account_id, "NON_COMPLIANT", event, annotation=annotation))

    return evaluations


def policies_grant_admin_access(managed_policies, inline_policies):
    """
    Return True if any of the given policies grants 'AdministratorAccess' 
    or if any inline document is effectively 'Action:*'/'Resource:*'.
    """
    return any(
        p.get("PolicyName", p.get("Name", "")) == "AdministratorAccess" for p in managed_policies
    ) or any(
        policy_doc_gives_admin_access(p.get("PolicyDocument", "{}")) for p in inline_policies
    )


def lambda_handler(event, context):
    """
    Main entry point for the AWS Lambda.
    """
    logger.info("Received Event: %s", json.dumps(event, indent=2))

    invoking_event = json.loads(event["invokingEvent"])
    if not is_scheduled_notification(invoking_event["messageType"]):
        logger.error("Skipping assessments as this is not a scheduled invocation")
        return

    # Load parameters from the Config rule
    rule_parameters = check_required_parameters(
        json.loads(event.get("ruleParameters", "{}")),
        ["ExecutionRoleName", "PrivilegedUsersFilePath", "NonPrivilegedUsersFilePath"],
    )
    execution_role_name = rule_parameters.get("ExecutionRoleName")
    audit_account_id = rule_parameters.get("AuditAccountID", "")
    aws_account_id = event["accountId"]
    is_not_audit_account = aws_account_id != audit_account_id

    aws_organizations_client = get_client("organizations", aws_account_id, execution_role_name, is_not_audit_account)

    # Ensure we are in the Management Account
    if aws_account_id != get_organizations_mgmt_account_id(aws_organizations_client):
        logger.info("Not checked in account %s as this is not the Management Account", aws_account_id)
        return

    # Clients
    aws_config_client = get_client("config", aws_account_id, execution_role_name, is_not_audit_account)
    aws_iam_client = get_client("iam", aws_account_id, execution_role_name, is_not_audit_account)
    aws_sso_admin_client = get_client("sso-admin", aws_account_id, execution_role_name, is_not_audit_account)
    aws_identity_store_client = get_client("identitystore", aws_account_id, execution_role_name, is_not_audit_account)
    aws_s3_client = get_client("s3")

    evaluations = []

    # Guardrail checks
    tags = get_account_tags(get_client("organizations", assume_role=False), aws_account_id)
    cloud_profile = get_cloud_profile_from_tags(tags)
    gr_requirement_type = check_guardrail_requirement_by_cloud_usage_profile(GuardrailType.Guardrail1, cloud_profile)

    if gr_requirement_type == GuardrailRequirementType.Recommended:
        return submit_evaluations(
            aws_config_client,
            event,
            [
                build_evaluation(
                    aws_account_id,
                    "COMPLIANT",
                    event,
                    gr_requirement_type=gr_requirement_type,
                )
            ],
        )
    elif gr_requirement_type == GuardrailRequirementType.Not_Required:
        return submit_evaluations(
            aws_config_client,
            event,
            [
                build_evaluation(
                    aws_account_id,
                    "NOT_APPLICABLE",
                    event,
                    gr_requirement_type=gr_requirement_type,
                )
            ],
        )

    # S3 file checks
    privileged_users_file_path = rule_parameters.get("PrivilegedUsersFilePath", "")
    non_privileged_users_file_path = rule_parameters.get("NonPrivilegedUsersFilePath", "")

    if not check_s3_object_exists(aws_s3_client, privileged_users_file_path):
        annotation = f"No privileged user file input provided at {privileged_users_file_path}."
        evaluations.append(build_evaluation(aws_account_id, "NON_COMPLIANT", event, annotation=annotation))
    elif not check_s3_object_exists(aws_s3_client, non_privileged_users_file_path):
        annotation = f"No non_privileged user file input provided at {non_privileged_users_file_path}."
        evaluations.append(build_evaluation(aws_account_id, "NON_COMPLIANT", event, annotation=annotation))
    else:
        # Fetch user lists from S3
        privileged_users_list = get_lines_from_s3_file(aws_s3_client, privileged_users_file_path)
        non_privileged_users_list = get_lines_from_s3_file(aws_s3_client, non_privileged_users_file_path)

        # Fetch SSO info
        sso_users_by_instance, sso_instance_id_by_arn = fetch_sso_users(aws_sso_admin_client, aws_identity_store_client)

        # Main check
        evaluations += check_users(
            aws_organizations_client,
            aws_sso_admin_client,
            aws_iam_client,
            aws_identity_store_client,
            privileged_users_list,
            non_privileged_users_list,
            event,
            aws_account_id,
            sso_users_by_instance,
            sso_instance_id_by_arn,
        )

    logger.info("AWS Config updating evaluations: %s", evaluations)
    submit_evaluations(aws_config_client, event, evaluations)