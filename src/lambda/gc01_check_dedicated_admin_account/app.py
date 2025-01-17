""" GC02 - Check IAM Password Policy
    https://canada-ca.github.io/cloud-guardrails/EN/02_Management-Admin-Privileges.html
"""

import json
import logging

import botocore.exceptions

from utils import is_scheduled_notification, check_required_parameters, check_guardrail_requirement_by_cloud_usage_profile, get_cloud_profile_from_tags, GuardrailType, GuardrailRequirementType
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
    instances = list_all_sso_admin_instances(sso_admin_client)
    users_by_instance = {}
    for i in instances:
        if i.get("Status") != "Active":
            continue

        instance_id = i.get("IdentityStoreId")
        instance_arn = i.get("InstanceArn")
        users_by_instance[instance_arn] = []
        nextToken = None
        try:
            while True:
                response = (
                    identity_store_client.list_users(IdentityStoreId=instance_id, NextToken=nextToken)
                    if nextToken
                    else identity_store_client.list_users(IdentityStoreId=instance_id)
                )
                users_by_instance[instance_arn] = users_by_instance[instance_arn] + response.get("Users", [])
                nextToken = response.get("NextToken")
                if not nextToken:
                    break
        except botocore.exceptions.ClientError as ex:
            ex.response["Error"]["Message"] = "InternalError"
            ex.response["Error"]["Code"] = "InternalError"
            raise ex
    return users_by_instance


def policy_doc_gives_admin_access(policy_doc: str) -> bool:
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
    policies = []
    marker = None
    try:
        # fetching policies directly attached to the user
        while True:
            response = (
                iam_client.list_user_policies(UserName=user_name, Marker=marker)
                if marker
                else iam_client.list_user_policies(UserName=user_name)
            )
            policies = policies + response.get("PolicyNames", [])
            marker = response.get("Marker")
            if not marker:
                break

        # fetching policies the user has access to through groups
        groups = []
        while True:
            response = (
                iam_client.list_groups_for_user(UserName=user_name, Marker=marker)
                if marker
                else iam_client.list_groups_for_user(UserName=user_name)
            )
            groups = groups + response.get("Groups", [])
            for g in groups:
                inner_marker = None
                while True:
                    response = (
                        iam_client.list_group_policies(GroupName=g.get("GroupName"), Marker=inner_marker)
                        if inner_marker
                        else iam_client.list_group_policies(GroupName=g.get("GroupName"))
                    )
                    policies = policies + response.get("PolicyNames", [])
                    inner_marker = response.get("Marker")
                    if not inner_marker:
                        break
            marker = response.get("Marker")

            if not marker:
                break

    except botocore.exceptions.ClientError as ex:
        if "NoSuchEntity" in ex.response["Error"]["Code"]:
            ex.response["Error"]["Message"] = f"Unable to fetch policies for user '{user_name}'. No such entity found."
        elif "InvalidInput" in ex.response["Error"]["Code"]:
            ex.response["Error"]["Message"] = f"Invalid username '{user_name}' or marker '{marker}' input received."
        else:
            ex.response["Error"]["Message"] = "InternalError"
            ex.response["Error"]["Code"] = "InternalError"
        raise ex

    try:
        for i in range(len(policies)):
            policies[i] = iam_client.get_user_policy(user_name, policies[i])
    except botocore.exceptions.ClientError as ex:
        if "NoSuchEntity" in ex.response["Error"]["Code"]:
            ex.response["Error"]["Message"] = "Unable to fetch inline policy information. No such entity found."
        elif "InvalidInput" in ex.response["Error"]["Code"]:
            ex.response["Error"]["Message"] = "Failed to fetch inline policy information. Invalid input."
        else:
            ex.response["Error"]["Message"] = "InternalError"
            ex.response["Error"]["Code"] = "InternalError"

    return policies


def fetch_aws_managed_user_policies(iam_client, user_name):
    policies = []
    marker = None
    try:
        # fetching policies directly attached to the user
        while True:
            response = (
                iam_client.list_attached_user_policies(UserName=user_name, Marker=marker)
                if marker
                else iam_client.list_attached_user_policies(UserName=user_name)
            )
            policies = policies + response.get("AttachedPolicies", [])
            marker = response.get("Marker")
            if not marker:
                break

        # fetching policies the user has access to through groups
        groups = []
        while True:
            response = (
                iam_client.list_groups_for_user(UserName=user_name, Marker=marker)
                if marker
                else iam_client.list_groups_for_user(UserName=user_name)
            )
            groups = groups + response.get("Groups", [])
            for g in groups:
                inner_marker = None
                while True:
                    response = (
                        iam_client.list_attached_group_policies(GroupName=g.get("GroupName"), Marker=inner_marker)
                        if inner_marker
                        else iam_client.list_attached_group_policies(GroupName=g.get("GroupName"))
                    )
                    policies = policies + response.get("AttachedPolicies", [])
                    inner_marker = response.get("Marker")
                    if not inner_marker:
                        break
            marker = response.get("Marker")

            if not marker:
                break

        return policies
    except botocore.exceptions.ClientError as ex:
        if "NoSuchEntity" in ex.response["Error"]["Code"]:
            ex.response["Error"]["Message"] = f"Unable to fetch policies for user '{user_name}'. No such entity found."
        elif "InvalidInput" in ex.response["Error"]["Code"]:
            ex.response["Error"]["Message"] = f"Invalid user name '{user_name}' or marker '{marker}' input received."
        else:
            ex.response["Error"]["Message"] = "InternalError"
            ex.response["Error"]["Code"] = "InternalError"
        raise ex


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
                        p.get(PolicyArn="Arn"), VersionId=p.get("DefaultVersionId")
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


def permission_set_has_admin_policies(iam_client, sso_admin_client, instance_arn, permission_set_arn):
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

        return policies_grant_admin_access(managed_policies, inline_policies)
    except botocore.exceptions.ClientError as ex:
        ex.response["Error"]["Message"] = "InternalError"
        ex.response["Error"]["Code"] = "InternalError"
        raise ex


def get_admin_permission_sets_for_instance_by_account(iam_client, sso_admin_client, instance_arn, organizations_client):
    permission_sets = {}
    next_token = None
    try:
        accounts = organizations_list_all_accounts(organizations_client)
        for a in accounts:
            account_id = a.get("Id")
            permission_sets[account_id] = []
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
                for p_set in response.get("PermissionSets"):
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


def user_assigned_to_permission_set(sso_admin_client, user_id, instance_arn, account_id, permission_set_arn):
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
                    AccountId=account_id, InstanceArn=instance_arn, PermissionSetArn=permission_set_arn
                )
            )
            for assignment in response.get("AccountAssignments"):
                if assignment.get("PrincipalId") == user_id:
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
):
    evaluations = []
    at_least_one_privileged_user_has_admin_access = False
    non_privileged_user_with_admin_access = []

    iam_users = list_all_iam_users(iam_client)
    sso_users_by_instance = fetch_sso_users(sso_admin_client, identity_store_client)

    # IAM Check
    for u in iam_users:
        user_name = u.get("UserName")
        logger.info(f"Checking iam users: {user_name}")
        if user_name in privileged_user_list:
            if at_least_one_privileged_user_has_admin_access == True:
                continue

            managed_policies = fetch_aws_managed_user_policies(iam_client, user_name)
            inline_policies = fetch_inline_user_policies(iam_client, user_name)

            at_least_one_privileged_user_has_admin_access = policies_grant_admin_access(
                managed_policies, inline_policies
            )

        elif user_name in non_privileged_user_list:
            managed_policies = fetch_aws_managed_user_policies(iam_client, user_name)
            inline_policies = fetch_inline_user_policies(iam_client, user_name)
            if policies_grant_admin_access(managed_policies, inline_policies):
                non_privileged_user_with_admin_access.append(user_name)

    # Identity Center Check
    for instance_arn in sso_users_by_instance.keys():
        admin_permission_sets_by_account = get_admin_permission_sets_for_instance_by_account(
            iam_client, sso_admin_client, instance_arn, organizations_client
        )
        for user in sso_users_by_instance[instance_arn]:
            user_name = user.get("UserName")
            logger.info(f"Checking sso instance user f{user_name}")
            user_id = user.get("UserId")
            if user_name in privileged_user_list:
                if at_least_one_privileged_user_has_admin_access == True:
                    continue

                for a_id in admin_permission_sets_by_account.keys():
                    for p_arn in admin_permission_sets_by_account[a_id]:
                        if user_assigned_to_permission_set(sso_admin_client, user_id, instance_arn, a_id, p_arn):
                            at_least_one_privileged_user_has_admin_access = True
                            break

            elif user_name in non_privileged_user_list:
                for a_id in admin_permission_sets_by_account.keys():
                    for p_arn in admin_permission_sets_by_account[a_id]:
                        if user_assigned_to_permission_set(sso_admin_client, user_id, instance_arn, a_id, p_arn):
                            non_privileged_user_with_admin_access.append(user_name)

    if at_least_one_privileged_user_has_admin_access and len(non_privileged_user_with_admin_access) == 0:
        evaluations.append(build_evaluation(aws_account_id, "COMPLIANT", event))
    else:
        failed_check_strings = [
            (
                "no privileged user with admin access was found"
                if not at_least_one_privileged_user_has_admin_access
                else None
            ),
            (
                f"non_privileged users {non_privileged_user_with_admin_access} have admin access"
                if len(non_privileged_user_with_admin_access) > 0
                else None
            ),
        ]
        annotation = " and ".join([e for e in failed_check_strings if e is not None]).capitalize()
        evaluations.append(build_evaluation(aws_account_id, "NON_COMPLIANT", event, annotation=annotation))

    return evaluations


def policies_grant_admin_access(managed_policies, inline_policies):
    return next((True for p in managed_policies if p.get("PolicyName", "") == "AdministratorAccess"), False) or next(
        (True for p in inline_policies if policy_doc_gives_admin_access(p.get("PolicyDocument", "{}"))), False
    )


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
        json.loads(event.get("ruleParameters", "{}")), ["ExecutionRoleName", "PrivilegedUsersFilePath", "NonPrivilegedUsersFilePath"]
    )
    execution_role_name = rule_parameters.get("ExecutionRoleName")
    audit_account_id = rule_parameters.get("AuditAccountID", "")
    aws_account_id = event["accountId"]
    is_not_audit_account = aws_account_id != audit_account_id

    aws_organizations_client = get_client("organizations", aws_account_id, execution_role_name, is_not_audit_account)

    if aws_account_id != get_organizations_mgmt_account_id(aws_organizations_client):
        # We're not in the Management Account
        logger.info("Not checked in account %s as this is not the Management Account", aws_account_id)
        return

    aws_config_client = get_client("config", aws_account_id, execution_role_name, is_not_audit_account)
    aws_iam_client = get_client("iam", aws_account_id, execution_role_name, is_not_audit_account)
    aws_sso_admin_client = get_client("sso-admin", aws_account_id, execution_role_name, is_not_audit_account)
    aws_identity_store_client = get_client("identitystore", aws_account_id, execution_role_name, is_not_audit_account)
    aws_s3_client = get_client("s3")
    
    evaluations = []
    
    # Check cloud profile
    tags = get_account_tags(get_client("organizations", assume_role=False), aws_account_id)
    cloud_profile = get_cloud_profile_from_tags(tags)
    gr_requirement_type = check_guardrail_requirement_by_cloud_usage_profile(GuardrailType.Guardrail1, cloud_profile)
    
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
    
    privileged_users_file_path = rule_parameters.get("PrivilegedUsersFilePath", "")
    non_privileged_users_file_path = rule_parameters.get("NonPrivilegedUsersFilePath", "")

    if not check_s3_object_exists(aws_s3_client, privileged_users_file_path):
        annotation = f"No privileged user file input provided at {privileged_users_file_path}."
        evaluations.append(build_evaluation(aws_account_id, "NON_COMPLIANT", event, annotation=annotation))
    elif not check_s3_object_exists(aws_s3_client, non_privileged_users_file_path):
        annotation = f"No non_privileged user file input provided at {non_privileged_users_file_path}."
        evaluations.append(build_evaluation(aws_account_id, "NON_COMPLIANT", event, annotation=annotation))
    else:
        privileged_users_list = get_lines_from_s3_file(aws_s3_client, privileged_users_file_path)
        non_privileged_users_list = get_lines_from_s3_file(aws_s3_client, non_privileged_users_file_path)

        evaluations = evaluations + check_users(
            aws_organizations_client,
            aws_sso_admin_client,
            aws_iam_client,
            aws_identity_store_client,
            privileged_users_list,
            non_privileged_users_list,
            event,
            aws_account_id,
        )

    logger.info("AWS Config updating evaluations: %s", evaluations)
    submit_evaluations(aws_config_client, event["resultToken"], evaluations)
