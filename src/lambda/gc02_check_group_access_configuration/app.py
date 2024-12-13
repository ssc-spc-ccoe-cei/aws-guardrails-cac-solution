""" GC02 - Check Group Access Configuration
    https://canada-ca.github.io/cloud-guardrails/EN/02_Management-Admin-Privileges.html
"""
import json
import logging
import re
from enum import Enum

import boto3
import botocore
import botocore.exceptions


# Logging setup
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Set to True to get the lambda to assume the Role attached on the Config Service
ASSUME_ROLE_MODE = True
DEFAULT_RESOURCE_TYPE = "AWS::::Account"
GROUP_RESOURCE_TYPE = "AWS::IAM::Group"


class GroupPermissionAssignment(Enum):
    ADMIN = 1
    NON_ADMIN = 2
    MIX = 3
    
# This gets the client after assuming the Config service role
# either in the same AWS account or cross-account.
def get_client(service, event):
    """Return the service boto client. It should be used instead of directly calling the client.
    Keyword arguments:
    service -- the service name used for calling the boto.client()
    event -- the event variable given in the lambda handler
    """
    if not ASSUME_ROLE_MODE or (AWS_ACCOUNT_ID == AUDIT_ACCOUNT_ID):
        return boto3.client(service)
    execution_role_arn = f"arn:aws:iam::{AWS_ACCOUNT_ID}:role/{EXECUTION_ROLE_NAME}"
    credentials = get_assume_role_credentials(execution_role_arn)
    return boto3.client(
        service,
        aws_access_key_id=credentials["AccessKeyId"],
        aws_secret_access_key=credentials["SecretAccessKey"],
        aws_session_token=credentials["SessionToken"],
    )


def get_assume_role_credentials(role_arn):
    """Returns the temporary credentials from ASSUME_ROLE_MODE role.
    Keyword arguments:
    role_arn -- the ARN of the role to assume
    """
    sts_client = boto3.client("sts")
    try:
        assume_role_response = sts_client.assume_role(
            RoleArn=role_arn,
            RoleSessionName="configLambdaExecution"
        )
        return assume_role_response["Credentials"]
    except botocore.exceptions.ClientError as ex:
        # Scrub error message for any internal account info leaks
        if "AccessDenied" in ex.response["Error"]["Code"]:
            ex.response["Error"]["Message"] = "AWS Config does not have permission to assume the IAM role."
        else:
            ex.response["Error"]["Message"] = "InternalError"
            ex.response["Error"]["Code"] = "InternalError"
        raise ex


def is_scheduled_notification(message_type):
    """Check whether the message is a ScheduledNotification or not.
    Keyword arguments:
    message_type -- the message type
    """
    return message_type == "ScheduledNotification"


def evaluate_parameters(rule_parameters):
    """Evaluate the rule parameters.
    Keyword arguments:
    rule_parameters -- the Key/Value dictionary of the rule parameters
    """
    if "s3ObjectPath" not in rule_parameters:
        logger.error('The parameter with "s3ObjectPath" as key must be defined.')
        raise ValueError('The parameter with "s3ObjectPath" as key must be defined.')
    if not rule_parameters["s3ObjectPath"]:
        logger.error('The parameter "s3ObjectPath" must have a defined value.')
        raise ValueError('The parameter "s3ObjectPath" must have a defined value.')
    return rule_parameters


# This generate an evaluation for config
def build_evaluation(
    resource_id,
    compliance_type,
    event,
    resource_type=DEFAULT_RESOURCE_TYPE,
    annotation=None,
):
    """Form an evaluation as a dictionary. Usually suited to report on scheduled rules.
    Keyword arguments:
    resource_id -- the unique id of the resource to report
    compliance_type -- either COMPLIANT, NON_COMPLIANT or NOT_APPLICABLE
    event -- the event variable given in the lambda handler
    resource_type -- the CloudFormation resource type (or AWS::::Account)
    to report on the rule (default DEFAULT_RESOURCE_TYPE)
    annotation -- an annotation to be added to the evaluation (default None)
    """
    eval_cc = {}
    if annotation:
        eval_cc["Annotation"] = annotation
    eval_cc["ComplianceResourceType"] = resource_type
    eval_cc["ComplianceResourceId"] = resource_id
    eval_cc["ComplianceType"] = compliance_type
    eval_cc["OrderingTimestamp"] = str(
        json.loads(event["invokingEvent"])["notificationCreationTime"]
    )
    return eval_cc

def extract_bucket_name_and_key(object_path):
    match = re.match(r"s3:\/\/([^/]+)\/((?:[^/]*/)*.*)", object_path)
    if match:
        bucket_name = match.group(1)
        key_name = match.group(2)
    else:
        logger.error("Unable to parse S3 object path %s", object_path)
        raise ValueError(f"Unable to parse S3 object path {object_path}")
    return bucket_name,key_name

def read_s3_object(s3_file_path) -> str:
    bucket, key = extract_bucket_name_and_key(s3_file_path)
    response = AWS_S3_CLIENT.get_object(Bucket=bucket, Key=key)
    rule_naming_convention = response.get("Body").read().decode("utf-8")
    return rule_naming_convention

def check_s3_object_exists(object_path):
    """Check if the S3 object exists
    Keyword arguments:
    object_path -- the S3 object path
    """
    # parse the S3 path
    bucket_name, key_name = extract_bucket_name_and_key(object_path)
    try:
        AWS_S3_CLIENT.head_object(Bucket=bucket_name, Key=key_name)
    except botocore.exceptions.ClientError as err:
        if err.response["Error"]["Code"] == "404":
            # The object does not exist.
            logger.info("Object %s not found in bucket %s", key_name, bucket_name)
            return False
        elif err.response["Error"]["Code"] == "403":
            # AccessDenied
            logger.info("Access denied to bucket %s", bucket_name)
            return False
        else:
            # Something else has gone wrong.
            logger.error("Error trying to find object %s in bucket %s", key_name, bucket_name)
            raise ValueError(f"Error trying to find object {key_name} in bucket {bucket_name}") from err
    else:
        # The object does exist.
        return True

def fetch_sso_instances():
    instances = []
    nextToken = None
    try:
        while True:
            response = AWS_SSO_ADMIN_CLIENT.list_instances(NextToken=nextToken) if nextToken else AWS_SSO_ADMIN_CLIENT.list_instances()
            instances = instances + response.get("Instances", [])
            nextToken = response.get("NextToken")
            if not nextToken:
                break
    except botocore.exceptions.ClientError as ex:
        logger.info(f"fetch_sso_instances exception: {ex}")
        ex.response["Error"]["Message"] = "InternalError"
        ex.response["Error"]["Code"] = "InternalError"
        raise ex
    
    return instances

def only_admin_policies(managed_policies, inline_policies):
    # Returns True if both managed policies and inline_policies only give admin access
    return next((False for p in managed_policies if p.get("PolicyName", "") != "AdministratorAccess"), True) and next((False for p in inline_policies if not policy_doc_gives_admin_access(p.get("PolicyDocument", '{}'))), True)

def only_non_admin_policies(managed_policies, inline_policies):
    # Returns True if both managed policies and inline_policies only give non admin access
    return next((False for p in managed_policies if p.get("PolicyName", "") == "AdministratorAccess"), True) and next((False for p in inline_policies if policy_doc_gives_admin_access(p.get("PolicyDocument", '{}'))), True)


def fetch_customer_managed_policy_documents_for_permission_set(customer_managed_policies):
    policy_docs = []
    try:
        marker = None
        while True:
            response = AWS_IAM_CLIENT.list_policies(Scope="Local", Marker=marker) if marker else AWS_IAM_CLIENT.list_policies(Scope="Local")
            policies = response.get("Policies")
            for p in policies:
                if p.get("PolicyName") in customer_managed_policies:
                    p_doc_response = AWS_IAM_CLIENT.get_policy_version(p.get(PolicyArn="Arn"), VersionId=p.get("DefaultVersionId"))
                    policy_docs.append(p_doc_response.get("PolicyVersion").get("Document"))
            marker = response.get("Marker")
            if not marker:
                break
    except botocore.exceptions.ClientError as ex:
        ex.response["Error"]["Message"] = "InternalError"
        ex.response["Error"]["Code"] = "InternalError"
        raise ex

    return policy_docs

def permission_set_only_has_admin_or_non_admin_policies(instance_arn, permission_set_arn) -> GroupPermissionAssignment:
    managed_policies = []
    inline_policies = []
    
    next_token = None
    try:
        # Fetch all AWS Managed policies for the permission set and add them to the list of managed policies
        while True:
            response = AWS_SSO_ADMIN_CLIENT.list_managed_policies_in_permission_set(InstanceArn=instance_arn, NextToken=next_token, PermissionSetArn=permission_set_arn) if next_token else AWS_SSO_ADMIN_CLIENT.list_managed_policies_in_permission_set(InstanceArn=instance_arn, PermissionSetArn=permission_set_arn)
            managed_policies = managed_policies + response.get("AttachedManagedPolicies")
            next_token = response.get("NextToken")
            if not next_token:
                break
        # Fetch the inline document for the permission set if any exists. If none exists the response will still be valid, just an empty policy doc.
        response =  AWS_SSO_ADMIN_CLIENT.get_inline_policy_for_permission_set(InstanceArn=instance_arn, PermissionSetArn=permission_set_arn)
        # If length is less than or equal to 1 then the policy doc is empty because there is no inline policy.The API specifies a min length of 1, but is a bit vague on what an empty policy doc would look like so we are covering the case of empty string 
        if len(response.get("InlinePolicy")) > 1:
            inline_policies.append({
                "PolicyDocument": response.get("InlinePolicy")
            })
        # Fetch all customer managed policy references, convert the references into their policy document on the account, and add them to the list of inline policies.
        while True:
            response = AWS_SSO_ADMIN_CLIENT.list_customer_managed_policy_references_in_permission_set(InstanceArn=instance_arn, NextToken=next_token, PermissionSetArn=permission_set_arn) if next_token else AWS_SSO_ADMIN_CLIENT.list_customer_managed_policy_references_in_permission_set(InstanceArn=instance_arn, PermissionSetArn=permission_set_arn)
            for policy_doc in fetch_customer_managed_policy_documents_for_permission_set([p.get("Name") for p in response.get("CustomerManagedPolicyReferences")]):
                inline_policies.append({
                    "PolicyDocument": policy_doc
                })
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

def get_permission_sets_for_group(instance_arn, group_id):
    permission_sets = set()
    next_token = None
    try:
        while True:
            response = AWS_SSO_ADMIN_CLIENT.list_account_assignments_for_principal(nstanceArn=instance_arn, PrincipalId=group_id, PrincipalType="GROUP", NextToken = next_token) if next_token else AWS_SSO_ADMIN_CLIENT.list_account_assignments_for_principal(InstanceArn=instance_arn, PrincipalId=group_id, PrincipalType="GROUP")
            
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

def fetch_identity_center_groups(instance_id):
    groups = []
    next_token = None
    try:
        while True:
            response = AWS_IDENTITY_STORE_CLIENT.list_groups(IdentityStoreId=instance_id, NextToken=next_token) if next_token else AWS_IDENTITY_STORE_CLIENT.list_groups(IdentityStoreId=instance_id)
            groups = groups + response.get("Groups", [])
            next_token = response.get("NextToken")
            if not next_token:
                break
    except botocore.exceptions.ClientError as ex:
        ex.response["Error"]["Message"] = "InternalError"
        ex.response["Error"]["Code"] = "InternalError"
        raise ex
    
    return groups

def fetch_identity_center_group_members(instance_id, group_id):
    members = set()
    next_token = None
    try:
        while True:
            response = AWS_IDENTITY_STORE_CLIENT.list_group_memberships(IdentityStoreId=instance_id, GroupId=group_id, NextToken=next_token) if next_token else AWS_IDENTITY_STORE_CLIENT.list_group_memberships(IdentityStoreId=instance_id, GroupId=group_id)
            for membership in response.get("GroupMemberships", []):
                user_id = membership.get("MemberId", {}).get("UserId", "")
                user_description = AWS_IDENTITY_STORE_CLIENT.describe_user(IdentityStoreId=instance_id, UserId=user_id)
                
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

def fetch_iam_groups():
    groups = []
    marker = None
    try:
        while True:
            response = AWS_IAM_CLIENT.list_groups(Marker=marker) if marker else AWS_IAM_CLIENT.list_groups()
            groups = groups + response.get("Groups", [])
            marker = response.get("Marker")
            if not marker:
                break
    except botocore.exceptions.ClientError as ex:
        ex.response["Error"]["Message"] = "InternalError"
        ex.response["Error"]["Code"] = "InternalError"
        raise ex
    
    return groups

def check_iam_group_policies(group_name, admin_accounts, event):
    # Checks all group policies to ensure that there is not mixture of admin and non-admin roles.
    
    # Fetch aws managed and inline group policies
    managed_policies = fetch_aws_managed_group_policies(group_name)
    inline_policies = fetch_inline_group_policies(group_name)
    
    # Checks for the aws managed policy AdministratorAccess or an inline policy that gives the same access.
    has_admin_policy = next((True for p in managed_policies if p.get("PolicyName", "") == "AdministratorAccess"), False) or next((True for p in inline_policies if policy_doc_gives_admin_access(p.get("PolicyDocument", "{}"))), False)
    has_non_admin_policy = next((True for p in managed_policies if p.get("PolicyName", "") != "AdministratorAccess"), False) or next((True for p in inline_policies if not policy_doc_gives_admin_access(p.get("PolicyDocument", "{}"))), False)
    
    # Does the group have admin policies and non admin policies?
    if has_admin_policy and has_non_admin_policy:
        # yes, there is a mixture of admin and non-admin roles attached to the group. Return NON_COMPLIANT evaluation for group
        return build_evaluation(
            group_name,
            "NON_COMPLIANT",
            event,
            resource_type=GROUP_RESOURCE_TYPE,
            annotation=f"Group '{group_name}' has attached policies that contain both admin and non-admin roles."
        )
    
    # Is the group an admin group?
    if has_admin_policy:
        # yes, fetch group members and check against admin_accounts
        group_members = fetch_group_members(group_name)
        has_non_admin_member = next((m for m in group_members if m.get("UserName", "") not in admin_accounts), False)
        if has_non_admin_member:
            return build_evaluation(
                group_name,
                "NON_COMPLIANT",
                event,
                resource_type=GROUP_RESOURCE_TYPE,
                annotation=f"Group '{group_name}' is an admin group that contains non-admin members."
            )
            
    annotation = f"Group '{group_name}' has policies that only provides admin roles and only has admin members." if has_admin_policy else f"Group '{group_name}' has policies that only provides non-admin roles."
        
    return build_evaluation(
        group_name,
        "COMPLIANT",
        event,
        resource_type=GROUP_RESOURCE_TYPE,
        annotation=annotation
    )
    
def check_identity_center_group_policies(instance_id, instance_arn, group, admin_accounts, event):
    # Checks all group policies to ensure that there is not mixture of admin and non-admin roles.
    
    group_id = group.get("GroupId")
    group_name = group.get("DisplayName")
    permission_set_arns = get_permission_sets_for_group(instance_id, group_id)
    group_members = fetch_identity_center_group_members(instance_id, group_id)
    has_non_admin_member = next((m for m in group_members if m.get("UserName", "") not in admin_accounts), False)
    has_admin_pset = False
    has_non_admin_pset = False
    
    for p_set_arn in permission_set_arns:
        p_set_type = permission_set_only_has_admin_or_non_admin_policies(instance_arn, p_set_arn)\
        # Is the group an admin group?
        if p_set_type == GroupPermissionAssignment.ADMIN:
            # yes, fetch group members and check against admin_accounts
            has_admin_pset = True
            if has_non_admin_member:
                return build_evaluation(
                    group_name,
                    "NON_COMPLIANT",
                    event,
                    resource_type=GROUP_RESOURCE_TYPE,
                    annotation=f"Group '{group_name}' is a group containing non-admin members that has been assigned an admin permission set."
                )
        elif p_set_type == GroupPermissionAssignment.NON_ADMIN:
            has_non_admin_pset = True
        # Does the group have admin policies and non admin policies?
        elif p_set_type == GroupPermissionAssignment.MIX:
            # yes, there is a mixture of admin and non-admin roles attached to the group. Return NON_COMPLIANT evaluation for group
            return build_evaluation(
                group_name,
                "NON_COMPLIANT",
                event,
                resource_type=GROUP_RESOURCE_TYPE,
                annotation=f"Group '{group_name}' has an assigned permission set that contain both admin and non-admin roles."
            )
            
        if has_admin_pset and has_non_admin_pset:
            return build_evaluation(
                group_name,
                "NON_COMPLIANT",
                event,
                resource_type=GROUP_RESOURCE_TYPE,
                annotation=f"Group '{group_name}' has been assigned admin only and non admin only permission sets. Groups should only contain admin only permission sets or non admin only permission sets."
            )
            
    annotation = f"Group '{group_name}' has permission sets that apply policies granting only admin roles and only has admin members." if has_admin_pset else f"Group '{group_name}' permission sets that apply policies granting only non-admin roles."
        
    return build_evaluation(
        group_name,
        "COMPLIANT",
        event,
        resource_type=GROUP_RESOURCE_TYPE,
        annotation=annotation
    )
    
def fetch_group_members(group_name):
    members = []
    marker = None
    try:
        while True:
            response = AWS_IAM_CLIENT.get_group(GroupName=group_name, Marker=marker) if marker else AWS_IAM_CLIENT.get_group(GroupName=group_name)
            members = members + response.get("Users", [])
            marker = response.get("Marker")
            if not marker:
                break
    except botocore.exceptions.ClientError as ex:
        if "NoSuchEntity" in ex.response['Error']['Code']:
            ex.response['Error']['Message'] = f"Unable to fetch information for group '{group_name}'. No such entity found."
        else:
            ex.response["Error"]["Message"] = "InternalError"
            ex.response["Error"]["Code"] = "InternalError"
        raise ex
    
    return members
        
def policy_doc_gives_admin_access(policy_doc: str):
    document_dict = json.loads(policy_doc)
    statement = document_dict.get("Statement", [])
    for statement_component in statement:
        if statement_component.get("Effect", "") == "Allow" and statement_component.get("Action", "") == "*" and statement_component.get("Resource", "") == "*":
            return True
    return False
        
def fetch_inline_group_policies(group_name):
    policies = []
    marker = None
    try:
        while True:
            response = AWS_IAM_CLIENT.list_group_policies(GroupName=group_name, Marker=marker) if marker else AWS_IAM_CLIENT.list_group_policies(GroupName=group_name)      
            policies = policies + response.get("PolicyNames", [])
            marker = response.get("Marker")
            if not marker:
                break
    except botocore.exceptions.ClientError as ex:
        if "NoSuchEntity" in ex.response['Error']['Code']:
            ex.response['Error']['Message'] = f"Unable to fetch policies for group '{group_name}'. No such entity found."
        elif "InvalidInput" in ex.response['Error']['Code']:
            ex.response['Error']['Message'] = f"Invalid group name '{group_name}' or marker '{marker}' input received."
        else:
            ex.response["Error"]["Message"] = "InternalError"
            ex.response["Error"]["Code"] = "InternalError"
        raise ex
    
    try:
        for i in range(len(policies)):
            policies[i] = AWS_IAM_CLIENT.get_group_policy(group_name, policies[i])
    except botocore.exceptions.ClientError as ex:
        if "NoSuchEntity" in ex.response['Error']['Code']:
            ex.response['Error']['Message'] = "Unable to fetch inline policy information. No such entity found."
        elif "InvalidInput" in ex.response['Error']['Code']:
            ex.response['Error']['Message'] = "Failed to fetch inline policy information. Invalid input."
        else:
            ex.response["Error"]["Message"] = "InternalError"
            ex.response["Error"]["Code"] = "InternalError"
        
    return policies
    
def fetch_aws_managed_group_policies(group_name):
    policies = []
    marker = None
    try:
        while True:
            response = AWS_IAM_CLIENT.list_attached_group_policies(GroupName=group_name, Marker=marker) if marker else AWS_IAM_CLIENT.list_attached_group_policies(GroupName=group_name)      
            policies = policies + response.get("AttachedPolicies", [])
            marker = response.get("Marker")
            if not marker:
                break
        return policies
    except botocore.exceptions.ClientError as ex:
        if "NoSuchEntity" in ex.response['Error']['Code']:
            ex.response['Error']['Message'] = f"Unable to fetch policies for group '{group_name}'. No such entity found."
        elif "InvalidInput" in ex.response['Error']['Code']:
            ex.response['Error']['Message'] = f"Invalid group name '{group_name}' or marker '{marker}' input received."
        else:
            ex.response["Error"]["Message"] = "InternalError"
            ex.response["Error"]["Code"] = "InternalError"
        raise ex

def lambda_handler(event, context):
    """This function is the main entry point for Lambda.
    Keyword arguments:
    event -- the event variable given in the lambda handler
    context -- the context variable given in the lambda handler
    """
    global AWS_CONFIG_CLIENT
    global AWS_IAM_CLIENT
    global AWS_IDENTITY_STORE_CLIENT
    global AWS_SSO_ADMIN_CLIENT
    global AWS_ACCOUNT_ID
    global AWS_S3_CLIENT
    global EXECUTION_ROLE_NAME
    global AUDIT_ACCOUNT_ID

    evaluations = []
    rule_parameters = {}

    invoking_event = json.loads(event["invokingEvent"])
    logger.info("Received event: %s", json.dumps(event, indent=2))

    # parse parameters
    AWS_ACCOUNT_ID = event["accountId"]

    if "ruleParameters" in event:
        rule_parameters = json.loads(event["ruleParameters"])

    valid_rule_parameters = evaluate_parameters(rule_parameters)

    if "ExecutionRoleName" in valid_rule_parameters:
        EXECUTION_ROLE_NAME = valid_rule_parameters["ExecutionRoleName"]
    else:
        EXECUTION_ROLE_NAME = "AWSA-GCLambdaExecutionRole"

    if "AuditAccountID" in valid_rule_parameters:
        AUDIT_ACCOUNT_ID = valid_rule_parameters["AuditAccountID"]
    else:
        AUDIT_ACCOUNT_ID = ""

    AWS_CONFIG_CLIENT = get_client("config", event)
    AWS_IAM_CLIENT = get_client("iam", event)
    AWS_IDENTITY_STORE_CLIENT = get_client("identitystore", event)
    AWS_SSO_ADMIN_CLIENT = get_client("sso-admin", event)
    AWS_S3_CLIENT = boto3.client("s3")
    
    # is this a scheduled invokation?
    if is_scheduled_notification(invoking_event["messageType"]):
        # yes, proceed
        
        admin_accounts_file_path = valid_rule_parameters.get("s3ObjectPath", "")
        if check_s3_object_exists(admin_accounts_file_path) == False:
            evaluations.append(
                build_evaluation(
                    event["accountId"],
                    "NON_COMPLIANT",
                    event,
                    resource_type=DEFAULT_RESOURCE_TYPE,
                    annotation="No AdminAccountsFilePath input provided.",
                )
            )
        else:     
            is_compliant = True
            admin_accounts = read_s3_object(admin_accounts_file_path).splitlines()
            
            # IAM
            iam_groups = fetch_iam_groups()
            for g in iam_groups:
                eval = check_iam_group_policies(g.get("GroupName", ""), admin_accounts, event)
                if eval.get("ComplianceType", "NON_COMPLIANT") == "NON_COMPLIANT":
                    is_compliant = False
                evaluations.append(eval)
                
            #Identity Center
            instances = fetch_sso_instances()
            for i in instances:
                i_id = i.get("IdentityStoreId")
                i_arn = i.get("InstanceArn")
                identity_center_groups = fetch_identity_center_groups(i_id)
                for g in identity_center_groups:
                    eval = check_identity_center_group_policies(i_id, i_arn, g, admin_accounts, event)
                    if eval.get("ComplianceType", "NON_COMPLIANT") == "NON_COMPLIANT":
                        is_compliant = False
                    evaluations.append(eval)
                            
            
            if is_compliant:
                evaluations.append(
                    build_evaluation(
                        AWS_ACCOUNT_ID,
                        "COMPLIANT",
                        event,
                        resource_type=DEFAULT_RESOURCE_TYPE,
                        annotation="Account groups only have admin or only have non-admin roles, and admin groups only have admin members.",
                    )
                )
            else:
                evaluations.append(
                    build_evaluation(
                        AWS_ACCOUNT_ID,
                        "NON_COMPLIANT",
                        event,
                        resource_type=DEFAULT_RESOURCE_TYPE,
                        annotation="Account groups do not only have admin or only have non-admin roles, and admin groups only have admin members.",
                    )
                )
                
        AWS_CONFIG_CLIENT.put_evaluations(
            Evaluations=evaluations,
            ResultToken=event["resultToken"]
        )
