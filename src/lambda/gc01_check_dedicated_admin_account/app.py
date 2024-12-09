""" GC02 - Check IAM Password Policy
    https://canada-ca.github.io/cloud-guardrails/EN/02_Management-Admin-Privileges.html
"""
import json
import logging
import re

import boto3
import botocore
import botocore.exceptions

# Logging setup
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Set to True to get the lambda to assume the Role attached on the Config Service
ASSUME_ROLE_MODE = True
DEFAULT_RESOURCE_TYPE = "AWS::::Account"
USER_RESOURCE_TYPE = "AWS::IAM::User"


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
    # if "s3ObjectPath" not in rule_parameters:
    #     logger.error('The parameter with "s3ObjectPath" as key must be defined.')
    #     raise ValueError('The parameter with "s3ObjectPath" as key must be defined.')
    # if not rule_parameters["s3ObjectPath"]:
    #     logger.error('The parameter "s3ObjectPath" must have a defined value.')
    #     raise ValueError('The parameter "s3ObjectPath" must have a defined value.')
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

def fetch_users():
    users = []
    marker = None
    try:
        while True:
            response = AWS_IAM_CLIENT.list_users(Marker=marker) if marker else AWS_IAM_CLIENT.list_users()
            users = users + response.get("Users", [])
            if not marker:
                break
    except botocore.exceptions.ClientError as ex:
        logger.info(ex)
        ex.response["Error"]["Message"] = "InternalError"
        ex.response["Error"]["Code"] = "InternalError"
        raise ex
    return users
    
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
    
def fetch_sso_users():
    instances = fetch_sso_instances()
    users_by_instance = {}
    for i in instances:
        if i.get("Status") != "Active":
            continue
        
        instance_id = i.get("IdentityStoreId")
        instance_arn = i.get("InstanceArn")
        users_by_instance[instance_id]
        nextToken = None
        try:
            while True:
                response = AWS_IDENTITY_STORE_CLIENT.list_users(IdentityStoreId=instance_id, NextToken=nextToken) if nextToken else AWS_IDENTITY_STORE_CLIENT.list_users(IdentityStoreId=instance_id)
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
    return len(statement) == 1 and statement[0].get("Effect", "") == "Allow" and statement[0].get("Action", "") == "*" and statement[0].get("Resource", "") == "*"
        
def fetch_inline_user_policies(user_name):
    policies = []
    marker = None
    try:
        while True:
            response = AWS_IAM_CLIENT.list_user_policies(UserName=user_name, Marker=marker) if marker else AWS_IAM_CLIENT.list_user_policies(UserName=user_name)      
            policies = policies + response.get("PolicyNames", [])
            marker = response.get("Marker")
            if not marker:
                break
    except botocore.exceptions.ClientError as ex:
        if "NoSuchEntity" in ex.response['Error']['Code']:
            ex.response['Error']['Message'] = f"Unable to fetch policies for user '{user_name}'. No such entity found."
        elif "InvalidInput" in ex.response['Error']['Code']:
            ex.response['Error']['Message'] = f"Invalid username '{user_name}' or marker '{marker}' input received."
        else:
            ex.response["Error"]["Message"] = "InternalError"
            ex.response["Error"]["Code"] = "InternalError"
        raise ex
    
    try:
        for i in range(len(policies)):
            policies[i] = AWS_IAM_CLIENT.get_user_policy(user_name, policies[i])
    except botocore.exceptions.ClientError as ex:
        if "NoSuchEntity" in ex.response['Error']['Code']:
            ex.response['Error']['Message'] = "Unable to fetch inline policy information. No such entity found."
        elif "InvalidInput" in ex.response['Error']['Code']:
            ex.response['Error']['Message'] = "Failed to fetch inline policy information. Invalid input."
        else:
            ex.response["Error"]["Message"] = "InternalError"
            ex.response["Error"]["Code"] = "InternalError"
        
    return policies
    
def fetch_aws_managed_user_policies(user_name):
    policies = []
    marker = None
    try:
        while True:
            response = AWS_IAM_CLIENT.list_attached_user_policies(UserName=user_name, Marker=marker) if marker else AWS_IAM_CLIENT.list_attached_user_policies(UserName=user_name)      
            policies = policies + response.get("AttachedPolicies", [])
            marker = response.get("Marker")
            if not marker:
                break
        return policies
    except botocore.exceptions.ClientError as ex:
        if "NoSuchEntity" in ex.response['Error']['Code']:
            ex.response['Error']['Message'] = f"Unable to fetch policies for user '{user_name}'. No such entity found."
        elif "InvalidInput" in ex.response['Error']['Code']:
            ex.response['Error']['Message'] = f"Invalid user name '{user_name}' or marker '{marker}' input received."
        else:
            ex.response["Error"]["Message"] = "InternalError"
            ex.response["Error"]["Code"] = "InternalError"
        raise ex
    
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
            
def permission_set_has_admin_policies(instance_arn, permission_set_arn):
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
        
        return policies_grant_admin_access(managed_policies, inline_policies)
    except botocore.exceptions.ClientError as ex:
        ex.response["Error"]["Message"] = "InternalError"
        ex.response["Error"]["Code"] = "InternalError"
        raise ex
    
def get_admin_permission_sets_for_instance(instance_arn):
    permission_sets = []
    next_token = None
    try:
        while True:
            response = AWS_SSO_ADMIN_CLIENT.list_permission_sets_provisioned_to_account(AccountId=AWS_ACCOUNT_ID,InstanceArn=instance_arn, NextToken = next_token) if next_token else AWS_SSO_ADMIN_CLIENT.list_permission_sets_provisioned_to_account(InstanceArn=instance_arn)
            for p_set in response.get("PermissionSets"):
                if permission_set_has_admin_policies(instance_arn, p_set):
                    permission_sets.append(p_set)
            next_token = response.get("NextToken")
            if not next_token:
                break
    except botocore.exceptions.ClientError as ex:
        ex.response["Error"]["Message"] = "InternalError"
        ex.response["Error"]["Code"] = "InternalError"
        raise ex
    
    return permission_sets
  
def user_assigned_to_permission_set(user_id, instance_arn, permission_set_arn):
    try:
        response = AWS_SSO_ADMIN_CLIENT.list_account_assignments(AccountId=AWS_ACCOUNT_ID, InstanceArn=instance_arn, PermissionSetArn=permission_set_arn)
        for assignment in response.get("AccountAssignments"):
            if assignment.get("PrincipalId") == user_id:
                return True
        return False
    except botocore.exceptions.ClientError as ex:
        ex.response["Error"]["Message"] = "InternalError"
        ex.response["Error"]["Code"] = "InternalError"
        raise ex  

def check_users(iam_users, sso_users_by_instance, privileged_user_list, non_privileged_user_list, event):
    evaluations = []
    atleast_one_priveleged_user_has_admin_access = False   
    no_non_privileged_user_has_priviled_access = True
    
    for u in iam_users:
        user_name = u.get("UserName")
        if user_name in privileged_user_list:
            if atleast_one_priveleged_user_has_admin_access == True:
                continue
            
            managed_policies = fetch_aws_managed_user_policies(user_name)
            inline_policies = fetch_inline_user_policies(user_name)
            
            atleast_one_priveleged_user_has_admin_access = policies_grant_admin_access(managed_policies, inline_policies)
            
        elif user_name in non_privileged_user_list:
            managed_policies = fetch_aws_managed_user_policies(user_name)
            inline_policies = fetch_inline_user_policies(user_name)
            if policies_grant_admin_access(managed_policies, inline_policies):
                no_non_privileged_user_has_priviled_access = False
                evaluations.append(
                    build_evaluation(
                        u.get("Arn"),
                        "NON_COMPLIANT",
                        event,
                        USER_RESOURCE_TYPE,
                        f"User '{user_name}' is a non-privileged user with privileged access. "
                    )
                )
                
    for instance_arn in sso_users_by_instance.keys():
        admin_permssion_sets=get_admin_permission_sets_for_instance(instance_arn)
        for user in sso_users_by_instance[instance_arn]:
            user_name = user.get("UserName")
            user_id = user.get("UserId")
            if user_name in privileged_user_list:
                if atleast_one_priveleged_user_has_admin_access == True:
                    continue
              
                for p_arn in admin_permssion_sets:
                    if user_assigned_to_permission_set(user_id, instance_arn, p_arn):
                        atleast_one_priveleged_user_has_admin_access = True
                        break
                
            elif user_name in non_privileged_user_list:
                for p_arn in admin_permssion_sets:
                    if user_assigned_to_permission_set(user_id, instance_arn, p_arn):
                        no_non_privileged_user_has_priviled_access = False
                        evaluations.append(
                            build_evaluation(
                                u.get("Arn"),
                                "NON_COMPLIANT",
                                event,
                                USER_RESOURCE_TYPE,
                                f"SSO user '{user_name}' is a non-privileged user with privileged access from permission set {p_arn}."
                            )
                        )
    
    if atleast_one_priveleged_user_has_admin_access and no_non_privileged_user_has_priviled_access:
        evaluations.append(
            build_evaluation(
                AWS_ACCOUNT_ID,
                "COMPLIANT",
                event,
                DEFAULT_RESOURCE_TYPE
            )
        )
    else:
        evaluations.append(
            build_evaluation(
                AWS_ACCOUNT_ID,
                "NON_COMPLIANT",
                event,
                DEFAULT_RESOURCE_TYPE,
                "There is either no privileged user with admin access or a non-privileged user with admin access in the account. Please see evaluation results for more information."
            )
        )
    
    return evaluations

def policies_grant_admin_access(managed_policies, inline_policies):
    return next((p for p in managed_policies if p.get("PolicyName", "") == "AdministratorAccess"), False) or next((p for p in inline_policies if policy_doc_gives_admin_access(p.get("PolicyDocument", "\{\}"))), False)
    

def lambda_handler(event, context):
    """This function is the main entry point for Lambda.
    Keyword arguments:
    event -- the event variable given in the lambda handler
    context -- the context variable given in the lambda handler
    """
    global AWS_CONFIG_CLIENT
    global AWS_IAM_CLIENT
    global AWS_ACCOUNT_ID
    global AWS_S3_CLIENT
    global AWS_SSO_ADMIN_CLIENT
    global AWS_IDENTITY_STORE_CLIENT
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
    AWS_SSO_ADMIN_CLIENT = get_client("sso-admin", event)
    AWS_IDENTITY_STORE_CLIENT = get_client("identitystore", event)
    AWS_S3_CLIENT = boto3.client("s3")
    
    # is this a scheduled invokation?
    if is_scheduled_notification(invoking_event["messageType"]):
        # yes, proceed
        
        privileged_users_file_path = valid_rule_parameters.get("privilegedUsersFilePath", "")
        non_privileged_users_file_path = valid_rule_parameters.get("privilegedUsersFilePath", "")
        if check_s3_object_exists(privileged_users_file_path) == False or check_s3_object_exists(non_privileged_users_file_path):
            evaluations.append(
                build_evaluation(
                    event["accountId"],
                    "NON_COMPLIANT",
                    event,
                    resource_type=DEFAULT_RESOURCE_TYPE,
                    annotation="No privileged or non_privileged user file path input provided.",
                )
            )
        else:     
            privileged_users_list = read_s3_object(privileged_users_file_path).splitlines()
            non_privileged_users_file_path = read_s3_object(non_privileged_users_file_path).splitlines()
            
            iam_users = fetch_users()
            sso_users_by_instance = fetch_sso_users()
            
            evaluations = evaluations + check_users(iam_users, sso_users_by_instance, privileged_users_list, non_privileged_users_file_path, event)
                
        AWS_CONFIG_CLIENT.put_evaluations(
            Evaluations=evaluations,
            ResultToken=event["resultToken"]
        )
