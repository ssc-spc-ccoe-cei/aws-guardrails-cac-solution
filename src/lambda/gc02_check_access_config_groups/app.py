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
GROUP_RESOURCE_TYPE = "AWS::IAM::Group"


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
    for parameter in rule_parameters:
        if parameter in [
            "MinimumPasswordLength",
            "MaxPasswordAge",
            "PasswordReusePrevention",
        ]:
            PASSWORD_ASSESSMENT_POLICY[parameter] = int(rule_parameters[parameter])
        elif parameter in [
            "RequireSymbols",
            "RequireNumbers",
            "RequireUppercaseCharacters",
            "RequireLowercaseCharacters",
            "AllowUsersToChangePassword",
            "ExpirePasswords",
            "HardExpiry",
        ]:
            if str(rule_parameters[parameter]).lower() == "true":
                PASSWORD_ASSESSMENT_POLICY[parameter] = True
            elif str(rule_parameters[parameter]).lower() == "false":
                PASSWORD_ASSESSMENT_POLICY[parameter] = False
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

def read_s3_object(s3_file_path):
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

def fetch_groups():
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

def check_group_policies(group_name, admin_accounts, event):
    # Checks all group policies to ensure that there is not mixture of admin and non-admin roles.
    
    # Fetch aws managed and inline group policies
    managed_policies = fetch_aws_managed_group_policies(group_name)
    inline_policies = fetch_inline_group_policies(group_name)
    
    # Checks for the aws managed policy AdministratorAccess or an inline policy that gives the same access.
    has_admin_policy = next((p for p in managed_policies if p.get("PolicyName", "") == "AdministratorAccess"), False) or next((p for p in inline_policies if policy_doc_gives_admin_access(p.get("PolicyDocument", "\{\}"))), False)
    has_non_admin_policy = next((p for p in managed_policies if p.get("PolicyName", "") != "AdministratorAccess"), False) or next((p for p in inline_policies if not policy_doc_gives_admin_access(p.get("PolicyDocument", "\{\}"))), False)
    
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
        group_members = fetch_group_members(group_name, event)
        only_has_admins = next((m for m in group_members if m.get("UserName", "") not in admin_accounts), True)
        if not only_has_admins:
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
    
def fetch_group_members(group_name, event):
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
    return len(statement) == 1 and statement[0].get("Effect", "") == "Allow" and statement[0].get("Action", "") == "*" and statement[0].get("Resource", "") == "*"
        
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
    global AWS_ACCOUNT_ID
    global AWS_S3_CLIENT
    global EXECUTION_ROLE_NAME
    global AUDIT_ACCOUNT_ID
    global PASSWORD_ASSESSMENT_POLICY

    evaluations = []
    rule_parameters = {}

    PASSWORD_ASSESSMENT_POLICY = {
        "MinimumPasswordLength": 14,
        "RequireSymbols": True,
        "RequireNumbers": True,
        "RequireUppercaseCharacters": True,
        "RequireLowercaseCharacters": True,
        "AllowUsersToChangePassword": True,
        "ExpirePasswords": False,
        "MaxPasswordAge": 90,
        "PasswordReusePrevention": 24,
        "HardExpiry": False,
    }

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
    AWS_S3_CLIENT = boto3.client("s3")
    
    # is this a scheduled invokation?
    if is_scheduled_notification(invoking_event["messageType"]):
        # yes, proceed
        
        admin_accounts_file_path = valid_rule_parameters.get("AdminAccountsFilePath", "")
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
            admin_accounts_json_list = read_s3_object(admin_accounts_file_path)
            admin_accounts = json.loads(admin_accounts_json_list)
            
            groups = fetch_groups()
            for g in groups:
                eval = check_group_policies(g.get("GroupName", ""), admin_accounts, event)
                if eval.get("ComplianceType", "NON_COMPLIANT") == "NON_COMPLIANT":
                    is_compliant = False
            
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
