""" GC13 - Emergency Account Testing Lambda Function
    Verifies that testing of emergency accounts took place and that periodic testing is included
"""
import json
import logging
import time
from datetime import datetime, timedelta, timezone

import boto3
import botocore

# Logging setup
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Set to True to get the lambda to assume the Role attached on the Config Service
ASSUME_ROLE_MODE = True
DEFAULT_RESOURCE_TYPE = "AWS::::Account"
IAM_USER_RESOURCE_TYPE = "AWS::IAM::User"


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
    """Returns the credentials required to assume the passed role
    Keyword arguments:
    role_arn -- the arn of the role to assume"""
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
        logger.error("ERROR assuming role. %s", ex.response["Error"])
        raise ex


# Check whether the message is a ScheduledNotification or not.
def is_scheduled_notification(message_type):
    """Check whether the message is a ScheduledNotification or not.
    Keyword arguments:
    message_type -- the message type
    """
    return message_type == "ScheduledNotification"


def evaluate_parameters(rule_parameters):
    """Evaluate the rule parameters dictionary validity. Raise a Exception for invalid parameters.
    Keyword arguments:
    rule_parameters -- the Key/Value dictionary of the Config Rule parameters
    """
    return rule_parameters


def get_organizations_mgmt_account_id():
    """Calls the AWS Organizations API to obtain the Management Account ID"""
    management_account_id = ""
    i_retry_limit = 10
    i_retries = 0
    b_completed = False
    b_retry = True
    while (b_retry and (not b_completed)) and (i_retries < i_retry_limit):
        try:
            response = AWS_ORGANIZATIONS_CLIENT.describe_organization()
            if response:
                organization = response.get("Organization", None)
                if organization:
                    management_account_id = organization.get("MasterAccountId", "")
                else:
                    logger.error("Unable to read the Organization from the dict")
            else:
                logger.error("Invalid response.")
            b_completed = True
        except botocore.exceptions.ClientError as ex:
            if "AccessDenied" in ex.response["Error"]["Code"]:
                logger.error("ACCESS DENIED when trying to describe_organization")
                management_account_id = "ERROR"
                b_retry = False
            elif "AWSOrganizationsNotInUse" in ex.response["Error"]["Code"]:
                logger.error("AWS Organizations not in use")
                management_account_id = "ERROR"
                b_retry = False
            elif "ServiceException" in ex.response["Error"]["Code"]:
                logger.error("AWS Organizations Service Exception")
                management_account_id = "ERROR"
                b_retry = False
            elif ("ConcurrentModification" in ex.response["Error"]["Code"]) or (
                "TooManyRequests" in ex.response["Error"]["Code"]
            ):
                # throttling
                logger.info("AWS Organizations API is throttling requests or going through a modification. Will retry.")
                time.sleep(2)
                if i_retries >= i_retry_limit:
                    logger.error("Retry limit reached. Returning an error")
                    management_account_id = "ERROR"
                    b_retry = False
                else:
                    i_retries += 1
        except ValueError:
            logger.error("Unknown exception - get_organizations_mgmt_account_id.")
            management_account_id = "ERROR"
    return management_account_id


# This generate an evaluation for config
def build_evaluation(resource_id, compliance_type, event, resource_type=DEFAULT_RESOURCE_TYPE, annotation=None):
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
    eval_cc["OrderingTimestamp"] = str(json.loads(event["invokingEvent"])["notificationCreationTime"])
    return eval_cc


def get_iam_user(user_name: str) -> dict | None:
    try:
        response = AWS_IAM_CLIENT.get_user(UserName=user_name)
        user = response.get("User")
        return {
            "UserName": user.get("UserName"),
            "UserId": user.get("UserId"),
            "Arn": user.get("Arn"),
            "PasswordLastUsed": user.get("PasswordLastUsed", None),
        }
    except botocore.exceptions.ClientError as ex:
        # Scrub error message for any internal account info leaks
        if "NoSuchEntity" in ex.response["Error"]["Code"]:
            return None
        elif "AccessDenied" in ex.response["Error"]["Code"]:
            ex.response["Error"]["Message"] = "AWS Config does not have permission to assume the IAM role."
        elif "ServiceFailure" in ex.response["Error"]["Code"]:
            ex.response["Error"]["Message"] = "AWS IAM service failure."
        else:
            ex.response["Error"]["Message"] = "InternalError"
            ex.response["Error"]["Code"] = "InternalError"
        logger.error("ERROR getting iam user. %s", ex.response["Error"])
        raise ex


def last_use_of_password_is_within_one_year(password_last_used_date: datetime | None) -> bool:
    if not password_last_used_date:
        return False
    one_year_ago = datetime.now().astimezone() - timedelta(days=365)
    return password_last_used_date > one_year_ago


def lambda_handler(event, context):
    """
    This function is the main handler for the Lambda function.
    It will call the appropriate functions based on the event type. Keyword arguments:
    event -- the event variable given in the lambda handler
    context -- the context variable given in the lambda handler
    """

    global AWS_CONFIG_CLIENT
    global AWS_IAM_CLIENT
    global AWS_ORGANIZATIONS_CLIENT
    global AWS_ACCOUNT_ID
    global EXECUTION_ROLE_NAME
    global AUDIT_ACCOUNT_ID

    evaluations = []
    rule_parameters = {}
    invoking_event = json.loads(event["invokingEvent"])
    logger.info("Received Event: %s", json.dumps(event, indent=2))

    # is this a scheduled invocation?
    if not is_scheduled_notification(invoking_event["messageType"]):
        # no, do not proceed
        return

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
    AWS_ORGANIZATIONS_CLIENT = get_client("organizations", event)

    if AWS_ACCOUNT_ID != get_organizations_mgmt_account_id():
        # We're not in the Management Account
        logger.info("Emergency Account Verification not checked in account %s as this is not the Management Account", AWS_ACCOUNT_ID)
        return

    bg_account_names = [valid_rule_parameters["BgUser1"], valid_rule_parameters["BgUser2"]]
    num_compliant = 0
    missing_users = []

    for account_name in bg_account_names:
        iam_account = get_iam_user(account_name)
        user_id = iam_account.get("UserId") if iam_account else None
        logger.info("Processing account with name '%s': %s", account_name, iam_account)

        if not iam_account:
            annotation = f"Account with name '{account_name}' was NOT found in IAM."
            missing_users.append(account_name)
        elif not last_use_of_password_is_within_one_year(iam_account.get("PasswordLastUsed")):
            annotation = f"Account with name '{account_name}' has NOT used it's password within 1 year."
            evaluations.append(build_evaluation(user_id, "NON_COMPLIANT", event, IAM_USER_RESOURCE_TYPE, annotation))
        else:
            num_compliant = num_compliant + 1
            annotation = f"Account with name '{account_name}' exists and has used it's password within 1 year."
            evaluations.append(build_evaluation(user_id, "COMPLIANT", event, IAM_USER_RESOURCE_TYPE, annotation))
        logger.info(annotation)

    # Report any missing users
    if not missing_users:
        annotation = f"No missing break-glass user(s) in IAM"
        evaluations.append(build_evaluation(event["accountId"], "COMPLIANT", event, IAM_USER_RESOURCE_TYPE, annotation))
    else:
        annotation = f"Missing break-glass user(s) in IAM with name(s): '{ "', '".join(missing_users) }'"
        evaluations.append(build_evaluation(event["accountId"], "NON_COMPLIANT", event, IAM_USER_RESOURCE_TYPE, annotation))
    logger.info(annotation)

    if len(bg_account_names) == num_compliant:
        annotation = "All break-glass accounts exist and have used their password within 1 year."
        evaluations.append(build_evaluation(event["accountId"], "COMPLIANT", event, DEFAULT_RESOURCE_TYPE, annotation))
    else:
        annotation = "NOT all break-glass accounts exist and have used their password within 1 year."
        evaluations.append(build_evaluation(event["accountId"], "NON_COMPLIANT", event, DEFAULT_RESOURCE_TYPE, annotation))
    logger.info(annotation)

    AWS_CONFIG_CLIENT.put_evaluations(
        Evaluations=evaluations,
        ResultToken=event["resultToken"]
    )
