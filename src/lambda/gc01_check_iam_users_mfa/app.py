""" GC01 - Check IAM Users MFA
    https://canada-ca.github.io/cloud-guardrails/EN/02_Management-Admin-Privileges.html
"""
import json
import logging

import boto3
import botocore

logger = logging.getLogger()
logger.setLevel(logging.INFO)

ASSUME_ROLE_MODE = True
DEFAULT_RESOURCE_TYPE = "AWS::IAM::User"


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
    return rule_parameters


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


def get_iam_users(bg_accounts):
    """Get a list of IAM users in the account."""
    result_iam_users = []
    try:
        response = AWS_IAM_CLIENT.list_users()
        b_more_data = True
        while b_more_data:
            if response:
                logger.info("Found %s IAM users in account %s", len(response.get("Users")), AWS_ACCOUNT_ID)
                users = response.get("Users")
                if users:
                    for user in users:
                        if user.get("UserName") not in bg_accounts:
                            result_iam_users.append({"UserName": user.get("UserName"), "Arn": user.get("Arn")})
                    if response.get("IsTruncated"):
                        marker = response.get("Marker")
                        response = AWS_IAM_CLIENT.list_users(Marker=marker)
                    else:
                        b_more_data = False
                else:
                    logger.info("No IAM users found in account %s", AWS_ACCOUNT_ID)
                    b_more_data = False
            else:
                logger.error("Empty response while trying to list_users in account %s", AWS_ACCOUNT_ID)
                b_more_data = False
    except botocore.exceptions.ClientError as ex:
        logger.error("Error while trying to list_users. %s", ex)
        raise ex
    return result_iam_users


def check_iam_users_mfa(event, bg_accounts):
    """Check if any IAM users have MFA enabled.
    Keyword arguments:
    event -- the event variable given in the lambda handler
    """
    result = []
    # get a list of usernames and ARNs
    iam_users = get_iam_users(bg_accounts)
    if iam_users:
        # check each user
        for user in iam_users:
            # let's check if the user has a login profile
            # (users without one do not have a password for console access)
            try:
                response = AWS_IAM_CLIENT.get_login_profile(UserName=user.get("UserName"))
            except botocore.exceptions.ClientError as ex:
                if "NoSuchEntity" in ex.response["Error"]["Code"]:
                    # user does not have a password for console access
                    result.append(
                        build_evaluation(
                            user.get("UserName"),
                            "NOT_APPLICABLE",
                            event,
                            resource_type=DEFAULT_RESOURCE_TYPE,
                            annotation="IAM User does not have console access.",
                        )
                    )
                    logger.info("User %s does not have console access.", user.get("UserName"))
                    continue
                else:
                    logger.error("Error while trying to get_login_profile for user %s.", user.get("UserName"))
                    logger.error(ex)
                    raise ex
            # if we're here, the user has a console password
            try:
                response = AWS_IAM_CLIENT.list_mfa_devices(UserName=user.get("UserName"))
                if response:
                    # let's check if the user has at least 1 MFA device
                    logger.info("User %s has %d MFA device(s).", user.get("UserName"), len(response.get("MFADevices", [])))
                    if len(response.get("MFADevices", [])) > 0:
                        # yes, at least 1 device found
                        result.append(
                            build_evaluation(
                                user.get("UserName"),
                                "COMPLIANT",
                                event,
                                resource_type=DEFAULT_RESOURCE_TYPE,
                                annotation="MFA Device(s) found",
                            )
                        )
                    else:
                        # no, user is not compliant
                        result.append(
                            build_evaluation(
                                user.get("UserName"),
                                "NON_COMPLIANT",
                                event,
                                resource_type=DEFAULT_RESOURCE_TYPE,
                                annotation="No MFA Device found",
                            )
                        )
                else:
                    logger.error("Empty response on the list_mfa_devices call for user %s", user.get("UserName"))
            except botocore.exceptions.ClientError as ex:
                logger.error("Error while trying to list_mfa_devices.")
                logger.error(ex)
                raise ex
    else:
        # no users in account
        result = [
            build_evaluation(
                AWS_ACCOUNT_ID,
                "NOT_APPLICABLE",
                event,
                resource_type="AWS::::Account",
                annotation="No IAM Users found",
            )
        ]
    return result


def lambda_handler(event, context):
    """This function is the main entry point for Lambda.
    Keyword arguments:
    event -- the event variable given in the lambda handler
    context -- the context variable given in the lambda handler
    """
    global AWS_CONFIG_CLIENT
    global AWS_IAM_CLIENT
    global AWS_ACCOUNT_ID
    global EXECUTION_ROLE_NAME
    global AUDIT_ACCOUNT_ID

    evaluations = []
    rule_parameters = {}

    invoking_event = json.loads(event["invokingEvent"])
    logger.info("Received Event: %s", json.dumps(event, indent=2))

    # parse parameters
    AWS_ACCOUNT_ID = event["accountId"]

    if "ruleParameters" in event:
        rule_parameters = json.loads(event["ruleParameters"])

    valid_rule_parameters = evaluate_parameters(rule_parameters)

    # Retrieve breakglass accounts
    bg_accounts = [valid_rule_parameters["BgUser1"], valid_rule_parameters["BgUser2"]]

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

    # is this a scheduled invokation?
    if is_scheduled_notification(invoking_event["messageType"]):
        # yes, proceed
        # Update AWS Config with the evaluation result
        evaluations = check_iam_users_mfa(event, bg_accounts)
        AWS_CONFIG_CLIENT.put_evaluations(
            Evaluations=evaluations,
            ResultToken=event["resultToken"]
        )
