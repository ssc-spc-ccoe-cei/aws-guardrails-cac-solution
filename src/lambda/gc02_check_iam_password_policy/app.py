""" GC02 - Check IAM Password Policy
    https://canada-ca.github.io/cloud-guardrails/EN/02_Management-Admin-Privileges.html
"""
import json
import logging

import boto3
import botocore

# Logging setup
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Set to True to get the lambda to assume the Role attached on the Config Service
ASSUME_ROLE_MODE = True
DEFAULT_RESOURCE_TYPE = "AWS::::Account"


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


def assess_iam_password_policy():
    """Obtains the IAM Password Policy in the account and assesses it against the parameters"""
    compliance_status = "COMPLIANT"
    compliance_annotation = ""
    try:
        # get the current policy
        response = AWS_IAM_CLIENT.get_account_password_policy()
        if response:
            current_password_policy = response.get("PasswordPolicy", {})
            if current_password_policy:
                # we have a policy, let's check
                if int(PASSWORD_ASSESSMENT_POLICY.get("MinimumPasswordLength", -1)) > 0:
                    if current_password_policy.get("MinimumPasswordLength", -1) < PASSWORD_ASSESSMENT_POLICY.get("MinimumPasswordLength"):
                        compliance_status = "NON_COMPLIANT"
                        compliance_annotation += "MinimumPasswordLength;"
                if int(PASSWORD_ASSESSMENT_POLICY.get("MaxPasswordAge", -1)) > 0:
                    if current_password_policy.get("MaxPasswordAge", -1) < PASSWORD_ASSESSMENT_POLICY.get("MaxPasswordAge"):
                        compliance_status = "NON_COMPLIANT"
                        compliance_annotation += "MaxPasswordAge;"
                if (int(PASSWORD_ASSESSMENT_POLICY.get("PasswordReusePrevention", -1)) > 0):
                    if current_password_policy.get("PasswordReusePrevention", -1) < PASSWORD_ASSESSMENT_POLICY.get("PasswordReusePrevention"):
                        compliance_status = "NON_COMPLIANT"
                        compliance_annotation += "PasswordReusePrevention;"
                # The Policy items below are ONLY assessed IF they are required (True)
                if PASSWORD_ASSESSMENT_POLICY.get("RequireSymbols", False):
                    if current_password_policy.get("RequireSymbols", False) != PASSWORD_ASSESSMENT_POLICY.get("RequireSymbols"):
                        compliance_status = "NON_COMPLIANT"
                        compliance_annotation += "RequireSymbols;"
                if PASSWORD_ASSESSMENT_POLICY.get("RequireNumbers", False):
                    if current_password_policy.get("RequireNumbers", False) != PASSWORD_ASSESSMENT_POLICY.get("RequireNumbers"):
                        compliance_status = "NON_COMPLIANT"
                        compliance_annotation += "RequireNumbers;"
                if PASSWORD_ASSESSMENT_POLICY.get("RequireUppercaseCharacters", False):
                    if current_password_policy.get("RequireUppercaseCharacters", False) != PASSWORD_ASSESSMENT_POLICY.get("RequireUppercaseCharacters"):
                        compliance_status = "NON_COMPLIANT"
                        compliance_annotation += "RequireUppercaseCharacters;"
                if PASSWORD_ASSESSMENT_POLICY.get("RequireLowercaseCharacters", False):
                    if current_password_policy.get("RequireLowercaseCharacters", False) != PASSWORD_ASSESSMENT_POLICY.get("RequireLowercaseCharacters"):
                        compliance_status = "NON_COMPLIANT"
                        compliance_annotation += "RequireLowercaseCharacters;"
                if PASSWORD_ASSESSMENT_POLICY.get("AllowUsersToChangePassword", False):
                    if current_password_policy.get("AllowUsersToChangePassword", False) != PASSWORD_ASSESSMENT_POLICY.get("AllowUsersToChangePassword"):
                        compliance_status = "NON_COMPLIANT"
                        compliance_annotation += "AllowUsersToChangePassword;"
                if PASSWORD_ASSESSMENT_POLICY.get("ExpirePasswords", False):
                    if current_password_policy.get("ExpirePasswords", False) != PASSWORD_ASSESSMENT_POLICY.get("ExpirePasswords"):
                        compliance_status = "NON_COMPLIANT"
                        compliance_annotation += "ExpirePasswords;"
                if PASSWORD_ASSESSMENT_POLICY.get("HardExpiry", False):
                    if current_password_policy.get("HardExpiry", False) != PASSWORD_ASSESSMENT_POLICY.get("HardExpiry"):
                        compliance_status = "NON_COMPLIANT"
                        compliance_annotation += "HardExpiry;"
            else:
                compliance_status = "NON_COMPLIANT"
                compliance_annotation = "Empty password policy read. Unable to assess"
                logger.error(compliance_annotation)
        else:
            compliance_status = "NON_COMPLIANT"
            compliance_annotation = "Empty password policy read. Unable to assess"
            logger.error(compliance_annotation)
    except botocore.exceptions.ClientError as ex:
        compliance_status = "NON_COMPLIANT"
        compliance_annotation = "Unable to get_account_password_policy. Unable to assess"
        logger.error(compliance_annotation)
        logger.error(ex)
    return {"status": compliance_status, "annotation": compliance_annotation}


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

    if "EXECUTION_ROLE_NAME" in valid_rule_parameters:
        EXECUTION_ROLE_NAME = valid_rule_parameters["ExecutionRoleName"]
    else:
        EXECUTION_ROLE_NAME = "AWSA-GCLambdaExecutionRole"

    if "AuditAccountID" in valid_rule_parameters:
        AUDIT_ACCOUNT_ID = valid_rule_parameters["AuditAccountID"]
    else:
        AUDIT_ACCOUNT_ID = ""

    AWS_CONFIG_CLIENT = get_client("config", event)
    AWS_IAM_CLIENT = get_client("iam", event)

    if AWS_ACCOUNT_ID == AUDIT_ACCOUNT_ID:
        # is this a scheduled invokation?
        if is_scheduled_notification(invoking_event["messageType"]):
            # yes, proceed
            # Update AWS Config with the evaluation result
            assessment_result = assess_iam_password_policy()
            evaluations = [
                build_evaluation(
                    AWS_ACCOUNT_ID,
                    assessment_result["status"],
                    event,
                    resource_type="AWS::::Account",
                    annotation=assessment_result["annotation"],
                )
            ]
            AWS_CONFIG_CLIENT.put_evaluations(
                Evaluations=evaluations,
                ResultToken=event["resultToken"]
            )
    else:
        logger.info("IAM Password Policy not checked in account %s - not the Audit account", AWS_ACCOUNT_ID)
