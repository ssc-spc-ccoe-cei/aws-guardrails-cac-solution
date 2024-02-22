""" GC04 - Check Enterprise Monitoring
    https://canada-ca.github.io/cloud-guardrails/EN/04_Enterprise-Monitoring-Accounts.html
"""
import json
import logging
import time

import boto3
import botocore

logger = logging.getLogger()
logger.setLevel(logging.INFO)
ASSUME_ROLE_MODE = True
DEFAULT_RESOURCE_TYPE = "AWS::::Account"


def get_client(service, event):
    """Return the service boto client. It should be used instead of directly calling the client.
    Keyword arguments:
    service -- the service name used for calling the boto.client()
    event -- the event variable given in the lambda handler
    """
    if not ASSUME_ROLE_MODE:
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
    """Return the service boto client. It should be used instead of directly calling the client.
    Keyword arguments:
    service -- the service name used for calling the boto.client()
    event -- the event variable given in the lambda handler
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
    """Evaluate the rule parameters dictionary.
    Keyword arguments:
    rule_parameters -- the Key/Value dictionary of the Config rule parameters
    """
    if "IAM_Role_Name" not in rule_parameters:
        raise ValueError('The parameter with "IAM_Role_Name" as key must be defined.')
    if not rule_parameters["IAM_Role_Name"]:
        raise ValueError('The parameter "IAM_Role_Name" must have a defined value.')
    if "IAM_Trusted_Principal" not in rule_parameters:
        raise ValueError('The parameter with "IAM_Trusted_Principal" as key must be defined.')
    if not rule_parameters["IAM_Trusted_Principal"]:
        raise ValueError('The parameter "IAM_Trusted_Principal" must have a defined value.')
    return rule_parameters


def check_enterprise_monitoring_accounts(parameters):
    """
    This function checks if the Enterprise Monitoring Account is configured
    :param parameters:
    :return:
    """
    trusted_principal = parameters.get("IAM_Trusted_Principal")
    role_name = parameters.get("IAM_Role_Name")
    b_role_found = False
    b_trust_policy_found = False
    try:
        response = AWS_IAM_CLIENT.get_role(RoleName=role_name)
        if response:
            if response.get("Role").get("RoleName") == role_name:
                b_role_found = True
                try:
                    policy_document = response.get("Role").get("AssumeRolePolicyDocument")
                except ValueError:
                    # invalid or empty policy
                    policy_document = {}
                if policy_document:
                    for statement in policy_document.get("Statement"):
                        # check Principal
                        principal = statement.get("Principal", {})
                        if principal:
                            aws = principal.get("AWS", "")
                            if aws:
                                if aws == trusted_principal:
                                    if (statement.get("Effect") == "Allow") and (statement.get("Action") == "sts:AssumeRole"):
                                        b_trust_policy_found = True
                                        logger.info("Trust policy validated for role %s", role_name)
                                        break
    except botocore.exceptions.ClientError as err:
        if "NoSuchEntity" in err.response["Error"]["Code"]:
            b_role_found = False
        else:
            raise err
    return {"RoleFound": b_role_found, "TrustPolicyFound": b_trust_policy_found}


def get_organizations_mgmt_account_id():
    """
    This function returns the management account ID for the AWS Organizations
    :return:
    """
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
            elif ("ConcurrentModification" in ex.response["Error"]["Code"]) or ("TooManyRequests" in ex.response["Error"]["Code"]):
                logger.info("AWS Organizations API is throttling requests or going through a modification. Will retry.")
                time.sleep(2)
                if i_retries >= i_retry_limit:
                    logger.error("Retry limit reached. Returning an error")
                    management_account_id = "ERROR"
                    b_retry = False
                else:
                    i_retries += 1
        except ValueError:
            logger.error("Unknown exception - get_organizations_mgmt_account_id")
            management_account_id = "ERROR"
    return management_account_id


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
    annotation -- an annotation to be added to the evaluation (default None).
    It will be truncated to 255 if longer.
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


def lambda_handler(event, context):
    """Lambda handler to check CloudTrail trails are logging.
    Keyword arguments:
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

    compliance_value = "NOT_APPLICABLE"
    custom_annotation = "Guardrail only applicable in the Management Account"

    AWS_CONFIG_CLIENT = get_client("config", event)
    AWS_IAM_CLIENT = get_client("iam", event)
    AWS_ORGANIZATIONS_CLIENT = get_client("organizations", event)

    # is this a scheduled invokation?
    if is_scheduled_notification(invoking_event["messageType"]):
        # yes, are we in the management account?
        if AWS_ACCOUNT_ID == get_organizations_mgmt_account_id():
            # yes, proceed with checking IAM
            # check if object exists in IAM
            results = check_enterprise_monitoring_accounts(valid_rule_parameters)
            if results.get("RoleFound"):
                if results.get("TrustPolicyFound"):
                    compliance_value = "COMPLIANT"
                    custom_annotation = "IAM Role and trust policy compliant"
                else:
                    compliance_value = "NON_COMPLIANT"
                    custom_annotation = "IAM Role found; Trust policy NOT compliant"
            else:
                compliance_value = "NON_COMPLIANT"
                custom_annotation = "IAM Role NOT found. Trust policy cannot be assessed."
            # Update AWS Config with the evaluation result
            evaluations.append(
                build_evaluation(
                    event["accountId"],
                    compliance_value,
                    event,
                    resource_type=DEFAULT_RESOURCE_TYPE,
                    annotation=custom_annotation,
                )
            )
            AWS_CONFIG_CLIENT.put_evaluations(
                Evaluations=evaluations,
                ResultToken=event["resultToken"]
            )
        else:
            # We're not in the Management Account
            logger.info("Enterprise Monitoring Accounts not checked in account %s as this is not the Management Account", AWS_ACCOUNT_ID)
