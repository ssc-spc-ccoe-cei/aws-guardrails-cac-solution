""" GC01 - Check Root MFA
    https://canada-ca.github.io/cloud-guardrails/EN/01_Protect-Root-Account.html
"""
import json
import logging
import time

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
    """Evaluate the rule parameters dictionary.
    Keyword arguments:
    rule_parameters -- the Key/Value dictionary of the Config rule parameters
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


def get_root_mfa_enabled():
    """Generates an IAM Credential report and confirms if MFA is enabled for the root user"""
    b_root_account_mfa = False
    b_root_account_found = False
    b_retry = True
    i_retry_limit = 10
    i_retries = 0
    report_content = ""
    logger.info("Generating IAM Credential report...")
    while b_retry and i_retries < i_retry_limit:
        try:
            response = AWS_IAM_CLIENT.get_credential_report()
            if response:
                report_content = response.get("Content").decode("utf-8")
                b_retry = False
            else:
                logger.error("Invalid response from the get_credential_report call.")
                time.sleep(1)
        except botocore.exceptions.ClientError as error:
            print(error)
            if ("ReportNotPresent" in error.response["Error"]["Code"]) or (
                "ReportExpired" in error.response["Error"]["Code"]
            ):
                # we need to request report generation
                try:
                    response = AWS_IAM_CLIENT.generate_credential_report()
                    logger.info("Generating credential report...sleeping for 5 seconds")
                    time.sleep(5)
                except botocore.exceptions.ClientError as err:
                    if "LimitExceeded" in err.response["Error"]["Code"]:
                        # exceeding an internal AWS limit
                        logger.info("LimitExceededException...sleeping for 2 seconds")
                        time.sleep(2)
                    else:
                        # something else
                        logger.error("Error while trying to generate_credential_report - boto3 Client error - %s", error)
                        b_retry = False
            elif ("ReportNotReady" in error.response["Error"]["Code"]) or (
                "ReportInProgress" in error.response["Error"]["Code"]
            ):
                # we need to wait a bit more for it to be ready
                logger.info("Credential report not ready...sleeping for 2 seconds")
                time.sleep(2)
            else:
                # something else
                logger.error("Error while trying to get_credential_report - boto3 Client error - %s", error)
                b_retry = False
        i_retries += 1
    lines = report_content.split("\n")
    # do we have lines in the report?
    if len(lines) > 1:
        # yes, let's get the header
        header = lines[0]
        column_names = header.split(",")
        # were we able to get the column names?
        if column_names:
            # yes, so let's find the indices we're looking for
            try:
                user_column_index = column_names.index("user")
                mfa_column_index = column_names.index("mfa_active")
            except ValueError:
                # column not found
                logger.error("Invalid header line.")
                return False
            # now iterate over the remaining lines to find the root account
            for line in lines[1:]:
                line = line.strip()
                # is the line empty?
                if line:
                    # no, great! Process it.
                    try:
                        if line.split(",")[user_column_index] == "<root_account>":
                            # root account found
                            b_root_account_found = True
                            if line.split(",")[mfa_column_index].lower() == "true":
                                # MFA is enabled
                                logger.info("Root account MFA confirmed to be enabled.")
                                b_root_account_mfa = True
                            break
                    except ValueError:
                        logger.error("Error parsing line %s", line)
                else:
                    logger.info("Skipping empty line")
        else:
            logger.error("Unable to split header line")
    else:
        logger.error("Empty credential report")
    if not b_root_account_found:
        logger.error("Root account was NOT found in the credential report")
    return b_root_account_mfa


def lambda_handler(event, context):
    """This function is the main entry point for Lambda.
    Keyword arguments:
    event -- the event variable given in the lambda handler
    context -- the context variable given in the lambda handler
    """
    logger.debug("Received event: %s", event)

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
            # check if Root Account has MFA enabled
            logger.info("Root Account MFA check in account %s", AWS_ACCOUNT_ID)
            if get_root_mfa_enabled():
                compliance_value = "COMPLIANT"
                custom_annotation = "Root Account MFA enabled"
            else:
                compliance_value = "NON_COMPLIANT"
                custom_annotation = "Root Account MFA NOT enabled."
            # Update AWS Config with the evaluation result
            logger.info("Updating AWS Config with Evaluation Result: %s", compliance_value)
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
            logger.info("Root Account MFA not checked in account %s as this is not the Management Account", AWS_ACCOUNT_ID)
