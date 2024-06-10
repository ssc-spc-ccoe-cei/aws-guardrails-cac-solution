""" GC03 - Check IAM/ CloudWatch Alarms
    https://canada-ca.github.io/cloud-guardrails/EN/03_Cloud-Console-Access.html
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
        # Scrub error message for any internal account info leaks
        if "AccessDenied" in ex.response["Error"]["Code"]:
            ex.response["Error"]["Message"] = "AWS Config does not have permission to assume the IAM role."
        else:
            ex.response["Error"]["Message"] = "InternalError"
            ex.response["Error"]["Code"] = "InternalError"
        raise ex


# Check whether the message is a ScheduledNotification or not.
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
            logger.error("Unknown exception - get_organizations_mgmt_account_id")
            management_account_id = "ERROR"
    return management_account_id


# This generates an evaluation for config
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


def check_cloudwatch_alarms(
    alarm_names=[
        "AWS-IAM-Authentication-From-Unapproved-IP",
        "AWS-SSO-Authentication-From-Unapproved-IP",
        "AWS-Console-SignIn-Without-MFA",
    ]
):
    """Check CloudWatch alarms for compliance.
    Keyword arguments:
    alarm_names -- the list of CloudWatch alarms to check
    """
    result = {"status": "NON_COMPLIANT", "annotation": "No alarms found"}
    if len(alarm_names) < 1:
        # no alarms to check
        result = {
            "status": "COMPLIANT",
            "annotation": "No alarms checked for compliance",
        }
        return result
    # initialize our lists
    alarms_not_found = alarm_names
    alarms_found = []
    try:
        # describe CloudWatch alarms
        response = AWS_CLOUDWATCH_CLIENT.describe_alarms(
            AlarmNames=alarm_names,
            AlarmTypes=["MetricAlarm"],
        )
        # results may be paginated, and we may have to retry
        b_more_data = True
        i_retries = 0
        i_retry_limit = 10
        next_token = ""
        while b_more_data and (i_retries < i_retry_limit):
            # did we get a response?
            if response:
                # yes
                alarms_found.extend(response.get("MetricAlarms"))
                # results paginated?
                next_token = response.get("NextToken")
                if next_token:
                    # yes
                    response = AWS_CLOUDWATCH_CLIENT.describe_alarms(
                        AlarmNames=alarm_names,
                        AlarmTypes=["MetricAlarm"],
                        NextToken=next_token,
                    )
                else:
                    # no more data
                    b_more_data = False
            else:
                logger.error("Empty response. Retry call.")
                i_retries += 1
                if next_token:
                    response = AWS_CLOUDWATCH_CLIENT.describe_alarms(
                        AlarmNames=alarm_names,
                        AlarmTypes=["MetricAlarm"],
                        NextToken=next_token,
                    )
                else:
                    response = AWS_CLOUDWATCH_CLIENT.describe_alarms(
                        AlarmNames=alarm_names,
                        AlarmTypes=["MetricAlarm"],
                    )
        # did we time out trying?
        if i_retries >= i_retry_limit:
            # yes
            result["annotation"] = "Empty response while trying describe_alarms in CloudWatch API."
            return result
    except botocore.exceptions.ClientError as error:
        logger.error("Error while trying to describe_alarms - boto3 Client error - %s", error)
        result["annotation"] = "Error while trying to describe_alarms."
        return result
    # let's look at the alarms we found
    for alarm in alarms_found:
        # are we still looking for alarms that we haven't found?
        if alarms_not_found:
            # yes; is this alarm found in the list we're looking for?
            # if alarm.get("AlarmName") in alarms_not_found:
            #     # yes
            #     logger.info("CloudWatch Alarm %s found.", alarm.get("AlarmName"))
            #     try:
            #         alarms_not_found.remove(alarm.get("AlarmName"))
            #     except ValueError:
            #         # value not in the list
            #         pass
            for a in alarms_not_found:
                # Check each alarm not found, is it a substring of the alarm we're looking for?
                if a in alarm.get("AlarmName"):
                    # yes
                    logger.info("CloudWatch Alarm %s found.", alarm.get("AlarmName"))
                    try:
                        alarms_not_found.remove(a)
                    except ValueError:
                        # value not in the list
                        pass
        else:
            # no, we're done
            break
    # prepare the annotation (if needed)
    if len(alarms_not_found) > 0:
        annotation = "Alarms not found: "
        for alarm in alarms_not_found:
            annotation += f"{alarm}; "
        result["annotation"] = annotation
    else:
        result = {"status": "COMPLIANT", "annotation": "All alarms found"}
    logger.info(result)
    return result


def lambda_handler(event, context):
    """Lambda handler to check CloudTrail trails are logging.
    Keyword arguments:
    event -- the event variable given in the lambda handler
    context -- the context variable given in the lambda handler
    """
    global AWS_CONFIG_CLIENT
    global AWS_CLOUDWATCH_CLIENT
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
    AWS_CLOUDWATCH_CLIENT = get_client("cloudwatch", event)
    AWS_ORGANIZATIONS_CLIENT = get_client("organizations", event)

    # is this a scheduled invokation?
    if is_scheduled_notification(invoking_event["messageType"]):
        # yes, are we in the management account?
        if AWS_ACCOUNT_ID == get_organizations_mgmt_account_id():
            # yes, proceed with checking CloudWatch Alarms
            # check if alarms exist in CloudWatch Alarms
            results = check_cloudwatch_alarms(alarm_names=str(
                valid_rule_parameters["AlarmList"]).split(","))
            if results:
                compliance_value = results.get("status")
                custom_annotation = results.get("annotation")
            else:
                compliance_value = "NON_COMPLIANT"
                custom_annotation = "Unable to assess CloudWatch Alarms"
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
            logger.info("CloudWatch Alarms not checked in account %s as this is not the Management Account", AWS_ACCOUNT_ID)
