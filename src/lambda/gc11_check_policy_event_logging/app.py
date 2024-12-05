""" GC11 - Confirms that the policy for event logging is implemented
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
ACCOUNT_RESOURCE_TYPE = "AWS::::Account"


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


def get_assume_role_credentials(role_arn, region="ca-central-1"):
    """Returns the temporary credentials for the service account.
    Keyword arguments:
    role_arn -- the ARN of the service account
    region -- the region where the service account exists
    """
    sts_client = boto3.client("sts", region_name=region)
    try:
        assume_role_response = sts_client.assume_role(RoleArn=role_arn, RoleSessionName="configLambdaExecution")
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


# This generates an evaluation for config
def build_evaluation(
    resource_id,
    compliance_type,
    event,
    resource_type=ACCOUNT_RESOURCE_TYPE,
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
    eval_cc["OrderingTimestamp"] = str(json.loads(event["invokingEvent"])["notificationCreationTime"])
    return eval_cc


def submit_evaluations(
    aws_config_client, result_token: str, evaluations: list[dict], interval_between_calls: float = 0.1
):
    max_evaluations_per_call = 100
    while evaluations:
        batch_of_evaluations, evaluations = (
            evaluations[:max_evaluations_per_call],
            evaluations[max_evaluations_per_call:],
        )
        aws_config_client.put_evaluations(Evaluations=batch_of_evaluations, ResultToken=result_token)
        if evaluations:
            time.sleep(interval_between_calls)


def config_describe_all_rules(config_client, interval_between_calls: float = 0.1) -> list[dict]:
    """
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/config/paginator/DescribeConfigRules.html
    """
    resources: list[dict] = []
    paginator = config_client.get_paginator("describe_config_rules")
    page_iterator = paginator.paginate()
    for page in page_iterator:
        resources.extend(page.get("ConfigRules", []))
        time.sleep(interval_between_calls)
    return resources


def assess_aws_managed_rules(config_client, event: dict) -> tuple[list[dict], bool]:
    # There is no available resource type for the config rules, fallback to the account type
    resource_type = ACCOUNT_RESOURCE_TYPE
    evaluations = []
    all_resources_are_compliant = True

    config_rules = config_describe_all_rules(config_client)

    required_aws_managed_rules = {
        "AWSAccelerator-cloudtrail-s3-dataevents-enabled": {},
        "AWSAccelerator-cloudtrail-enabled": {},
        "AWSAccelerator-cloudtrail-security-trail-enabled": {},
    }

    for rule in config_rules:
        name = rule.get("ConfigRuleName")
        if name in required_aws_managed_rules:
            required_aws_managed_rules[name] = rule

    for rule in required_aws_managed_rules.values():
        name = rule.get("ConfigRuleName")
        resource_id = rule.get("ConfigRuleArn", name)

        if rule.get("ConfigRuleState") != "ACTIVE":
            compliance_type = "NON_COMPLIANT"
            annotation = f"Required Config Rule is NOT enabled: '{name}'"
        else:
            compliance_type = "COMPLIANT"
            annotation = f"Required Config Rule is enabled: '{name}'"

        logger.info(f"{compliance_type}: {annotation}")
        evaluations.append(build_evaluation(resource_id, compliance_type, event, resource_type, annotation))
        if compliance_type == "NON_COMPLIANT":
            all_resources_are_compliant = False

    return evaluations, all_resources_are_compliant


def lambda_handler(event, context):
    """Lambda handler to check CloudTrail trails are logging.
    Keyword arguments:
    event -- the event variable given in the lambda handler
    context -- the context variable given in the lambda handler
    """
    global AWS_ACCOUNT_ID
    global EXECUTION_ROLE_NAME
    global AUDIT_ACCOUNT_ID

    rule_parameters = json.loads(event.get("ruleParameters", "{}"))
    invoking_event = json.loads(event["invokingEvent"])
    logger.info("Received Event: %s", json.dumps(event, indent=2))

    # parse parameters
    AWS_ACCOUNT_ID = event["accountId"]
    logger.info("Assessing account %s", AWS_ACCOUNT_ID)

    if not is_scheduled_notification(invoking_event["messageType"]):
        logger.error("Skipping assessments as this is not a scheduled invocation")
        return

    valid_rule_parameters = evaluate_parameters(rule_parameters)
    EXECUTION_ROLE_NAME = valid_rule_parameters.get("ExecutionRoleName", "AWSA-GCLambdaExecutionRole")
    AUDIT_ACCOUNT_ID = valid_rule_parameters.get("AuditAccountID", "")

    aws_config_client = get_client("config", event)
    evaluations, all_aws_managed_rules_are_compliant = assess_aws_managed_rules(aws_config_client, event)

    if not all_aws_managed_rules_are_compliant:
        compliance_type = "NON_COMPLIANT"
        annotation = "Non-compliant resources found in scope."
    else:
        compliance_type = "COMPLIANT"
        annotation = "All resources found are compliant and AWS Config is enabled."

    logger.info(f"{compliance_type}: {annotation}")
    evaluations.append(build_evaluation(AWS_ACCOUNT_ID, compliance_type, event, ACCOUNT_RESOURCE_TYPE, annotation))
    submit_evaluations(aws_config_client, event["resultToken"], evaluations)