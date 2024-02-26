""" GC12 - Check Marketplace Configuration
    https://canada-ca.github.io/cloud-guardrails/EN/12_Cloud-Marketplace-Config.html
"""
import logging
import json
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
def get_client(service, event, region="ca-central-1"):
    """Return the service boto client. It should be used instead of directly calling the client.
    Keyword arguments:
    service -- the service name used for calling the boto.client()
    event -- the event variable given in the lambda handler
    """
    if not ASSUME_ROLE_MODE or (AWS_ACCOUNT_ID == AUDIT_ACCOUNT_ID):
        return boto3.client(service, region_name=region)
    execution_role_arn = f"arn:aws:iam::{AWS_ACCOUNT_ID}:role/{EXECUTION_ROLE_NAME}"
    credentials = get_assume_role_credentials(execution_role_arn, region)
    return boto3.client(
        service,
        region_name=region,
        aws_access_key_id=credentials["AccessKeyId"],
        aws_secret_access_key=credentials["SecretAccessKey"],
        aws_session_token=credentials["SessionToken"],
    )


def get_assume_role_credentials(role_arn, region="ca-central-1"):
    """Gets the temporary credentials using the STS service of the AWS account.
    Keyword arguments:
    role_arn -- the ARN of the role to assume
    region -- the region where the AWS account is located
    Returns:
    credentials -- a dictionary of temporary credentials returned by boto3
    """
    sts_client = boto3.client("sts", region_name=region)
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
        logger.error("ERROR assuming role.\n%s", ex.response["Error"])
        raise ex


def is_scheduled_notification(message_type):
    """Check whether the message is a ScheduledNotification or not"""
    return message_type == "ScheduledNotification"


def evaluate_parameters(rule_parameters):
    """Evaluate the rule parameters dictionary.
    Keyword arguments:
    rule_parameters -- the Key/Value dictionary of the Config rule parameters
    """
    return rule_parameters


def check_private_marketplace():
    """Check whether the account is using a private marketplace.
    Returns:
    True if the account is using a private marketplace, False otherwise.
    Raises:
    ValueError if the Marketplace Catalog is not available.
    ValueError if the Marketplace Catalog returns an error.
    """
    try:
        response = AWS_MARKETPLACECATALOG_CLIENT.list_entities(
            Catalog="AWSMarketplace",
            EntityType="Experience",
            FilterList=[
                {
                    "Name": "Scope",
                    "ValueList": [
                        "SharedWithMe",
                    ],
                },
            ],
        )
    except botocore.exceptions.ClientError as err:
        # something has gone wrong
        raise ValueError(f"Error in AWS Marketplace Catalog: {err}") from err
    else:
        # did we get a response?
        if response:
            # yes
            entity_summary_list = response.get("EntitySummaryList")
            for entity in entity_summary_list:
                if entity.get("EntityType") == "Experience":
                    # found a private marketplace
                    return True
        else:
            raise ValueError("No response from AWS Marketplace Catalog")
    # if we got here we have not found a private marketplace
    return False


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


def lambda_handler(event, context):
    """This function is the main entry point for Lambda.
    Keyword arguments:
    event -- the event variable given in the lambda handler
    context -- the context variable given in the lambda handler
    """
    global AWS_CONFIG_CLIENT
    global AWS_MARKETPLACECATALOG_CLIENT
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

    if "ExecutionRoleName" in valid_rule_parameters:
        EXECUTION_ROLE_NAME = valid_rule_parameters["ExecutionRoleName"]
    else:
        EXECUTION_ROLE_NAME = "AWSA-GCLambdaExecutionRole"

    if "AuditAccountID" in valid_rule_parameters:
        AUDIT_ACCOUNT_ID = valid_rule_parameters["AuditAccountID"]
    else:
        AUDIT_ACCOUNT_ID = ""

    compliance_value = "NOT_APPLICABLE"
    custom_annotation = ""

    AWS_CONFIG_CLIENT = get_client("config", event)
    AWS_MARKETPLACECATALOG_CLIENT = get_client(
        "marketplace-catalog",
        event,
        region="us-east-1"
    )

    # is this a scheduled invokation?
    if is_scheduled_notification(invoking_event["messageType"]):
        # yes, proceed with checking the marketplace
        # check if a private marketplace has been shared with us
        if check_private_marketplace():
            compliance_value = "COMPLIANT"
            custom_annotation = "Private Marketplace found"
        else:
            compliance_value = "NON_COMPLIANT"
            custom_annotation = "Private Marketplace NOT found"
        logger.info(custom_annotation)

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
