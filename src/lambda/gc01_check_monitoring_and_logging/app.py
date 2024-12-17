""" GC01 - Check Monitoring And Logging
    https://github.com/canada-ca/cloud-guardrails/blob/master/EN/01_Protect-user-accounts-and-identities.md
"""

import json
import logging

from utils import is_scheduled_notification, check_required_parameters
from boto_util.client import get_client
from boto_util.config import build_evaluation, submit_evaluations
from boto_util.cloud_trail import list_all_cloud_trails

import botocore.exceptions

# Logging setup
logger = logging.getLogger()
logger.setLevel(logging.INFO)


def check_trail_status(cloudtrail_client, trails, event):
    resource_type = "AWS::CloudTrail::Trail"
    evaluations = []

    for t in trails:
        try:
            trail_arn = t.get("TrailARN")
            status = cloudtrail_client.get_trail_status(Name=trail_arn)

            if status.get("IsLogging", False):
                compliance_type = "COMPLIANT"
                annotation = "CloudTrail is logging"
            else:
                compliance_type = "NON_COMPLIANT"
                annotation = "CloudTrail is not logging"

            evaluations.append(build_evaluation(trail_arn, compliance_type, event, resource_type, annotation))
        except botocore.exceptions.ClientError as ex:
            logger.error("Error while trying to fetch cloudtrail status.")
            logger.error(ex)
            raise ex

    return evaluations


def lambda_handler(event, context):
    """
    This function is the main entry point for Lambda.

    Keyword arguments:

    event -- the event variable given in the lambda handler

    context -- the context variable given in the lambda handler
    """
    logger.info("Received Event: %s", json.dumps(event, indent=2))

    invoking_event = json.loads(event["invokingEvent"])
    if not is_scheduled_notification(invoking_event["messageType"]):
        logger.error("Skipping assessments as this is not a scheduled invocation")
        return

    rule_parameters = json.loads(event.get("ruleParameters", "{}"))
    valid_rule_parameters = check_required_parameters(rule_parameters, [])
    execution_role_name = valid_rule_parameters.get("ExecutionRoleName", "AWSA-GCLambdaExecutionRole")
    audit_account_id = valid_rule_parameters.get("AuditAccountID", "")
    aws_account_id = event["accountId"]
    is_not_audit_account = aws_account_id != audit_account_id
    evaluations = []

    aws_config_client = get_client("config", aws_account_id, execution_role_name)
    aws_cloudtrail_client = get_client("cloudtrail", aws_account_id, execution_role_name)

    trails = list_all_cloud_trails(aws_cloudtrail_client)

    if trails:
        evaluations.extend(check_trail_status(aws_cloudtrail_client, trails, event))
    else:
        evaluations.append(
            build_evaluation(aws_account_id, "NON_COMPLIANT", event, annotation="No CloudTrails found in account")
        )

    logger.info("AWS Config updating evaluations: %s", evaluations)
    submit_evaluations(aws_config_client, event["resultToken"], evaluations)
