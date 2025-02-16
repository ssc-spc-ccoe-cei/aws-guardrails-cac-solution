""" GC03 - Check IAM/ CloudWatch Alarms
    https://canada-ca.github.io/cloud-guardrails/EN/03_Cloud-Console-Access.html
"""

import json
import logging

from utils import is_scheduled_notification, check_required_parameters, check_guardrail_requirement_by_cloud_usage_profile, get_cloud_profile_from_tags, GuardrailType, GuardrailRequirementType
from boto_util.organizations import get_account_tags, get_organizations_mgmt_account_id
from boto_util.client import get_client
from boto_util.config import build_evaluation, submit_evaluations

import botocore.exceptions

# Logging setup
logger = logging.getLogger()
logger.setLevel(logging.INFO)


def check_cloudwatch_alarms(
    cloudwatch_client,
    alarm_names=[
        "AWS-IAM-Authentication-From-Unapproved-IP",
        "AWS-SSO-Authentication-From-Unapproved-IP",
        "AWS-Console-SignIn-Without-MFA",
        "AWSAccelerator-AWS-IAM-Authentication-From-Unapproved-IP",
        "AWSAccelerator-AWS-SSO-Authentication-From-Unapproved-IP",
        "AWSAccelerator-AWS-Console-SignIn-Without-MFA"        
    ],
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
        response = cloudwatch_client.describe_alarms(
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
                    response = cloudwatch_client.describe_alarms(
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
                    response = cloudwatch_client.describe_alarms(
                        AlarmNames=alarm_names,
                        AlarmTypes=["MetricAlarm"],
                        NextToken=next_token,
                    )
                else:
                    response = cloudwatch_client.describe_alarms(
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

    # checking the alarms we found
    alarms_not_found_set = set(alarms_not_found)
    for alarm in alarms_found:
        if not alarms_not_found_set:
            # All alarms have been found, exit the loop
            break
        alarm_name = alarm.get("AlarmName")
        if alarm_name:
            for not_found_alarm in alarms_not_found_set:
                if not_found_alarm in alarm_name:
                    logger.info("CloudWatch Alarm %s found.", alarm_name)
                    alarms_not_found_set.remove(not_found_alarm)

                    # Stop the inner loop as we found a match
                    break

    # prepare the annotation (if needed)
    if len(alarms_not_found_set) > 0:
        annotation = "Alarms not found: "
        for alarm in alarms_not_found_set:
            annotation += f"{alarm}; "
        result["annotation"] = annotation
    else:
        result = {"status": "COMPLIANT", "annotation": "All alarms found"}

    logger.info(result)
    return result


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

    rule_parameters = check_required_parameters(
        json.loads(event.get("ruleParameters", "{}")), ["ExecutionRoleName", "AlarmList"]
    )
    execution_role_name = rule_parameters.get("ExecutionRoleName")
    audit_account_id = rule_parameters.get("AuditAccountID", "")
    aws_account_id = event["accountId"]
    is_not_audit_account = aws_account_id != audit_account_id

    evaluations = []

    try:
        client = get_client("organizations")
        response = client.describe_account(AccountId=aws_account_id)
        account_status = response["Account"]["Status"]

        logger.info(f"account_status is {account_status}")

        if account_status != "ACTIVE":
            return

        aws_organizations_client = get_client("organizations", aws_account_id, execution_role_name)
            
        if aws_account_id != get_organizations_mgmt_account_id(aws_organizations_client):
            logger.info(
                "CloudWatch Alarms not checked in account %s as this is not the Management Account",
                aws_account_id,
            )
            return
        

        aws_config_client = get_client("config", aws_account_id, execution_role_name)
        aws_cloudwatch_client = get_client("cloudwatch", aws_account_id, execution_role_name)

        # Check cloud profile
        tags = get_account_tags(get_client("organizations", assume_role=False), aws_account_id)
        cloud_profile = get_cloud_profile_from_tags(tags)
        gr_requirement_type = check_guardrail_requirement_by_cloud_usage_profile(GuardrailType.Guardrail3, cloud_profile)
        
        # If the guardrail is recommended
        if gr_requirement_type == GuardrailRequirementType.Recommended:
            return submit_evaluations(aws_config_client, event, [build_evaluation(
                aws_account_id,
                "COMPLIANT",
                event,
                gr_requirement_type=gr_requirement_type
            )])
        # If the guardrail is not required
        elif gr_requirement_type == GuardrailRequirementType.Not_Required:
            return submit_evaluations(aws_config_client, event, [build_evaluation(
                aws_account_id,
                "NOT_APPLICABLE",
                event,
                gr_requirement_type=gr_requirement_type
            )])
            
        results = check_cloudwatch_alarms(
            aws_cloudwatch_client, alarm_names=str(rule_parameters["AlarmList"]).split(",")
        )
        if results:
            compliance_type = results.get("status")
            annotation = results.get("annotation")
        else:
            compliance_type = "NON_COMPLIANT"
            annotation = "Unable to assess CloudWatch Alarms"

        logger.info(f"{compliance_type}: {annotation}")
        evaluations.append(build_evaluation(aws_account_id, compliance_type, event, annotation=annotation))
        submit_evaluations(aws_config_client, event, evaluations)

    except:
        logger.info("This account Id is not active. Compliance evaluation not available for suspended accounts")
