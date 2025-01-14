""" GC01 - Check Root MFA
    https://canada-ca.github.io/cloud-guardrails/EN/01_Protect-Root-Account.html
"""

import json
import logging
import time

import botocore.exceptions

from utils import is_scheduled_notification, check_required_parameters, check_guardrail_requirement_by_cloud_usage_profile, get_cloud_profile_from_tags, GuardrailType, GuardrailRequirementType
from boto_util.organizations import get_account_tags, get_organizations_mgmt_account_id
from boto_util.client import get_client
from boto_util.config import build_evaluation, submit_evaluations

# Logging setup
logger = logging.getLogger()
logger.setLevel(logging.INFO)


def get_root_mfa_enabled(iam_client):
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
            response = iam_client.get_credential_report()
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
                    response = iam_client.generate_credential_report()
                    logger.info("Generating credential report...sleeping for 5 seconds")
                    time.sleep(5)
                except botocore.exceptions.ClientError as err:
                    if "LimitExceeded" in err.response["Error"]["Code"]:
                        # exceeding an internal AWS limit
                        logger.info("LimitExceededException...sleeping for 2 seconds")
                        time.sleep(2)
                    else:
                        # something else
                        logger.error(
                            "Error while trying to generate_credential_report - boto3 Client error - %s", error
                        )
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

    rule_parameters = check_required_parameters(json.loads(event.get("ruleParameters", "{}")), ["ExecutionRoleName"])
    execution_role_name = rule_parameters.get("ExecutionRoleName")
    audit_account_id = rule_parameters.get("AuditAccountID", "")
    aws_account_id = event["accountId"]
    is_not_audit_account = aws_account_id != audit_account_id
    evaluations = []

    aws_organizations_client = get_client("organizations", aws_account_id, execution_role_name)
    
    # Check cloud profile
    tags = get_account_tags(aws_organizations_client, aws_account_id)
    cloud_profile = get_cloud_profile_from_tags(tags)
    gr_requirement_type = check_guardrail_requirement_by_cloud_usage_profile(GuardrailType.Guardrail1, cloud_profile)
    
    # If the guardrail is recommended
    if gr_requirement_type == GuardrailRequirementType.Recommended:
        return submit_evaluations(aws_config_client, [build_evaluation(
            aws_account_id,
            "COMPLIANT",
            event,
            gr_requirement_type=gr_requirement_type
        )])
    # If the guardrail is not required
    elif gr_requirement_type == GuardrailRequirementType.Not_Required:
        return submit_evaluations(aws_config_client, [build_evaluation(
            aws_account_id,
            "NOT_APPLICABLE",
            event,
            gr_requirement_type=gr_requirement_type
        )])
        
    if aws_account_id != get_organizations_mgmt_account_id(aws_organizations_client):
        logger.info("Root Account MFA not checked in account %s as this is not the Management Account", aws_account_id)
        return

    aws_config_client = get_client("config", aws_account_id, execution_role_name)
    aws_iam_client = get_client("iam", aws_account_id, execution_role_name)

    if get_root_mfa_enabled(aws_iam_client):
        compliance_type = "COMPLIANT"
        annotation = "Root Account MFA enabled"
    else:
        compliance_type = "NON_COMPLIANT"
        annotation = "Root Account MFA NOT enabled."

    logger.info(f"{compliance_type}: {annotation}")
        
    evaluations.append(build_evaluation(aws_account_id, compliance_type, event, annotation=annotation))
    submit_evaluations(aws_config_client, event["resultToken"], evaluations)
