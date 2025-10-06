""" GC01 - Check IAM Users MFA
    https://canada-ca.github.io/cloud-guardrails/EN/02_Management-Admin-Privileges.html
"""

import json
import logging

import botocore.exceptions

from utils import is_scheduled_notification, check_required_parameters, check_guardrail_requirement_by_cloud_usage_profile, get_cloud_profile_from_tags, GuardrailType, GuardrailRequirementType
from boto_util.organizations import get_account_tags
from boto_util.client import get_client
from boto_util.config import build_evaluation, submit_evaluations
from boto_util.iam import list_all_iam_users

# Logging setup
logger = logging.getLogger()
logger.setLevel(logging.INFO)


def check_iam_users_mfa(iam_client, aws_account_id, event, bg_accounts):
    iam_users = [x for x in list_all_iam_users(iam_client) if x.get("UserName") not in bg_accounts]

    if not iam_users:
        return [build_evaluation(aws_account_id, "NOT_APPLICABLE", event, annotation="No IAM Users found")]

    resource_type = "AWS::IAM::User"
    evaluations = []

    for user in iam_users:
        user_name = user.get("UserName", "")
        # let's check if the user has a login profile
        # (users without one do not have a password for console access)
        try:
            response = iam_client.get_login_profile(UserName=user_name)
        except botocore.exceptions.ClientError as ex:
            if "NoSuchEntity" in ex.response["Error"]["Code"]:
                # user does not have a password for console access
                annotation = "IAM User does not have console access."
                evaluations.append(build_evaluation(user_name, "NOT_APPLICABLE", event, resource_type, annotation))
                logger.info("User '%s' does not have console access.", user_name)
                continue
            else:
                logger.error("Error while trying to get_login_profile for user '%s'.", user_name)
                logger.error(ex)
                raise ex
        # if we're here, the user has a console password
        try:
            response = iam_client.list_mfa_devices(UserName=user_name)
            if response:
                # let's check if the user has at least 1 MFA device
                logger.info("User '%s' has %d MFA device(s).", user_name, len(response.get("MFADevices", [])))
                if len(response.get("MFADevices", [])) > 0:
                    # yes, at least 1 device found
                    annotation = "MFA Device(s) found"
                    evaluations.append(build_evaluation(user_name, "COMPLIANT", event, resource_type, annotation))
                else:
                    # no, user is not compliant
                    annotation = "No MFA Device found"
                    evaluations.append(build_evaluation(user_name, "NON_COMPLIANT", event, resource_type, annotation))
            else:
                logger.error("Empty response on the list_mfa_devices call for user '%s'", user_name)
        except botocore.exceptions.ClientError as ex:
            logger.error("Error while trying to list_mfa_devices.")
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

    rule_parameters = check_required_parameters(json.loads(event.get("ruleParameters", "{}")), ["ExecutionRoleName"])
    execution_role_name = rule_parameters.get("ExecutionRoleName")
    audit_account_id = rule_parameters.get("AuditAccountID", "")
    aws_account_id = event["accountId"]
    is_not_audit_account = aws_account_id != audit_account_id
    evaluations = []

    bg_accounts = [rule_parameters["BgUser1"], rule_parameters["BgUser2"]]

    aws_config_client = get_client("config", aws_account_id, execution_role_name, is_not_audit_account)
    aws_iam_client = get_client("iam", aws_account_id, execution_role_name, is_not_audit_account)
        
    # Check cloud profile
    tags = get_account_tags(get_client("organizations", assume_role=False), aws_account_id)
    cloud_profile = get_cloud_profile_from_tags(tags)
    gr_requirement_type = check_guardrail_requirement_by_cloud_usage_profile(GuardrailType.Guardrail1, cloud_profile)
    
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
        
    evaluations = check_iam_users_mfa(aws_iam_client, aws_account_id, event, bg_accounts)

    logger.info("AWS Config updating evaluations: %s", evaluations)
    submit_evaluations(aws_config_client, event, evaluations)
