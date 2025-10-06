""" GC02 - Check IAM Password Policy
    https://canada-ca.github.io/cloud-guardrails/EN/02_Management-Admin-Privileges.html
"""

import json
import logging

import botocore

from utils import is_scheduled_notification, check_required_parameters, check_guardrail_requirement_by_cloud_usage_profile, get_cloud_profile_from_tags, GuardrailType, GuardrailRequirementType
from boto_util.organizations import get_account_tags
from boto_util.client import get_client
from boto_util.config import build_evaluation, submit_evaluations
from boto_util.iam import account_has_federated_users

logger = logging.getLogger()
logger.setLevel(logging.INFO)


def overlay_policy_from_parameters(rule_parameters, password_assessment_policy):
    for parameter in rule_parameters:
        if parameter in [
            "MinimumPasswordLength",
            "MaxPasswordAge",
            "PasswordReusePrevention",
        ]:
            password_assessment_policy[parameter] = int(rule_parameters[parameter])
        elif parameter in [
            "RequireSymbols",
            "RequireNumbers",
            "RequireUppercaseCharacters",
            "RequireLowercaseCharacters",
            "AllowUsersToChangePassword"
           # "ExpirePasswords",
           # "HardExpiry",
        ]:
            if str(rule_parameters[parameter]).lower() == "true":
                password_assessment_policy[parameter] = True
            elif str(rule_parameters[parameter]).lower() == "false":
                password_assessment_policy[parameter] = False
    return password_assessment_policy


def assess_iam_password_policy(iam_client, password_assessment_policy):
    """Obtains the IAM Password Policy in the account and assesses it against the parameters"""
    compliance_status = "COMPLIANT"
    compliance_annotation = (
        "Dependent on the compliance of Federated IdP" if account_has_federated_users(iam_client) else ""
    )
    try:
        # get the current policy
        response = iam_client.get_account_password_policy()
        if response:
            current_password_policy = response.get("PasswordPolicy", {})
            if current_password_policy:
                # we have a policy, let's check
                if int(password_assessment_policy.get("MinimumPasswordLength", -1)) > 0:
                    if current_password_policy.get("MinimumPasswordLength", -1) < password_assessment_policy.get(
                        "MinimumPasswordLength"
                    ):
                        compliance_status = "NON_COMPLIANT"
                        compliance_annotation += "MinimumPasswordLength;"
                if int(password_assessment_policy.get("PasswordReusePrevention", -1)) > 0:
                    if current_password_policy.get("PasswordReusePrevention", -1) < password_assessment_policy.get(
                        "PasswordReusePrevention"
                    ):
                        compliance_status = "NON_COMPLIANT"
                        compliance_annotation += "PasswordReusePrevention;"
                # The Policy items below are ONLY assessed IF they are required (True)
                if password_assessment_policy.get("RequireSymbols", False):
                    if current_password_policy.get("RequireSymbols", False) != password_assessment_policy.get(
                        "RequireSymbols"
                    ):
                        compliance_status = "NON_COMPLIANT"
                        compliance_annotation += "RequireSymbols;"
                if password_assessment_policy.get("RequireNumbers", False):
                    if current_password_policy.get("RequireNumbers", False) != password_assessment_policy.get(
                        "RequireNumbers"
                    ):
                        compliance_status = "NON_COMPLIANT"
                        compliance_annotation += "RequireNumbers;"
                if password_assessment_policy.get("RequireUppercaseCharacters", False):
                    if current_password_policy.get(
                        "RequireUppercaseCharacters", False
                    ) != password_assessment_policy.get("RequireUppercaseCharacters"):
                        compliance_status = "NON_COMPLIANT"
                        compliance_annotation += "RequireUppercaseCharacters;"
                if password_assessment_policy.get("RequireLowercaseCharacters", False):
                    if current_password_policy.get(
                        "RequireLowercaseCharacters", False
                    ) != password_assessment_policy.get("RequireLowercaseCharacters"):
                        compliance_status = "NON_COMPLIANT"
                        compliance_annotation += "RequireLowercaseCharacters;"
                if password_assessment_policy.get("AllowUsersToChangePassword", False):
                    if current_password_policy.get(
                        "AllowUsersToChangePassword", False
                    ) != password_assessment_policy.get("AllowUsersToChangePassword"):
                        compliance_status = "NON_COMPLIANT"
                        compliance_annotation += "AllowUsersToChangePassword;"
                # if password_assessment_policy.get("ExpirePasswords", False):
                #     if current_password_policy.get("ExpirePasswords", False) != password_assessment_policy.get(
                #         "ExpirePasswords"
                #     ):
                #         compliance_status = "NON_COMPLIANT"
                #         compliance_annotation += "ExpirePasswords;"
                # if password_assessment_policy.get("HardExpiry", False):
                #     if current_password_policy.get("HardExpiry", False) != password_assessment_policy.get("HardExpiry"):
                #         compliance_status = "NON_COMPLIANT"
                #         compliance_annotation += "HardExpiry;"
                # if int(password_assessment_policy.get("MaxPasswordAge", -1)) > 0:
                #     if current_password_policy.get("MaxPasswordAge", -1) < password_assessment_policy.get(
                #         "MaxPasswordAge"
                #     ):
                #         compliance_status = "NON_COMPLIANT"
                #         compliance_annotation += "MaxPasswordAge;"
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
    """
    This function is the main entry point for Lambda.

    Keyword arguments:

    event -- the event variable given in the lambda handler

    context -- the context variable given in the lambda handler
    """
    logger.info("Received Event: %s", json.dumps(event, indent=2))

    invoking_event = json.loads(event["invokingEvent"])
    if not is_scheduled_notification(invoking_event["messageType"]):
        return

    default_assessment_policy = {
        "MinimumPasswordLength": 12,
        "RequireSymbols": True,
        "RequireNumbers": True,
        "RequireUppercaseCharacters": True,
        "RequireLowercaseCharacters": True,
        "AllowUsersToChangePassword": True,
        "PasswordReusePrevention": 24
        # "HardExpiry": False,
        # "ExpirePasswords": False,
        # "MaxPasswordAge": 90,
    }

    rule_parameters = check_required_parameters(json.loads(event.get("ruleParameters", "{}")), ["ExecutionRoleName"])
    execution_role_name = rule_parameters.get("ExecutionRoleName")
    audit_account_id = rule_parameters.get("AuditAccountID", "")
    aws_account_id = event["accountId"]
    is_not_audit_account = aws_account_id != audit_account_id

    password_assessment_policy = overlay_policy_from_parameters(rule_parameters, default_assessment_policy)
    evaluations = []

    aws_config_client = get_client("config", aws_account_id, execution_role_name, is_not_audit_account)
    aws_iam_client = get_client("iam", aws_account_id, execution_role_name, is_not_audit_account)
    
    # Check cloud profile
    tags = get_account_tags(get_client("organizations", assume_role=False), aws_account_id)
    cloud_profile = get_cloud_profile_from_tags(tags)
    gr_requirement_type = check_guardrail_requirement_by_cloud_usage_profile(GuardrailType.Guardrail2, cloud_profile)
    
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
        
    assessment_result = assess_iam_password_policy(aws_iam_client, password_assessment_policy)

    logger.info(f"{assessment_result["status"]}: {assessment_result["annotation"]}")
    evaluations = [
        build_evaluation(aws_account_id, assessment_result["status"], event, annotation=assessment_result["annotation"])
    ]
    submit_evaluations(aws_config_client, event, evaluations)
