""" GC13 - Emergency Account Testing Lambda Function
    Verifies that testing of emergency accounts took place and that periodic testing is included
"""

import json
import logging
from datetime import datetime, timedelta, timezone

from utils import is_scheduled_notification, check_required_parameters, check_guardrail_requirement_by_cloud_usage_profile, get_cloud_profile_from_tags, GuardrailType, GuardrailRequirementType
from boto_util.client import get_client
from boto_util.config import build_evaluation, submit_evaluations
from boto_util.organizations import get_organizations_mgmt_account_id, get_account_tags
from boto_util.iam import get_iam_user

# Logging setup
logger = logging.getLogger()
logger.setLevel(logging.INFO)


def last_use_of_password_is_within_one_year(password_last_used_date: datetime | None) -> bool:
    if not password_last_used_date:
        return False
    one_year_ago = datetime.now().astimezone() - timedelta(days=365)
    return password_last_used_date > one_year_ago


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
        json.loads(event.get("ruleParameters", "{}")), ["ExecutionRoleName", "BgUser1", "BgUser2"]
    )
    execution_role_name = rule_parameters.get("ExecutionRoleName")
    audit_account_id = rule_parameters.get("AuditAccountID", "")
    aws_account_id = event["accountId"]
    is_not_audit_account = aws_account_id != audit_account_id

    evaluations = []

    aws_config_client = get_client("config", aws_account_id, execution_role_name, is_not_audit_account)
    aws_iam_client = get_client("iam", aws_account_id, execution_role_name, is_not_audit_account)
    aws_organizations_client = get_client("organizations", aws_account_id, execution_role_name, is_not_audit_account)
    
    if aws_account_id != get_organizations_mgmt_account_id(aws_organizations_client):
        # We're not in the Management Account
        logger.info(
            "Emergency Account Verification not checked in account %s as this is not the Management Account",
            aws_account_id,
        )
        return
    
    # Check cloud profile
    tags = get_account_tags(get_client("organizations", assume_role=False), aws_account_id)
    cloud_profile = get_cloud_profile_from_tags(tags)
    gr_requirement_type = check_guardrail_requirement_by_cloud_usage_profile(GuardrailType.Guardrail13, cloud_profile)
    
    # If the guardrail is recommended
    if gr_requirement_type == GuardrailRequirementType.Recommended:
        return submit_evaluations(aws_config_client, event["resultToken"], [build_evaluation(
            aws_account_id,
            "COMPLIANT",
            event,
            gr_requirement_type=gr_requirement_type
        )])
    # If the guardrail is not required
    elif gr_requirement_type == GuardrailRequirementType.Not_Required:
        return submit_evaluations(aws_config_client, event["resultToken"], [build_evaluation(
            aws_account_id,
            "NOT_APPLICABLE",
            event,
            gr_requirement_type=gr_requirement_type
        )])
        
    iam_user_resource_type = "AWS::IAM::User"
    bg_account_names = [rule_parameters["BgUser1"], rule_parameters["BgUser2"]]
    num_compliant = 0
    missing_users = []

    for account_name in bg_account_names:
        iam_account = get_iam_user(aws_iam_client, account_name)
        user_id = iam_account.get("UserId") if iam_account else None
        logger.info("Processing account with name '%s': %s", account_name, iam_account)

        if not iam_account:
            annotation = f"Account with name '{account_name}' was NOT found in IAM."
            missing_users.append(account_name)
        elif not last_use_of_password_is_within_one_year(iam_account.get("PasswordLastUsed")):
            annotation = f"Account with name '{account_name}' has NOT used it's password within 1 year."
            evaluations.append(build_evaluation(user_id, "NON_COMPLIANT", event, iam_user_resource_type, annotation))
        else:
            num_compliant = num_compliant + 1
            annotation = f"Account with name '{account_name}' exists and has used it's password within 1 year."
            evaluations.append(build_evaluation(user_id, "COMPLIANT", event, iam_user_resource_type, annotation))
        logger.info(annotation)

    # Report any missing users
    if not missing_users:
        compliance_type = "COMPLIANT"
        annotation = f"No missing break-glass user(s) in IAM"
    else:
        compliance_type = "NON_COMPLIANT"
        annotation = f"Missing break-glass user(s) in IAM with name(s): '{ "', '".join(missing_users) }'"

    logger.info(f"{compliance_type}: {annotation}")
    evaluations.append(build_evaluation(aws_account_id, compliance_type, event, iam_user_resource_type, annotation))

    if len(bg_account_names) == num_compliant:
        compliance_type = "COMPLIANT"
        annotation = "All break-glass accounts exist and have used their password within 1 year."
    else:
        compliance_type = "NON_COMPLIANT"
        annotation = "NOT all break-glass accounts exist and have used their password within 1 year."

    logger.info(f"{compliance_type}: {annotation}")
    evaluations.append(build_evaluation(aws_account_id, compliance_type, event, annotation=annotation))
    submit_evaluations(aws_config_client, event["resultToken"], evaluations)
