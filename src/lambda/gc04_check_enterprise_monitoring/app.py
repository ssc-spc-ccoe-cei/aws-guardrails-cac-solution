""" GC04 - Check Enterprise Monitoring
    https://canada-ca.github.io/cloud-guardrails/EN/04_Enterprise-Monitoring-Accounts.html
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

def get_role_arn(iam_client, cb_role_pattern: str) -> str | None:
    """
    aws iam list-roles --query "Roles[?contains(RoleName, 'CloudBrokering')].[RoleName, Arn]"
    """
    try:
        paginator = iam_client.get_paginator("list_roles")
        matched_roles = []

        for page in paginator.paginate():
            for role in page["Roles"]:
                if cb_role_pattern in role["RoleName"]:
                    matched_roles.append(role)

        if not matched_roles:
            return None

        # Return the ARN of the first matched role
        return matched_roles[0]["Arn"]
    except botocore.exceptions.ClientError as ex:
        ex.response["Error"]["Message"] = "Error listing or matching roles."
        ex.response["Error"]["Code"] = "InternalError"
        raise ex



def check_enterprise_monitoring_accounts(aws_iam_client, trusted_principal, role_pattern): 
    b_role_found = False
    b_trust_policy_found = False
    try:
        matched_arn = get_role_arn(aws_iam_client, role_pattern)
        if not matched_arn:
            # No matching role found
            return {"RoleFound": False, "TrustPolicyFound": False}

        # Extract the actual role name from the ARN
        actual_role_name = matched_arn.split('/')[-1]
        b_role_found = True

        # Retrieve the role and its trust policy
        role_response = aws_iam_client.get_role(RoleName=actual_role_name)
        policy_document = role_response["Role"].get("AssumeRolePolicyDocument", {})

        if isinstance(policy_document, str):
            policy_document = json.loads(policy_document)

        for statement in policy_document.get("Statement", []):
            principal = statement.get("Principal", {})
            if principal:
                aws = principal.get("AWS", "")
                if (
                    aws == trusted_principal
                    and statement.get("Effect") == "Allow"
                    and "sts:AssumeRole" in statement.get("Action", [])
                ):
                    b_trust_policy_found = True
                    break

    except Exception as e:
        logger.error("Error checking enterprise monitoring accounts: %s", e)
        return {"RoleFound": False, "TrustPolicyFound": False}

    return {"RoleFound": b_role_found, "TrustPolicyFound": b_trust_policy_found} 



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
        json.loads(event.get("ruleParameters", "{}")),
        ["ExecutionRoleName", "IAM_Role_Name", "IAM_Trusted_Principal"]
    )
    execution_role_name = rule_parameters.get("ExecutionRoleName")
    aws_account_id = event["accountId"]
    evaluations = []
    aws_organizations_client = get_client("organizations", aws_account_id, execution_role_name)
    mgmt_account_id = get_organizations_mgmt_account_id(aws_organizations_client)
    # lets skip if not mngt acc
    if aws_account_id != mgmt_account_id:
        logger.info(
            "Account %s is not the management account (%s). skipping checks.",
            aws_account_id, mgmt_account_id
        )
        return


    aws_config_client = get_client("config", aws_account_id, execution_role_name)
    aws_iam_client = get_client("iam", aws_account_id, execution_role_name)
    
    # Check cloud profile
    tags = get_account_tags(get_client("organizations", assume_role=False), aws_account_id)
    cloud_profile = get_cloud_profile_from_tags(tags)
    gr_requirement_type = check_guardrail_requirement_by_cloud_usage_profile(GuardrailType.Guardrail4, cloud_profile)
    
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
        
    trusted_principal = rule_parameters.get("IAM_Trusted_Principal")
    role_name = rule_parameters.get("IAM_Role_Name")
    results = check_enterprise_monitoring_accounts(aws_iam_client, trusted_principal, role_name)
    if results.get("RoleFound"):
        if results.get("TrustPolicyFound"):
            compliance_type = "COMPLIANT"
            annotation = "IAM Role and trust policy compliant"
        else:
            compliance_type = "NON_COMPLIANT"
            annotation = "IAM Role found; Trust policy NOT compliant"
    else:
        compliance_type = "NON_COMPLIANT"
        annotation = "IAM Role NOT found. Trust policy cannot be assessed."

    logger.info(f"{compliance_type}: {annotation}")
    evaluations.append(build_evaluation(event["accountId"], compliance_type, event, annotation=annotation))
    submit_evaluations(aws_config_client, event, evaluations)
