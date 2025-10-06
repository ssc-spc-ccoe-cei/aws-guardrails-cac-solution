""" GC02 - Check Access Management Attestation
"""

import json
import logging

from utils import (
    is_scheduled_notification,
    check_required_parameters,
    check_guardrail_requirement_by_cloud_usage_profile,
    get_cloud_profile_from_tags,
    GuardrailType,
    GuardrailRequirementType,
)
from boto_util.organizations import get_account_tags
from boto_util.client import get_client
from boto_util.config import build_evaluation, submit_evaluations
from boto_util.s3 import check_s3_object_exists

# Logging setup
logger = logging.getLogger()
logger.setLevel(logging.INFO)


def lambda_handler(event, context):
    """
    Main entry point for Lambda.

    event -- the event variable given in the lambda handler
    context -- the context variable given in the lambda handler
    """
    logger.info("Received Event: %s", json.dumps(event, indent=2))

    invoking_event = json.loads(event["invokingEvent"])
    if not is_scheduled_notification(invoking_event["messageType"]):
        logger.error("Skipping assessments as this is not a scheduled invocation")
        return

    # Require both S3 paths for the attestation and the privileged roles review documents
    rule_parameters = check_required_parameters(
        json.loads(event.get("ruleParameters", "{}")),
        ["ExecutionRoleName", "s3AccessManagementAttestationPath", "s3RoleAssignmentReviewPath"]
    )
    execution_role_name = rule_parameters.get("ExecutionRoleName")
    audit_account_id = rule_parameters.get("AuditAccountID", "")
    aws_account_id = event["accountId"]
    is_not_audit_account = aws_account_id != audit_account_id

    evaluations = []

    if is_not_audit_account:
        logger.info(
            "Access Management Attestation documents not checked in account %s - not the Audit account",
            aws_account_id
        )
        return

    aws_config_client = get_client("config")
    aws_s3_client = get_client("s3")

    # Check cloud profile and guardrail requirement
    tags = get_account_tags(get_client("organizations", assume_role=False), aws_account_id)
    cloud_profile = get_cloud_profile_from_tags(tags)
    gr_requirement_type = check_guardrail_requirement_by_cloud_usage_profile(GuardrailType.Guardrail2, cloud_profile)

    if gr_requirement_type == GuardrailRequirementType.Recommended:
        return submit_evaluations(
            aws_config_client,
            event,
            [build_evaluation(aws_account_id, "COMPLIANT", event, gr_requirement_type=gr_requirement_type)]
        )
    elif gr_requirement_type == GuardrailRequirementType.Not_Required:
        return submit_evaluations(
            aws_config_client,
            event,
            [build_evaluation(aws_account_id, "NOT_APPLICABLE", event, gr_requirement_type=gr_requirement_type)]
        )

    # Retrieve the S3 paths from rule parameters
    attestation_path = rule_parameters["s3AccessManagementAttestationPath"]
    privileged_roles_path = rule_parameters["s3RoleAssignmentReviewPath"]

    # Check that both S3 objects exist
    attestation_exists = check_s3_object_exists(aws_s3_client, attestation_path)
    privileged_roles_exists = check_s3_object_exists(aws_s3_client, privileged_roles_path)

    if attestation_exists and privileged_roles_exists:
        compliance_type = "COMPLIANT"
        annotation = "Both access management attestation and privileged roles review documents found."
    else:
        compliance_type = "NON_COMPLIANT"
        missing_docs = []
        if not attestation_exists:
            missing_docs.append("access management attestation document")
        if not privileged_roles_exists:
            missing_docs.append("privileged roles review document")
        annotation = "Missing " + " and ".join(missing_docs) + "."

    logger.info(f"{compliance_type}: {annotation}")
    evaluations.append(build_evaluation(aws_account_id, compliance_type, event, annotation=annotation))
    submit_evaluations(aws_config_client, event, evaluations)
