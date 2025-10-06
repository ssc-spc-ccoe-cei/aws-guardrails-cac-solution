""" GC07 - Check Certificate Authorities
"""

import json
import logging

from utils import is_scheduled_notification, check_required_parameters, check_guardrail_requirement_by_cloud_usage_profile, get_cloud_profile_from_tags, GuardrailType, GuardrailRequirementType
from boto_util.organizations import get_account_tags
from boto_util.client import get_client
from boto_util.config import build_evaluation, submit_evaluations
from boto_util.s3 import check_s3_object_exists, get_lines_from_s3_file
from boto_util.acm import list_all_acm_certificates, describe_acm_certificate


# Logging setup
logger = logging.getLogger()
logger.setLevel(logging.INFO)


def assess_certificate_manager_enforcement(
    certificate_descriptions: list[dict], cas_currently_in_use: list[str], event: dict
) -> tuple[list, bool]:
    resource_type = "AWS::ACM::Certificate"
    evaluations = []
    all_resources_are_compliant = True

    for cert_description in certificate_descriptions:
        cert_arn: str = cert_description.get("CertificateArn", "")
        cert_issuer: str = cert_description.get("Issuer", "")

        if cert_issuer in cas_currently_in_use:
            annotation = "The certificate is issued by a current CA and the attestation file exists."
            compliance_type = "COMPLIANT"
        else:
            annotation = f"The certificate is NOT issued by a current CA ({cert_issuer})."
            compliance_type = "NON_COMPLIANT"

        logger.info(f"{annotation} Certificate ARN: '{cert_arn}'")
        evaluations.append(build_evaluation(cert_arn, compliance_type, event, resource_type, annotation))
        if compliance_type == "NON_COMPLIANT":
            all_resources_are_compliant = False

    return evaluations, all_resources_are_compliant


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

    file_param_name = "S3CasCurrentlyInUsePath"
    rule_parameters = check_required_parameters(
        json.loads(event.get("ruleParameters", "{}")), ["ExecutionRoleName", file_param_name]
    )
    execution_role_name = rule_parameters.get("ExecutionRoleName")
    audit_account_id = rule_parameters.get("AuditAccountID", "")
    aws_account_id = event["accountId"]
    is_not_audit_account = aws_account_id != audit_account_id

    page_size = 100
    interval_between_api_calls = 0.1

    aws_config_client = get_client("config", aws_account_id, execution_role_name, is_not_audit_account)
    # Get the S3 client for the current (Audit) account where this lambda runs from
    aws_s3_client = get_client("s3")
    aws_acm_client = get_client("acm", aws_account_id, execution_role_name, is_not_audit_account)
    
    # Check cloud profile
    tags = get_account_tags(get_client("organizations", assume_role=False), aws_account_id)
    cloud_profile = get_cloud_profile_from_tags(tags)
    gr_requirement_type = check_guardrail_requirement_by_cloud_usage_profile(GuardrailType.Guardrail7, cloud_profile)
    
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
        
    cas_currently_in_use_file_path = rule_parameters.get(file_param_name, "")

    if not check_s3_object_exists(aws_s3_client, cas_currently_in_use_file_path):
        annotation = (
            f"No file found for s3 path '{cas_currently_in_use_file_path}' via '{file_param_name}' input parameter."
        )
        logger.info(annotation)
        evaluations = [build_evaluation(aws_account_id, "NON_COMPLIANT", event, annotation=annotation)]
        submit_evaluations(aws_config_client, event, evaluations, interval_between_api_calls)
        return

    cas_currently_in_use = get_lines_from_s3_file(aws_s3_client, cas_currently_in_use_file_path)
    logger.info("cas_currently_in_use from the file in s3: %s", cas_currently_in_use)

    certificates_summaries = list_all_acm_certificates(aws_acm_client, page_size, interval_between_api_calls)
    certificates_descriptions = [
        describe_acm_certificate(aws_acm_client, x.get("CertificateArn", "")) for x in certificates_summaries
    ]

    evaluations, all_acm_resources_are_compliant = assess_certificate_manager_enforcement(
        certificates_descriptions, cas_currently_in_use, event
    )

    if all_acm_resources_are_compliant:
        compliance_type = "COMPLIANT"
        annotation = "All resources found are compliant."
    else:
        compliance_type = "NON_COMPLIANT"
        annotation = "Non-compliant resources found in scope."

    logger.info(f"{compliance_type}: {annotation}")
    evaluations.append(build_evaluation(aws_account_id, compliance_type, event, annotation=annotation))
    submit_evaluations(aws_config_client, event, evaluations, interval_between_api_calls)
