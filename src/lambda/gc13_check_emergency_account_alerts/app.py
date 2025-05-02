""" GC13 - Check Emergency Account Alerts Lambda Function
    Checking for the existence of EventBridge alerts as evidence to support the Guardrails
"""

import json
import logging

import botocore.exceptions

from utils import is_scheduled_notification, check_required_parameters, check_guardrail_requirement_by_cloud_usage_profile, get_cloud_profile_from_tags, GuardrailType, GuardrailRequirementType
from boto_util.organizations import get_account_tags, get_organizations_mgmt_account_id
from boto_util.client import get_client
from boto_util.config import build_evaluation, submit_evaluations
from boto_util.s3 import check_s3_object_exists, get_lines_from_s3_file
from boto_util.event_bridge import list_all_event_bridge_rule_targets, list_all_event_bridge_rules
from boto_util.sns import list_all_sns_subscriptions_by_topic


# Logging setup
logger = logging.getLogger()
logger.setLevel(logging.INFO)


def subscription_is_confirmed(sns_client, subscription_arn: str) -> bool:
    try:
        response = sns_client.get_subscription_attributes(SubscriptionArn=subscription_arn)
        attributes = response.get("Attributes")
        logger.info("Subscription attributes: %s", attributes)
        return attributes != None and attributes.get("PendingConfirmation") == "false"
    except botocore.exceptions.ClientError as ex:
        if "NotFound" in ex.response["Error"]["Code"]:
            ex.response["Error"]["Message"] = "Failed to get subscription attributes. Resource not found."
        elif "InvalidParameter" in ex.response["Error"]["Code"]:
            ex.response["Error"]["Message"] = "Failed to get subscription attributes. Invalid parameter."
        elif "AuthorizationError" in ex.response["Error"]["Code"]:
            ex.response["Error"]["Message"] = "Failed to get subscription attributes. User is unauthorized."
        else:
            ex.response["Error"]["Message"] = "InternalError"
            ex.response["Error"]["Code"] = "InternalError"
        raise ex


def rule_is_configured_to_notify_authorized_personnel(sns_client, event_bridge_client, rule_name: str) -> bool:
    targets = list_all_event_bridge_rule_targets(event_bridge_client, rule_name)

    for target in targets:
        logger.info("Checking rule target: %s", target)
        # is target an SNS input transformer?
        target_arn: str = target.get("Arn", "")
        if target_arn.startswith("arn:aws:sns:"):
            # yes, get a list of topic subscriptions
            subscriptions = list_all_sns_subscriptions_by_topic(sns_client, target_arn)
            # then search topic for a subscription with "email" protocol and is confirmed
            for subscription in subscriptions:
                logger.info("Checking target subscriptions: %s", subscription)
                if subscription.get("Protocol") == "email" and subscription_is_confirmed(
                    sns_client, subscription.get("SubscriptionArn")
                ):
                    return True

    return False


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
        json.loads(event.get("ruleParameters", "{}")), ["ExecutionRoleName", "s3ObjectPath"]
    )
    execution_role_name = rule_parameters.get("ExecutionRoleName")
    audit_account_id = rule_parameters.get("AuditAccountID", "")
    aws_account_id = event["accountId"]
    is_not_audit_account = aws_account_id != audit_account_id
    aws_config_client = get_client("config", aws_account_id, execution_role_name)
    aws_organizations_client = get_client("organizations", aws_account_id, execution_role_name, is_not_audit_account)
    if aws_account_id != get_organizations_mgmt_account_id(aws_organizations_client):
        logger.info("Not checked in account %s as this is not the Management Account", aws_account_id)
        return submit_evaluations(aws_config_client, event, [build_evaluation(
            aws_account_id,
            "NOT_APPLICABLE",
            event
        )])

    evaluations = []

    
    aws_s3_client = get_client("s3")
    aws_event_bridge_client = get_client("events", aws_account_id, execution_role_name)
    aws_sns_client = get_client("sns", aws_account_id, execution_role_name)
    
    # Check cloud profile
    tags = get_account_tags(get_client("organizations", assume_role=False), aws_account_id)
    cloud_profile = get_cloud_profile_from_tags(tags)
    gr_requirement_type = check_guardrail_requirement_by_cloud_usage_profile(GuardrailType.Guardrail13, cloud_profile)
    
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
        
    rule_resource_type = "AWS::Events::Rule"
    file_param_name = "s3ObjectPath"
    rule_names_file_path = rule_parameters.get(file_param_name, "")

    if not check_s3_object_exists(aws_s3_client, rule_names_file_path):
        annotation = f"No file found for s3 path '{rule_names_file_path}' via '{file_param_name}' input parameter."
        logger.info(annotation)
        evaluations.append(build_evaluation(event["accountId"], "NON_COMPLIANT", event, annotation=annotation))

    else:
        rule_names = get_lines_from_s3_file(aws_s3_client, rule_names_file_path)
        logger.info("rule_names from the file in s3: %s", rule_names)

        if not rule_names:
            logger.info("No rule names found in input file.")
            evaluations.append(
                build_evaluation(
                    event["accountId"],
                    "NON_COMPLIANT",
                    event,
                    annotation=f"No rule names provided. The input file for {file_param_name} is empty.",
                )
            )

        else:
            event_bridge_rules = list_all_event_bridge_rules(aws_event_bridge_client)
            num_compliant_rules = 0
            missing_rules = []

            for rule_name in rule_names:
                rule = next((r for r in event_bridge_rules if r.get("Name", "") == rule_name), None)
                logger.info("Processing EventBridge rule with name '%s': %s", rule_name, rule)

                if not rule:
                    annotation = f"Rule with name '{rule_name}' was not found in the EventBridge rule set."
                    missing_rules.append(rule_name)
                elif rule.get("State") == "DISABLED":
                    annotation = f"Rule with name '{rule_name}' is 'DISABLED' in the EventBridge rule set."
                    evaluations.append(
                        build_evaluation(rule.get("Name"), "NON_COMPLIANT", event, rule_resource_type, annotation)
                    )
                elif not rule_is_configured_to_notify_authorized_personnel(
                    aws_sns_client, aws_event_bridge_client, rule_name
                ):
                    annotation = f"Rule with name '{rule_name}' is NOT configured to send notifications."
                    evaluations.append(
                        build_evaluation(rule.get("Name"), "NON_COMPLIANT", event, rule_resource_type, annotation)
                    )
                else:
                    num_compliant_rules = num_compliant_rules + 1
                    annotation = f"Rule with name '{rule_name}' is enabled and configured to send notifications."
                    evaluations.append(
                        build_evaluation(rule.get("Name"), "COMPLIANT", event, rule_resource_type, annotation)
                    )
                logger.info(annotation)

            # Report any missing rules
            if not missing_rules:
                annotation = f"No missing rule(s) in the EventBridge rule"
                evaluations.append(
                    build_evaluation(event["accountId"], "COMPLIANT", event, rule_resource_type, annotation)
                )
            else:
                annotation = f"Missing rule(s) in the EventBridge rule set with name: '{ "', '".join(missing_rules) }'"
                evaluations.append(
                    build_evaluation(event["accountId"], "NON_COMPLIANT", event, rule_resource_type, annotation)
                )
            logger.info(annotation)

            if len(rule_names) == num_compliant_rules:
                annotation = "All required rules are enabled and configured with an SNS topic and subscription to send notification"
                evaluations.append(build_evaluation(event["accountId"], "COMPLIANT", event, annotation=annotation))
            else:
                annotation = "NOT all required rules are enabled and configured with an SNS topic and subscription to send notification"
                evaluations.append(build_evaluation(event["accountId"], "NON_COMPLIANT", event, annotation=annotation))
            logger.info(annotation)

    submit_evaluations(aws_config_client, event, evaluations)
