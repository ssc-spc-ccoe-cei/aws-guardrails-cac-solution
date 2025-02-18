""" GC04 - Check Alerts Flag Misuse
    https://canada-ca.github.io/cloud-guardrails/EN/04_Enterprise-Monitoring-Accounts.html
"""

import json
import logging

from utils import (
    is_scheduled_notification,
    check_required_parameters,
    flatten_dict,
    check_guardrail_requirement_by_cloud_usage_profile,
    get_cloud_profile_from_tags,
    GuardrailType,
    GuardrailRequirementType,
)
from boto_util.organizations import get_account_tags
from boto_util.client import get_client
from boto_util.config import build_evaluation, submit_evaluations
from boto_util.event_bridge import list_all_event_bridge_rules, list_all_event_bridge_rule_targets
from boto_util.sns import list_all_sns_subscriptions_by_topic

import botocore.exceptions

# Logging setup
logger = logging.getLogger()
logger.setLevel(logging.INFO)


def subscription_is_confirmed(sns_client, subscription_arn):
    try:
        response = sns_client.get_subscription_attributes(SubscriptionArn=subscription_arn)
        attributes = response.get("Attributes")
        logger.info("Subscription attributes: %s", attributes)

        if attributes is None:
            return False

        return attributes.get("PendingConfirmation") == "false"
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


def rule_matches_against_cb_role_identity(rule_event_pattern, cb_role_arn):
    logger.info("rule_event_pattern: %s", rule_event_pattern)
    if rule_event_pattern is None:
        return False

    event_pattern_dict = json.loads(rule_event_pattern)
    logger.info("event_pattern_dict: %s", event_pattern_dict)

    ep_detail = flatten_dict(event_pattern_dict.get("detail", {}))
    return cb_role_arn in ep_detail.get(
        "userIdentity.sessionContext.sessionIssuer.arn", []
    ) and "Role" in ep_detail.get("userIdentity.sessionContext.sessionIssuer.type", [])


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


def check_cb_role(cloud_trail_client, cb_role, event, aws_account_id):

    role_change_events = [
        "DeleteRolePolicy",
        "AttachRolePolicy",
        "DeleteRole",
        "DetachRolePolicy",
        "PutRolePolicy",
        "UpdateAssumeRolePolicy",
    ]
    next_token = None
    while True:
        response = cloud_trail_client.lookup_events(
            LookupAttributes=[{"AttributeKey": "ResourceName", "AttributeValue": cb_role}]
        )
        next_token = response.get("NextToken")

        for e in response.get("Events", []):
            event_name = e.get("EventName", "")
            if event_name in role_change_events:
                return build_evaluation(
                    aws_account_id,
                    "NON_COMPLIANT",
                    event,
                    annotation=f'Event "{e.get("EventId")}" was found performing action "{event_name}" on Cloud Broker role.',
                )

        if not next_token:
            break

    return build_evaluation(aws_account_id, "COMPLIANT", event)


def check_rule_sns_target_is_setup(sns_client, event_bridge_client, rule, event):
    resource_type = "AWS::Events::Rule"

    logger.info("Checking rule: %s", rule)
    if rule.get("State") == "DISABLED":
        return build_evaluation(rule.get("Name"), "NON_COMPLIANT", event, resource_type, "Rule is disabled.")

    rule_name = rule.get("Name")
    targets = list_all_event_bridge_rule_targets(event_bridge_client, rule_name)

    for target in targets:
        logger.info("Checking rule target: %s", target)
        target_arn: str = target.get("Arn")
        # is target an SNS input transformer?
        if target_arn.startswith("arn:aws:sns:"):
            # yes, get a list of topic subscriptions
            subscriptions = list_all_sns_subscriptions_by_topic(sns_client, target_arn)
            # then search topic for a subscription with "email" protocol and is confirmed
            for subscription in subscriptions:
                logger.info("Checking target subscriptions: %s", subscription)
                if subscription.get("Protocol") == "email":
                    subscription_arn = subscription.get("SubscriptionArn")
                    if subscription_is_confirmed(sns_client, subscription_arn):
                        return build_evaluation(
                            rule.get("Name"),
                            "COMPLIANT",
                            event,
                            resource_type,
                            annotation="An Event rule that has a SNS topic and subscription to send notification emails is setup and confirmed.",
                        )

    return build_evaluation(
        rule.get("Name"),
        "NON_COMPLIANT",
        event,
        resource_type,
        annotation="An Event rule that has a SNS topic and subscription to send notification emails is not setup or confirmed.",
    )


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
        json.loads(event.get("ruleParameters", "{}")), ["ExecutionRoleName", "IAM_Role_Name"]
    )
    execution_role_name = rule_parameters.get("ExecutionRoleName")
    audit_account_id = rule_parameters.get("AuditAccountID", "")
    aws_account_id = event["accountId"]

    evaluations = []

    aws_config_client = get_client("config", aws_account_id, execution_role_name)
    aws_event_bridge_client = get_client("events", aws_account_id, execution_role_name)
    aws_sns_client = get_client("sns", aws_account_id, execution_role_name)
    aws_cloud_trail_client = get_client("cloudtrail", aws_account_id, execution_role_name)
    aws_iam_client = get_client("iam", aws_account_id, execution_role_name)

    # Check cloud profile
    tags = get_account_tags(get_client("organizations", assume_role=False), aws_account_id)
    cloud_profile = get_cloud_profile_from_tags(tags)
    gr_requirement_type = check_guardrail_requirement_by_cloud_usage_profile(GuardrailType.Guardrail4, cloud_profile)

    # If the guardrail is recommended
    if gr_requirement_type == GuardrailRequirementType.Recommended:
        return submit_evaluations(
            aws_config_client,
            event,
            [
                build_evaluation(
                    aws_account_id,
                    "COMPLIANT",
                    event,
                    gr_requirement_type=gr_requirement_type,
                )
            ],
        )
    # If the guardrail is not required
    elif gr_requirement_type == GuardrailRequirementType.Not_Required:
        return submit_evaluations(
            aws_config_client,
            event,
            [
                build_evaluation(
                    aws_account_id,
                    "NOT_APPLICABLE",
                    event,
                    gr_requirement_type=gr_requirement_type,
                )
            ],
        )

    rules = list_all_event_bridge_rules(aws_event_bridge_client)
    cb_role_pattern = rule_parameters["IAM_Role_Name"]

    # Now we lookup the CloudBroker role by partial match
    cb_role_arn = get_role_arn(aws_iam_client, cb_role_pattern)

    if not cb_role_arn:
        compliance_type = "NON_COMPLIANT"
        annotation = f"Cloud Broker Role containing '{cb_role_pattern}' in the name was not found."
        evaluation = build_evaluation(aws_account_id, compliance_type, event, annotation=annotation)
        logger.info(f"{compliance_type}: {annotation}")
        submit_evaluations(aws_config_client, event, [evaluation])
        return

    cb_rules = [
        rule
        for rule in rules
        if rule_matches_against_cb_role_identity(rule.get("EventPattern"), cb_role_arn)
    ]

    if len(cb_rules) == 0:
        evaluations.append(
            build_evaluation(
                aws_account_id,
                "NON_COMPLIANT",
                event,
                annotation="No event bridge rule found that alerts authorized personnel of misuse, suspicious sign-in attempts, or when changes are made to the cloud broker account.",
            )
        )
    else:
        rules_are_compliant = False
        for rule in cb_rules:
            logger.info(f"Checking rule: {rule}")
            rule_evaluation = check_rule_sns_target_is_setup(aws_sns_client, aws_event_bridge_client, rule, event)
            if rule_evaluation.get("ComplianceType", "COMPLIANT") == "COMPLIANT":
                rules_are_compliant = True
            evaluations.append(rule_evaluation)

        if rules_are_compliant:
            extracted_role_name = cb_role_arn.split("/")[-1] if "/" in cb_role_arn else cb_role_arn
            evaluations.append(check_cb_role(aws_cloud_trail_client, extracted_role_name, event, aws_account_id))
        else:
            evaluations.append(
                build_evaluation(
                    aws_account_id,
                    "NON_COMPLIANT",
                    event,
                    annotation="One or more event bridge rules are not compliant.",
                )
            )

    submit_evaluations(aws_config_client, event, evaluations)