""" GC01 - Check Root MFA
    https://canada-ca.github.io/cloud-guardrails/EN/01_Protect-Root-Account.html
"""

import json
import logging
import re

import botocore.exceptions

from utils import is_scheduled_notification, check_required_parameters, check_guardrail_requirement_by_cloud_usage_profile, get_cloud_profile_from_tags, GuardrailType, GuardrailRequirementType
from boto_util.organizations import get_account_tags, get_organizations_mgmt_account_id
from boto_util.client import get_client
from boto_util.config import build_evaluation, submit_evaluations
from boto_util.s3 import check_s3_object_exists, read_s3_object
from boto_util.guard_duty import guard_duty_is_enabled
from boto_util.event_bridge import list_all_event_bridge_rules, list_all_event_bridge_rule_targets
from boto_util.sns import list_all_sns_subscriptions_by_topic

# Logging setup
logger = logging.getLogger()
logger.setLevel(logging.INFO)


def subscription_is_confirmed(sns_client, subscription_arn):
    try:
        response = sns_client.get_subscription_attributes(SubscriptionArn=subscription_arn)
        attributes = response.get("Attributes")
        logger.info("Subscription attributes: %s", attributes)

        if attributes == None:
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


def rule_event_pattern_matches_guard_duty_findings(rule_event_pattern: str | None):
    if rule_event_pattern == None:
        return False
    logger.info("rule_event_pattern: %s", rule_event_pattern)

    event_pattern_dict = json.loads(rule_event_pattern)
    logger.info("event_pattern_dict: %s", event_pattern_dict)
    return "aws.guardduty" in event_pattern_dict.get("source", []) and "GuardDuty Finding" in event_pattern_dict.get(
        "detail-type", []
    )


def check_rule_sns_or_log_grp_target_is_setup(sns_client, event_bridge_client, rule, event, log_source_attestation_file_path):
    resource_type = "AWS::Events::Rule"
    

    logger.info("Checking rule: %s", rule)
    if rule.get("State") == "DISABLED":
        return build_evaluation(
            rule.get("Name"),
            "NON_COMPLIANT",
            event,
            resource_type=resource_type,
            annotation="Rule is disabled.",
        )

    rule_name = rule.get("Name")
    targets = list_all_event_bridge_rule_targets(event_bridge_client, rule_name)
    
    for target in targets:
        logger.info("Checking rule target: %s", target)
        # is target an SNS input transformer?
        target_arn: str = target.get("Arn")

        if target_arn.startswith("arn:aws:sns:"):
            # yes, get a list of topic subscriptions
            subscriptions = list_all_sns_subscriptions_by_topic(sns_client, target_arn)
            # then search topic for a subscription with "email" protocol and is confirmed
            for subscription in subscriptions:
                logger.info("Checking target subscriptions: %s", subscription)
                protocol = subscription.get("Protocol")
                if protocol in ["email", "lambda"]:
                    subscription_arn = subscription.get("SubscriptionArn")
                    if subscription_is_confirmed(sns_client, subscription_arn):
                        return build_evaluation(
                            rule.get("Name"),
                            "COMPLIANT",
                            event,
                            resource_type=resource_type,
                            annotation="An Event rule that has a SNS topic and subscription to send notification emails is setup and confirmed.",
                        )
        elif target_arn.startswith("arn:aws:logs:"):
            return build_evaluation(
                            rule.get("Name"),
                            "COMPLIANT",
                            event,
                            resource_type=resource_type,
                            annotation="An Event rule that has a CloudWatch log group is setup and confirmed.",
                        )
        else:
            #  check for attestation file path
            s3_client = get_client("s3")
            log_source_attestation_file_exists_flag = check_s3_object_exists(s3_client, log_source_attestation_file_path)
            if log_source_attestation_file_exists_flag:
                logger.info("### Log source attestation file exists")
                return build_evaluation(
                            rule.get("Name"),
                            "COMPLIANT",
                            event,
                            resource_type=resource_type,
                            annotation="Log Source Attestation File Provided.",
                        )      
    
    
    return build_evaluation(
        rule.get("Name"),
        "NON_COMPLIANT",
        event,
        resource_type=resource_type,
        annotation="An Event rule that has a CloudWatch log group or SNS topic and subscription to send notification emails is not setup or confirmed.",
    )

   # is target an SNS input transformer?
  
def check_alerts_flag_misuse(event, rule_parameters, aws_account_id, evaluations, aws_s3_client, aws_guard_duty_client, aws_event_bridge_client, aws_sns_client, aws_cloudwatch_client, log_source_attestation_file_path):
    rules = list_all_event_bridge_rules(aws_event_bridge_client)

    guard_duty_is_setup = False

    if guard_duty_is_enabled(aws_guard_duty_client):
            # yes, filter for rules that target GuardDuty findings
        logger.info("GuardDuty is enabled.")
        guardduty_rules = [r for r in rules if rule_event_pattern_matches_guard_duty_findings(r.get("EventPattern"))]
        logger.info("GuardDuty rules count: %d", len(guardduty_rules))
            # are there any rules that target GuardDuty findings
        if len(guardduty_rules) > 0:
                # yes, check that an SNS target is setup that sends an email notification to authorized personnel
            for rule in guardduty_rules:
                eval = check_rule_sns_or_log_grp_target_is_setup(aws_sns_client, aws_event_bridge_client, rule, event, log_source_attestation_file_path)
                if eval.get("ComplianceType") == "COMPLIANT":
                    guard_duty_is_setup = True
                evaluations.append(eval)
            logger.info(
                    "GuardDuty is setup and rules are setup to notify authorized personnel: %s", guard_duty_is_setup
                )

        # are the GuardDuty rules found to be COMPLIANT?
    if guard_duty_is_setup:
            # yes, add compliance evaluation for account
        evaluations.append(
                build_evaluation(
                    aws_account_id,
                    "COMPLIANT",
                    event,
                    annotation="GuardDuty is enabled, and a rule is setup to notify authorized personnel of GuardDuty findings.",
                )
            )
    else:
            # no, check for EventBridge rules with naming convention
        rule_naming_convention_file_path = rule_parameters.get("RuleNamingConventionFilePath", "")
        if not check_s3_object_exists(aws_s3_client, rule_naming_convention_file_path):
            evaluations.append(
                    build_evaluation(
                        aws_account_id,
                        "NON_COMPLIANT",
                        event,
                        annotation="No RuleNamingConventionFilePath input provided.",
                    )
                )
        else:
            evaluations = []
            is_compliant = False
            rule_naming_convention = read_s3_object(aws_s3_client, rule_naming_convention_file_path).strip()
            reg = re.compile(rule_naming_convention)
            logger.info("Filtering rules by rule_naming_convention: %s", rule_naming_convention)

           
            

            filtered_rules = [r for r in rules if reg.search(r.get("Name", ""))]

                # are there any rules matching the naming convention?
            if len(filtered_rules) > 0:
                    # yes, check that an SNS target is setup that sends an email notification to authorized personnel or a log group is setup
                for rule in filtered_rules:
                    
                    eval = check_rule_sns_or_log_grp_target_is_setup(aws_sns_client, aws_event_bridge_client, rule, event, log_source_attestation_file_path)
                    if eval.get("ComplianceType") == "COMPLIANT":
                        is_compliant = True
                        evaluations.append(eval)
      
                # are EventBridge rules setup to notify authorized personnel of misuse?
            if is_compliant:
                    # yes, append COMPLIANT results for account
                evaluations.append(
                        build_evaluation(
                            aws_account_id,
                            "COMPLIANT",
                            event,
                            annotation="EventBridge rules have been setup to notify authorized personnel of misuse or suspicious activity.",
                        )
                    )
            else:
                #if Eventbridge rules are not compliant, check for CloudWatch alarms with confirmed email subscriptions
                eval_cw = check_cloudwatch_alarms_naming_convention(aws_sns_client, aws_cloudwatch_client, rule_naming_convention, event, aws_account_id)
                logger.info("### CW EVAL: %s", eval_cw)
                evaluations.clear()
                if eval_cw.get("ComplianceType") == "COMPLIANT":
                    evaluations.append(eval_cw)
                else:
                # no, append to NON_COMPLIANT results for account
                    evaluations.append(
                            build_evaluation(
                                aws_account_id,
                                "NON_COMPLIANT",
                                event,
                                annotation="GuardDuty is not enabled OR there are no EventBridge rules setup or no Cloudwatch alarms with confirmed email subscription are setup to notify authorized personnel of misuse or suspicious activity.",
                            )
                        )
                
    return evaluations


def check_cloudwatch_alarms_naming_convention(aws_sns_client, aws_cloudwatch_client, rule_naming_convention, event, aws_account_id):
    """
    Check if CloudWatch alarms are created based on given naming convention rules
    """
    
    cloudwatch_compliance_flag = False
    try:
        # Compile the regex pattern for alarm naming convention
        reg = re.compile(rule_naming_convention)
        
        # Get all CloudWatch alarms
        response = aws_cloudwatch_client.describe_alarms()
        alarms = response.get('MetricAlarms', [])
        
        # Continue paginating if there are more alarms
        while response.get('NextToken'):
            response = aws_cloudwatch_client.describe_alarms(NextToken=response['NextToken'])
            alarms.extend(response.get('MetricAlarms', []))
        
        # Filter alarms by naming convention
        matching_alarms = [alarm for alarm in alarms if reg.search(alarm.get('AlarmName', ''))]
        
        logger.info("### matching alarms %s ", matching_alarms)

        #Filter alarms that have SNS actions
        alarms_with_sns = []

        if matching_alarms:
            for alarm in matching_alarms:
                alarm_actions = alarm.get('AlarmActions', [])
                sns_actions = [action for action in alarm_actions if action.startswith('arn:aws:sns:')]
                
                if sns_actions:
                    alarms_with_sns.append({
                    'name': alarm.get('AlarmName'),
                    'sns_actions': sns_actions
                    })
            
            #check for email protocol
            for alarm in alarms_with_sns:
                for sns_arn in alarm['sns_actions']:
                    subscriptions = list_all_sns_subscriptions_by_topic(aws_sns_client, sns_arn)
                    email_subscriptions = [sub for sub in subscriptions if sub.get('Protocol') == 'email']
                    
                    confirmed_email_subscriptions = [
                        sub for sub in email_subscriptions 
                        if subscription_is_confirmed(aws_sns_client, sub.get('SubscriptionArn'))
                    ]

                    logger.info("###confirmed_email_subscriptions %s ", confirmed_email_subscriptions)

                    if confirmed_email_subscriptions:
                        cloudwatch_compliance_flag = True
                        break
                        

        
        # Check if any alarms match the naming convention
        if cloudwatch_compliance_flag:
            return build_evaluation(
                aws_account_id,
                "COMPLIANT",
                event,
                annotation=f"CloudWatch alarms are created based on naming convention rules with confirmed email subscriptions. Found {len(matching_alarms)} matching alarms."
            )
        else:
            return build_evaluation(
                aws_account_id,
                "NON_COMPLIANT",
                event,
                annotation="No CloudWatch alarms found matching the required naming convention and confirmed email subscriptions."
            )
    except botocore.exceptions.ClientError as ex:
        logger.error("Error checking CloudWatch alarms: %s", ex)
        return build_evaluation(
            aws_account_id,
            "NON_COMPLIANT",
            event,
            annotation=f"Error checking CloudWatch alarms: {str(ex)}"
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

    rule_parameters = check_required_parameters(json.loads(event.get("ruleParameters", "{}")), ["ExecutionRoleName"])
    execution_role_name = rule_parameters.get("ExecutionRoleName")
    audit_account_id = rule_parameters.get("AuditAccountID", "")
    aws_account_id = event["accountId"]
    is_not_audit_account = aws_account_id != audit_account_id
    aws_config_client = get_client("config", aws_account_id, execution_role_name, is_not_audit_account)
    aws_organizations_client = get_client("organizations", aws_account_id, execution_role_name, is_not_audit_account)

    log_source_attestation_file_path = rule_parameters.get("LogSourceAttestationFilePath", "")
    
    if aws_account_id != get_organizations_mgmt_account_id(aws_organizations_client):
        logger.info("Not checked in account %s as this is not the Management Account", aws_account_id)
        return submit_evaluations(aws_config_client, event, [build_evaluation(
            aws_account_id,
            "NOT_APPLICABLE",
            event
        )])

    evaluations = []

    
    aws_s3_client = get_client("s3")
    aws_guard_duty_client = get_client("guardduty", aws_account_id, execution_role_name, is_not_audit_account)
    aws_event_bridge_client = get_client("events", aws_account_id, execution_role_name, is_not_audit_account)
    aws_sns_client = get_client("sns", aws_account_id, execution_role_name, is_not_audit_account)
    aws_cloudwatch_client = get_client("cloudwatch", aws_account_id, execution_role_name, is_not_audit_account)
    
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
    
    evaluations = check_alerts_flag_misuse(event, rule_parameters, aws_account_id, evaluations, aws_s3_client, aws_guard_duty_client, aws_event_bridge_client, aws_sns_client, aws_cloudwatch_client, log_source_attestation_file_path)

    logger.info("AWS Config updating evaluations: %s", evaluations)
    submit_evaluations(aws_config_client, event, evaluations)

