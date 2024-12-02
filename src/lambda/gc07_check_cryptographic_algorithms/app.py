""" GC07 - Check Cryptographic Algorithms
"""

import json
import logging
import time
import re

import boto3
import botocore

ASSUME_ROLE_MODE = True
ACCOUNT_RESOURCE_TYPE = "AWS::::Account"

# See https://www.cyber.gc.ca/en/guidance/guidance-securely-configuring-network-protocols-itsp40062
#   section 3.1 TLS Cipher suites (Table 2 and Table 3)
ITSP_40_062_ALLOWED_SUITES = {
    "TLSv1.2": [
        "ECDHE-ECDSA-AES256-GCM-SHA384",
        "ECDHE-ECDSA-AES256-CCM",
        "ECDHE-ECDSA-AES128-GCM-SHA256",
        "ECDHE-ECDSA-AES128-CCM",
        "ECDHE-RSA-AES256-GCM-SHA384",
        "ECDHE-RSA-AES128-GCM-SHA256",
        "DHE-RSA-AES256-GCM-SHA384",
        "DHE-DSS-AES256-GCM-SHA384",
        "DHE-RSA-AES256-CCM",
        "DHE-RSA-AES128-GCM-SHA256",
        "DHE-DSS-AES128-GCM-SHA256",
        "DHE-RSA-AES128-CCM",
        "ECDHE-ECDSA-AES256-CCM-8",
        "ECDHE-ECDSA-AES128-CCM-8",
        "ECDHE-ECDSA-AES256-CBC-SHA384",
        "ECDHE-ECDSA-AES128-CBC-SHA256",
        "ECDHE-RSA-AES256-CBC-SHA384",
        "ECDHE-RSA-AES128-CBC-SHA256",
        "DHE-RSA-AES256-CBC-SHA256",
        "DHE-RSA-AES128-CBC-SHA256",
    ],
    "TLSv1.3": [
        "AES256-GCM-SHA384",
        "AES128-GCM-SHA256",
        "AES128-CCM-SHA256",
        "AES128-CCM-8-SHA256",
    ],
}


def evaluate_parameters(rule_parameters):
    """Evaluate the rule parameters dictionary validity. Raise a Exception for invalid parameters.
    Keyword arguments:
    rule_parameters -- the Key/Value dictionary of the Config Rule parameters
    """
    if "s3ObjectPath" not in rule_parameters:
        logger.error('The parameter with "s3ObjectPath" as key must be defined.')
        raise ValueError('The parameter with "s3ObjectPath" as key must be defined.')
    if not rule_parameters["s3ObjectPath"]:
        logger.error('The parameter "s3ObjectPath" must have a defined value.')
        raise ValueError('The parameter "s3ObjectPath" must have a defined value.')
    return rule_parameters


def build_evaluation(resource_id, compliance_type, event, resource_type, annotation=None):
    """Form an evaluation as a dictionary. Usually suited to report on scheduled rules.
    Keyword arguments:
    resource_id -- the unique id of the resource to report
    compliance_type -- either COMPLIANT, NON_COMPLIANT or NOT_APPLICABLE
    event -- the event variable given in the lambda handler
    resource_type -- the CloudFormation resource type (or AWS::::Account) to report on the rule
    annotation -- an annotation to be added to the evaluation (default None)
    """
    eval_cc = {}
    if annotation:
        eval_cc["Annotation"] = annotation
    eval_cc["ComplianceResourceType"] = resource_type
    eval_cc["ComplianceResourceId"] = resource_id
    eval_cc["ComplianceType"] = compliance_type
    eval_cc["OrderingTimestamp"] = str(json.loads(event["invokingEvent"])["notificationCreationTime"])
    return eval_cc


def get_client(service, event, region="ca-central-1"):
    """Return the service boto client. It should be used instead of directly calling the client.
    Keyword arguments:
    service -- the service name used for calling the boto.client()
    event -- the event variable given in the lambda handler
    """
    if not ASSUME_ROLE_MODE or (AWS_ACCOUNT_ID == AUDIT_ACCOUNT_ID):
        return boto3.client(service, region_name=region)
    execution_role_arn = f"arn:aws:iam::{AWS_ACCOUNT_ID}:role/{EXECUTION_ROLE_NAME}"
    credentials = get_assume_role_credentials(execution_role_arn, region)
    return boto3.client(
        service,
        region_name=region,
        aws_access_key_id=credentials["AccessKeyId"],
        aws_secret_access_key=credentials["SecretAccessKey"],
        aws_session_token=credentials["SessionToken"],
    )


def get_assume_role_credentials(role_arn, region="ca-central-1"):
    """Return the service boto client. It should be used instead of directly calling the client.
    Keyword arguments:
    service -- the service name used for calling the boto.client()
    event -- the event variable given in the lambda handler
    """
    sts_client = boto3.client("sts", region_name=region)
    try:
        assume_role_response = sts_client.assume_role(RoleArn=role_arn, RoleSessionName="configLambdaExecution")
        return assume_role_response["Credentials"]
    except botocore.exceptions.ClientError as ex:
        if "AccessDenied" in ex.response["Error"]["Code"]:
            ex.response["Error"]["Message"] = "AWS Config does not have permission to assume the IAM role."
        else:
            ex.response["Error"]["Message"] = "InternalError"
            ex.response["Error"]["Code"] = "InternalError"
        raise ex


def is_scheduled_notification(message_type):
    """Check whether the message is a ScheduledNotification or not.
    Keyword arguments:
    message_type -- the message type
    """
    return message_type == "ScheduledNotification"


def check_s3_object_exists(aws_s3_client, object_path: str) -> bool:
    """Check if the S3 object exists
    Keyword arguments:
    object_path -- the S3 object path
    """
    # parse the S3 path
    match = re.match(r"s3:\/\/([^/]+)\/((?:[^/]*/)*.*)", object_path)
    if match:
        bucket_name = match.group(1)
        key_name = match.group(2)
    else:
        logger.error("Unable to parse S3 object path %s", object_path)
        raise ValueError(f"Unable to parse S3 object path {object_path}")
    try:
        aws_s3_client.head_object(Bucket=bucket_name, Key=key_name)
    except botocore.exceptions.ClientError as err:
        if err.response["Error"]["Code"] == "404":
            # The object does not exist.
            logger.info("Object %s not found in bucket %s", key_name, bucket_name)
            return False
        elif err.response["Error"]["Code"] == "403":
            # AccessDenied
            logger.info("Access denied to bucket %s", bucket_name)
            return False
        else:
            # Something else has gone wrong.
            logger.error("Error trying to find object %s in bucket %s", key_name, bucket_name)
            raise ValueError(f"Error trying to find object {key_name} in bucket {bucket_name}") from err
    else:
        # The object does exist.
        return True


def elb_describe_load_balancer_policies(elb_client, load_balancer_name: str, policy_names: list[str]) -> list[dict]:
    try:
        response = elb_client.describe_load_balancer_policies(
            LoadBalancerName=load_balancer_name, PolicyNames=policy_names
        )
        return [] if not response else response.get("PolicyDescriptions", [])
    except botocore.exceptions.ClientError as ex:
        # Scrub error message for any internal account info leaks
        if "AccessDenied" in ex.response["Error"]["Code"]:
            ex.response["Error"]["Message"] = "AWS Config does not have permission to assume the IAM role."
        elif "AccessPointNotFound" in ex.response["Error"]["Code"]:
            ex.response["Error"]["Message"] = "AccessPointNotFound Error calling 'describe_load_balancer_policies'"
        elif "PolicyNotFound" in ex.response["Error"]["Code"]:
            ex.response["Error"]["Message"] = "PolicyNotFound Error calling 'describe_load_balancer_policies'"
        else:
            ex.response["Error"]["Message"] = "InternalError"
            ex.response["Error"]["Code"] = "InternalError"
        raise ex


def elb_describe_all_load_balancers(
    elb_client, page_size: int = 400, interval_between_calls: float = 0.25
) -> list[dict]:
    """
    Get a list of all the Classic Load Balancers
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/elb/paginator/DescribeLoadBalancers.html
    """
    resources: list[dict] = []
    paginator = elb_client.get_paginator("describe_load_balancers")
    page_iterator = paginator.paginate(PaginationConfig={"PageSize": page_size})
    for page in page_iterator:
        resources.extend(page.get("LoadBalancerDescriptions", []))
        time.sleep(interval_between_calls)
    return resources


def extract_custom_policies(policies: list[dict]) -> list[dict]:
    return [
        policy
        for policy in policies
        if not policy.get("PolicyName", "").startswith("ELBSecurityPolicy")
        and not policy.get("PolicyName", "").startswith("ELBSample")
    ]


def flat(list):
    return [x for sub_list in list for x in sub_list]


def policy_protocols_and_cipher_suites_meet_recommendations(lb_name: str, policies: list[dict]) -> bool:
    all_meet_recommendations = True
    for policy in policies:
        # Example: attributes = [
        #   {"AttributeName": "Protocol-TLSv1.2", "AttributeValue": "true"},
        #   {"AttributeName": "AES128-SHA", "AttributeValue": "false"}
        # ]
        attributes = policy.get("PolicyAttributeDescriptions", [])
        policy_name = policy.get("PolicyName", "")

        ### Section: Verify that all policies are only using recommended protocols
        # Example: enabled_protocols = ["TLSv1.3"]
        enabled_protocols = [
            attr.get("AttributeName", "").lstrip("Protocol-")
            for attr in attributes
            if attr.get("AttributeName", "").startswith("Protocol") and attr.get("AttributeValue", "") == "true"
        ]
        disallowed_and_enabled_protocols = [x for x in enabled_protocols if x not in ITSP_40_062_ALLOWED_SUITES.keys()]
        if disallowed_and_enabled_protocols:
            logger.info(
                f"Invalid protocol(s) '{ "', '".join(disallowed_and_enabled_protocols) }' enabled for Policy '{policy_name}' in Load Balancer '{lb_name}'."
            )
            all_meet_recommendations = False

        ### Section: Verify that all policies are only using recommended cipher suites
        # Merge the lists of allowed suites for all the protocols that are enabled
        allowed_suites = flat([v for k, v in ITSP_40_062_ALLOWED_SUITES.items() if k in enabled_protocols])
        enabled_suites = [
            attr.get("AttributeName", "")
            for attr in attributes
            if (
                not attr.get("AttributeName", "").startswith("Protocol")
                and not attr.get("AttributeName", "") == "Server-Defined-Cipher-Order"
                and attr.get("AttributeValue", "") == "true"
            )
        ]
        disallowed_and_enabled_suites = [x for x in enabled_suites if x not in allowed_suites]
        if disallowed_and_enabled_suites:
            logger.info(
                f"Invalid cipher suite(s) '{ "', '".join(disallowed_and_enabled_suites) }' enabled for Policy '{policy_name}' in Load Balancer '{lb_name}'."
            )
            all_meet_recommendations = False

    return all_meet_recommendations


def assess_load_balancer_enforcement(
    load_balancers_details: list[dict], attestation_file_exists: bool, event
) -> list[dict]:
    resource_type = "AWS::ElasticLoadBalancing::LoadBalancer"
    evaluations = []
    all_resources_are_compliant = True

    for load_balancer_details in load_balancers_details:
        lb_name: str = load_balancer_details["Description"]["LoadBalancerName"]
        resource_id = lb_name
        custom_policies = extract_custom_policies(load_balancer_details.get("Policies", []))
        logger.info("Custom Policies found for Load Balancer '%s': %s", lb_name, custom_policies)

        if custom_policies:
            if policy_protocols_and_cipher_suites_meet_recommendations(lb_name, custom_policies):
                if attestation_file_exists:
                    annotation = "The load balancer is using a custom policy and the protocol and cipher suite meet recommendations, but the attestation file exists."
                    compliance_type = "COMPLIANT"
                else:
                    annotation = "The load balancer is using a custom policy and the protocol and cipher suite meet recommendations, but the attestation file does NOT exist."
                    compliance_type = "NON_COMPLIANT"
            else:
                annotation = "The load balancer is using a custom policy, but the protocol and/or cipher suite do NOT meet recommendations."
                compliance_type = "NON_COMPLIANT"
        else:
            if attestation_file_exists:
                annotation = "The load balancer is NOT using a custom policy, but the attestation file exists."
                compliance_type = "COMPLIANT"
            else:
                annotation = "The load balancer is NOT using a custom policy, but the attestation file does NOT exist."
                compliance_type = "NON_COMPLIANT"

        logger.info(f"{annotation} LoadBalancerName: '{resource_id}'")
        evaluations.append(build_evaluation(resource_id, compliance_type, event, resource_type, annotation))
        if compliance_type == "NON_COMPLIANT":
            all_resources_are_compliant = False

    return evaluations, all_resources_are_compliant


def submit_evaluations(
    aws_config_client, result_token: str, evaluations: list[dict], interval_between_calls: float = 0.25
):
    max_evaluations_per_call = 100
    while evaluations:
        batch_of_evaluations, evaluations = (
            evaluations[:max_evaluations_per_call],
            evaluations[max_evaluations_per_call:],
        )
        aws_config_client.put_evaluations(Evaluations=batch_of_evaluations, ResultToken=result_token)
        if evaluations:
            time.sleep(interval_between_calls)


def lambda_handler(event, context):
    """Lambda handler to check CloudTrail trails are logging.
    Keyword arguments:
    event -- the event variable given in the lambda handler
    context -- the context variable given in the lambda handler
    """
    global logger
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)

    global AWS_ACCOUNT_ID
    global AUDIT_ACCOUNT_ID
    global EXECUTION_ROLE_NAME

    page_size = 100
    interval_between_api_calls = 0.25

    rule_parameters = json.loads(event.get("ruleParameters", "{}"))
    invoking_event = json.loads(event.get("invokingEvent", "{}"))
    logger.info("Received event: %s", json.dumps(event, indent=2))

    AWS_ACCOUNT_ID = event["accountId"]
    logger.info("Assessing account %s", AWS_ACCOUNT_ID)

    valid_rule_parameters = evaluate_parameters(rule_parameters)
    EXECUTION_ROLE_NAME = valid_rule_parameters.get("ExecutionRoleName", "AWSA-GCLambdaExecutionRole")
    AUDIT_ACCOUNT_ID = valid_rule_parameters.get("AuditAccountID", "")

    if not is_scheduled_notification(invoking_event["messageType"]):
        logger.error("Skipping assessments as this is not a scheduled invocation")
        return

    aws_config_client = get_client("config", event)
    # Not using get_client to get S3 client for the Audit account
    aws_s3_client = boto3.client("s3")
    # Using older 'elb' api instead of 'elbv2' so that we get the 'Classic' load balancers
    aws_elb_client = get_client("elb", event)

    load_balancers_details = [
        {
            "Description": x,
            "Policies": elb_describe_load_balancer_policies(
                aws_elb_client, x.get("LoadBalancerName"), x.get("Policies", {}).get("OtherPolicies", [])
            ),
        }
        for x in elb_describe_all_load_balancers(aws_elb_client, page_size, interval_between_api_calls)
    ]

    attestation_file_exists = check_s3_object_exists(aws_s3_client, valid_rule_parameters["s3ObjectPath"])
    evaluations, all_resources_are_compliant = assess_load_balancer_enforcement(
        load_balancers_details, attestation_file_exists, event
    )

    status = "COMPLIANT" if all_resources_are_compliant and attestation_file_exists else "NON_COMPLIANT"
    resources_annotation = (
        "All resources found are compliant."
        if all_resources_are_compliant
        else "Non-compliant resources found in scope."
    )
    file_annotation = (
        "Cryptographic Algorithms Attestation file exists."
        if attestation_file_exists
        else "Cryptographic Algorithms Attestation file DOES NOT exist."
    )
    annotation = f"{resources_annotation} {file_annotation}"

    logger.info(f"{status}: {annotation}")
    evaluations.append(build_evaluation(AWS_ACCOUNT_ID, status, event, ACCOUNT_RESOURCE_TYPE, annotation))

    submit_evaluations(aws_config_client, event["resultToken"], evaluations, interval_between_api_calls)
