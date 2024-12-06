""" GC12 - Check Marketplace Configuration
    https://canada-ca.github.io/cloud-guardrails/EN/12_Cloud-Marketplace-Config.html
"""

import logging
import json
import time

import boto3
import botocore

# Logging setup
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Set to True to get the lambda to assume the Role attached on the Config Service
ASSUME_ROLE_MODE = True
ACCOUNT_RESOURCE_TYPE = "AWS::::Account"


# This gets the client after assuming the Config service role
# either in the same AWS account or cross-account.
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
    """Gets the temporary credentials using the STS service of the AWS account.
    Keyword arguments:
    role_arn -- the ARN of the role to assume
    region -- the region where the AWS account is located
    Returns:
    credentials -- a dictionary of temporary credentials returned by boto3
    """
    sts_client = boto3.client("sts", region_name=region)
    try:
        assume_role_response = sts_client.assume_role(RoleArn=role_arn, RoleSessionName="configLambdaExecution")
        return assume_role_response["Credentials"]
    except botocore.exceptions.ClientError as ex:
        # Scrub error message for any internal account info leaks
        if "AccessDenied" in ex.response["Error"]["Code"]:
            ex.response["Error"]["Message"] = "AWS Config does not have permission to assume the IAM role."
        else:
            ex.response["Error"]["Message"] = "InternalError"
            ex.response["Error"]["Code"] = "InternalError"
        logger.error("ERROR assuming role.\n%s", ex.response["Error"])
        raise ex


def is_scheduled_notification(message_type):
    """Check whether the message is a ScheduledNotification or not"""
    return message_type == "ScheduledNotification"


def evaluate_parameters(rule_parameters):
    """Evaluate the rule parameters dictionary.
    Keyword arguments:
    rule_parameters -- the Key/Value dictionary of the Config rule parameters
    """
    return rule_parameters


# This generates an evaluation for config
def build_evaluation(
    resource_id,
    compliance_type,
    event,
    resource_type=ACCOUNT_RESOURCE_TYPE,
    annotation=None,
):
    """Form an evaluation as a dictionary. Usually suited to report on scheduled rules.
    Keyword arguments:
    resource_id -- the unique id of the resource to report
    compliance_type -- either COMPLIANT, NON_COMPLIANT or NOT_APPLICABLE
    event -- the event variable given in the lambda handler
    resource_type -- the CloudFormation resource type (or AWS::::Account)
    to report on the rule (default DEFAULT_RESOURCE_TYPE)
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


def get_organizations_mgmt_account_id(aws_organizations_client):
    """Calls the AWS Organizations API to obtain the Management Account ID"""
    management_account_id = ""
    i_retry_limit = 10
    i_retries = 0
    b_completed = False
    b_retry = True
    while (b_retry and (not b_completed)) and (i_retries < i_retry_limit):
        try:
            response = aws_organizations_client.describe_organization()
            if response:
                organization = response.get("Organization", None)
                if organization:
                    management_account_id = organization.get("MasterAccountId", "")
                else:
                    logger.error("Unable to read the Organization from the dict")
            else:
                logger.error("Invalid response.")
            b_completed = True
        except botocore.exceptions.ClientError as ex:
            if "AccessDenied" in ex.response["Error"]["Code"]:
                logger.error("ACCESS DENIED when trying to describe_organization")
                management_account_id = "ERROR"
                b_retry = False
            elif "AWSOrganizationsNotInUse" in ex.response["Error"]["Code"]:
                logger.error("AWS Organizations not in use")
                management_account_id = "ERROR"
                b_retry = False
            elif "ServiceException" in ex.response["Error"]["Code"]:
                logger.error("AWS Organizations Service Exception")
                management_account_id = "ERROR"
                b_retry = False
            elif ("ConcurrentModification" in ex.response["Error"]["Code"]) or (
                "TooManyRequests" in ex.response["Error"]["Code"]
            ):
                # throttling
                logger.info("AWS Organizations API is throttling requests or going through a modification. Will retry.")
                time.sleep(2)
                if i_retries >= i_retry_limit:
                    logger.error("Retry limit reached. Returning an error")
                    management_account_id = "ERROR"
                    b_retry = False
                else:
                    i_retries += 1
        except ValueError:
            logger.error("Unknown exception - get_organizations_mgmt_account_id.")
            management_account_id = "ERROR"
    return management_account_id


def private_marketplace_is_configured(marketplace_catalog_client):
    """Check whether the account is using a private marketplace.
    Returns:
    True if the account is using a private marketplace, False otherwise.
    Raises:
    ValueError if the Marketplace Catalog is not available.
    ValueError if the Marketplace Catalog returns an error.
    """
    try:
        response = marketplace_catalog_client.list_entities(
            Catalog="AWSMarketplace",
            EntityType="Experience",
            FilterList=[{"Name": "Scope", "ValueList": ["SharedWithMe"]}],
        )
    except botocore.exceptions.ClientError as err:
        raise ValueError(f"Error in AWS Marketplace Catalog: {err}") from err
    else:
        if response:
            entity_summary_list = response.get("EntitySummaryList")
            for entity in entity_summary_list:
                if entity.get("EntityType") == "Experience":
                    # found a private marketplace
                    return True
        else:
            raise ValueError("No response from AWS Marketplace Catalog")
    # if we got here we have not found a private marketplace
    return False


def policy_restricts_marketplace_access(iam_client, policy_content: str, interval_between_calls: float = 0.1) -> bool:
    args = {"PolicyInputList": [policy_content], "ActionNames": ["aws-marketplace-management:*", "aws-marketplace:*"]}
    resources: list[dict] = []
    while True:
        response = iam_client.simulate_custom_policy(**args)

        if response:
            resources.extend(response.get("EvaluationResults", []))
            args["Marker"] = response.get("Marker")
        else:
            args["Marker"] = None

        if not args.get("Marker"):
            break
        else:
            time.sleep(interval_between_calls)

    for eval_result in resources:
        if eval_result.get("EvalDecision") == "allowed":
            return False

    return True


def organizations_list_all_service_control_policies(
    organizations_client, interval_between_calls: float = 0.1
) -> list[dict]:
    """
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/organizations/paginator/ListPolicies.html
    """
    resources: list[dict] = []
    paginator = organizations_client.get_paginator("list_policies")
    page_iterator = paginator.paginate(Filter="SERVICE_CONTROL_POLICY")
    for page in page_iterator:
        resources.extend(page.get("Policies", []))
        time.sleep(interval_between_calls)
    return resources


def get_policies_that_restrict_marketplace_access(
    organizations_client, iam_client, interval_between_calls: float = 0.1
):
    policies = organizations_list_all_service_control_policies(organizations_client, interval_between_calls)
    selected_policy_summaries: list[dict] = []

    for policy_summary in policies:
        response = organizations_client.describe_policy(PolicyId=policy_summary.get("Id"))
        policy = response.get("Policy", {})
        policy_content = policy.get("Content")

        if not policy_content:
            break

        if policy_restricts_marketplace_access(iam_client, policy_content, interval_between_calls):
            selected_policy_summaries.append(policy_summary)
            break

    logger.info("Marketplace restriction policies found: %s", selected_policy_summaries)
    return selected_policy_summaries


def organizations_list_all_roots(organizations_client, interval_between_calls: float = 0.1) -> list[dict]:
    """
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/organizations/paginator/ListRoots.html
    """
    resources: list[dict] = []
    paginator = organizations_client.get_paginator("list_roots")
    page_iterator = paginator.paginate()
    for page in page_iterator:
        resources.extend(page.get("Roots", []))
        time.sleep(interval_between_calls)
    return resources


def organizations_list_all_organizational_units(
    organizations_client, parent_id: str | None = None, interval_between_calls: float = 0.1
) -> list[dict]:
    """
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/organizations/paginator/ListOrganizationalUnitsForParent.html
    """
    resources: list[dict] = []
    if not parent_id:
        roots = organizations_list_all_roots(organizations_client, interval_between_calls)
        for root in roots:
            resources.extend(
                organizations_list_all_organizational_units(
                    organizations_client, root.get("Id"), interval_between_calls
                )
            )
        return resources

    paginator = organizations_client.get_paginator("list_organizational_units_for_parent")
    page_iterator = paginator.paginate(ParentId=parent_id)
    for page in page_iterator:
        batch = page.get("OrganizationalUnits", [])
        resources.extend(batch)
        time.sleep(interval_between_calls)
        for ou in batch:
            resources.extend(
                organizations_list_all_organizational_units(organizations_client, ou.get("Id"), interval_between_calls)
            )
    return resources


def organizations_list_all_targets_for_policy(
    organizations_client, policy_id: str, page_size: int = 10, interval_between_calls: int = 0.1
):
    """
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/organizations/paginator/ListTargetsForPolicy.html
    """
    resources: list[dict] = []
    paginator = organizations_client.get_paginator("list_targets_for_policy")
    page_iterator = paginator.paginate(PolicyId=policy_id, PaginationConfig={"PageSize": page_size})
    for page in page_iterator:
        resources.extend(page.get("Targets", []))
        time.sleep(interval_between_calls)
    return resources


def organizations_list_all_policies_for_target(
    organizations_client, target_id: str, page_size: int = 10, interval_between_calls: int = 0.1
):
    """
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/organizations/paginator/ListPoliciesForTarget.html
    """
    resources: list[dict] = []
    paginator = organizations_client.get_paginator("list_policies_for_target")
    page_iterator = paginator.paginate(
        TargetId=target_id, Filter="SERVICE_CONTROL_POLICY", PaginationConfig={"PageSize": page_size}
    )
    for page in page_iterator:
        resources.extend(page.get("Policies", []))
        time.sleep(interval_between_calls)
    return resources


def policy_is_attached(
    organizations_client, target_id: str, policy_ids: list[str], interval_between_calls: int = 0.1
) -> bool:
    policies = organizations_list_all_policies_for_target(
        organizations_client, target_id, interval_between_calls=interval_between_calls
    )
    logger.info("Policies found for target '%s': %s", target_id, policies)
    return next((True for x in policies if x.get("Id", "") in policy_ids), False)


def assess_policy_attachment(
    organizations_client, policy_summaries: list[dict], current_account_id: str, interval_between_calls: float = 0.1
) -> tuple[str, str]:
    policy_ids = [x.get("Id") for x in policy_summaries]
    policy_is_attached_to_account = policy_is_attached(
        organizations_client, current_account_id, policy_ids, interval_between_calls
    )
    management_account_id = get_organizations_mgmt_account_id(organizations_client)
    is_management_account = current_account_id == management_account_id

    if is_management_account:
        # Only Check OUs when in the management account since they are global for the organization
        ou_list = organizations_list_all_organizational_units(
            organizations_client, interval_between_calls=interval_between_calls
        )
        ou_ids_missing_policy = [
            x.get("Id")
            for x in ou_list
            if not policy_is_attached(organizations_client, x.get("Id"), policy_ids, interval_between_calls)
        ]

        compliance_type = "NON_COMPLIANT" if policy_is_attached_to_account or ou_ids_missing_policy else "COMPLIANT"

        if ou_ids_missing_policy:
            annotation = f"The marketplace restriction policy is NOT attached to the OUs '{ "', '".join(ou_ids_missing_policy) }'."
        else:
            annotation = "The marketplace restriction policy is attached to all the OUs."

        if policy_is_attached_to_account:
            annotation = (
                f"A marketplace restriction policy should not be attached to the Management Account. {annotation}"
            )

    elif not policy_is_attached_to_account:
        compliance_type = "NON_COMPLIANT"
        annotation = "The account does NOT have a marketplace restriction policy attached."
    else:
        compliance_type = "COMPLIANT"
        annotation = "The account has a marketplace restriction policy attached."

    return compliance_type, annotation


def lambda_handler(event, context):
    """This function is the main entry point for Lambda.
    Keyword arguments:
    event -- the event variable given in the lambda handler
    context -- the context variable given in the lambda handler
    """
    global AWS_ACCOUNT_ID
    global EXECUTION_ROLE_NAME
    global AUDIT_ACCOUNT_ID

    interval_between_calls = 0.1
    rule_parameters = json.loads(event.get("ruleParameters", "{}"))
    invoking_event = json.loads(event["invokingEvent"])
    logger.info("Received Event: %s", json.dumps(event, indent=2))

    # parse parameters
    AWS_ACCOUNT_ID = event["accountId"]
    logger.info("Assessing account %s", AWS_ACCOUNT_ID)

    valid_rule_parameters = evaluate_parameters(rule_parameters)
    EXECUTION_ROLE_NAME = valid_rule_parameters.get("ExecutionRoleName", "AWSA-GCLambdaExecutionRole")
    AUDIT_ACCOUNT_ID = valid_rule_parameters.get("AuditAccountID", "")

    if not is_scheduled_notification(invoking_event["messageType"]):
        logger.error("Skipping assessments as this is not a scheduled invocation")
        return

    aws_config_client = get_client("config", event)
    aws_iam_client = get_client("iam", event)
    aws_organizations_client = get_client("organizations", event)

    selected_policy_summaries = get_policies_that_restrict_marketplace_access(
        aws_organizations_client, aws_iam_client, interval_between_calls
    )

    if not selected_policy_summaries:
        compliance_type = "NON_COMPLIANT"
        annotation = "A policy that restricts marketplace access was NOT found."
        logger.info(f"{compliance_type}: {annotation}")
        evaluations = [build_evaluation(AWS_ACCOUNT_ID, compliance_type, event, ACCOUNT_RESOURCE_TYPE, annotation)]
        aws_config_client.put_evaluations(Evaluations=evaluations, ResultToken=event["resultToken"])
        return

    compliance_type, annotation = assess_policy_attachment(
        aws_organizations_client, selected_policy_summaries, AWS_ACCOUNT_ID, interval_between_calls
    )

    if compliance_type == "COMPLIANT":
        aws_marketplace_catalog_client = get_client("marketplace-catalog", event, region="us-east-1")
        if not private_marketplace_is_configured(aws_marketplace_catalog_client):
            compliance_type = "NON_COMPLIANT"
            annotation = "Private Marketplace NOT found."
        else:
            compliance_type = "COMPLIANT"
            annotation = f"Private Marketplace found. {annotation}"

    # Update AWS Config with the evaluation result
    logger.info(f"{compliance_type}: {annotation}")
    evaluations = [build_evaluation(AWS_ACCOUNT_ID, compliance_type, event, ACCOUNT_RESOURCE_TYPE, annotation)]
    aws_config_client.put_evaluations(Evaluations=evaluations, ResultToken=event["resultToken"])
