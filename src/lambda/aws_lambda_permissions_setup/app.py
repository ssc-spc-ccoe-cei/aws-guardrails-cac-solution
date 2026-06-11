"""AWS Lambda Permissions Setup

Synchronizes the resource-based policy of each guardrail Lambda clone so that
`config.amazonaws.com` is allowed to invoke it on behalf of every AWS account
assigned to the clone's partition (as recorded in the
`gc-guardrails-partition-state` DynamoDB table written by
`aws_account_partitioner`).

For each base guardrail name (e.g., ``gc01_check_root_mfa``) and each
partition in DynamoDB, the clone function name is:

  * partition 1 -> ``<OrganizationName><suffix>``
  * partition N -> ``<OrganizationName><suffix>_pN`` (N > 1)

For each clone, the Lambda:

  1. Reads the current resource-based policy via ``lambda:GetPolicy``.
  2. ADDS an ``lambda:AddPermission`` statement for each account in the
     partition that is missing from the policy.
  3. REMOVES the existing statement for each account that is in the policy
     but no longer present in the partition's DynamoDB entries. In normal
     operation this only happens when an account has been removed (closed,
     suspended, or transferred out) from the AWS Organization, since the
     partitioner never re-assigns an existing account to a different
     partition.

If a clone Lambda does not yet exist (e.g., the StackSet that creates the
partition-2/3 clones has not yet been updated), the clone is skipped with a
warning rather than failing the whole run. This keeps the sync idempotent and
safe to run between the partitioner and the StackSet update.

Invocation contexts
-------------------
  * CloudFormation Custom Resource (RequestType: Create / Update / Delete)
  * Step Function step             (RequestType: StepFunction)
"""

import os
import json
import logging
import time

import boto3
import botocore
import urllib3


SUCCESS = "SUCCESS"
FAILED = "FAILED"

# cfnresponse replacement
http = urllib3.PoolManager()

# Logging setup
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Configuration from environment variables
PARTITION_TABLE_NAME = os.environ.get(
    "PARTITION_TABLE_NAME", "gc-guardrails-partition-state"
)

# Guardrail base function suffixes (one entry per guardrail). Each entry yields
# one Lambda per partition: ``<org_name><suffix>`` for partition 1 and
# ``<org_name><suffix>_pN`` for higher partitions.
GUARDRAIL_LAMBDA_SUFFIXES = [
    "gc01_check_alerts_flag_misuse",
    "gc01_check_dedicated_admin_account",
    "gc01_check_federated_users_mfa",
    "gc01_check_iam_users_mfa",
    "gc01_check_mfa_digital_policy",
    "gc01_check_monitoring_and_logging",
    "gc01_check_root_mfa",
    "gc02_check_group_access_configuration",
    "gc02_check_iam_password_policy",
    "gc02_check_password_protection_mechanisms",
    "gc02_check_privileged_roles_review",
    "gc03_check_endpoint_access_config",
    "gc03_check_trusted_devices_admin_access",
    "gc04_check_alerts_flag_misuse",
    "gc04_check_enterprise_monitoring",
    "gc05_check_data_location",
    "gc06_check_encryption_at_rest_part1",
    "gc06_check_encryption_at_rest_part2",
    "gc07_check_certificate_authorities",
    "gc07_check_cryptographic_algorithms",
    "gc07_check_encryption_in_transit",
    "gc08_check_cloud_deployment_guide",
    "gc08_check_cloud_segmentation_design",
    "gc08_check_target_network_architecture",
    "gc09_check_non_public_storage_accounts",
    "gc10_check_cyber_center_sensors",
    "gc11_check_monitoring_all_users",
    "gc11_check_monitoring_use_cases",
    "gc11_check_policy_event_logging",
    "gc11_check_security_contact",
    "gc11_check_timezone",
    "gc11_check_trail_logging",
    "gc12_check_private_marketplace",
    "gc13_check_emergency_account_alerts",
    "gc13_check_emergency_account_management",
    "gc13_check_emergency_account_mgmt_approvals",
    "gc13_check_emergency_account_testing",
]


# ---------------------------------------------------------------------------
# DynamoDB partition state
# ---------------------------------------------------------------------------

def read_partition_state(table_name):
    """Reads the partition state table and returns a partition -> accounts map.

    :param table_name: DynamoDB table name.
    :return: dict mapping ``PartitionId`` (int) -> set of account-id strings.
    """
    dynamodb = boto3.resource("dynamodb")
    table = dynamodb.Table(table_name)
    partitions = {}

    response = table.scan()
    for item in response.get("Items", []):
        pid = int(item["PartitionId"])
        partitions.setdefault(pid, set()).add(item["AccountId"])

    while "LastEvaluatedKey" in response:
        response = table.scan(ExclusiveStartKey=response["LastEvaluatedKey"])
        for item in response.get("Items", []):
            pid = int(item["PartitionId"])
            partitions.setdefault(pid, set()).add(item["AccountId"])

    return partitions


# ---------------------------------------------------------------------------
# Lambda clone naming & policy inspection
# ---------------------------------------------------------------------------

def clone_function_name(organization_name, suffix, partition_id):
    """Computes the clone function name for a guardrail and partition.

    Partition 1 keeps the legacy base name (no suffix) so existing
    deployments and Config rules continue to work unchanged.
    """
    if partition_id == 1:
        return f"{organization_name}{suffix}"
    return f"{organization_name}{suffix}_p{partition_id}"


def lambda_function_exists(client, function_name):
    """Returns True if the Lambda function exists, False if not.

    Re-raises any other ClientError.
    """
    try:
        client.get_function(FunctionName=function_name)
        return True
    except botocore.exceptions.ClientError as error:
        if error.response["Error"]["Code"] == "ResourceNotFoundException":
            return False
        raise


def get_current_authorized_accounts(client, function_name):
    """Returns the accounts currently authorized to invoke ``function_name``.

    :return: tuple ``(authorized, function_missing)`` where:

        * ``authorized`` is a dict mapping ``account_id`` (str) -> ``Sid`` (str)
          for every ``config.amazonaws.com`` ``lambda:InvokeFunction`` Allow
          statement found in the resource-based policy. Returns ``{}`` if the
          function exists but has no policy.
        * ``function_missing`` is True when the function itself does not exist.
          In that case ``authorized`` is None.
    """
    try:
        response = client.get_policy(FunctionName=function_name)
    except botocore.exceptions.ClientError as error:
        code = error.response["Error"]["Code"]
        if code == "ResourceNotFoundException":
            # GetPolicy returns ResourceNotFoundException both when the function
            # is missing and when it has no resource policy. Disambiguate.
            if not lambda_function_exists(client, function_name):
                return None, True
            return {}, False
        raise

    authorized = {}
    try:
        policy_doc = json.loads(response.get("Policy", "{}"))
    except (ValueError, TypeError):
        logger.error("Unparseable policy returned for %s", function_name)
        return {}, False

    for statement in policy_doc.get("Statement", []):
        principal = statement.get("Principal", {})
        service = principal.get("Service") if isinstance(principal, dict) else None

        if (
            service == "config.amazonaws.com"
            and statement.get("Action") == "lambda:InvokeFunction"
            and statement.get("Effect") == "Allow"
        ):
            condition = statement.get("Condition", {})
            source_account = None
            if isinstance(condition, dict):
                source_account = (
                    condition.get("StringEquals", {}).get("AWS:SourceAccount")
                )
            sid = statement.get("Sid", "")
            if source_account and sid:
                authorized[source_account] = sid

    return authorized, False


# ---------------------------------------------------------------------------
# Per-statement add / remove with retry-and-backoff
# ---------------------------------------------------------------------------

def _add_permission(client, function_name, account_id, sid, max_retries=5):
    """Adds an Allow-config statement to ``function_name`` for ``account_id``.

    Returns True on success, False on a non-retryable error.
    """
    for attempt in range(max_retries):
        try:
            client.add_permission(
                Action="lambda:InvokeFunction",
                FunctionName=function_name,
                Principal="config.amazonaws.com",
                SourceAccount=account_id,
                StatementId=sid,
            )
            return True
        except botocore.exceptions.ClientError as error:
            code = error.response["Error"]["Code"]
            if code == "TooManyRequestsException":
                wait = 0.25 * (attempt + 1)
                logger.warning(
                    "Throttled on AddPermission(%s, %s); sleeping %.2fs",
                    function_name, account_id, wait,
                )
                time.sleep(wait)
                continue
            if code == "ResourceConflictException":
                # Sid already present (likely concurrent run). Treat as success.
                logger.info(
                    "Sid %s already present on %s for account %s; skipping add",
                    sid, function_name, account_id,
                )
                return True
            logger.error(
                "AddPermission failed for %s / %s: %s",
                function_name, account_id, error,
            )
            return False
    logger.error(
        "AddPermission exhausted retries for %s / %s", function_name, account_id
    )
    return False


def _remove_permission(client, function_name, sid, account_id, max_retries=5):
    """Removes statement ``sid`` from ``function_name``.

    Returns True on success, False on a non-retryable error.
    """
    for attempt in range(max_retries):
        try:
            client.remove_permission(FunctionName=function_name, StatementId=sid)
            return True
        except botocore.exceptions.ClientError as error:
            code = error.response["Error"]["Code"]
            if code == "TooManyRequestsException":
                wait = 0.25 * (attempt + 1)
                logger.warning(
                    "Throttled on RemovePermission(%s, %s); sleeping %.2fs",
                    function_name, sid, wait,
                )
                time.sleep(wait)
                continue
            if code == "ResourceNotFoundException":
                # Already gone — fine.
                logger.info(
                    "Sid %s already absent on %s (account %s); skipping remove",
                    sid, function_name, account_id,
                )
                return True
            logger.error(
                "RemovePermission failed for %s / %s: %s",
                function_name, sid, error,
            )
            return False
    logger.error(
        "RemovePermission exhausted retries for %s / %s", function_name, sid
    )
    return False


# ---------------------------------------------------------------------------
# Per-clone synchronization
# ---------------------------------------------------------------------------

def _make_sid(used_sids):
    """Returns the smallest ``p<n>`` (n >= 1) not present in ``used_sids``.

    Uses a short prefix to keep each statement compact: every byte saved in
    the Sid is a byte that doesn't count against Lambda's 20 KB resource
    policy cap. Caller is responsible for adding the returned Sid to
    ``used_sids`` after a successful AddPermission.
    """
    n = 1
    while f"p{n}" in used_sids:
        n += 1
    return f"p{n}"


def sync_clone_permissions(client, function_name, desired_accounts):
    """Synchronizes ``function_name``'s resource policy to ``desired_accounts``.

    :return: dict with keys ``added``, ``removed``, ``skipped`` (True iff the
        clone Lambda does not exist), ``errors`` (count of non-retryable
        failures).
    """
    authorized, missing = get_current_authorized_accounts(client, function_name)
    if missing:
        logger.warning(
            "Lambda %s does not exist; skipping. "
            "(Expected if partition clones have not been deployed yet.)",
            function_name,
        )
        return {"added": 0, "removed": 0, "skipped": True, "errors": 0}

    current_accounts = set(authorized.keys())
    to_add = desired_accounts - current_accounts
    to_remove = current_accounts - desired_accounts

    if not to_add and not to_remove:
        logger.info(
            "%s already in sync (%d account(s))", function_name, len(current_accounts)
        )
        return {"added": 0, "removed": 0, "skipped": False, "errors": 0}

    logger.info(
        "Syncing %s: %d desired, %d current, +%d add, -%d remove",
        function_name,
        len(desired_accounts),
        len(current_accounts),
        len(to_add),
        len(to_remove),
    )

    used_sids = set(authorized.values())
    added = 0
    removed = 0
    errors = 0

    for account_id in sorted(to_add):
        sid = _make_sid(used_sids)
        if _add_permission(client, function_name, account_id, sid):
            used_sids.add(sid)
            added += 1
        else:
            errors += 1

    for account_id in sorted(to_remove):
        sid = authorized[account_id]
        if _remove_permission(client, function_name, sid, account_id):
            removed += 1
        else:
            errors += 1

    logger.info(
        "Synced %s: +%d / -%d (%d errors)", function_name, added, removed, errors
    )
    return {"added": added, "removed": removed, "skipped": False, "errors": errors}


# ---------------------------------------------------------------------------
# Top-level orchestration
# ---------------------------------------------------------------------------

def apply_lambda_permissions():
    """Synchronizes every guardrail clone's resource policy against DynamoDB.

    :return: 1 on success, -1 on error.
    """
    organization_name = os.environ.get("OrganizationName", "")
    logger.info("Organization Name: %s", organization_name)
    logger.info("Partition table:  %s", PARTITION_TABLE_NAME)

    try:
        partitions = read_partition_state(PARTITION_TABLE_NAME)
    except botocore.exceptions.ClientError as error:
        logger.error(
            "Failed to read partition state from %s: %s",
            PARTITION_TABLE_NAME, error,
        )
        return -1

    if not partitions:
        logger.warning(
            "Partition state table %s is empty. The partitioner Lambda may "
            "not have run yet. Nothing to do.",
            PARTITION_TABLE_NAME,
        )
        # Treat as a successful no-op so the CFN Custom Resource doesn't fail
        # on a fresh deploy where the partitioner runs in the same stack.
        return 1

    partition_sizes = {pid: len(accts) for pid, accts in partitions.items()}
    logger.info(
        "Loaded %d partition(s) from DynamoDB: %s",
        len(partitions), partition_sizes,
    )

    client = boto3.client("lambda")
    total_added = 0
    total_removed = 0
    total_skipped = 0
    total_errors = 0

    for suffix in GUARDRAIL_LAMBDA_SUFFIXES:
        for partition_id, accounts in sorted(partitions.items()):
            function_name = clone_function_name(
                organization_name, suffix, partition_id
            )
            try:
                result = sync_clone_permissions(client, function_name, accounts)
            except botocore.exceptions.ClientError as error:
                logger.error("Unexpected error syncing %s: %s", function_name, error)
                total_errors += 1
                continue
            total_added += result["added"]
            total_removed += result["removed"]
            total_errors += result["errors"]
            if result["skipped"]:
                total_skipped += 1

    logger.info(
        "Sync complete: +%d added, -%d removed, %d clones skipped, %d errors",
        total_added, total_removed, total_skipped, total_errors,
    )

    return 1 if total_errors == 0 else -1


# ---------------------------------------------------------------------------
# CloudFormation response helper
# ---------------------------------------------------------------------------

def send(event, context, response_status, response_data,
         physical_resource_id=None, no_echo=False, reason=None):
    """Sends a response to CloudFormation."""
    response_url = event["ResponseURL"]
    logger.info("Response URL: %s", response_url)
    response_body = {
        "Status": response_status,
        "Reason": reason or f"See the details in CloudWatch Log Stream: {context.log_stream_name}",
        "PhysicalResourceId": physical_resource_id or context.log_stream_name,
        "StackId": event["StackId"],
        "RequestId": event["RequestId"],
        "LogicalResourceId": event["LogicalResourceId"],
        "NoEcho": no_echo,
        "Data": response_data,
    }
    json_response_body = json.dumps(response_body)
    logger.info("Response body: %s", json_response_body)
    headers = {"content-type": "", "content-length": str(len(json_response_body))}
    try:
        response = http.request("PUT", response_url, headers=headers, body=json_response_body)
        logger.info("Status code: %s", response.status)
    except (ValueError, TypeError, urllib3.exceptions.HTTPError) as err:
        logger.error("send(..) failed executing http.request(..): %s", err)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def lambda_handler(event, context):
    """Main entry point.

    Supports:
      * CloudFormation Custom Resource (RequestType: Create / Update / Delete)
      * Step Function step             (RequestType: StepFunction)
    """
    logger.info("Received Event: %s", json.dumps(event, indent=2))
    request_type = event.get("RequestType", "")
    response_data = {}

    if request_type == "Delete":
        # Nothing to tear down — Lambda permissions are removed automatically
        # when the function itself is deleted.
        if "ResponseURL" in event:
            send(event, context, SUCCESS, response_data)
        return

    if request_type in ("Create", "Update"):
        result = apply_lambda_permissions()
        if result != 1:
            response_data["Reason"] = (
                "Failed to sync Lambda permissions. Check CloudWatch Logs."
            )
            send(event, context, FAILED, response_data)
        else:
            response_data["Reason"] = (
                "Successfully synced Lambda permissions. Check CloudWatch Logs."
            )
            send(event, context, SUCCESS, response_data)
        return

    if request_type == "StepFunction":
        # Step Function invocation — return result directly; raise on failure
        # so the state machine can branch on it.
        result = apply_lambda_permissions()
        if result != 1:
            raise RuntimeError(
                "Failed to sync Lambda permissions. Check CloudWatch Logs."
            )
        return {"status": "success", "reason": "Synced Lambda permissions"}

    # Unknown request type
    logger.error("Unknown RequestType: %s", request_type)
    if "ResponseURL" in event:
        send(
            event, context, FAILED, response_data,
            reason=f"Unknown RequestType: {request_type}",
        )
    else:
        raise ValueError(f"Unknown RequestType: {request_type}")
