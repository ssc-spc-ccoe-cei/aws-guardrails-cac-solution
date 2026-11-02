"""AWS Account Partitioner

Manages partition state for guardrail Lambda cloning. Partitions organize
accounts into groups of ≤60 so each Lambda clone's resource-based policy
stays under the 20 KB limit. Up to 4 partitions are supported
(4 x 60 = 240 addressable accounts).

Invocation contexts:
  - CloudFormation Custom Resource (Create/Update/Delete)
  - Step Function step (RequestType: "StepFunction")
"""

import os
import json
import logging
import time
from collections import defaultdict

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
PARTITION_TABLE_NAME = os.environ.get("PARTITION_TABLE_NAME", "gc-guardrails-partition-state")
MAX_ACCOUNTS_PER_PARTITION = int(os.environ.get("MAX_ACCOUNTS_PER_PARTITION", "60"))
MAX_PARTITIONS = int(os.environ.get("MAX_PARTITIONS", "4"))

# CloudFormation hard-caps the Custom Resource response body at 4096
# bytes (the whole JSON envelope, not just ``Data``). The per-partition
# ``AccountsInPx`` strings are by far the largest contributor, so the
# response is measured before it is sent and the resource is failed with
# an explicit, actionable message rather than being silently truncated /
# rejected by the S3 pre-signed PUT.
#
# Budget at the supported maximum: 4 partitions x 60 accounts = 240 IDs
# at 13 bytes each (12 digits + separator). Measured end-to-end response
# body at that size is ~3.75 KB, i.e. ~350 bytes under the cap. That thin
# margin is exactly why MAX_PARTITIONS is capped at 4 — a 5th partition
# would not fit (see doc/RESOURCE_POLICY_FIX.md).
CFN_RESPONSE_MAX_BYTES = 4096

# Headroom reserved below the hard cap so the guard trips before
# CloudFormation does, leaving room for a readable failure Reason. Kept
# deliberately small: at the supported maximum of 240 accounts the body
# is already ~3.75 KB, so a large margin would reject a supported
# configuration.
CFN_RESPONSE_SAFETY_MARGIN_BYTES = 128

# Emit a warning once the response passes this fraction of the hard cap,
# so operators get advance notice in CloudWatch before a future account
# onboarding actually breaks the deployment.
CFN_RESPONSE_WARN_RATIO = 0.85


def get_active_accounts():
    """Queries AWS Organizations and returns a list of active account IDs.

    :return: set of 12-digit account ID strings
    """
    account_ids = set()
    client = boto3.client("organizations")
    b_retry = True
    b_completed = False

    while b_retry and not b_completed:
        try:
            response = client.list_accounts()
            if not response:
                logger.error("Empty response from organizations:ListAccounts")
                b_retry = False
                continue

            for acct in response.get("Accounts", []):
                if str(acct.get("Status", "")).upper() == "ACTIVE":
                    account_ids.add(acct["Id"])

            next_token = response.get("NextToken")
            while next_token:
                response = client.list_accounts(NextToken=next_token)
                for acct in response.get("Accounts", []):
                    if str(acct.get("Status", "")).upper() == "ACTIVE":
                        account_ids.add(acct["Id"])
                next_token = response.get("NextToken")

            b_completed = True
        except botocore.exceptions.ClientError as error:
            if error.response["Error"]["Code"] == "TooManyRequestsException":
                logger.warning("API call limit exceeded; backing off and retrying...")
                time.sleep(0.25)
                b_retry = True
            else:
                logger.error("Error listing accounts: %s", error)
                raise
        except (ValueError, TypeError) as error:
            logger.error("Unknown exception listing accounts: %s", error)
            raise

    return account_ids


def read_partition_state(table_name):
    """Reads all items from the DynamoDB partition state table.

    :param table_name: DynamoDB table name
    :return: dict mapping AccountId -> PartitionId
    """
    dynamodb = boto3.resource("dynamodb")
    table = dynamodb.Table(table_name)
    state = {}

    response = table.scan()
    for item in response.get("Items", []):
        state[item["AccountId"]] = int(item["PartitionId"])

    # Handle pagination
    while "LastEvaluatedKey" in response:
        response = table.scan(ExclusiveStartKey=response["LastEvaluatedKey"])
        for item in response.get("Items", []):
            state[item["AccountId"]] = int(item["PartitionId"])

    return state


def compute_partition_counts(state):
    """Returns a dict of partition_id -> count of accounts in that partition.

    :param state: dict mapping AccountId -> PartitionId
    :return: defaultdict(int) of partition_id -> count
    """
    counts = defaultdict(int)
    for partition_id in state.values():
        counts[partition_id] += 1
    return counts


def assign_partitions(active_accounts, current_state):
    """Determines partition assignments for new accounts and removals for stale ones.

    New accounts are assigned in deterministic sorted order to whichever
    existing partition has room (lowest-numbered first), or to a new
    partition if no existing slot can take them. Accounts already in
    ``current_state`` are never moved.

    :param active_accounts: set of active account IDs from Organizations
    :param current_state: dict mapping AccountId -> PartitionId from DynamoDB
    :return: tuple (accounts_to_add, accounts_to_remove, new_partition_count, partitions_changed)
        - accounts_to_add: dict of AccountId -> PartitionId for new assignments
        - accounts_to_remove: set of AccountIds to remove from DynamoDB
        - new_partition_count: int, total partitions after assignment
        - partitions_changed: bool, whether partition count changed
          (informational only — see ``run_partitioner`` docstring for how
          this is consumed downstream)
    """
    # Identify accounts to remove (in DynamoDB but no longer active)
    accounts_to_remove = set(current_state.keys()) - active_accounts

    # Identify accounts to add (active but not yet in DynamoDB)
    accounts_to_add_ids = active_accounts - set(current_state.keys())

    # Build working state (current minus removals)
    working_state = {k: v for k, v in current_state.items() if k not in accounts_to_remove}
    counts = compute_partition_counts(working_state)

    # Determine current partition count
    if counts:
        current_partition_count = max(counts.keys())
    else:
        current_partition_count = 1  # Start with partition 1

    # Assign new accounts
    accounts_to_add = {}
    for account_id in sorted(accounts_to_add_ids):
        assigned = False
        # Try to find a partition with room
        for p in range(1, current_partition_count + 1):
            if counts[p] < MAX_ACCOUNTS_PER_PARTITION:
                accounts_to_add[account_id] = p
                counts[p] += 1
                assigned = True
                break

        if not assigned:
            # Need a new partition
            new_partition = current_partition_count + 1
            if new_partition > MAX_PARTITIONS:
                logger.error(
                    "Cannot create partition %d — exceeds MAX_PARTITIONS (%d). "
                    "Account %s cannot be assigned. Total active accounts: %d",
                    new_partition, MAX_PARTITIONS, account_id, len(active_accounts)
                )
                raise RuntimeError(
                    f"Organization has more than {MAX_PARTITIONS * MAX_ACCOUNTS_PER_PARTITION} "
                    f"active accounts ({len(active_accounts)}). Cannot create partition "
                    f"{new_partition} — exceeds MAX_PARTITIONS={MAX_PARTITIONS}. "
                    f"Manual intervention required."
                )
            current_partition_count = new_partition
            accounts_to_add[account_id] = new_partition
            counts[new_partition] += 1

    # Determine if partition count changed
    old_partition_count = max(current_state.values()) if current_state else 0
    new_partition_count = current_partition_count

    # Check if removals collapsed a partition (all accounts removed from highest partition)
    while new_partition_count > 1 and counts.get(new_partition_count, 0) == 0:
        new_partition_count -= 1

    partitions_changed = old_partition_count != new_partition_count

    return accounts_to_add, accounts_to_remove, new_partition_count, partitions_changed


def write_partition_state(table_name, accounts_to_add, accounts_to_remove):
    """Writes partition state changes to DynamoDB.

    :param table_name: DynamoDB table name
    :param accounts_to_add: dict of AccountId -> PartitionId
    :param accounts_to_remove: set of AccountIds
    """
    dynamodb = boto3.resource("dynamodb")
    table = dynamodb.Table(table_name)

    # Remove stale accounts
    for account_id in accounts_to_remove:
        logger.info("Removing account %s from partition state", account_id)
        table.delete_item(Key={"AccountId": account_id})

    # Add new accounts
    for account_id, partition_id in accounts_to_add.items():
        logger.info("Assigning account %s to partition %d", account_id, partition_id)
        table.put_item(Item={"AccountId": account_id, "PartitionId": partition_id})


def build_partition_account_lists(state, partition_count):
    """Groups partition state into per-partition account-id lists.

    The returned dict has an entry for every partition slot from 1 to
    ``MAX_PARTITIONS`` (not just the populated ones) so the caller can
    safely look up ``AccountsInP1`` ... ``AccountsInP4`` regardless of
    how many partitions are currently in use. Slots above
    ``partition_count`` map to empty lists.

    :param state: dict mapping AccountId -> PartitionId
    :param partition_count: total number of partitions in use (int >= 1)
    :return: dict mapping partition_id (1..MAX_PARTITIONS) -> sorted list
        of AccountId strings.
    """
    lists = {p: [] for p in range(1, MAX_PARTITIONS + 1)}
    for account_id, partition_id in state.items():
        if partition_id in lists:
            lists[partition_id].append(account_id)
    for partition_id in lists:
        lists[partition_id].sort()
    return lists


def run_partitioner():
    """Main partitioning logic. Returns result dict.

    :return: dict with the following keys:

        * ``partitionCount`` -- int, total partitions in use (1..MAX_PARTITIONS)
        * ``partitionsChanged`` -- bool, whether partition *count* changed
          (a new partition was opened or a trailing one collapsed).
          **Returned for observability only.** Surfaced in CloudWatch
          logs, the Custom Resource response, and the Step Function
          execution history so operators can tell at a glance whether a
          sync run opened/collapsed a partition vs. merely added an
          account to an existing one. The Step Function's
          ``MembershipChanged?`` choice does NOT branch on this flag,
          because every partition-count change is necessarily also a
          membership change — testing it would be strictly redundant
          with ``accountsChanged``.
        * ``accountsChanged`` -- bool, whether partition *membership* changed
          (at least one account was added to or removed from the
          ``gc-guardrails-partition-state`` table on this run). **The
          Step Function gates the root-stack UpdateStack cascade on this
          flag alone.** It covers both the count-changing cases
          (opening/collapsing a partition) and the count-stable
          membership-change case: new accounts joining a multi-
          partition org must be added to the OTHER partitions'
          ``ExcludedAccounts`` lists, which only happens when the
          ConformancePackStack nested stack is re-rendered.
        * ``accountsInPartition`` -- dict mapping partition_id (1..MAX_PARTITIONS)
          -> list of account-id strings; slots above partitionCount are empty
          lists. Used by the CloudFormation Custom Resource caller to compute
          ``ExcludedAccounts`` lists for each Organization Conformance Pack.
    """
    logger.info("Starting account partitioning...")
    logger.info("Configuration: MAX_ACCOUNTS_PER_PARTITION=%d, MAX_PARTITIONS=%d",
                MAX_ACCOUNTS_PER_PARTITION, MAX_PARTITIONS)

    # Step 1: Get active accounts from Organizations
    active_accounts = get_active_accounts()
    logger.info("Found %d active accounts in the organization", len(active_accounts))

    # Step 2: Read current partition state from DynamoDB
    current_state = read_partition_state(PARTITION_TABLE_NAME)
    logger.info("Current partition state has %d entries", len(current_state))

    # Step 3: Compute assignments
    accounts_to_add, accounts_to_remove, partition_count, partitions_changed = assign_partitions(
        active_accounts, current_state
    )

    accounts_changed = bool(accounts_to_add) or bool(accounts_to_remove)

    logger.info(
        "Partition result: %d new assignments, %d removals, %d total partitions, "
        "partitions_changed=%s, accounts_changed=%s",
        len(accounts_to_add), len(accounts_to_remove), partition_count,
        partitions_changed, accounts_changed,
    )

    # Step 4: Write changes to DynamoDB
    write_partition_state(PARTITION_TABLE_NAME, accounts_to_add, accounts_to_remove)

    # Step 5: Build per-partition account lists from the final state. We
    # recompute "final state" locally rather than re-scanning DynamoDB to
    # avoid a race window where a parallel run could see stale data.
    final_state = {k: v for k, v in current_state.items() if k not in accounts_to_remove}
    final_state.update(accounts_to_add)
    accounts_in_partition = build_partition_account_lists(final_state, partition_count)

    for p in sorted(accounts_in_partition):
        logger.info(
            "Partition %d holds %d account(s)", p, len(accounts_in_partition[p])
        )

    return {
        "partitionCount": partition_count,
        "partitionsChanged": partitions_changed,
        "accountsChanged": accounts_changed,
        "accountsInPartition": accounts_in_partition,
    }


def send(event, context, response_status, response_data, physical_resource_id=None, no_echo=False, reason=None):
    """Sends a response to CloudFormation."""
    response_url = event["ResponseURL"]
    logger.info("Response URL: %s", response_url)

    json_response_body = json.dumps(
        _build_response_body(
            event, context, response_status, response_data, physical_resource_id, no_echo, reason
        )
    )
    logger.info("Response body: %s", json_response_body)
    logger.info("Response body size: %d bytes (CloudFormation limit: %d)",
                len(json_response_body.encode("utf-8")), CFN_RESPONSE_MAX_BYTES)

    headers = {"content-type": "", "content-length": str(len(json_response_body))}
    try:
        response = http.request("PUT", response_url, headers=headers, body=json_response_body)
        logger.info("Status code: %s", response.status)
    except (ValueError, TypeError, urllib3.exceptions.HTTPError) as err:
        logger.error("send(..) failed executing http.request(..): %s", err)


def _build_response_body(event, context, response_status, response_data,
                         physical_resource_id=None, no_echo=False, reason=None):
    """Builds the CloudFormation Custom Resource response envelope."""
    reason = reason or f"See the details in CloudWatch Log Stream: {context.log_stream_name}"
    # Keep the Reason bounded so a long failure message can never be the
    # thing that pushes the response over CloudFormation's 4 KB cap.
    if len(reason) > 1024:
        reason = reason[:1021] + "..."
    return {
        "Status": response_status,
        "Reason": reason,
        "PhysicalResourceId": physical_resource_id or context.log_stream_name,
        "StackId": event["StackId"],
        "RequestId": event["RequestId"],
        "LogicalResourceId": event["LogicalResourceId"],
        "NoEcho": no_echo,
        "Data": response_data,
    }


def assert_cfn_response_fits(event, context, response_data):
    """Fails fast if the Custom Resource response would exceed CloudFormation's cap.

    CloudFormation rejects Custom Resource responses larger than
    ``CFN_RESPONSE_MAX_BYTES`` (4096). Without this guard the symptom is
    an opaque ``Response object is too long`` / stack-timeout failure
    well after the partitioner has already written to DynamoDB, which is
    painful to diagnose. Measuring here lets us fail the resource with an
    explicit message naming the cause and the remediation options.

    :param event: the CloudFormation Custom Resource event
    :param context: the Lambda context object
    :param response_data: the ``Data`` dict about to be returned
    :raises RuntimeError: when the serialized body exceeds the budget
    """
    body = json.dumps(_build_response_body(event, context, SUCCESS, response_data))
    size = len(body.encode("utf-8"))
    budget = CFN_RESPONSE_MAX_BYTES - CFN_RESPONSE_SAFETY_MARGIN_BYTES

    logger.info("Custom Resource response body is %d bytes (budget %d, hard limit %d)",
                size, budget, CFN_RESPONSE_MAX_BYTES)

    if size <= budget:
        if size >= CFN_RESPONSE_MAX_BYTES * CFN_RESPONSE_WARN_RATIO:
            logger.warning(
                "Custom Resource response body is %d bytes — within %d%% of "
                "CloudFormation's %d byte hard limit. The organization is "
                "approaching the maximum this design can carry inline "
                "(%d partitions x %d accounts).",
                size, int(CFN_RESPONSE_WARN_RATIO * 100), CFN_RESPONSE_MAX_BYTES,
                MAX_PARTITIONS, MAX_ACCOUNTS_PER_PARTITION,
            )
        return

    account_total = sum(
        len([a for a in str(v).split(",") if a])
        for k, v in response_data.items()
        if k.startswith("AccountsInP")
    )
    raise RuntimeError(
        f"Account partitioner response is too large for CloudFormation: "
        f"{size} bytes for {account_total} account(s) across "
        f"{MAX_PARTITIONS} partition(s), which exceeds the usable budget of "
        f"{budget} bytes (CloudFormation hard limit is {CFN_RESPONSE_MAX_BYTES} "
        f"bytes per Custom Resource response)."
    )


def _build_cfn_response_data(result):
    """Builds the ``Data`` dict returned to CloudFormation Custom Resource.

    Per-partition account lists are returned as comma-separated strings (one
    string per slot, padded out to ``MAX_PARTITIONS``) so the nested
    ConformancePackPartitions stack can compute ``ExcludedAccounts`` lists
    with ``Fn::Split`` / ``Fn::Join``.

    The total response body is capped at 4 KB by CloudFormation; with
    ``MAX_ACCOUNTS_PER_PARTITION * MAX_PARTITIONS = 240`` account IDs at
    13 bytes each (12 digits + comma), the combined payload stays under
    that limit with ~500 bytes of headroom. ``assert_cfn_response_fits``
    enforces this at runtime.
    """
    accounts_in_partition = result["accountsInPartition"]
    data = {
        "PartitionCount": str(result["partitionCount"]),
        "PartitionsChanged": str(result["partitionsChanged"]),
        "AccountsChanged": str(result["accountsChanged"]),
    }
    for partition_id in range(1, MAX_PARTITIONS + 1):
        key = f"AccountsInP{partition_id}"
        data[key] = ",".join(accounts_in_partition.get(partition_id, []))
    return data


def lambda_handler(event, context):
    """Main entry point for Lambda.

    Supports:
      - CloudFormation Custom Resource (Create/Update/Delete)
      - Step Function invocation (RequestType: "StepFunction")
    """
    logger.info("Received Event: %s", json.dumps(event, indent=2))

    request_type = event.get("RequestType", "")

    if request_type == "Delete":
        # Nothing to tear down — DynamoDB table is managed by CloudFormation.
        # Return a fully-shaped (zeroed) payload so any !GetAtt references
        # in the consuming template still resolve cleanly during stack
        # deletion.
        empty = {
            "PartitionCount": "0",
            "PartitionsChanged": "false",
            "AccountsChanged": "false",
        }
        for partition_id in range(1, MAX_PARTITIONS + 1):
            empty[f"AccountsInP{partition_id}"] = ""
        send(event, context, SUCCESS, empty)
        return

    if request_type in ("Create", "Update"):
        # CloudFormation Custom Resource invocation
        try:
            result = run_partitioner()
            response_data = _build_cfn_response_data(result)
            # Fail loudly (and legibly) rather than letting CloudFormation
            # reject an oversized response after state has been written.
            assert_cfn_response_fits(event, context, response_data)
            send(event, context, SUCCESS, response_data)
        except Exception as e:
            logger.error("Partitioner failed: %s", e)
            send(event, context, FAILED, {}, reason=str(e))
        return

    if request_type == "StepFunction":
        # Step Function invocation — return result directly. Convert the
        # per-partition lists to the same comma-separated string shape as
        # the Custom Resource response so downstream steps can rely on a
        # single contract.
        try:
            result = run_partitioner()
            return _build_cfn_response_data(result)
        except Exception as e:
            logger.error("Partitioner failed: %s", e)
            raise

    # Unknown request type
    logger.error("Unknown RequestType: %s", request_type)
    if "ResponseURL" in event:
        send(event, context, FAILED, {}, reason=f"Unknown RequestType: {request_type}")
    else:
        raise ValueError(f"Unknown RequestType: {request_type}")
