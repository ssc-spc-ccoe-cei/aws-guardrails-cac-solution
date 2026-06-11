# aws_account_partitioner

Manages the partition state for guardrail Lambda cloning.

## Purpose

Partitions AWS Organization accounts into groups of ≤70 to keep each
guardrail Lambda's resource-based policy under the 20 KB limit.

## Invocation Contexts

| Context | Trigger |
|---------|---------|
| **Deployment** | CloudFormation Custom Resource in `main.yaml` |
| **Post-deployment** | Step 1 of the `gc-guardrails-partition-sync` Step Function (EventBridge cron) |

## Behaviour

1. Lists all active accounts via `organizations:ListAccounts`.
2. Reads current partition state from the `gc-guardrails-partition-state` DynamoDB table.
3. Assigns unassigned accounts to existing partitions with room (< 70), or creates a new partition (max 3).
4. Removes entries for inactive/deleted accounts.
5. Writes updated state back to DynamoDB.
6. Returns `partitionCount`, `partitionsChanged`, `accountsChanged`, and per-partition account lists.

## Return Shape

The Custom Resource response and the Step Function `Payload` share the same flat shape so downstream consumers have a single contract:

| Field | Type | Meaning |
|-------|------|---------|
| `PartitionCount` | `"0".."3"` | Total partitions in use |
| `PartitionsChanged` | `"True"` / `"False"` | A partition was opened or collapsed on this run. **Observability only** — surfaced in logs and the Step Function execution history so operators can quickly distinguish a sync run that opened/closed a partition from one that merely added an account to an existing one. Not branched on by the state machine. |
| `AccountsChanged` | `"True"` / `"False"` | At least one account was added to, or removed from, the DynamoDB state on this run (membership change, count may be unchanged). |
| `AccountsInP1` / `AccountsInP2` / `AccountsInP3` | comma-separated account IDs | Final per-partition membership; empty string for unused partition slots |

The Step Function's `MembershipChanged?` choice triggers a root-stack update when `AccountsChanged="True"`. This single condition covers both partition-count changes (opening or collapsing a partition is always accompanied by a membership change) and the count-stable membership-change case — a new account joining an existing partition with room leaves `PartitionCount` unchanged, but the *other* partitions' `ExcludedAccounts` lists must still be re-rendered so the new account doesn't receive multiple Organization Conformance Packs simultaneously. Testing `PartitionsChanged` in the choice would be strictly redundant, so it isn't.

## Environment Variables

| Variable | Description |
|----------|-------------|
| `PARTITION_TABLE_NAME` | Name of the DynamoDB partition state table |
| `MAX_ACCOUNTS_PER_PARTITION` | Max accounts per partition (default 70) |
| `MAX_PARTITIONS` | Maximum number of partitions allowed (default 3) |
