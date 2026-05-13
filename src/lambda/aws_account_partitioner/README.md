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
6. Returns `partitionCount` and `partitionsChanged`.

## Environment Variables

| Variable | Description |
|----------|-------------|
| `PARTITION_TABLE_NAME` | Name of the DynamoDB partition state table |
| `MAX_ACCOUNTS_PER_PARTITION` | Max accounts per partition (default 70) |
| `MAX_PARTITIONS` | Maximum number of partitions allowed (default 3) |
