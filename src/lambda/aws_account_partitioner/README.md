# aws_account_partitioner

Manages the partition state for guardrail Lambda cloning.

## Purpose

Partitions AWS Organization accounts into groups of ≤60 to keep each
guardrail Lambda's resource-based policy under the 20 KB limit.

## Invocation Contexts

| Context | Trigger |
|---------|---------|
| **Deployment** | CloudFormation Custom Resource in `main.yaml` |
| **Post-deployment** | Step 1 of the `gc-guardrails-partition-sync` Step Function (EventBridge cron) |

## Behaviour

1. Lists all active accounts via `organizations:ListAccounts`.
2. Reads current partition state from the `gc-guardrails-partition-state` DynamoDB table.
3. Assigns unassigned accounts to existing partitions with room (< 60), or creates a new partition (max 4).
4. Removes entries for inactive/deleted accounts.
5. Writes updated state back to DynamoDB.
6. Verifies the resulting CloudFormation Custom Resource response fits inside the 4096-byte cap (see [Response-size guard](#response-size-guard)).
7. Returns `partitionCount`, `partitionsChanged`, `accountsChanged`, and per-partition account lists.

## Return Shape

The Custom Resource response and the Step Function `Payload` share the same flat shape so downstream consumers have a single contract:

| Field | Type | Meaning |
|-------|------|---------|
| `PartitionCount` | `"0".."4"` | Total partitions in use |
| `PartitionsChanged` | `"True"` / `"False"` | A partition was opened or collapsed on this run. **Observability only** — surfaced in logs and the Step Function execution history so operators can quickly distinguish a sync run that opened/closed a partition from one that merely added an account to an existing one. Not branched on by the state machine. |
| `AccountsChanged` | `"True"` / `"False"` | At least one account was added to, or removed from, the DynamoDB state on this run (membership change, count may be unchanged). |
| `AccountsInP1` / `AccountsInP2` / `AccountsInP3` / `AccountsInP4` | comma-separated account IDs | Final per-partition membership; empty string for unused partition slots |

The Step Function's `MembershipChanged?` choice triggers a root-stack update when `AccountsChanged="True"`. This single condition covers both partition-count changes (opening or collapsing a partition is always accompanied by a membership change) and the count-stable membership-change case — a new account joining an existing partition with room leaves `PartitionCount` unchanged, but the *other* partitions' `ExcludedAccounts` lists must still be re-rendered so the new account doesn't receive multiple Organization Conformance Packs simultaneously. Testing `PartitionsChanged` in the choice would be strictly redundant, so it isn't.

## Environment Variables

| Variable | Description |
|----------|-------------|
| `PARTITION_TABLE_NAME` | Name of the DynamoDB partition state table |
| `MAX_ACCOUNTS_PER_PARTITION` | Max accounts per partition (default 60) |
| `MAX_PARTITIONS` | Maximum number of partitions allowed (default 4) |

## Response-size guard

A CloudFormation Custom Resource response body is hard-capped at
**4096 bytes**. Because this Lambda returns the *full* per-partition
account lists, the response grows linearly with the account count —
and at the maximum supported scale it is close to that cap:

| Active accounts | Partitions | Response body |
|---:|:---:|---:|
| 1 | 1 | 633 B |
| 60 | 1 | 1400 B |
| 120 | 2 | 2179 B |
| 180 | 3 | 2958 B |
| 240 (max) | 4 | **3737 B** |

This is why `MAX_PARTITIONS` is 4 and not higher: a 5th partition
would push the response past 4096 bytes.

`assert_cfn_response_fits()` serialises the exact body that `send()`
would upload to the pre-signed S3 URL, and:

- logs a **WARNING** when the body exceeds `CFN_RESPONSE_WARN_RATIO`
  (85 %) of the cap — expected at 240 accounts, and an early signal
  that the org is approaching the design ceiling;
- raises a `RuntimeError` when the body exceeds
  `CFN_RESPONSE_MAX_BYTES − CFN_RESPONSE_SAFETY_MARGIN_BYTES`
  (`4096 − 128 = 3968` bytes), **before** attempting the send.

The handler catches that error and returns a `FAILED` Custom Resource
status with the message as the CloudFormation `Reason`, giving a clean
explanatory rollback instead of CloudFormation blocking for an hour on
a response S3 silently rejected. The message notes explicitly that
raising `MaxPartitions` will *not* help — more partitions make the
response larger, not smaller — and points to
`doc/RESOURCE_POLICY_FIX.md`.

| Constant | Value | Purpose |
|---|---:|---|
| `CFN_RESPONSE_MAX_BYTES` | 4096 | CloudFormation's hard cap |
| `CFN_RESPONSE_SAFETY_MARGIN_BYTES` | 128 | Headroom reserved for presigned-URL/header variance |
| `CFN_RESPONSE_WARN_RATIO` | 0.85 | Utilisation above which a WARNING is logged |
