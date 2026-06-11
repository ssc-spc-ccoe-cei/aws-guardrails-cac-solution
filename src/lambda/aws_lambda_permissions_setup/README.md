# aws_lambda_permissions_setup

Synchronizes each guardrail Lambda clone's resource-based policy against the
account-to-partition mapping maintained by `aws_account_partitioner` in the
`gc-guardrails-partition-state` DynamoDB table.

## Why

AWS Lambda resource-based policies are capped at **20 KB**. With one
`AddPermission` statement per organization account, the policy on each
guardrail Lambda overflows around **~70 accounts**. To support up to **210
accounts**, accounts are split across up to **3 partitions of ≤70**, and each
guardrail Lambda is cloned per partition. This Lambda keeps each clone's
policy in sync with its partition's accounts so every clone stays well under
the 20 KB limit.

## Clone naming convention

For an organization name prefix `<org>` and guardrail suffix `<suffix>`:

| Partition | Clone function name        |
|-----------|----------------------------|
| 1         | `<org><suffix>`            |
| 2         | `<org><suffix>_p2`         |
| 3         | `<org><suffix>_p3`         |

## Per-run behaviour

1. Scan `gc-guardrails-partition-state` to build `{partition_id: {account_ids}}`.
2. For each (guardrail suffix × partition) pair:
   1. Compute the clone function name.
   2. `lambda:GetPolicy` → parse existing `config.amazonaws.com` /
      `lambda:InvokeFunction` Allow statements into `{account_id: Sid}`.
   3. **Add** an `AddPermission` statement for every desired account missing
      from the policy. The Sid is the smallest free `p<n>` (e.g., `p1`,
      `p2`, …) — kept short to minimize bytes against Lambda's 20 KB
      resource-policy cap.
   4. **Remove** the existing statement for every account in the policy that
      is no longer present in the partition's DynamoDB entries. In normal
      operation this only happens when an account has been closed,
      suspended, or transferred out of the AWS Organization — the
      partitioner never re-assigns an existing account to a different
      partition.
   5. If the clone Lambda does not exist (e.g., the `_p2`/`_p3` StackSet
      hasn't been updated yet), the clone is skipped with a warning — not a
      failure.

The sync is idempotent: re-running it when everything is already in sync is a
no-op (no API calls per clone beyond `GetPolicy`).

## Invocation contexts

| Context        | `RequestType` | Notes                                                                                     |
|----------------|---------------|-------------------------------------------------------------------------------------------|
| CloudFormation | `Create` / `Update` / `Delete` | Custom Resource in `AuditAccountPreRequisitesPartN.yaml`.                  |
| Step Function  | `StepFunction`                 | Final step of the `gc-guardrails-partition-sync` state machine (post-deploy ongoing sync). |

`Delete` is a no-op — Lambda permissions are removed automatically when the
function itself is deleted.

> The previous EventBridge cron that invoked this Lambda directly with
> `RequestType: Cron` has been removed; the post-deploy 6-hour schedule is
> now owned by the Step Function (see step 9 of `doc/RESOURCE_POLICY_FIX.md`).

## Environment variables

| Variable               | Default                          | Description                                                  |
|------------------------|----------------------------------|--------------------------------------------------------------|
| `OrganizationName`     | _(required)_                     | Prefix used in front of each guardrail suffix to build the Lambda function names. |
| `PARTITION_TABLE_NAME` | `gc-guardrails-partition-state`  | DynamoDB table that maps `AccountId` -> `PartitionId`. Wired in from `main.yaml` via the `PartitionStateTableName` StackSet parameter. |

## Required IAM

```yaml
- Sid: AllowLambdaPermissions
  Action:
    - "lambda:AddPermission"
    - "lambda:RemovePermission"
    - "lambda:GetPolicy"
    - "lambda:GetFunction"
  Resource:
    - "arn:aws:lambda:<region>:<account>:function:<OrganizationName>gc*"
  Effect: Allow
- Sid: AllowDynamoDBReadPartitionState
  Action:
    - "dynamodb:Scan"
    - "dynamodb:GetItem"
  Resource:
    - "arn:aws:dynamodb:<region>:<account>:table/gc-guardrails-partition-state"
  Effect: Allow
```

> Note: `organizations:*` is no longer required. Account enumeration is
> delegated to `aws_account_partitioner`.

## Sid scheme

Each new `AddPermission` statement is given the smallest free `p<n>` Sid
(e.g., `p1`, `p2`, …, `p70`). The short prefix keeps each statement compact
so the resource policy stays well within the 20 KB limit.

The association between Sid and account is **not** deterministic across runs
— the source of truth for "which account does this statement allow" is the
statement's `Condition.StringEquals.AWS:SourceAccount` value, which is what
this Lambda uses when computing add / remove diffs.
