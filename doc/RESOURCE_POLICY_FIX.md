# Resource Policy Size Limit Fix — Design Document

## Problem Statement

AWS Lambda resource-based policies have a **20KB size limit**. The current `aws_lambda_permissions_setup` Lambda adds one `lambda:AddPermission` statement per AWS account in the organization to every guardrail Lambda function (`gc*`). Each statement allows `config.amazonaws.com` to invoke the Lambda on behalf of that account.

At approximately **70 accounts**, the accumulated policy statements exceed 20KB, causing `PolicyLengthExceededException` errors. SSC customers operate environments with up to **200 accounts**, making this a blocking deployment issue.

## Current Behaviour

1. `AuditAccountPreRequisitesPart1–8` each deploy a set of guardrail Lambdas (e.g., `gc01_check_root_mfa`).
2. `AuditAccountPreRequisitesPartN` deploys `aws_lambda_permissions_setup`, which iterates every org account and calls `lambda:AddPermission` on each `gc*` Lambda — one statement per account.
3. `ConformancePack.yaml` defines Config Custom Rules pointing each account's evaluation at the single `gc*` Lambda by ARN.
4. An EventBridge cron re-runs `aws_lambda_permissions_setup` every 6 hours to pick up new accounts.

**Failure mode:** When the organization grows past ~70 accounts, the per-Lambda resource policy exceeds 20KB and `AddPermission` calls fail.

## Proposed Solution — Partitioned Lambda Cloning

> **Companion document:** [`CONFORMANCE_PACK_IMPLEMENTATION.md`](./CONFORMANCE_PACK_IMPLEMENTATION.md)
> covers the conformance-pack and Audit Manager portions of this design
> (Sections 4 and 5 below) in greater depth — including the full
> `ExcludedAccounts` YAML, per-partition condition combinations, the
> CloudFormation 4 KB response-cap analysis, and Audit Manager evidence
> routing diagrams. This document is the high-level design overview.

### Core Idea

Partition the organization's accounts into groups of **≤70** and create **one clone of each guardrail Lambda per partition**. Each clone's resource policy only contains the accounts in its partition, staying well within 20KB.

| Accounts | Partitions | Lambda copies per guardrail |
|----------|------------|-----------------------------|
| 1–70     | 1          | 1 (no change)               |
| 71–140   | 2          | 2                           |
| 141–210  | 3          | 3                           |

### Naming Convention

```
<org_name>gc01_check_root_mfa          ← partition 1 (or sole partition)
<org_name>gc01_check_root_mfa_p2       ← partition 2
<org_name>gc01_check_root_mfa_p3       ← partition 3
```

---

## New Components

### 1. DynamoDB Partition State Table

A single DynamoDB table stores the account-to-partition mapping. The schema is intentionally minimal — consuming processes reconstruct partition lists, counts, etc. at runtime.

**Table Name:** `gc-guardrails-partition-state`

| Attribute | Type | Description |
|-----------|------|-------------|
| `AccountId` (PK) | String | 12-digit AWS Account ID |
| `PartitionId` | Number | Partition number (1, 2, or 3) |

**Example items:**
```
{ "AccountId": "111111111111", "PartitionId": 1 }
{ "AccountId": "222222222222", "PartitionId": 1 }
{ "AccountId": "333333333333", "PartitionId": 2 }
```

Consumers can:
- **Get partition for an account:** `GetItem(AccountId)`.
- **Get all accounts in a partition:** `Scan` with `FilterExpression: PartitionId = :p` (≤210 items total, scan is fine).
- **Count accounts per partition:** Aggregate at runtime.
- **Get total partition count:** `max(PartitionId)` from a full scan.

The table is created in `main.yaml` alongside the partitioner Lambda.

#### Data durability and disruption safeguards

The table resource sets `DeletionPolicy: Retain` and `UpdateReplacePolicy: Retain` so a `cloudformation delete-stack` on the root cannot destroy live partition state, `DeletionProtectionEnabled: true` to block accidental console/CLI deletes, and `PointInTimeRecoverySpecification.PointInTimeRecoveryEnabled: true` for 35-day continuous backup - allowing for a point-in-time restore within minutes.

### 2. Account Partition Lambda (`aws_account_partitioner`)

A new Lambda function responsible for **managing partition state**. It runs in two contexts:

- **At deployment time:** As a CloudFormation Custom Resource in `main.yaml` (initial setup).
- **Post-deployment:** As Step 1 of the Step Function orchestration (triggered by cron).

**Behaviour:**

1. Queries `organizations:ListAccounts` for all active accounts.
2. Reads current partition state from DynamoDB.
3. Identifies new accounts not yet assigned and removed/suspended accounts.
4. **Greedily** assigns new (sorted) accounts to the lowest-numbered partition with room (< `MAX_ACCOUNTS_PER_PARTITION`), opening a new partition as needed up to `MAX_PARTITIONS`.
5. Removes entries for inactive/deleted accounts.
6. **Stable assignment:** existing rows in DynamoDB are never re-balanced — only new accounts are placed.
7. If a *trailing* partition becomes empty (e.g. every P3 account leaves), `partitionCount` is reduced to the highest occupied partition. Non-trailing partitions are **not** collapsed (an empty P2 with P3 still occupied leaves `partitionCount=3`).
8. Writes updated state back to DynamoDB.

**Return shape (identical in both CFN Custom Resource and Step Function contexts):**

| Field | Type | Description |
|---|---|---|
| `partitionCount` | int | Current number of partitions in use (1..`MAX_PARTITIONS`). |
| `partitionsChanged` | bool | True if `partitionCount` differs from the previous run. **Returned for observability only** — surfaced in CloudWatch logs, the Custom Resource response, and the Step Function execution history so operators can tell at a glance whether a sync run opened/collapsed a partition vs. merely added an account to an existing one. The Step Function does **not** branch on this flag (see `accountsChanged` below). |
| `accountsChanged` | bool | True if at least one account was added to, or removed from, the partition state on this run. **Critical:** the Step Function gates the root-stack UpdateStack cascade on this flag alone. It covers both the count-changing cases (opening or collapsing a partition is always accompanied by a membership change) and the count-stable case — a new account joining an existing partition with room leaves `partitionCount` unchanged, but the *other* partitions' `ExcludedAccounts` lists must still be re-rendered so the new account doesn't receive multiple Organization Conformance Packs simultaneously. Testing `partitionsChanged` in the choice would be strictly redundant. |
| `AccountsInP1` | string | Comma-separated 12-digit account IDs in partition 1. Empty string if unused. |
| `AccountsInP2` | string | As above for partition 2. |
| `AccountsInP3` | string | As above for partition 3. |

The per-partition account lists are consumed downstream by `ConformancePackPartitions.yaml` (see Section 4) to build each Organization Conformance Pack's `ExcludedAccounts`.

**CloudFormation 4 KB response-body cap.** Custom Resource response bodies are capped at 4096 bytes. With `MAX_ACCOUNTS_PER_PARTITION × MAX_PARTITIONS = 70 × 3 = 210` account IDs at ~14 bytes each (12-digit + comma), the combined `AccountsInPx` payload at 210 accounts is ~3.4 KB plus envelope — fits comfortably. Raising either limit further would require revisiting this.

---

### 3. Modified `AuditAccountPreRequisitesPart1–8.yaml`

Each template receives `PartitionCount` as a parameter. Using CloudFormation `Conditions`, it conditionally creates cloned Lambda functions:

```yaml
Conditions:
  CreatePartition2: !Not [!Equals [!Ref PartitionCount, "1"]]
  CreatePartition3: !Equals [!Ref PartitionCount, "3"]

Resources:
  GC01CheckRootMFALambda:          # always created (partition 1)
    ...
  GC01CheckRootMFALambdaP2:        # created if PartitionCount >= 2
    Condition: CreatePartition2
    ...
  GC01CheckRootMFALambdaP3:        # created if PartitionCount == 3
    Condition: CreatePartition3
    ...
```

All clones share the same code package and IAM execution role — only the `FunctionName` differs.

---

### 4. Modified `ConformancePack.yaml` + new `ConformancePackPartitions.yaml` — One Pack Per Partition

The original design considered deploying one Organization Conformance Pack containing
**three copies** of each Config rule (conditionally created per partition), with all
copies deployed to every account and the un-permitted ones failing closed.
**This was abandoned** because:

- CloudFormation `Conditions` are evaluated at template-processing time and cannot
  reference `!GetAtt` from a Custom Resource, so the per-partition account assignments
  produced by `aws_account_partitioner` cannot drive `Conditions` inside `main.yaml`.
- Fail-closed evaluations would muddy Config and Audit Manager evidence.

The adopted approach instead deploys **up to three separate `AWS::Config::OrganizationConformancePack` resources** — one per non-empty partition — each running the **same 37-rule template** (`ConformancePack.yaml`) but parameterised with a different Lambda-clone target. Per-pack `ExcludedAccounts` ensures every org account receives **exactly one** pack.

#### 4a. `ConformancePack.yaml` — single `PartitionSuffix` parameter

Rather than duplicating every rule three times, a single new input parameter is added:

```yaml
PartitionSuffix:
  Type: String
  Default: ""
  AllowedValues: ["", "_p2", "_p3"]
```

…and appended to every `ConfigRuleName` and to the Lambda function name in every
`SourceIdentifier` (37 rules × 2 substitutions). Example:

```yaml
# Before
ConfigRuleName: gc01_check_root_mfa
SourceIdentifier:
  Fn::Join: ["", ["arn:aws:lambda:ca-central-1:", !Ref AuditAccountID,
                  !Sub ":function:${OrganizationName}gc01_check_root_mfa"]]

# After
ConfigRuleName: !Sub "gc01_check_root_mfa${PartitionSuffix}"
SourceIdentifier:
  Fn::Join: ["", ["arn:aws:lambda:ca-central-1:", !Ref AuditAccountID,
                  !Sub ":function:${OrganizationName}gc01_check_root_mfa${PartitionSuffix}"]]
```

When the P2 pack passes `PartitionSuffix: "_p2"`, the deployed rule becomes
`gc01_check_root_mfa_p2` and targets the `<org>gc01_check_root_mfa_p2` Lambda clone.

#### 4b. `ConformancePackPartitions.yaml` — new nested stack

A new nested template replaces the single inline
`AWS::Config::OrganizationConformancePack` in `main.yaml`. **The logical name
`ConformancePack` is preserved** so the existing
`AuditAccountAuditManager DependsOn: ConformancePack` reference still resolves.

Why a nested stack: the per-partition account lists arrive from the partitioner as
`!GetAtt` values, which cannot be used in parent-stack `Conditions`. Passing them
into a nested stack as regular parameters lets the nested stack's `Conditions`
gate each pack on partition emptiness.

| Resource | Condition | `PartitionSuffix` | `ExcludedAccounts` |
|---|---|---|---|
| `ConformancePackP1` (`${OrganizationName}-GC-CP-Guardrails`)    | `HasAccountsInP1` | `""`    | union of P2 ∪ P3 (whichever are non-empty), or `AWS::NoValue` |
| `ConformancePackP2` (`${OrganizationName}-GC-CP-Guardrails-P2`) | `HasAccountsInP2` | `"_p2"` | union of P1 ∪ P3 (whichever are non-empty), or `AWS::NoValue` |
| `ConformancePackP3` (`${OrganizationName}-GC-CP-Guardrails-P3`) | `HasAccountsInP3` | `"_p3"` | union of P1 ∪ P2 (whichever are non-empty), or `AWS::NoValue` |

Each pack's `ExcludedAccounts` is built with a nested `!If` ladder so empty
`AccountsInP*` strings are never `!Split` into the list (which would produce
trailing empty elements that fail Config's `^\d{12}$` validation).

**Result:** every org account is targeted by exactly one pack — the one matching
its DynamoDB-assigned partition. For organisations with ≤ 70 accounts the result
is **indistinguishable from the pre-fix deployment**: one pack, no exclusions,
base `<org>gc*` Lambdas only — the upgrade path requires no manual configuration.

> See [`CONFORMANCE_PACK_IMPLEMENTATION.md`](./CONFORMANCE_PACK_IMPLEMENTATION.md)
> for the complete `ExcludedAccounts` `!If`-ladder YAML, all condition
> combinations, and the full parameter forwarding list.

---

### 5. Audit Manager custom framework — three `controlMappingSources` per control

Because Audit Manager controls reference Config rules by *name* (not ARN), each
control's `controlMappingSources` list is expanded from one entry to three —
one per partition variant (`…`, `…_p2`, `…_p3`) — so evidence is collected
regardless of which partition's Config rule produced an evaluation.

```python
"controlMappingSources": [
    {"sourceName": "RootMFA-check",     ..., "keywordValue": "Custom_gc01_check_root_mfa-conformance-pack"},
    {"sourceName": "RootMFA-check-p2",  ..., "keywordValue": "Custom_gc01_check_root_mfa_p2-conformance-pack"},
    {"sourceName": "RootMFA-check-p3",  ..., "keywordValue": "Custom_gc01_check_root_mfa_p3-conformance-pack"},
],
```

Key properties:

- Audit Manager's `CreateControl` / `UpdateControl` does **not** validate that
  the referenced Config rules exist — `keywordValue` is a soft string reference.
  At ≤ 70 accounts the `_p2` / `_p3` sources simply return zero evidence and
  contribute nothing to the merged control.
- Applies to **37 of 38 controls**; `gc01_check_attestation_letter` is documentation-only
  and stays at one mapping.
- Audit Manager's per-control limit of 5 `controlMappingSources` is well above the 3 used.
- **Forward-compatible with growth:** when an org later crosses 70 (or 140)
  accounts and `ConformancePackP2` (or `P3`) is deployed, the previously-empty
  sources start returning real evaluations on the next collection cycle — no
  framework redeploy, no control rename.

Control names themselves are unchanged, so `aws_compile_audit_report` (which
groups evidence by control name) continues to produce the same 38 CSV rows
regardless of partition count.

---

### 6. Modified `aws_lambda_permissions_setup` — Single Responsibility: Sync Permissions

The existing Lambda is simplified to a **single concern**: ensure each Lambda clone's resource-based policy matches the accounts in its DynamoDB partition.

**Behaviour:**

1. Read all items from `gc-guardrails-partition-state` DynamoDB table.
2. Reconstruct partition → account list mapping at runtime.
3. For each base guardrail Lambda and each partition:
   - Determine clone name (`gc*` for partition 1, `gc*_p2` for partition 2, etc.).
   - Call `GetPolicy` to read current resource-based policy statements.
   - **Add** `lambda:AddPermission` for accounts in the partition that are missing from the policy.
   - **Remove** `lambda:RemovePermission` for accounts in the policy that are no longer in the partition.
4. Return success/failure.

No state management, no account detection, no Lambda cloning. Just permission synchronization.

---

### 7. Step Function Orchestration — Post-Deployment Account Growth

A Step Function provides **observability** and **orchestration** for the ongoing sync process.

**Trigger:** EventBridge cron rule (every 6 hours).

**State Machine:**

```
┌─────────────────────────────────────────────────────────────┐
│  Step Function: gc-guardrails-partition-sync                 │
│                                                             │
│  ┌─────────────────────────┐                                │
│  │ Step 1: Invoke          │                                │
│  │ aws_account_partitioner │                                │
│  │                         │                                │
│  │ Output:                 │                                │
│  │  accountsChanged:   T/F │  (gates Step 2)                │
│  │  partitionCount:    N   │                                │
│  │  partitionsChanged: T/F │  (observability only)          │
│  │  AccountsInP1/P2/P3     │                                │
│  └────────────┬────────────┘                                │
│               │                                             │
│               ▼                                             │
│  ┌─────────────────────────┐                                │
│  │ Step 2: Choice          │                                │
│  │                         │                                │
│  │ MembershipChanged?      │                                │
│  │  (accountsChanged)      │                                │
│  └──┬──────────────────┬───┘                                │
│     │ true             │ false                              │
│     ▼                  │                                    │
│  ┌──────────────────┐  │                                    │
│  │ Step 3: Update   │  │                                    │
│  │ root stack       │  │                                    │
│  │ (UsePrevious-    │  │                                    │
│  │  Template=true)  │  │                                    │
│  │                  │  │                                    │
│  │ - Custom         │  │                                    │
│  │   Resource re-   │  │                                    │
│  │   runs           │  │                                    │
│  │ - Part1-8        │  │                                    │
│  │   StackSets see  │  │                                    │
│  │   new            │  │                                    │
│  │   PartitionCount │  │                                    │
│  │ - Conformance-   │  │                                    │
│  │   Pack nested    │  │                                    │
│  │   stack re-      │  │                                    │
│  │   renders with   │  │                                    │
│  │   fresh          │  │                                    │
│  │   ExcludedAccts  │  │                                    │
│  └────────┬─────────┘  │                                    │
│           │             │                                    │
│           ▼             ▼                                    │
│  ┌─────────────────────────────┐                            │
│  │ Step 4: Invoke              │                            │
│  │ aws_lambda_permissions_setup│                            │
│  │                             │                            │
│  │ Syncs resource policies     │                            │
│  │ for all Lambda clones       │                            │
│  └─────────────────────────────┘                            │
└─────────────────────────────────────────────────────────────┘
```

**Why Step Functions:**
- The `.sync` integration pattern natively waits for CloudFormation StackSet operations to complete — no Lambda timeout concerns, no polling logic.
- Full execution history for auditability and debugging.
- Built-in retry and error handling per step.
- Visual workflow in the AWS Console.

**Step 3 detail:** Uses the Step Functions AWS SDK integration to call `cloudformation:UpdateStackSet` with the `.sync` suffix. This updates `AuditAccountPreRequisitesPart1–8` with the new `PartitionCount` parameter (which conditionally creates/removes Lambda clones) and triggers re-evaluation of the `ConformancePackPartitions` nested stack, which adds or removes whole conformance packs based on which partitions are now non-empty.

---

## Proposed Solution Diagrams

The system has two distinct flows: a one-shot **deployment-time** flow
driven by CloudFormation, and a recurring **post-deployment runtime**
flow driven by an EventBridge cron and a Step Function. They are shown
separately below.

### Diagram 1 — Deployment-time (CloudFormation orchestration)

Runs once per `aws cloudformation deploy` of `root.yaml`. The partitioner
runs as a CloudFormation Custom Resource, populates the
`gc-guardrails-partition-state` DynamoDB table, and returns
`PartitionCount` + `AccountsInP1/P2/P3` as Custom Resource attributes
that the rest of the template `!GetAtt`s into the StackSets and the
nested `ConformancePack` stack. The Step Function and its EventBridge
rule are created here but do not fire until 6 hours after deployment.

```mermaid
flowchart TB
    subgraph DEPLOY["Deployment-time — CloudFormation Orchestration (one shot)"]
        direction TB

        root["root.yaml"]
        main["main.yaml"]

        ddb["DynamoDB:\ngc-guardrails-partition-state"]
        partLambda["aws_account_partitioner\n(Lambda)"]
        partCR["InvokeAccountPartitioner\n(CFN Custom Resource)"]

        parts["AuditAccountPreRequisitesPart1..8\n(StackSets — base gc* Lambdas\n+ conditional _p2 / _p3 clones)"]
        partN["AuditAccountPreRequisitesPartN\n(StackSet)"]
        permLambda["aws_lambda_permissions_setup\n(Lambda + CFN Custom Resource —\ninitial policy sync)"]

        nested["ConformancePackPartitions\n(nested stack)"]
        packs["1..3 OrganizationConformancePack\nresources, each loading\nConformancePack.yaml with a\ndifferent PartitionSuffix"]

        am["AuditAccountAuditManager\n(StackSet)"]
        framework["audit_manager_custom_framework.py\n(3 controlMappingSources / control)"]

        psStack["PartitionSyncStack\n(nested stack)"]
        sfn["PartitionSyncStateMachine\n(defined — idle for first 6h)"]
        cron["PartitionSyncScheduleRule\n(EventBridge rate(6 hours) —\nfirst fire in 6h)"]

        root --> main

        main --> ddb
        main --> partLambda
        main --> partCR
        partCR -->|"invokes once"| partLambda
        partLambda -->|"PutItem per\nactive account"| ddb
        partCR -.->|"PartitionCount,\nAccountsInP1/P2/P3"| main

        main -->|"PartitionCount"| parts
        main -->|"AccountsInP1/P2/P3"| nested
        nested --> packs

        main --> psStack
        psStack --> sfn
        psStack --> cron

        main --> partN
        psStack -.->|"DependsOn\n(role must exist before\nLambdaPermissionsLambda-\nInvokeByStateMachine\ncalls AddPermission)"| partN
        partN --> permLambda
        permLambda -->|"reads, then\nAddPermission per account"| ddb

        main --> am
        am -.->|"loads"| framework
    end

    classDef yaml fill:#fff,stroke:#e91e63,stroke-width:2px,color:#333;
    classDef aws fill:#f28c28,stroke:#f28c28,color:#fff;
    classDef newcomp fill:#4caf50,stroke:#388e3c,color:#fff;
    classDef ddb fill:#1565c0,stroke:#0d47a1,color:#fff;
    classDef idle fill:#eee,stroke:#999,color:#666,stroke-dasharray: 5 5;

    class root,main,parts,partN,nested,packs,am,psStack yaml;
    class permLambda,framework aws;
    class partLambda,partCR newcomp;
    class ddb ddb;
    class sfn,cron idle;
```

### Diagram 2 — Post-deployment runtime (Step Function on 6-hour cron)

After deployment, the EventBridge rule fires every 6 hours and starts
the `PartitionSyncStateMachine`. The state machine refreshes the
partition state in DynamoDB and — whenever partition *membership*
changed (any account added to or removed from the table) — calls
`cloudformation:UpdateStack` on the root with a bumped `InvokeUpdate`
parameter. That re-runs the `InvokeAccountPartitioner` Custom Resource
(which has `InvokeUpdate: !Ref InvokeUpdate` as a property), cascading
fresh `AccountsInP1/P2/P3` into the nested `ConformancePack` stack and
fresh `PartitionCount` into the Part1-8 StackSets. The state machine
polls the root stack until `UPDATE_COMPLETE`, then invokes the
permissions Lambda to bring each clone's resource-based policy in line
with the new DynamoDB state.

> **Why the choice gates on `accountsChanged` alone.** Every partition-
> count change is necessarily accompanied by a membership change (the
> account that opened the new partition, or the removal that collapsed
> a trailing one), so `accountsChanged` is sufficient on its own —
> testing `partitionsChanged` in the choice would be strictly redundant.
> `accountsChanged` also covers the count-stable membership-change
> case: a new account joining an existing partition with room leaves
> `partitionCount` unchanged, but the *other* partitions'
> `ExcludedAccounts` lists must still be re-rendered so the new account
> doesn't simultaneously receive both the P1 pack (because it's no
> longer in P1's exclusion list) and its assigned partition's pack —
> that would produce `INSUFFICIENT_DATA` Config evaluations on the
> duplicated rules until the next CICD deploy. `partitionsChanged` is
> still returned by the partitioner and captured into the Step Function
> execution history for observability (it lets operators quickly tell a
> partition-opening run from a routine account-add), but the choice
> ignores it.

```mermaid
flowchart TB
    subgraph RUNTIME["Post-deployment Runtime — Step Function (every 6 hours)"]
        direction TB

        cron["PartitionSyncScheduleRule\n(EventBridge rate(6 hours))"]

        subgraph SF["PartitionSyncStateMachine"]
            direction TB
            s1["1. InvokePartitioner\n(Lambda Task)"]
            s2{"2. MembershipChanged?\n(accountsChanged)"}
            s3["3. UpdateRootStack\n(SDK: cloudformation:updateStack —\nbump InvokeUpdate only,\nUsePreviousTemplate=true)"]
            s4["4. WaitForStackUpdate (60s)\n→ DescribeRootStack\n→ poll until UPDATE_COMPLETE"]
            s5["5. InvokePermissionsSync\n(Lambda Task)"]
            s1 --> s2
            s2 -->|"True"| s3
            s3 --> s4
            s4 --> s5
            s2 -->|"False"| s5
        end

        partLambda["aws_account_partitioner"]
        permLambda["aws_lambda_permissions_setup"]
        ddb["DynamoDB:\ngc-guardrails-partition-state"]

        root["Root stack\n(CFN re-evaluates on UpdateStack)"]
        cr["InvokeAccountPartitioner\nCustom Resource\n(property change → re-runs)"]
        parts["Part1..8 StackSets"]
        nested["ConformancePackPartitions\nnested stack"]
        clones["Lambda clones:\ngc*  /  gc*_p2  /  gc*_p3"]
        packs["1..3 OrganizationConformancePacks"]

        cron -->|"triggers"| SF

        s1 -->|"invoke"| partLambda
        partLambda -->|"PutItem / DeleteItem"| ddb

        s3 -->|"UpdateStack"| root
        root -->|"re-runs"| cr
        cr -->|"invoke"| partLambda
        cr -.->|"new PartitionCount,\nAccountsInP1/P2/P3"| root
        root -->|"new PartitionCount"| parts
        parts -->|"create / destroy"| clones
        root -->|"new AccountsInP1/P2/P3"| nested
        nested -->|"create / destroy"| packs

        s5 -->|"invoke"| permLambda
        permLambda -->|"Scan"| ddb
        permLambda -->|"AddPermission /\nRemovePermission"| clones
    end

    classDef sfstate fill:#f3e5f5,stroke:#7b1fa2,color:#4a148c;
    classDef sfchoice fill:#fff,stroke:#7b1fa2,color:#4a148c,stroke-width:2px;
    classDef aws fill:#f28c28,stroke:#f28c28,color:#fff;
    classDef cron fill:#e91e63,stroke:#e91e63,color:#fff;
    classDef newcomp fill:#4caf50,stroke:#388e3c,color:#fff;
    classDef ddb fill:#1565c0,stroke:#0d47a1,color:#fff;
    classDef yaml fill:#fff,stroke:#e91e63,stroke-width:2px,color:#333;

    class s1,s3,s4,s5 sfstate;
    class s2 sfchoice;
    class partLambda,permLambda,clones aws;
    class cron cron;
    class ddb ddb;
    class root,parts,nested,packs yaml;
    class cr newcomp;
```

---

## Post-Deployment Account Growth Handling

The **key requirement** is that after initial deployment, when new accounts join the organization, permissions are adjusted automatically without manual redeployment.

### Behaviour at Each Scale

| Active accounts | Partitions | Packs deployed | Behaviour |
|---:|:---:|:---|:---|
| 1–70 | 1 | `…-GC-CP-Guardrails` only | **Indistinguishable from pre-fix deployment.** No `ExcludedAccounts`. Every account targets base `<org>gc*` Lambdas. |
| 71–140 | 2 | `…` + `…-P2` | Each pack lists the *other* partition's accounts in `ExcludedAccounts`, so every account receives exactly one pack. P1 accounts target base Lambdas; P2 accounts target `_p2` clones. |
| 141–210 | 3 | `…` + `…-P2` + `…-P3` | Each pack excludes the union of the other two partitions' accounts. Three sets of Lambda clones, three packs, every account in exactly one of them. |
| >210 | — | (failure) | Partitioner raises and the Custom Resource / Step Function step fails. Manual intervention required (raise `MaxAccountsPerPartition`, `MaxPartitions`, or both — but mind the CFN 4 KB response cap). |

Existing account-to-partition assignments are **stable**: they are never re-balanced, only new accounts are placed.

### Flow by Scenario

| Scenario | Step Function Behaviour |
|----------|------------------------|
| **No change** (steady state) | Partitioner sees no diff vs. DynamoDB. `accountsChanged=false` (and `partitionsChanged=false`). UpdateRootStack branch skipped. Permissions Lambda still runs and is a no-op on the resource policies. |
| **New account, partition has room** | Partitioner assigns account to a partition that's still under 70 and writes to DynamoDB. `accountsChanged=true` (`partitionsChanged=false`, since count is unchanged), so the UpdateRootStack branch fires. The root-stack update re-renders `ConformancePackPartitions` with fresh `ExcludedAccounts` lists for every pack (the new account appears in the OTHER packs' exclusion lists so it only receives its own partition's pack). Permissions Lambda then calls `AddPermission` for the new account on the relevant clone. |
| **New account, all partitions full** | Partitioner opens a new partition and writes to DynamoDB. `accountsChanged=true` (and `partitionsChanged=true`, logged for observability). UpdateRootStack branch fires; the StackSet update creates the new Lambda clones, the root re-renders `ConformancePackPartitions` which adds the new `ConformancePackP2`/`P3`. Permissions Lambda then adds permissions for all accounts in the new partition. |
| **Account removed/suspended** | Partitioner removes the account from DynamoDB. `accountsChanged=true` (and `partitionsChanged=true` if the removal empties a *trailing* partition and drops `partitionCount`, otherwise `partitionsChanged=false`). UpdateRootStack branch fires; `ConformancePackPartitions` re-renders with the removed account stripped from every `ExcludedAccounts` list. Permissions Lambda calls `RemovePermission` for the stale account on the relevant clone. |
| **>210 accounts** | Partitioner raises and the Custom Resource / Step Function step fails. CloudWatch alarm fires. Manual intervention required. |
| **Step Function step fails** | Built-in retry (configurable). Execution history shows exactly which step failed. Next cron in 6h retries from scratch. |

### Deployment-Time vs. Post-Deployment

| Phase | What runs | How |
|-------|-----------|-----|
| **Initial deploy** | `aws_account_partitioner` as CFN Custom Resource → outputs `PartitionCount` + `AccountsInP1/P2/P3` → StackSets and `ConformancePackPartitions` nested stack consume them → `aws_lambda_permissions_setup` runs as CFN Custom Resource in PartN | CloudFormation orchestrates everything |
| **Post-deploy (cron)** | Step Function: partitioner → (optional StackSet update) → permissions sync | EventBridge → Step Function |

---

## Required IAM Permissions

### `aws_account_partitioner`

```yaml
- Sid: AllowOrganizationsRead
  Action:
    - "organizations:ListAccounts"
    - "organizations:DescribeOrganization"
  Resource: "*"
  Effect: Allow
- Sid: AllowDynamoDBAccess
  Action:
    - "dynamodb:PutItem"
    - "dynamodb:DeleteItem"
    - "dynamodb:Scan"
    - "dynamodb:GetItem"
  Resource:
    - !GetAtt PartitionStateTable.Arn
  Effect: Allow
```

### `aws_lambda_permissions_setup`

```yaml
- Sid: AllowLambdaPermissions
  Action:
    - "lambda:AddPermission"
    - "lambda:RemovePermission"
    - "lambda:GetPolicy"
  Resource:
    - !Sub "arn:aws:lambda:${AWS::Region}:${AWS::AccountId}:function:${OrganizationName}gc*"
  Effect: Allow
- Sid: AllowDynamoDBRead
  Action:
    - "dynamodb:Scan"
    - "dynamodb:GetItem"
  Resource:
    - !GetAtt PartitionStateTable.Arn
  Effect: Allow
```

### Step Function Execution Role

```yaml
- Sid: AllowInvokeLambdas
  Action:
    - "lambda:InvokeFunction"
  Resource:
    - !GetAtt AccountPartitionerLambda.Arn
    - !GetAtt LambdaPermissionsLambda.Arn
  Effect: Allow
- Sid: AllowStackSetUpdates
  Action:
    - "cloudformation:UpdateStackSet"
    - "cloudformation:DescribeStackSetOperation"
  Resource:
    - !Sub "arn:aws:cloudformation:${AWS::Region}:${AWS::AccountId}:stackset/*"
  Effect: Allow
- Sid: AllowParentStackUpdate
  # Needed to re-render the ConformancePackPartitions nested stack
  # when AccountsInP1/P2/P3 change.
  Action:
    - "cloudformation:UpdateStack"
    - "cloudformation:DescribeStacks"
    - "cloudformation:DescribeStackEvents"
  Resource:
    - !Sub "arn:aws:cloudformation:${AWS::Region}:${AWS::AccountId}:stack/${AWS::StackName}/*"
  Effect: Allow
```

---

## Testing Plan

### Preconditions

- Dev AWS Organization with management-account access plus permission
  to call `organizations:CreateAccount` and
  `organizations:CloseAccount`. (Closed accounts cannot be reactivated
  and remain `SUSPENDED` against the org account quota for ~90 days —
  size the dev-org quota to ≥ 250 before starting.)
- Starting state: organisation has only a handful (≤ 10) of active
  accounts, and the DynamoDB table
  `${OrganizationName}-gc-guardrails-partition-state` does **not** yet
  exist (the first deploy creates it).

### Phase 1 — Initial deployment at 1 partition

#### T1 — Fresh deploy with empty DynamoDB

**Goal:** Validate the deployment-time CloudFormation orchestration on
a small organisation. Confirms the partitioner Custom Resource, the
DynamoDB table creation, the conditional-Lambda-clone logic (none
should be created), the single Organization Conformance Pack, the
Audit Manager framework, and the initial `aws_lambda_permissions_setup`
Custom Resource all run cleanly. **This is also the baseline against
which behaviour at ≤ 70 accounts must be "indistinguishable from the
pre-fix deployment".**

**Preconditions:** Org has ~5 active accounts; no prior deployment.

**Steps:**
1. From the management account, run `make deploy`.
2. Wait for the root stack to reach `CREATE_COMPLETE` (~30–60 min
   due to StackSet propagation).
3. Record the DynamoDB scan output to the scratchpad as the **T1
   snapshot** for later stability comparison.

**Success criteria:**
- DynamoDB table exists with `DeletionProtectionEnabled=true`, PITR
  enabled, and one item per active account, all with `PartitionId=1`.
- For every guardrail base Lambda `<org>gc*`:
  - **Only** the base version exists — no `_p2` or `_p3` clones.
  - `aws lambda get-policy` returns one statement per active
    account ID; policy size is well under 20 KB.
- Exactly **one** `AWS::Config::OrganizationConformancePack` resource:
  `<org>-GC-CP-Guardrails`, with **no** `ExcludedAccounts`.
- `InvokeAccountPartitioner` Custom-Resource `Data` shows:
  `PartitionCount=1`, `AccountsInP1=<CSV of all active account IDs>`,
  `AccountsInP2=""`, `AccountsInP3=""`.
- Audit Manager custom framework deployed; each of the 37 controls
  has 3 `controlMappingSources` (`gc01_check_root_mfa`,
  `…_p2`, `…_p3`); `gc01_check_attestation_letter` has 1.
- `PartitionSyncStateMachine` exists and the
  `PartitionSyncScheduleRule` EventBridge rule is `Enabled`.

---

### Phase 2 — Post-deployment scale-up (monotonic account creation)

> Between every account-creation batch in this phase, **either** wait
> for the next 6-hour cron firing of `PartitionSyncStateMachine`,
> **or** start an execution manually (`aws stepfunctions start-execution
> …`). Manual triggers are recommended throughout testing to keep
> wall-clock time down. Expect each scale-up Step Function run that
> branches into `UpdateRootStack` to take ~15–30 min (StackSet cascade).

#### T2 — Grow to 70 accounts (still 1 partition)

**Goal:** Confirm the partitioner adds new accounts to partition 1
greedily without opening partition 2 while there is still room.

**Account op:** Create accounts until total active = **70**
(`+65 vs. T1`). Batches of ~10 in parallel are safe.

**Steps:**
1. Create the new accounts.
2. Manually start the Step Function and wait for `Succeeded`.

**Success criteria:**
- DynamoDB has exactly **70 items, all `PartitionId=1`**.
- Partitioner Step output: `partitionCount=1`,
  `partitionsChanged=False`, `accountsChanged=True`,
  `AccountsInP1` lists all 70 IDs.
- Step Function choice took the `MembershipChanged?=True` branch and
  executed `UpdateRootStack` (because `accountsChanged=True`).
- Still **only base Lambdas** exist (no `_p2`/`_p3`); base Lambda
  resource policies now list all 70 accounts.
- Still **one** Conformance Pack, still no `ExcludedAccounts`.

#### T3 — Add 71st account (cross the 1→2 boundary)

**Goal:** Validate the boundary at `MAX_ACCOUNTS_PER_PARTITION+1`.
The partitioner must open partition 2 and place the new account
there; StackSet update must create the `_p2` Lambda clones; nested
`ConformancePackPartitions` must create `ConformancePackP2`.

**Account op:** Create **1** account (`+1 vs. T2`, total = 71).

**Steps:**
1. Create the 71st account.
2. Manually start the Step Function and wait for `Succeeded`
   (allow ~30 min for the cascading StackSet update).
3. Record the 71-account DDB snapshot.

**Success criteria:**
- DynamoDB has **70 items in P1**, **1 item in P2**.
- Partitioner output: `partitionCount=2`, `partitionsChanged=True`,
  `accountsChanged=True`.
- For every guardrail: both `<org>gc*` *and* `<org>gc*_p2` Lambdas
  exist. `_p3` clones still do **not** exist.
- `<org>gc*` resource policy lists 70 accounts; `<org>gc*_p2`
  resource policy lists 1 account.
- **Two** Conformance Packs deployed:
  - `<org>-GC-CP-Guardrails` with `ExcludedAccounts = [<71st account ID>]`.
  - `<org>-GC-CP-Guardrails-P2` with `ExcludedAccounts = <70 P1 IDs>`.
- The 71st account receives **exactly one** pack (P2), the others
  receive only P1; verify in AWS Config console under the new
  account's view.

#### T4 — Grow to 140 accounts (still 2 partitions, fill P2)

**Goal:** Confirm new accounts continue filling P2 up to its
capacity without opening P3.

**Account op:** Create **69** accounts (total = 140).

**Steps:**
1. Create the accounts (batches of ~10).
2. Manually start the Step Function; wait for `Succeeded`.

**Success criteria:**
- DDB: **70 in P1, 70 in P2**.
- Partitioner: `partitionCount=2`, `partitionsChanged=False`,
  `accountsChanged=True`.
- Still only base + `_p2` clones (no `_p3`).
- Base Lambda resource policy: 70 accounts; `_p2` policy: 70 accounts.
- Both packs' `ExcludedAccounts` lists are exact mirrors of the
  *other* partition (70 IDs each).

#### T5 — Initial deploy at 2 partitions (tear-down + clear DDB + redeploy)

**Goal:** Validate the **initial-deploy code path** at the
2-partition scale, exercising the partitioner Custom Resource on a
clean DDB with 140 active accounts. This is the only opportunity to
test this path without further account churn.

**Account op:** None.

**Steps:**
1. Disable DDB deletion protection, delete the partition-state table
   (see "Note on clear DDB steps" above).
2. `aws cloudformation delete-stack --stack-name <root-stack>` and
   wait for `DELETE_COMPLETE`. (The Audit Manager framework and any
   AWS Config recorders are removed too — expected.)
3. `make deploy` from a clean checkout.
4. Wait for `CREATE_COMPLETE`.

**Success criteria:**
- New DDB table created, 140 items, **70 in P1, 70 in P2**.
- Partitioner Custom-Resource succeeds; `Data` includes both
  `AccountsInP1` and `AccountsInP2`, `AccountsInP3=""`.
- Base Lambdas + `_p2` clones created; no `_p3`.
- Two Conformance Packs deployed with correct `ExcludedAccounts`.
- Audit Manager framework redeployed with 3 mapping sources per
  control.
- No `lambda:PolicyLengthExceededException` in any Lambda invocation
  log (each clone's policy holds at most 70 accounts).

#### T6 — Add 141st account (cross the 2→3 boundary)

**Goal:** Boundary test for opening partition 3.

**Account op:** Create **1** account (total = 141).

**Steps:** Create the account, manually start the Step Function,
wait for `Succeeded`.

**Success criteria:**
- DDB: **70 in P1, 70 in P2, 1 in P3**.
- Partitioner: `partitionCount=3`, `partitionsChanged=True`,
  `accountsChanged=True`.
- Base + `_p2` + `_p3` clones all exist for every guardrail.
- `<org>gc*_p3` resource policy lists exactly 1 account.
- **Three** Conformance Packs deployed; each one's
  `ExcludedAccounts` is the union of the other two partitions'
  members.

#### T7 — Grow to 200 accounts (4 KB CFN cap during *update* path)

**Goal:** Stress-test the partitioner Custom Resource at near-maximum
load over the Step Function's `UpdateRootStack` update path.
Confirms the combined `AccountsInP1/P2/P3` payload fits under the
4096-byte CloudFormation Custom-Resource response cap.

**Account op:** Create **59** accounts (total = 200). Recommend doing
this in **one** large batch and triggering the Step Function **once**
afterward, rather than after every account, to compress the
~30 min update cascade into a single execution.

**Steps:**
1. Create the accounts.
2. Manually start the Step Function; wait for `Succeeded`.
3. Open the root stack → `InvokeAccountPartitioner` → **Data** and
   measure the JSON response size (or check the partitioner's
   CloudWatch logs for the line where it logs the response body).

**Success criteria:**
- DDB: **70 in P1, 70 in P2, 60 in P3**.
- Partitioner Custom-Resource response body **< 4096 bytes**.
  (210 accounts × ~14 B + envelope ≈ 3.4 KB headroom; 200 accounts
  is well within this.)
- All three sets of clones exist; resource-policy sizes for each
  clone remain well under 20 KB.
- All 200 accounts are covered by exactly one of the three packs.

#### T8 — Account-stability spot check (no account ops)

**Goal:** Verify that across T1 → T7, the partitioner **never
re-balanced** existing assignments — only placed new accounts.

**Steps:**
1. Take a fresh DDB scan.
2. Diff the **T1 snapshot** account IDs against the current DDB —
   every T1 account ID must still appear with `PartitionId=1`.
3. Diff the **T3 snapshot** (the original 71st account) — must still
   appear with `PartitionId=2`.

**Success criteria:**
- 100 % of the T1 accounts have the same `PartitionId=1` they were
  first assigned.
- The T3 boundary-account is still in `PartitionId=2`.

---

### Phase 3 — Redeploy validation at 3 partitions (no account changes)

#### T9 — Tear-down + redeploy with DynamoDB retained

**Goal:** Validate `DeletionPolicy: Retain` on the partition-state
table — a `delete-stack` must leave the DDB items intact, and a
subsequent `make deploy` must preserve every prior assignment.

**Account op:** None.

**Steps:**
1. Record the current DDB scan as the **pre-T9 snapshot**.
2. `delete-stack` the root; wait for `DELETE_COMPLETE`. Do **not**
   touch the DDB table.
3. `make deploy`; wait for `CREATE_COMPLETE`.
4. Re-scan DDB.

**Success criteria:**
- The post-redeploy DDB scan is **bit-for-bit identical** to the
  pre-T9 snapshot (same account → partition mapping).
- Partitioner Custom-Resource output reports `accountsChanged=False`
  and `partitionsChanged=False` (the existing assignments matched
  the live org list).
- No Lambda resource-policy churn (the permissions Lambda finds
  every account already permitted on the correct clone).
- All three packs come back with the same `ExcludedAccounts` they
  had before tear-down.

#### T10 — Tear-down + clear DDB + redeploy at 200 (initial deploy at 3 partitions)

**Goal:** Validate the **initial-deploy code path at maximum scale**
— specifically the 4 KB Custom-Resource response cap during the
first run of the partitioner, when the response cannot be incremental.

**Account op:** None.

**Steps:**
1. Clear the DDB table (per "Note on clear DDB steps").
2. `delete-stack` the root; wait for `DELETE_COMPLETE`.
3. `make deploy`; wait for `CREATE_COMPLETE`.
4. Record the new DDB scan as the **post-T10 snapshot**.

**Success criteria:**
- All criteria from T1 + T6 + T7 hold.
- Partitioner Custom-Resource response body **< 4096 bytes** on
  this fresh deploy (the most critical instance of this test — a
  failure here would block deployment entirely, with no Step
  Function safety net yet running).
- The new assignment is greedy/dense (P1=70, P2=70, P3=60) but the
  *specific* account → partition mapping may differ from the
  pre-T9 snapshot — that is expected after a clear-DDB.

---

### Phase 4 — Post-deployment scale-down (monotonic account closures)

> **Pick the accounts to close from the post-T10 DDB snapshot** so
> the test exercises a specific partition. Use:
>
> ```bash
> aws dynamodb scan --table-name <org>-gc-guardrails-partition-state \
>   --filter-expression "PartitionId = :p" \
>   --expression-attribute-values '{":p":{"N":"1"}}' \
>   --projection-expression AccountId \
>   --output text | awk '{print $2}'
> ```
>
> `CloseAccount` is **irreversible** and the account stays
> `SUSPENDED` against the org quota for ~90 days. Sanity-check the
> list before closing.

#### T11 — Steady-state no-op (no ops at all)

**Goal:** Confirm that a Step Function run with **no** account changes
since the previous partitioner run skips the `UpdateRootStack`
branch entirely, and that the permissions Lambda is a no-op.

**Account op:** None.

**Steps:**
1. Immediately after T10 (DDB matches the org), manually start the
   Step Function.
2. Inspect the execution graph.

**Success criteria:**
- Partitioner step output: `accountsChanged=False`,
  `partitionsChanged=False`.
- The choice state takes the **`False`** branch — `UpdateRootStack`,
  `WaitForStackUpdate`, `DescribeRootStack`, `StackUpdateComplete?`
  states are **all skipped**.
- `InvokePermissionsSync` runs and logs zero `AddPermission` /
  `RemovePermission` calls.
- Execution duration < 30 s.

#### T12 — Empty non-trailing partition P1 (`partitionCount` stays at 3)

**Goal:** Validate the *non-trailing* emptying rule — a non-trailing
empty partition does **not** collapse `partitionCount`; the
"hole" is preserved so existing P2/P3 accounts keep their
assignments.

**Account op:** Close **all 70 accounts in P1** (use the projection
above to get the list). Total active: 200 → 130.

**Steps:**
1. `aws organizations close-account --account-id <id>` for each P1
   member. Wait ~1–2 min for `Status='SUSPENDED'` to propagate
   across all of them.
2. Confirm `list-accounts --query "Accounts[?Status=='ACTIVE'].Id"`
   returns exactly 130 IDs.
3. Manually start the Step Function; wait for `Succeeded`.

**Success criteria:**
- DDB: **0 items with `PartitionId=1`**, 70 with `PartitionId=2`,
  60 with `PartitionId=3`. Total items: 130.
- Partitioner output: **`partitionCount=3`** (unchanged because P3
  is still occupied), `partitionsChanged=False`,
  `accountsChanged=True`.
- All three sets of Lambda clones **still exist** (the StackSet is
  not asked to destroy any clones because `PartitionCount` did not
  change).
- `<org>gc*` (base/P1) resource policy is now **empty** (or holds
  only the AddPermission sids that were never removed — verify the
  permissions Lambda issued `RemovePermission` for all 70).
- **All three** Conformance Packs are still deployed.
  - `<org>-GC-CP-Guardrails` (P1) has no live targets but is **not
    deleted** — `ConformancePackP1`'s `HasAccountsInP1` condition is
    based on `AccountsInP1` being non-empty; with `AccountsInP1=""`
    the pack is **destroyed**. (Either outcome is acceptable as long
    as no account is multi-targeted; verify by spot-checking a P2
    and a P3 account in the Config console — each should still show
    exactly one pack.)
- The T7-recorded P2 and P3 account IDs still have their
  original `PartitionId` (stability across the scale-down).

#### T13 — Empty trailing partition P3 (collapse `partitionCount` to 2)

**Goal:** Validate the *trailing* collapse rule — when the
highest-numbered partition empties, `partitionCount` drops to the
new highest occupied partition.

**Account op:** Close **all 60 accounts in P3**. Total active: 130 → 70.

**Steps:**
1. Close each P3 account (`close-account`).
2. Wait for `SUSPENDED` propagation; confirm 70 active accounts.
3. Manually start the Step Function; wait for `Succeeded`.

**Success criteria:**
- DDB: 0 items in P1, 70 in P2, **0 items with `PartitionId=3`**.
  Total items: 70.
- Partitioner output: **`partitionCount=2`** (collapsed from 3
  because P3 was trailing), `partitionsChanged=True`,
  `accountsChanged=True`.
- StackSet update **destroys** every `<org>gc*_p3` Lambda clone.
- `ConformancePackP3` is **destroyed** by the nested-stack update.
- `<org>gc*_p2` resource policy still lists its 70 P2 accounts —
  unchanged by the trailing collapse.
- P2 account → partition mapping is unchanged (stability).

---

### Phase 5 — Final validation (initial deploy at 1 partition, re-densing)

#### T14 — Tear-down + clear DDB + redeploy at 70 accounts

**Goal:** Re-validate the 1-partition initial-deploy path with a
moderate (not tiny) account count, and confirm that a **clear-DDB
redeploy** re-denses the previously-sparse P1/P2/P3 layout back into
a dense P1.

**Account op:** None.

**Steps:**
1. Clear the DDB table.
2. `delete-stack` the root; wait for `DELETE_COMPLETE`.
3. `make deploy`; wait for `CREATE_COMPLETE`.

**Success criteria:**
- DDB has exactly **70 items, all `PartitionId=1`** (re-densed —
  the previously-empty "P1 hole" from T12 has been backfilled by
  the partitioner reassigning from scratch).
- Only base `<org>gc*` Lambdas exist; no `_p2` or `_p3` clones.
- Only **one** Conformance Pack: `<org>-GC-CP-Guardrails`, no
  `ExcludedAccounts`.
- Steady-state behaviour from this point is **indistinguishable from
  a brand-new ≤ 70-account deployment**.