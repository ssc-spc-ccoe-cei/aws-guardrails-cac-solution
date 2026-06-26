# Enhancing the Existing Solution

This document describes how to add new rules to the solution.

> **Partition-aware deployment.** Since the resource-policy size fix
> (see [`RESOURCE_POLICY_FIX.md`](./RESOURCE_POLICY_FIX.md) and
> [`CONFORMANCE_PACK_IMPLEMENTATION.md`](./CONFORMANCE_PACK_IMPLEMENTATION.md)),
> every guardrail Lambda may exist in **up to three partition variants**
> — `<org>gcXX_check_<name>`, `<org>gcXX_check_<name>_p2`, and
> `<org>gcXX_check_<name>_p3` — to keep each clone's resource-based
> policy under Lambda's 20 KB limit at >70 accounts. The instructions
> below were updated accordingly.

## Prerequisites

- A new Lambda source directory under `src/lambda/gcXX_check_<name>/`
  containing `app.py`, `__init__.py`, `requirements.txt`, `template.yaml`,
  and a `README.md` (mirror an existing guardrail directory).
- The Lambda must follow the existing naming convention:
  - **Setup** lambdas start with `aws_` (e.g. `aws_buckets_setup`).
  - **Guardrail** lambdas start with `gcXX_check_` where `XX` is the
    two-digit guardrail family number (`01` through `13`).

## Step 1 — Add the Lambda (base + two partition clones) to a `Part*.yaml`

Pick the `AuditAccountPreRequisitesPart1.yaml` … `Part8.yaml` template
that owns the guardrail family (e.g. `gc02_*` Lambdas live in
`Part1.yaml` alongside the other `gc01`/`gc02` rules). Inside it,
declare **three** Lambda resources sharing the same code package and
execution role — the partition conditions are already declared at the
top of every Part template:

```yaml
Conditions:
  # ... existing conditions ...
  CreatePartition2: !Not [!Equals [!Ref PartitionCount, "1"]]
  CreatePartition3: !Equals [!Ref PartitionCount, "3"]
  IsAuditAccountAndCreatePartition2: !And
    - !Condition IsAuditAccount
    - !Condition CreatePartition2
  IsAuditAccountAndCreatePartition3: !And
    - !Condition IsAuditAccount
    - !Condition CreatePartition3
```

Then add the three Lambda resources (example using a hypothetical
`gc02_check_new_thing`):

```yaml
GC02CheckNewThingLambda:
  Condition: IsAuditAccount
  Type: AWS::Lambda::Function
  Properties:
    FunctionName: !Sub "${OrganizationName}gc02_check_new_thing"
    Code: "../../src/lambda/gc02_check_new_thing/build/GC02CheckNewThingLambda/"
    Handler: app.lambda_handler
    Role: !GetAtt GCDefaultLambdaExecutionRole.Arn
    Runtime: !Ref PythonRuntime
    Timeout: 90
    Layers:
      - !Ref CloudGuardrailsCommonLayer
    LoggingConfig:
      LogGroup: !Sub "${OrganizationName}gc_guardrails"
      LogFormat: "JSON"
    Environment:
      Variables:
        DEFAULT_CLOUD_PROFILE: !Ref DefaultCloudProfile

GC02CheckNewThingLambdaP2:
  Condition: IsAuditAccountAndCreatePartition2
  Type: AWS::Lambda::Function
  Properties:
    FunctionName: !Sub "${OrganizationName}gc02_check_new_thing_p2"
    # ...identical to the base resource above except FunctionName...

GC02CheckNewThingLambdaP3:
  Condition: IsAuditAccountAndCreatePartition3
  Type: AWS::Lambda::Function
  Properties:
    FunctionName: !Sub "${OrganizationName}gc02_check_new_thing_p3"
    # ...identical to the base resource above except FunctionName...
```

Rules of thumb:

- **Code path is identical** for all three clones — they share the
  build output directory.
- **IAM role is shared** — every clone references the same
  `GCDefaultLambdaExecutionRole` (or `GCLambdaExecutionRole2` for the
  privileged Lambdas), so any new permissions added in Step 5 cover
  all three automatically.
- **Conditions are pre-declared.** Do not redefine them — every
  `Part*.yaml` already carries `CreatePartition2`, `CreatePartition3`,
  and the two `IsAuditAccountAndCreatePartition*` composites.
- Adding a brand-new `Part9.yaml` (rather than extending an existing
  Part) requires copying the same `PartitionCount` parameter +
  conditions block, plus a new `AWS::CloudFormation::StackSet`
  resource in `main.yaml` that passes `PartitionCount: !GetAtt
  InvokeAccountPartitioner.PartitionCount` through.

## Step 2 — Register the Lambda for permission sync

Edit `src/lambda/aws_lambda_permissions_setup/app.py` and append the
**base** guardrail name (no suffix, no org prefix) to the
`GUARDRAIL_LAMBDA_SUFFIXES` list:

```python
GUARDRAIL_LAMBDA_SUFFIXES = [
    # ... existing entries ...
    "gc02_check_new_thing",
]
```

That single entry causes `aws_lambda_permissions_setup` to sync the
resource-based policy on `<org>gc02_check_new_thing`,
`<org>gc02_check_new_thing_p2`, and `<org>gc02_check_new_thing_p3`
for every account in the corresponding DynamoDB partition. **Do not
add `_p2` or `_p3` entries here** — the partition fan-out is handled
inside the Lambda.

## Step 3 — Add the Config rule to `ConformancePack.yaml`

Add one `AWS::Config::ConfigRule` resource. Use a **literal string** for
`ConfigRuleName` (AWS Config's conformance-pack template engine silently
ignores `!Sub` in this field). Append `${PartitionSuffix}` only to the
Lambda `SourceIdentifier` ARN.

```yaml
GC02CheckNewThingConfigRule:
  Type: "AWS::Config::ConfigRule"
  Properties:
    ConfigRuleName: gc02_check_new_thing
    Description: <one-line description>
    InputParameters:
      ExecutionRoleName:
        Fn::If:
          - GCLambdaExecutionRoleName
          - Ref: GCLambdaExecutionRoleName
          - Ref: AWS::NoValue
      AuditAccountID:
        Fn::If:
          - auditAccountID
          - Ref: AuditAccountID
          - Ref: AWS::NoValue
    Scope:
      ComplianceResourceTypes:
        - AWS::Account
    MaximumExecutionFrequency: TwentyFour_Hours
    Source:
      Owner: CUSTOM_LAMBDA
      SourceIdentifier:
        Fn::Join:
          - ""
          - - "arn:aws:lambda:ca-central-1:"
            - Ref: AuditAccountID
            - !Sub ":function:${OrganizationName}gc02_check_new_thing${PartitionSuffix}"
      SourceDetails:
        - EventSource: "aws.config"
          MessageType: "ScheduledNotification"
```

## Step 4 — Add the Audit Manager control (one mapping source)

Edit `src/lambda/aws_auditmanager_resources_config_setup/audit_manager_custom_framework.py`
and append a new control entry under the relevant `controlSets` block
(matched by guardrail family — `01-Protect User Accounts And Identities`,
`02-Manage Access`, etc.). Each control needs **one** `controlMappingSources`
entry using the `Custom_<rule_name>-conformance-pack` keyword format. The
same keyword matches the (identically-named) deployed Config rule in every
partition, so one entry covers the whole org.

```python
{
    "type": "Custom",
    "name": "gc02_check_new_thing",
    "description": "<description>",
    "testingInformation": "<what it validates>",
    "actionPlanTitle": "<short action title>",
    "actionPlanInstructions": "<remediation steps>",
    "controlSources": "AWS Config",
    "controlMappingSources": [
        {
            "sourceName": "NewThing-check",
            "sourceSetUpOption": "System_Controls_Mapping",
            "sourceType": "AWS_Config",
            "sourceKeyword": {
                "keywordInputType": "SELECT_FROM_LIST",
                "keywordValue": "Custom_gc02_check_new_thing-conformance-pack",
            },
        },
    ],
    "tags": {},
},
```

Notes:

- The `sourceName` must be **unique within a control** and **≤ 100
  characters**.

## Step 5 — Update IAM execution role(s) if needed

Before adding anything, check [`PERMISSIONS.md`](./PERMISSIONS.md) for
the current action catalogue — most read-only API calls
(`Describe*` / `Get*` / `List*` on the major AWS services) are already
permitted on the two cross-account roles, so no role change is needed.

If the Lambda needs an API that isn't already allowed, there are
**two distinct role types** in play:

- **Execute-as role (audit account).**
  `GCDefaultLambdaExecutionRole` in
  `arch/templates/AuditAccountPreRequisitesPart1.yaml`. This is the
  role every guardrail Lambda (including all `_p2` / `_p3` clones)
  *runs as* in the audit account. Update the embedded
  `GCDefaultLambdaExecutionRolePolicy` statement here for actions the
  Lambda performs against audit-account resources or the org-level
  APIs (`organizations:*`, `account:*`, etc.).
- **Assume-into roles (member accounts).** `GCLambdaExecutionRole`
  (broad read, includes IAM, Marketplace, S3 bucket access) and
  `GCLambdaExecutionRole2` (broad read, no IAM/Marketplace) in
  `arch/templates/main.yaml`. The audit-account Lambda assumes one of
  these into each member account to perform the compliance check.
  Update the embedded `Policies:` block on the role itself for a
  service-wide grant, or add a new dedicated inline policy resource
  alongside the existing
  `GCLambdaExecutionRoleS3AccessPolicy` /
  `…CWLogsPolicy` /
  `…OpenSearchPolicy` /
  `…MarketPlacePolicy` /
  `…InTransitEncryptionPolicy` for a narrowly-scoped grant.

Because all three partition clones share the same execute-as role,
adding a permission once covers the base Lambda and both clones.

**Keep `doc/PERMISSIONS.md` in sync.** Any action added to either of
the assume-into roles must also be appended to the matching role
section in `PERMISSIONS.md`.

## Step 6 — Redeploy

Redeploy the main stack via makefile or manually