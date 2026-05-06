# AWS Guardrails CaC Solution — Deployment Overview

## Summary

This solution deploys the **Government of Canada Cloud Guardrails** compliance assessment framework across an AWS Organization. It uses **CloudFormation nested stacks and StackSets** to provision resources in the management account and target member accounts (primarily the Audit account), and an **AWS Config Organization Conformance Pack** to deploy custom Config rules backed by Lambda functions.

## Deployment Entry Points

Deployment is orchestrated via a `Makefile`. The primary commands are:

| Command | Description |
|---------|-------------|
| `make all` | Full clean deployment: creates S3 pipeline bucket, builds Lambda packages, and deploys the root stack |
| `make deploy` | Rebuild and redeploy the main stack |
| `make update-ssN` | Redeploy a specific StackSet (1–8) after Lambda code changes |
| `make destroy` | Tear down the entire stack |

## Deployment Flow

### 1. Pipeline Bucket Setup

An S3 **pipeline bucket** is created in the management account. All packaged CloudFormation templates and Lambda deployment artifacts are uploaded to this bucket, versioned under a `DeployVersion` prefix. A bucket policy grants read access to the entire AWS Organization.

### 2. `root.yaml` → `main.yaml`

`root.yaml` is the top-level CloudFormation template. It creates a single nested stack (`GuardRailsStack`) pointing to `main.yaml`, passing through all configuration parameters (Organization ID, Audit Account ID, Accelerator role names, breakglass accounts, etc.).

### 3. `main.yaml` — Management Account Prerequisites (Part 1)

Within `main.yaml`, the following resources are created directly in the **management account**:

- **`aws_create_role` Lambda** — Assumes the Accelerator pipeline role into each member account and creates `GCLambdaExecutionRole` and `GCLambdaExecutionRole2` with the necessary IAM policies for guardrail assessments (Config rule execution, read access to IAM/S3/CloudTrail/Organizations/etc.).
- **`aws_config_setup` Lambda** — Enables AWS Config as an Organization service and registers the Audit account as a delegated administrator.
- **`aws_auditmanager_setup` Lambda** — Enables AWS Audit Manager as an Organization service and registers the Audit account as a delegated administrator.
- **`aws_generate_bucket_name` Lambda** — Generates unique names for the evidence and AWS Config Conformance Pack S3 buckets.
- **IAM Execution Roles & Policies** — Multiple fine-grained IAM policies are attached to `GCLambdaExecutionRole` and `GCLambdaExecutionRole2` covering S3, CloudWatch Logs, IAM, CloudTrail, Organizations, CloudFront, ACM, datastores, marketplace, and encryption-in-transit checks.

### 4. `AuditAccountPreRequisitesPart1–8` + `PartN` — Audit Account StackSets (Part 2)

These are deployed as **CloudFormation StackSets** targeting the Security OU (specifically the Audit account). Each StackSet deploys a subset of guardrail Lambda functions (GC01–GC13 checks) plus supporting resources:

- **Parts 1–8**: Each part bundles a group of `gc*` Lambda functions (e.g., GC01 MFA checks, GC02 password policy, GC06 encryption at rest, GC07 encryption in transit, etc.) along with their supporting IAM roles.
- **PartN** (`AuditAccountPreRequisitesPartN`): Deploys the **`aws_lambda_permissions_setup`** Lambda, which is critical for granting AWS Config the permission to invoke each guardrail Lambda. It:
  1. Runs as a CloudFormation Custom Resource on stack create/update.
  2. Calls `lambda:AddPermission` on every `gc*` Lambda, allowing the AWS Config service principal to invoke them.
  3. Is also triggered on a **6-hour cron schedule** (via EventBridge) to keep permissions in sync as new accounts join the Organization.

### 5. Conformance Pack (Part 4)

After all StackSets complete, an **`AWS::Config::OrganizationConformancePack`** is deployed from `ConformancePack.yaml`. This:

- Defines **AWS Config Custom Rules** for each guardrail (GC01–GC13), each backed by a Lambda function in the Audit account.
- Each rule references the `GCLambdaExecutionRoleName` so Config can assume the appropriate cross-account role.
- Rules are parameterized with evidence file paths (S3 URIs to attestation documents, policy files, etc.) and organization-specific settings.
- The Conformance Pack is deployed organization-wide, evaluating compliance in every member account.

### 6. Audit Manager (Part 5)

Finally, an `AuditAccountAuditManager` StackSet deploys Audit Manager resources (custom frameworks, assessments) into the Audit account, wiring up the Config rule results as automated evidence sources.

## How Guardrail Lambda Permissions Are Set Up

```
┌─────────────────────────────────────────────────────────┐
│  AuditAccountPreRequisitesPartN (StackSet → Audit Acct) │
│                                                         │
│  1. Creates LambdaPermissionsExecutionRole (IAM)        │
│     - Allows lambda:AddPermission on gc* functions      │
│     - Allows organizations:List*/Describe*              │
│                                                         │
│  2. Deploys aws_lambda_permissions_setup Lambda          │
│     - On Create/Update: iterates all gc* Lambdas and    │
│       calls AddPermission for config.amazonaws.com      │
│     - On Cron (every 6h): re-syncs permissions          │
│                                                         │
│  3. EventBridge Rule triggers Lambda every 6 hours       │
└─────────────────────────────────────────────────────────┘
```

## How AWS Config Custom Rules Are Set Up

```
┌──────────────────────────────────────────────────────────┐
│  ConformancePack.yaml (Org Conformance Pack)             │
│                                                          │
│  For each guardrail (e.g., GC01CheckRootMFA):            │
│  ┌────────────────────────────────────────────────┐      │
│  │ AWS::Config::ConfigRule                        │      │
│  │  - Source: CUSTOM_LAMBDA                       │      │
│  │  - SourceIdentifier: arn:...:function:gc*      │      │
│  │  - InputParameters: evidence paths, settings   │      │
│  │  - Scope: all resources / specific types       │      │
│  └────────────────────────────────────────────────┘      │
│                                                          │
│  Lambda assumes GCLambdaExecutionRole into target        │
│  account, evaluates compliance, calls PutEvaluations     │
└──────────────────────────────────────────────────────────┘
```

## Adding a New Guardrail

Per `doc/ENHANCE.md`:

1. Create a new guardrail Lambda function (prefix `gc_`).
2. Add it to a new or existing `AuditAccountPreRequisitesPart` StackSet template.
3. Update `aws_lambda_permissions_setup` mappings to include the new Lambda.
4. Update `GCLambdaExecutionRole` / `GCLambdaExecutionRole2` policies if new IAM permissions are needed.
5. Add the new Config rule to `ConformancePack.yaml`.
6. Redeploy.

## Deployment Architecture Diagram

```mermaid
flowchart TD
    subgraph MgmtAccount["Management Account"]
        ROOT["root.yaml"]
        MAIN["main.yaml (nested stack)"]
        
        subgraph Part1["Part 1 — Mgmt Account Prerequisites"]
            CR["aws_create_role Lambda"]
            CS["aws_config_setup Lambda"]
            AM["aws_auditmanager_setup Lambda"]
            GB["aws_generate_bucket_name Lambda"]
            ROLES["GCLambdaExecutionRole\n& GCLambdaExecutionRole2\n+ IAM Policies"]
        end
    end

    subgraph AuditAccount["Audit Account (via StackSets)"]
        subgraph Part2["Part 2 — StackSets 1-8"]
            SS1["AuditAccountPreReqPart1\n(GC Lambdas batch 1)"]
            SS2["AuditAccountPreReqPart2\n(GC Lambdas batch 2)"]
            SSN_DOTS["... Parts 3-8"]
        end

        subgraph PartN["PartN — Lambda Permissions"]
            LPS["aws_lambda_permissions_setup\nLambda"]
            EB["EventBridge Rule\n(every 6 hours)"]
            PERM["lambda:AddPermission\nfor config.amazonaws.com\non all gc* Lambdas"]
        end

        subgraph Part4["Part 4 — Conformance Pack"]
            CP["AWS::Config::\nOrganizationConformancePack"]
            RULES["AWS Config Custom Rules\n(GC01–GC13)\neach backed by gc* Lambda"]
        end

        subgraph Part5["Part 5 — Audit Manager"]
            AMA["AuditAccountAuditManager\nStackSet"]
        end
    end

    subgraph MemberAccounts["All Member Accounts"]
        EVAL["Config Rules evaluate\ncompliance per account"]
    end

    ROOT -->|"nested stack"| MAIN
    MAIN --> CR
    MAIN --> CS
    MAIN --> AM
    MAIN --> GB
    CR -->|"assumes AcceleratorRole\ninto member accounts"| ROLES

    MAIN -->|"StackSets to\nSecurity OU"| SS1
    MAIN --> SS2
    MAIN --> SSN_DOTS
    MAIN -->|"StackSet"| LPS

    LPS --> PERM
    EB -->|"cron trigger"| LPS

    SS1 & SS2 & SSN_DOTS -->|"deploy gc*\nLambda functions"| LPS
    PERM -->|"grants Config\ninvoke permission"| RULES

    MAIN -->|"after all StackSets"| CP
    CP --> RULES
    RULES -->|"Lambda assumes\nGCLambdaExecutionRole"| EVAL

    CP -->|"after Conformance Pack"| AMA
    AMA -->|"automated evidence\nfrom Config rules"| EVAL

    style ROOT fill:#f9a825,color:#000
    style MAIN fill:#ff8f00,color:#000
    style LPS fill:#e53935,color:#fff
    style PERM fill:#e53935,color:#fff
    style CP fill:#1565c0,color:#fff
    style RULES fill:#1565c0,color:#fff
    style ROLES fill:#6a1b9a,color:#fff
```

# Resource Policy Current Solution Diagram Hiren
```mermaid
flowchart TB
    %% Title
    subgraph CS["Current Solution"]
        direction TB

        root["root.yaml"]
        main["main.yaml"]

        left["AuditAccountPreRequisitesPart1..8.yaml"]
        bottom["AuditAccountPreRequisitesPartN.yaml"]
        right["ConformancePack.yaml"]

        cron["CronJob"]
        lambda["aws_lambda_permissions_setup"]

        root --> main

        main -->|1| left
        main -->|2| bottom
        main -->|3| right

        bottom --> lambda
        cron --> lambda

        noteL["creates lambda functions<br/>for each guardrail"]
        noteR["create config rules. for<br/>each config rule, assign<br/>lambda function as<br/>custom target."]
        noteB["sets resource permission<br/>for each lambda function.<br/>adds each account id in<br/>organization to the<br/>policy."]

        noteL -.-> left
        right -.-> noteR
        lambda -.-> noteB
    end

    %% Styling approximation
    classDef yaml fill:#fff,stroke:#e91e63,stroke-width:2px,color:#333;
    classDef note fill:#f6efad,stroke:#d6c97a,color:#333;
    classDef aws fill:#f28c28,stroke:#f28c28,color:#fff;
    classDef cron fill:#e91e63,stroke:#e91e63,color:#fff;

    class root,main,left,bottom,right yaml;
    class noteL,noteR,noteB note;
    class lambda aws;
    class cron cron;
```