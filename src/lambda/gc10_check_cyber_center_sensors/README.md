# GC10 - Check Cyber Center Sensors

## Overview

Confirms that the Canadian Centre for Cyber Security (CCCS) **Cloud Based Sensor (CBS)** is actually in place, per [GC Guardrail 10 - Cyber Defense Services](https://github.com/canada-ca/cloud-guardrails/blob/master/EN/10_Cyber-Defense-Services.md).

The Lambda runs in the Audit account and assumes `ExecutionRoleName` into the account under evaluation. It performs two independent assessments.

### 1. CBS reader role — evaluated in **every** account

The CBS onboarding package deploys the `cbs-global-reader` role to every member account via StackSet, so an instance should exist everywhere. The role is the access path CCCS uses to read each account's configuration; an account without it is a blind spot for the Cyber Centre.

For the account being evaluated, the rule asserts that the role:

1. exists;
2. has a trust policy admitting a principal from the CBS account (`CBSAccountID`); and
3. has the required managed policies attached (`ReadOnlyAccess` by default).

Evaluating the role in each account rather than checking the StackSet is deliberate: it catches the same drift (failed, outdated, or missing StackSet instances; accounts created before onboarding; accounts moved between OUs) while remaining agnostic to how CBS was deployed, requiring no CloudFormation permissions in the management account, and attributing each failure to the offending account.

### 2. Log bucket replication — evaluated only in the **Log Archive** account

Each bucket named in the `S3LogBucketsPath` evidence file must have a replication rule that is:

- **Enabled**;
- **unfiltered** — replicating the whole bucket, not a prefix or tag subset (`Filter: {}` and `Filter: {Prefix: ""}` both count as unfiltered); and
- **destined for the Cyber Centre** — `Destination.Account` must equal `CBSAccountID`. The destination *account* is matched rather than the destination bucket name, since the name is not authoritative.

The IAM role named by the replication configuration is then assessed, because a replication configuration can exist and silently fail forever if its role is not correctly permissioned.

**Enforced (affect compliance):**

| Scope | Actions |
| --- | --- |
| Trust policy | assumable by `s3.amazonaws.com` |
| Source bucket | `s3:ListBucket`, `s3:GetReplicationConfiguration` |
| Source objects | `s3:GetObjectVersionForReplication` |
| Destination objects | `s3:ReplicateObject`, `s3:ReplicateDelete` |

**Advisory only (logged, never fail the check)** — these are only exercised when ACLs, tags, Object Lock, or SSE-KMS are in use, and that cannot be determined from the replication configuration alone: `s3:GetObjectVersionAcl`, `s3:GetObjectVersionTagging`, `s3:GetObjectRetention`, `s3:GetObjectLegalHold`, `s3:ReplicateTags`, `s3:ObjectOwnerOverrideToBucketOwner`, `kms:Decrypt`, `kms:Encrypt`.

If the role's policies use `NotAction`/`NotResource`, or a policy document cannot be read, the permission assessment is treated as *indeterminate* and skipped rather than failed — this avoids false `NON_COMPLIANT` results on policies the Lambda cannot soundly evaluate. Deny statements are not simulated; this is an "are the grants present" check.

## Usage

The lambda handler function is `lambda_handler`, which accepts the standard lambda event and context arguments.

## Configuration

Provided via AWS Config rule input parameters. All are required — the Lambda holds no defaults of its own, so a value missing from the conformance pack raises a `ValueError` rather than being silently assumed. Defaults live in `ConformancePack.yaml`.

| Parameter | Default (set in `ConformancePack.yaml`) | Description |
| --- | --- | --- |
| `S3LogBucketsPath` | — (supplied per partition) | Full S3 path to the newline-delimited list of log buckets, e.g. `s3://mybucket/gc-10/log_buckets.txt` |
| `LogArchiveAccountName` | — (supplied per partition) | Name of the Log Archive account in AWS Organizations |
| `ExecutionRoleName` | — (supplied per partition) | IAM role name to assume in the account under evaluation |
| `CBSAccountID` | `346725238039` | 12-digit account ID of the CCCS Cloud Based Sensor |
| `CBSRoleName` | `cbs-global-reader` | Name of the CBS cross-account reader role |
| `CBSRoleManagedPolicyArns` | `arn:aws:iam::aws:policy/ReadOnlyAccess` | Comma-separated managed policy ARNs that must be attached to the CBS reader role |
| `AuditAccountID` | — | Optional. Explicitly specify the Audit account ID |

`CBSAccountID` is additionally surfaced all the way up the stack (`config.yaml` → `root.yaml` → `main.yaml` → `ConformancePackPartitions.yaml` → `ConformancePack.yaml`) so it can be overridden at deployment time if CCCS onboards a department to a different CBS account. `CBSRoleName` and `CBSRoleManagedPolicyArns` are overridable at the conformance pack level only.

## Required permissions

No additions are needed: `${AccelRolePrefix}GCLambdaExecutionRole` already grants `iam:Get*`, `iam:List*`, `s3:Get*`, and `s3:List*`, which cover `GetBucketReplication`, `GetRole`, `ListRolePolicies`, `GetRolePolicy`, `ListAttachedRolePolicies`, `GetPolicy`, and `GetPolicyVersion`.

## Remediation

- **Role missing or misconfigured** — deploy/repair the CBS onboarding StackSet from the management account so an instance lands in the reported account.
- **Bucket not replicating to the Cyber Centre** — create an enabled, unfiltered replication rule on the bucket whose destination is owned by the CBS account.
- **Replication role missing permissions** — the annotation names the exact missing actions and whether they apply to the source or the destination.
