# ./src/lambda/gc12_check_marketplace/app.py

## Overview

This Lambda function checks if the account is using a private AWS Marketplace by calling the AWS Marketplace Catalog API. 

It is meant to be run in the central auditing account, triggered on a schedule by AWS Config.

## Usage

This Lambda is triggered by AWS Config on a schedule. It will check if a private AWS Marketplace catalog has been shared with the account.

It expects to run in the central auditing account specified in the `AuditAccountID` parameter.

The IAM role to assume in the target account is specified in the `ExecutionRoleName` parameter. 

## Lambda Handler

The main handler function is `lambda_handler`. This is triggered by AWS Lambda and handles:

- Loading parameters
- Getting boto3 clients
- Checking if this is a scheduled run
- Delegating to `assess_guardrail_12`
- Building and sending an evaluation result to AWS Config

If `assess_guardrail_12` raises an unexpected exception, `lambda_handler` still submits a
`NON_COMPLIANT` evaluation with an annotation describing the failure. Without this, a failed
evaluation produces no result at all, which makes the account silently disappear from the
Audit Manager evidence and the daily CSV report.

## Management account only

The guardrail is only assessed in the organization's management account:

- Workload accounts are normally denied `organizations:ListPolicies`, which generated a large
  volume of `AccessDeniedException` noise in the logs.
- The management account assessment already walks every OU in the organization, so running
  the check in other accounts is redundant.

Non-management accounts report `NOT_APPLICABLE` (rather than returning without an evaluation)
so that any stale result is overwritten and the account still appears in the report.

## Main Logic

1. **Find a restricting SCP.** `get_policies_that_restrict_marketplace_access` lists the
   organization's SCPs and evaluates each one statically against
   `PRIVATE_MARKETPLACE_ADMIN_ACTIONS`. A policy qualifies only if it denies **every** action
   in that list. If no restricting SCP exists → `NON_COMPLIANT`.
2. **Check the SCP's scope.** `assess_policy_attachment` confirms the restricting SCP is
   *not* attached to the management account, and that it applies to every other account.
   Results of `organizations:ListPoliciesForTarget` are cached per target. If any target is
   uncovered → `NON_COMPLIANT`, and step 3 is skipped.
3. **Check the Private Marketplace.** `assess_private_marketplace` requires an `Experience`
   entity with `Status: Enabled` *and* an audience that covers every account. If both hold →
   `COMPLIANT`, otherwise `NON_COMPLIANT`.

### Why step 1 is evaluated statically

This check previously used `iam:SimulateCustomPolicy` with the SCP as the only entry in
`PolicyInputList`. That is unsound: an SCP contains no `Allow` statements, so *every* action
evaluates to `implicitDeny` and the check returned "restricts marketplace access" for **any**
Deny-only policy — even one that never mentions the marketplace. In practice this meant the
control reported `COMPLIANT` in any organization that had at least one SCP attached.

`policy_restricts_marketplace_access` now parses the policy document directly, in the same
style as `policy_doc_gives_admin_access` in `gc01_check_dedicated_admin_account` and
`gc02_check_group_access_configuration`. It is deterministic, requires no API calls, and the
rules it applies are:

- only `Effect: Deny` statements count;
- **conditional denies are ignored** — a deny that only applies in certain regions or to
  certain principals (e.g. the LZA `GBL1` and `ROOT` statements) is not an unconditional
  restriction;
- the statement must apply to `Resource: "*"`, since these actions are not resource-scoped;
- both `Action` and `NotAction` are handled, with IAM `*` / `?` wildcard semantics;
- denials may be spread across multiple statements.

### Organization tree traversal

Steps 2 and 3 share `find_uncovered_targets`, which walks the organization tree **starting
explicitly from the root** (`organizations:ListRoots`) and returns the ids of any targets
that are not covered. Coverage is inherited, so once a target is covered its entire subtree
is skipped and no further API calls are made for it.

This matters for two cases that a flat "check every OU" loop gets wrong:

- **Accounts in the root container.** An account that is not inside any OU is visited as a
  direct child of the root, so it is never silently skipped.
- **Inheritance.** An SCP attached to the root (or to a parent OU) applies to everything
  beneath it, and a private marketplace audience principal set to an OU covers that OU's
  child accounts. Both are treated as covered rather than reported as missing.

The management account is excluded from the SCP traversal, because AWS exempts it from all
SCPs; it is checked separately and must *not* have the restricting SCP attached.

### Private Marketplace audience

The `Experience` entity's audience is stored in separate `Audience` entities, whose
`Principals` can be an **account id**, an **OU id**, or the **organization id**:

- The experience associated with the **organization id** is the default for every account,
  so finding it short-circuits the whole traversal as covered.
- An **OU id** covers the accounts beneath that OU.
- The organization **root** (`r-...`) is *not* a valid principal, so accounts sitting
  directly in the root container must be covered by the organization id or individually.

An experience that is disabled or archived has no effect — AWS removes all restrictions when
no enabled experience applies to an account — so only experiences with `Status: Enabled` are
considered.

## Required permissions

Beyond the usual Config/Organizations read access, this check needs:

- `aws-marketplace:ListEntities` and `aws-marketplace:DescribeEntity`
- `organizations:ListRoots`, `organizations:ListAccountsForParent`,
  `organizations:ListOrganizationalUnitsForParent`, `organizations:ListPoliciesForTarget`,
  `organizations:ListPolicies`, `organizations:DescribeOrganization`,
  `organizations:DescribePolicy`

`iam:SimulateCustomPolicy` is no longer used.

## Testing

No automated testing is included.

## Logging

Basic logging is configured to log to CloudWatch Logs.
