# aws_compile_audit_report

## Overview

This Lambda function compiles the daily GC Guardrails compliance report and
uploads it as a CSV to the evidence S3 bucket.

Compliance data is sourced from the organization AWS Config Aggregator
(deployed by `arch/templates/config-aggregator.yaml`). AWS Audit Manager has
been removed from this solution — it is being deprecated by AWS — but the CSV
shape is unchanged, so downstream consumers (including the dashboard Lambda)
are unaffected.

## Scoping rules

Two scoping filters keep out-of-scope data out of the CSV:

- **Conformance pack membership.** Only Config rules belonging to this
  solution's organization conformance packs are reported. The in-scope rule
  names are resolved per account from `AWS::Config::ConformancePackCompliance`
  items whose `resourceName` matches
  `OrgConformsPack-<OrganizationName>-GC-CP-Guardrails-P%`. Rules from
  unrelated conformance packs and standalone Config rules are excluded. This
  filter is pushed down into the query expression.
- **Account state.** Query results are checked against the set of accounts that
  are `ACTIVE` in AWS Organizations, and anything else is dropped. Inactive
  accounts linger in the aggregator and cannot be enriched through the
  Organizations tagging APIs (`ListTagsForResource` raises
  `TargetNotFoundException`), which previously failed the whole report. This
  filter is applied to results rather than pushed into the query: an
  `accountId NOT IN (...)` predicate cannot cover accounts that were removed
  from the organization outright, because they never appear in `ListAccounts`.

Evaluations with a `NOT_APPLICABLE` compliance type are skipped.

## Deployment

The function is deployed by `arch/templates/EvidenceCollectionComponents.yaml`
into the Audit account and requires the following environment variables:

- `AGGREGATOR_NAME` — name of the org AWS Config Aggregator to query
- `CAC_VERSION` — the deployed CaC solution version, emitted in each CSV row
- `ORG_ID` — the AWS Organization ID
- `ORG_NAME` — the organization name; also used to build the conformance pack
  name pattern
- `TENANT_ID` — the Azure tenant ID, emitted in each CSV row
- `source_target_bucket` — the S3 bucket the compiled CSV is uploaded to
- `DEFAULT_CLOUD_PROFILE` — fallback cloud profile when an account is untagged

The execution role needs `config:SelectAggregateResourceConfig`,
`organizations:DescribeOrganization`, `organizations:ListAccounts`,
`organizations:ListTagsForResource`, and write access to the evidence bucket.

## Lambda Handler

`lambda_handler` is the main entry point. It orchestrates:

- Resolving active accounts and the in-scope conformance pack rule names
- Querying the aggregator for `AWS::Config::ResourceCompliance` items
- Enriching each evaluation with the account's cloud profile (from account tags)
- Writing the rows to a CSV and uploading it to
  `s3://<source_target_bucket>/<management-account-id>_<YYYY-MM-DD>.csv`

## Key Functions

**`_get_active_account_ids`**

Returns the set of account IDs that are `ACTIVE` in AWS Organizations, using
the shared `organizations_list_all_accounts` helper from the
`cloud_guardrails` layer. Account state is read from the `State` field of the
`ListAccounts` response (the `Status` field was retired in September 2026).

**`_get_valid_rule_names`**

Returns a map of `accountId` to the set of Config rule names deployed by this
solution's conformance packs in that account.

**`_iter_aggregate_compliance`**

Yields one record per (resource, in-scope rule) pair from the aggregator.

**`_row_from_evaluation`**

Formats a single evaluation into a CSV row, including the control set name and
the account's cloud profile.

## Testing

No testing code included.

## Logging

Uses Python logging to log errors and key steps, including the excluded
inactive accounts and the number of accounts with resolved guardrail rules.
