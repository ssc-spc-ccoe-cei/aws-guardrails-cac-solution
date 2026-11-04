*This readme file was created by AWS Bedrock: anthropic.claude-v2*

# ./src/lambda/gc01_check_dedicated_admin_account/app.py

## Overview

GC01 - Check For Dedicated Admin Accounts

Demonstrates that there are dedicated user accounts for administration.

## Functions

### lambda_handler

This is the main handler function, the entry point for the Lambda function.

It loads the rule parameters, gets the relevant AWS clients with assumed roles if configured, checks if this is a scheduled run and runs the compliance check if so, returning evaluation results to AWS Config.

### build_evaluation

Builds an AWS Config evaluation object from the provided parameters.

## Configuration

### `PIM_ENABLED`

Feature flag for the PIM/JIT evaluation path (CloudTrail-based recent
elevation checks via IAM Identity Center). When unset or `false`, the
original evaluation behaviour is preserved.

The value is **not** hardcoded in the Lambda. It is set from the top-level
solution configuration and threaded down through CloudFormation:

| Layer | Key |
| --- | --- |
| `config.yaml` → `Parameters` | `PimEnabled: "false"` |
| `arch/params/base.json` | `{"ParameterKey": "PimEnabled", "ParameterValue": "false"}` |
| `arch/templates/root.yaml` | `PimEnabled` parameter → passed to `main.yaml` |
| `arch/templates/main.yaml` | `PimEnabled` parameter → passed to the `AuditAccountPreRequisitesPart2` StackSet |
| `arch/templates/AuditAccountPreRequisitesPart2.yaml` | `PIM_ENABLED: !Ref PimEnabled` env var on the base Lambda and the `_p2` / `_p3` / `_p4` partition clones |

Allowed values are lowercase `"true"` and `"false"` only — the templates
enforce this with `AllowedValues`. To enable the flag, edit `config.yaml`
and redeploy; no code change is required.

## Deployment

This function runs on AWS Lambda and is deployed via the Serverless Framework and CI/CD pipelines.

The Lambda execution role must have permissions to call AWS Config and IAM.

Cross account access can be enabled by passing the Audit account ID and Execution role name.

## Testing

Testing is done via unit tests and manual invocation.

## Logging

Logging is done via the Python logging library.

The lambda runtime logs are enabled.
