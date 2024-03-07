*This readme file was created by AWS Bedrock: anthropic.claude-v2*

# GC05 - Check Data Location

## Overview

This Lambda function implements the Cloud Guardrail "GC05 - Check Data Location" (https://canada-ca.github.io/cloud-guardrails/EN/05_Data-Location.html). 

It checks for resources in unauthorized regions and reports compliance.

## Deployment

The Lambda function is deployed with the following environment variables:

- `ALLOWED_REGIONS` - A comma-separated list of allowed regions. Default is `ca-central-1`.

It also requires the following parameters:

- `ExecutionRoleName` - The name of the IAM role that the Lambda function should assume. Default is `SSCGCLambdaExecutionRole`.
- `AuditAccountID` - The ID of the audit account.

## Functionality

The handler function `lambda_handler` performs the following:

- Checks if this is a scheduled invocation. If not, it exits.
- Gets a list of enabled regions from EC2.
- Builds a list of unauthorized regions by comparing enabled regions to allowed regions.
- Calls various AWS APIs to build a list of unauthorized resources in unauthorized regions:
  - Amazon S3 buckets
  - Amazon QLDB ledgers
  - Other resources found via Resource Explorer
- Checks each resource against an allowlist.
- Builds Config evaluations for non-compliant resources.
- Batches and sends the evaluations to Config.

It uses several helper functions:

- `get_client` - Gets boto3 clients, using assumed roles if configured
- `get_enabled_regions` - Gets a list of opted-in regions from EC2
- `get_non_authorized_resources_in_region` - Gets unauthorized resources in a region using Resource Explorer
- `get_s3_resources` - Gets S3 buckets in unauthorized regions
- `build_evaluation` - Builds a Config evaluation object

## Logging

The Lambda function uses the `logging` module to output log messages.

## Testing

Testing details not provided.

## License

License information not provided.
