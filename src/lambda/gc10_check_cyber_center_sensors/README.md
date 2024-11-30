_This readme file was created by AWS Bedrock: anthropic.claude-v2_

# GC08 - check Cyber Center Sensors

## Overview

This lambda confirms that the Cyber Centre’s sensors or other cyber defense services are implemented where available.. It is designed to run in the Audit account and report compliance back to AWS Config.

The S3 bucket location and optional Execution Role name can be provided via Config Rule parameters.

## Usage

The lambda handler function is `lambda_handler` which accepts the standard lambda event and context arguments.

## Configuration

The following parameters can be provided in the Config Rule payload:

- **s3ObjectPath** - Required - Full S3 path to object e.g. s3://mybucket/log_buckets.txt
- **LogArchiveAccountName** - Required - The name of the log archive account
- **ExecutionRoleName** - Optional - IAM Role name to assume in Audit account
- **AuditAccountId** - Optional - Explicitly specify Audit account ID
