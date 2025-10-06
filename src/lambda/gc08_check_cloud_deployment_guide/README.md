_This readme file was created by AWS Bedrock: anthropic.claude-v2_

# GC08 - check Target Cloud Deployment Guide

## Overview

This lambda checks for the existence of the Target Cloud Deployment Guide document in an S3 bucket. It is designed to run in the Audit account and report compliance back to AWS Config.

The S3 bucket location and optional Execution Role name can be provided via Config Rule parameters.

## Usage

The lambda handler function is `lambda_handler` which accepts the standard lambda event and context arguments.

Key steps:

- Validate input parameters
- Check if running in the Audit account
- Use STS AssumeRole to get credentials to access S3 in Audit account
- Check if S3 object exists
- Build compliance evaluation and send to Config via PutEvaluations API

## Configuration

The following parameters can be provided in the Config Rule payload:

- **s3ObjectPath** - Required - Full S3 path to object e.g. s3://mybucket/deployment_guide.pdf
- **ExecutionRoleName** - Optional - IAM Role name to assume in Audit account
- **AuditAccountId** - Optional - Explicitly specify Audit account ID

## Testing

Testing requires valid Config Rule test event payload and mocking of the STS and S3 clients.

Unit tests should cover:

- Parameter validation
- STS AssumeRole
- S3 object check
- Building Compliance evaluation

## Logging

Standard Python logging is used for debugging information.
