_This readme file was created by AWS Bedrock: anthropic.claude-v2_

# GC03 - Check endpoint access config

## Overview

This is a Lambda function that demonstrates that access configurations and policies are implemented for devices. It is designed to be used by AWS Config to evaluate compliance against a custom Config rule.

The Lambda will:

- Validate the rule parameters
- Assume the Config service role to get credentials
- Send an evaluation result back to Config:
  - COMPLIANT with annotation 'Dependent on the compliance of the Federated IdP.'

## Deployment

The Lambda function needs to be deployed to each account that will be monitored by Config. The execution role `AWSA-GCLambdaExecutionRole` must have permissions to assume the Config service role, S3, EventBridge, and SNS.

## Parameters

- `ExecutionRoleName` - The role name that the function will assume (default: `AWSA-GCLambdaExecutionRole`)
- `AuditAccountID` - The AWS account ID for the audit account (default: current account)

## Function entry point

The `lambda_handler` function is the entry point called by AWS Lambda. It handles:

- Parsing the input event
- Validating parameters
- Checking if this is a scheduled notification
- Assuming the Config role
- Checking for the S3 object
- Sending evaluations back to Config

## Testing

n/a

## Logging

n/a
