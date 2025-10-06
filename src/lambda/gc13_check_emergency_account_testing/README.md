_This readme file was created by AWS Bedrock: anthropic.claude-v2_

# GC13 - Emergency Account Testing

## Overview

This is a Lambda function that verifies that testing of emergency accounts took place and that periodic testing is included. It is designed to be used by AWS Config to evaluate compliance against a custom Config rule.

The Lambda will:

- Validate the rule parameters
- Assume the Config service role to get credentials
- Get a list of break-glass users
  - Ensure that each user exists in the management account
  - Ensure that each user has logged in within 1 year's time
  - Send an evaluation result back to Config:
    - COMPLIANT if the user meets the above criteria
    - NON_COMPLIANT if the user does not meet the above criteria
- Send an evaluation result back to Config:
  - COMPLIANT if all the users meet the above criteria
  - NON_COMPLIANT if one of the users do not meet the above criteria

## Deployment

The Lambda function needs to be deployed to each account that will be monitored by Config. The execution role `AWSA-GCLambdaExecutionRole` must have permissions to assume the Config service role, S3, EventBridge, and SNS.

## Parameters

- `ExecutionRoleName` - The role name that the function will assume (default: `AWSA-GCLambdaExecutionRole`)
- `AuditAccountID` - The AWS account ID for the audit account (default: current account)
- `BgUser1` - The IAM user name of the break-glass user number 1
- `BgUser2` - The IAM user name of the break-glass user number 2

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
