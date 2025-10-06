_This readme file was created by AWS Bedrock: anthropic.claude-v2_

# GC03 - Check trusted devices admin access

## Overview

This is a Lambda function that confirms that administrative access to cloud environments is from approved and trusted locations and devices. It is designed to be used by AWS Config to evaluate compliance against a custom Config rule.

The Lambda will:

- Validate the rule parameters
- Assume the Config service role to get credentials
- Check if the S3 object specified in the parameters exists and has a list of vpn ip ranges.
- Get a list of CloudTrail events with the type of `ConsoleLogin` that are not for the break-glass users
  - Ensure that each event has a source ip within one of the provided ranges
  - Send an evaluation result back to Config:
    - COMPLIANT if the source ip is in one of the provided ranges
    - NON_COMPLIANT if the source ip is NOT in one of the provided ranges
- Send an evaluation result back to Config:
  - COMPLIANT if all the events meet the above criteria
  - NON_COMPLIANT if one of the events does not meet the above criteria

## Deployment

The Lambda function needs to be deployed to each account that will be monitored by Config. The execution role `AWSA-GCLambdaExecutionRole` must have permissions to assume the Config service role, S3, EventBridge, and SNS.

## Parameters

- `s3ObjectPath` - The path to a file containing the list of valid source ip ranges in the CIDR format (required). The file must be a plain text file where each ip range is separated by a new line.
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
