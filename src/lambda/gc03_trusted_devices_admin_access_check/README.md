_This readme file was created by AWS Bedrock: anthropic.claude-v2_

# GC13 - Emergency Account Alerts

## Overview

This is a Lambda function that confirms that administrative access to cloud environments is from approved and trusted locations and devices. It is designed to be used by AWS Config to evaluate compliance against a custom Config rule.

The Lambda will:

- Validate the rule parameters
- Assume the Config service role to get credentials
- Check if the S3 object specified in the parameters exists and has a list of rules
- Get a list of EventBridge rules
  - Ensure that each rule provided by the input file exists in the list of EventBridge rules
  - Ensure that each rule provided by the input file is enabled in EventBridge
  - Ensure that each rule provided by the input file is configured to send notifications via SNS
  - Send an evaluation result back to Config:
    - COMPLIANT if the rule meets the above criteria
    - NON_COMPLIANT if the rule does not meet the above criteria
- Send an evaluation result back to Config:
  - COMPLIANT if all the rules meet the above criteria
  - NON_COMPLIANT if one of the rules does not meet the above criteria

## Deployment

The Lambda function needs to be deployed to each account that will be monitored by Config. The execution role `AWSA-GCLambdaExecutionRole` must have permissions to assume the Config service role, S3, EventBridge, and SNS.

## Parameters

- `s3ObjectPath` - The path to a file containing the list of EventBridge rule names that need to be in-place (required). The file is a text file where each rule name is separated by a new line.
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
