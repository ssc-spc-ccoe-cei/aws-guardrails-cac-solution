*This readme file was created by AWS Bedrock: anthropic.claude-v2*

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
- Calling `check_private_marketplace` 
- Building and sending an evaluation result to AWS Config

## Main Logic

The main logic is in `check_private_marketplace`. It calls the AWS Marketplace Catalog API to look for any "Experience" entities that have been shared. If any are found, it means a private AWS Marketplace has been configured.

## Testing

No automated testing is included.

## Logging

Basic logging is configured to log to CloudWatch Logs.
