*This readme file was created by AWS Bedrock: anthropic.claude-v2*

# ./src/lambda/gc04_check_enterprise_monitoring/app.py

## Overview

This Lambda function checks  alerts to authorized personnel have been implemented to flag misuse, suspicious sign-in attempts, or when changes are made to privileged and non-privileged accounts.

## Functions

### lambda_handler

Main entry point for the Lambda function.

- Checks if this is a scheduled invocation and if we're in the Management Account
- Gets the required AWS clients
- Calls `check_enterprise_monitoring_accounts` to validate the IAM role
- Builds an evaluation with the result and puts it via AWS Config

### check_enterprise_monitoring_accounts

Checks if the IAM role exists and if the trust policy is configured correctly.

- Tries to get the IAM role by name
- Checks if the role was found
- Parses the AssumeRole policy document to validate the trusted principal
- Returns a dict indicating if the role and policy are valid

### build_evaluation

Helper to build an evaluation object for AWS Config.

### Other functions

- `get_client`: Helper to get boto3 clients, supporting assume role
- `get_assume_role_credentials`: Get temporary credentials via assume role  
- `is_scheduled_notification`: Check if the event is a scheduled notification
- `evaluate_parameters`: Validate input parameters
- `get_organizations_mgmt_account_id`: Get the AWS Organizations management account ID

## Testing

No automated tests are included.

## Logging

Uses Python's standard logging library to log information.
