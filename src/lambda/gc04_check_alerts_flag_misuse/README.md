*This readme file was created by AWS Bedrock: anthropic.claude-v2*

# ./src/lambda/gc04_check_alerts_flag_misuse/app.py

## Overview

This Lambda function checks alerts to authorized personnel have been implemented to flag misuse, suspicious sign-in attempts, or when changes are made to the cloud broker account.

## Functions

### lambda_handler

Main entry point for the Lambda function.

- Checks if this is a scheduled invocation and if we're in the Management Account
- Gets the required AWS clients
- Calls `check_enterprise_monitoring_accounts` to validate the IAM role
- Builds an evaluation with the result and puts it via AWS Config

### build_evaluation

Helper to build an evaluation object for AWS Config.

### Other functions

- `get_client`: Helper to get boto3 clients, supporting assume role
- `get_assume_role_credentials`: Get temporary credentials via assume role  
- `is_scheduled_notification`: Check if the event is a scheduled notification
- `evaluate_parameters`: Validate input parameters

## Testing

No automated tests are included.

## Logging

Uses Python's standard logging library to log information.
