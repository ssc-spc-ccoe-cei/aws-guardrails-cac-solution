*This readme file was created by AWS Bedrock: anthropic.claude-v2*

# app.py

## Overview

This is a lambda function that checks for the existence of specific CloudWatch alarms related to IAM and console login events. It is intended to run in the AWS management account and submit evaluations to AWS Config.

## Main Functions

- `lambda_handler` - The main entry point for the lambda function. It checks if this is a scheduled invocation, and if so, calls the alarm checking function.

- `check_cloudwatch_alarms` - Checks if the specified CloudWatch alarms exist. Returns a compliance status and annotation.

- `build_evaluation` - Builds an evaluation object to submit to AWS Config.

- `get_client` - Gets a boto3 client, using STS assume role if needed.

- `get_organizations_mgmt_account_id` - Calls Organizations to get the management account ID.

- `is_scheduled_notification` - Checks if the invocation is a scheduled notification. 

- `evaluate_parameters` - Evaluates rule parameters.

## Input Events

- Lambda is triggered by AWS Config on a scheduled basis.
- Event contains account ID, region, invoking event, rule parameters etc.

## Output

- Evaluations are submitted to AWS Config using the PutEvaluations API.

## Permissions Required

- `organizations:DescribeOrganization` - To determine management account ID
- `cloudwatch:DescribeAlarms` - To check for existence of alarms
- `config:PutEvaluations` - To submit evaluations to AWS Config
- `sts:AssumeRole` - If assuming roles is enabled

## Logging

- Uses Python logging to log to CloudWatch Logs.

## Testing

No automated testing is included.
