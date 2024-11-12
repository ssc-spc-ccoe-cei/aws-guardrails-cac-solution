*This readme file was created by AWS Bedrock: anthropic.claude-v2*

# app.py

## Overview

This lambda function checks if any IAM users have MFA enabled in an AWS account. It is meant to be run by AWS Config rules.

The main entry point is the `lambda_handler` function.

## Functions

### get_client

Returns the boto client for the given service. Handles assuming the IAM role if configured.

- `service` - The service name to get the client for 
- `event` - The lambda event object

Returns: boto3 client object

### get_assume_role_credentials

Gets temporary credentials by assuming the IAM role. Used if `ASSUME_ROLE_MODE` is enabled.

- `role_arn` - The ARN of the IAM role to assume

Returns: Credentials dictionary with keys `AccessKeyId`, `SecretAccessKey`, `SessionToken`

### is_scheduled_notification

Checks if the invocation is from a scheduled AWS Config notification.

- `message_type` - The message type from the event 

Returns: True if it's a Scheduled Notification, False otherwise

### evaluate_parameters

Evaluates/parses the rule parameters.

- `rule_parameters` - The dictionary of rule parameters

Returns: Evaluated rule parameters

### build_evaluation

Builds an AWS Config evaluation object.

- `resource_id` - The ID of the resource to report on
- `compliance_type` - The compliance status - `COMPLIANT`, `NON_COMPLIANT`, or `NOT_APPLICABLE`
- `event` - The event object
- `resource_type` - Resource type to report on 
- `annotation` - Optional annotation for the evaluation

Returns: Evaluation object

### get_iam_users

Gets a list of IAM users in the account. 

Returns: List of IAM user objects with `UserName` and `Arn`

### check_iam_users_mfa

Checks if IAM users have MFA enabled.

- `event` - The lambda event object

Returns: List of AWS Config evaluation objects

### lambda_handler

Main entry point for lambda function.

- `event` - Lambda event object
- `context` - Lambda context object

Returns: List of AWS Config evaluation objects
