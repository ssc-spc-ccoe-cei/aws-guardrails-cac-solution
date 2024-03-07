*This readme file was created by AWS Bedrock: anthropic.claude-v2*

# app.py

## Overview

This Lambda function checks whether all CloudTrail trails are logging for the account it runs in. It is meant to run in the central auditing account to check trail logging compliance across an organization.

It is triggered on a scheduled basis by AWS Config rules. 

## Lambda Handler 

### lambda_handler

The main entry point for the Lambda function.

- Checks if this is running in the central auditing account. If not, it exits without checking anything.

- Calls `check_trail_logging` to validate the CloudTrail trails are logging.

- Formats the result into an AWS Config evaluation and sends it back.

## Main Logic

### check_trail_logging

Queries CloudTrail API to get all trails for the current account. 

Checks if each trail is logging via the `GetTrailStatus` API call.

Returns:

- 1 if all trails are logging
- 0 if any trail is found to not be logging  
- -1 if there was an issue querying the trails

## Helper Functions

### get_client

Creates the boto3 client to call AWS APIs. 

Handles assuming role into the central auditing account if needed.

### get_assume_role_credentials

Calls STS AssumeRole API to get temporary credentials for the central audit role.

### build_evaluation

Helper to build an AWS Config evaluation result.

### evaluate_parameters

Stub to evaluate rule parameters. Currently unused.

### is_scheduled_notification

Checks if the lambda trigger event is a scheduled notification.
