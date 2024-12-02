*This readme file was created by AWS Bedrock: anthropic.claude-v2*

# app.py

## Overview

This is a Lambda function that checks that storage accounts are not exposed to the public. 

It is designed to run in AWS Config as a custom Config Rule. The rule will evaluate to COMPLIANT if the document is found, NON_COMPLIANT if not, and NOT_APPLICABLE if run outside the Audit account.

## Functions

**get_client**

Returns a Boto3 client after assuming the execution role if running in cross-account mode.

**get_assume_role_credentials**

Gets temporary credentials by assuming the given IAM role. Used for cross-account access.

**is_scheduled_notification** 

Checks if the input event is a scheduled notification from AWS Config.

**evaluate_parameters**

Validates the required input parameters.

**build_evaluation**

Builds an AWS Config evaluation as a dictionary, ready to be submitted via the API.

## Testing

No automated testing code is included.

## Logging

Uses Python's built-in logging library. The `logger` object is pre-configured.
