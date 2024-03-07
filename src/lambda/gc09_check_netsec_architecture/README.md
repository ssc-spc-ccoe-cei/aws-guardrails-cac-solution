*This readme file was created by AWS Bedrock: anthropic.claude-v2*

# app.py

## Overview

This is a Lambda function that checks if a Network Security Architecture document exists in an S3 bucket. 

It is designed to run in AWS Config as a custom Config Rule. The rule will evaluate to COMPLIANT if the document is found, NON_COMPLIANT if not, and NOT_APPLICABLE if run outside the Audit account.

## Lambda Handler

The main entry point for the Lambda function is the `lambda_handler` function.

It performs the following key steps:

1. Parses the input parameters from the AWS Config event
2. Checks if this is a scheduled notification from Config
3. Gets the assumed role credentials if running in cross-account mode
4. Checks if the S3 object exists using `check_s3_object_exists`
5. Builds the AWS Config evaluation and puts it via the API

## Functions

**get_client**

Returns a Boto3 client after assuming the execution role if running in cross-account mode.

**get_assume_role_credentials**

Gets temporary credentials by assuming the given IAM role. Used for cross-account access.

**is_scheduled_notification** 

Checks if the input event is a scheduled notification from AWS Config.

**evaluate_parameters**

Validates the required input parameters.

**check_s3_object_exists**

Checks if the given S3 object exists. Returns a boolean.

**build_evaluation**

Builds an AWS Config evaluation as a dictionary, ready to be submitted via the API.

## Testing

No automated testing code is included.

## Logging

Uses Python's built-in logging library. The `logger` object is pre-configured.
