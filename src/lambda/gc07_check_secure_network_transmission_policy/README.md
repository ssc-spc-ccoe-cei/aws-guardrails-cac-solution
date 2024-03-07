*This readme file was created by AWS Bedrock: anthropic.claude-v2*

# app.py

## Overview

This lambda checks for the presence of a secure network transmission policy document in an S3 bucket. 

It is designed to run in the audit account and check if the policy document exists in the provided S3 path.

## Usage

This lambda is intended to be run on a scheduled basis in AWS Config rules.

The key parameters are:

- `s3ObjectPath` - The S3 URI of the secure network transmission policy document to check for existence.

It will return COMPLIANT if the object is found at the path, NON_COMPLIANT if not.

## Code Overview

- `get_client` - Helper to get boto3 clients, supporting cross-account AssumeRole
- `get_assume_role_credentials` - Get temporary credentials for AssumeRole
- `is_scheduled_notification` - Check if this is a scheduled notification
- `evaluate_parameters` - Validate input parameters 
- `check_s3_object_exists` - Check if the target object exists in S3
- `build_evaluation` - Construct an evaluation result for AWS Config
- `lambda_handler` - Main lambda entry point
  - Validate parameters
  - Check if we're in the audit account
  - Get clients
  - Check for policy document
  - Build and return evaluation

## Deployment

This lambda needs to be deployed in the audit account. 

The AWS Config rule should be created in the audit account and point to this lambda.

The rule should be triggered on a periodic basis.
