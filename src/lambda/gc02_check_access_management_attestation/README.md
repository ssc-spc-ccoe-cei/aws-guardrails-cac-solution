_This readme file was created by AWS Bedrock: anthropic.claude-v2_

# app.py

This is a lambda function that checks if a document verifying that access authorization mechanisms have been implemented.

It is designed to be used as a Config Rule and will run on a scheduled basis.

## Main entry point

The main entry point is the `lambda_handler` function.

## Functions

- `get_client` - Returns a boto3 client, handling assuming the execution role if needed.
- `get_assume_role_credentials` - Gets temporary credentials by assuming the given IAM role.
- `is_scheduled_notification` - Checks if the lambda trigger event is a scheduled notification.
- `evaluate_parameters` - Validates the rule parameters.
- `check_s3_object_exists` - Checks if the given S3 object path exists.
- `build_evaluation` - Builds the Config evaluation result.
- `lambda_handler` - The main entry point and handler for the lambda function.
- Calls the other functions to validate parameters, check if the S3 object exists, and submit the evaluation results to Config.

## Configuration

- `ASSUME_ROLE_MODE` - Controls if the lambda will assume the Config Service IAM Role for cross-account access.
- `DEFAULT_RESOURCE_TYPE` - The default resource type used in evaluations.
- `EXECUTION_ROLE_NAME` - The name of the IAM Role this lambda will assume.
- `AUDIT_ACCOUNT_ID` - The AWS Account ID of the audit account.

## Rule Parameters

- `s3ObjectPath` - Required - The S3 path of the account management plan document to check for.

## Testing

No automated testing code.

## Logging

Uses Python's built-in logging.
