*This readme file was created by AWS Bedrock: anthropic.claude-v2*

# app.py

This is a Lambda function that implements the GC10 AWS Config rule for checking the existence of a signed Memorandum of Understanding (MOU) in an S3 bucket.

## Functions

### get_client
Returns a boto3 client after assuming the Config service role in the same or different AWS account.

### get_assume_role_credentials
Gets temporary credentials by assuming the Config service role.

### is_scheduled_notification
Checks if the invocation event is a ScheduledNotification.

### evaluate_parameters
Validates the rule parameters. Checks for required `s3ObjectPath` parameter.

### check_s3_object_exists  
Checks if an S3 object exists at the given path.

### build_evaluation
Builds an evaluation result for AWS Config.

### lambda_handler
Main entry point for the Lambda function.
- Parses input parameters
- Checks if this is running in the Audit account
- Gets AWS clients after assuming role 
- Checks for MOU object in S3
- Builds and returns AWS Config evaluation

## Configuration
- Set `ASSUME_ROLE_MODE = True` to assume Config service role for cross-account access.
- Rule requires `s3ObjectPath` parameter pointing to S3 MOU object.
- Optionally takes `AuditAccountID` and `ExecutionRoleName` parameters.

## Testing
Not documented.

## Logging
Not documented.
