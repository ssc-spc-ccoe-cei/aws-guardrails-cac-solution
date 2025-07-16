*This readme file was created by AWS Bedrock: anthropic.claude-v2*

# gc01_check_monitoring_and_logging

## app.py

This is the main Lambda function for checking if monitoring and auditing is implemented for all user accounts.

### lambda_handler
- The main entry point for the Lambda function.
- Checks if this is a scheduled invocation and if we're in the management account using `is_scheduled_notification` and `get_organizations_mgmt_account_id`.
- Gets the root MFA status with `get_root_mfa_enabled`.
- Builds an evaluation with `build_evaluation` and compliance based on root MFA status.
- Puts the evaluation to AWS Config using `AWS_CONFIG_CLIENT.put_evaluations`.

### get_root_mfa_enabled
- Generates an IAM credential report.
- Checks if MFA is enabled for the root account in the report.
- Returns True if enabled, False otherwise.

### build_evaluation
- Builds an evaluation dictionary for AWS Config.
- Used to report compliance status.

### Other functions
- `get_client`: Gets boto3 clients, handling assume role if enabled.
- `get_assume_role_credentials`: Gets temporary credentials by assuming given role.
- `is_scheduled_notification`: Checks if invocation is scheduled.  
- `evaluate_parameters`: Evaluates rule parameters.
- `get_organizations_mgmt_account_id`: Gets management account ID from AWS Organizations.

## Testing
No testing code provided.

## Logging
No logging configuration provided.
