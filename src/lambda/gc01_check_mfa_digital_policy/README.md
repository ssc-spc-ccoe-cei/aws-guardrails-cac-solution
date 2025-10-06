*This readme file was created by AWS Bedrock: anthropic.claude-v2*

# gc01_check_mfa_digital_policy

## app.py

This is the main Lambda function for checking that an mfa digital policy is in place to ensure taht MFA configurations are enforced.

### lambda_handler
- The main entry point for the Lambda function.
- Checks if this is a scheduled invocation and if we're in the management account using `is_scheduled_notification` and `get_organizations_mgmt_account_id`.
- Puts the evaluation to AWS Config using `AWS_CONFIG_CLIENT.put_evaluations`.

### build_evaluation
- Builds an evaluation dictionary for AWS Config.
- Used to report compliance status.

### Other functions
- `get_client`: Gets boto3 clients, handling assume role if enabled.
- `get_assume_role_credentials`: Gets temporary credentials by assuming given role.
- `is_scheduled_notification`: Checks if invocation is scheduled.  
- `evaluate_parameters`: Evaluates rule parameters.

## Testing
No testing code provided.

## Logging
No logging configuration provided.
