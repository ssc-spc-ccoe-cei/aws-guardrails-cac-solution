*This readme file was created by AWS Bedrock: anthropic.claude-v2*

# app.py

This is a Lambda function that sets up Audit Manager resources for AWS.

## Functionality

The main things this Lambda does:

- Creates a custom assessment framework in Audit Manager
  - Iterates over the input framework data and creates/updates any custom controls
  - Creates or updates the assessment framework using the updated controls
- Creates an assessment using the custom framework
  - Queries AWS Organizations to get active accounts
  - Gets the list of in-scope AWS services
  - Creates the assessment with those accounts and services in scope
- Deletes an assessment, framework, and controls on delete events

## Main Functions

### lambda_handler

The main handler function that is triggered when the Lambda is invoked.

It checks the event type and calls the appropriate logic.

### create_auditmanager_resources

Creates the custom assessment framework and assessment.

Parameters:

- bucket_name - S3 bucket name 
- assessment_owner_role_arns - List of IAM role ARNs that will own the assessment

Returns status code based on success/failure.

### create_assessment_framework

Creates or updates a custom assessment framework. 

Iterates through the input control sets and creates/updates any custom controls.

Parameters:

- client - Boto3 AuditManager client
- framework_data - Dictionary containing framework configuration

Returns ID of created framework.

### create_assessment

Creates a new assessment using the given framework ID.

Parameters:

- framework_id - ID of framework to use
- bucket_name - S3 bucket for assessment reports
- assessment_owner_role_arns - List of IAM role ARNs that will own assessment

Returns status code based on success/failure.

### delete_assessment_resources 

Deletes the assessment, framework, and controls.

Parameters: 

- client - Boto3 AuditManager client
- assessment_name - Name of assessment to delete

Returns status code based on success/failure.

## Testing

No automated tests are included.

## Logging

Uses Python logging to log to CloudWatch.
