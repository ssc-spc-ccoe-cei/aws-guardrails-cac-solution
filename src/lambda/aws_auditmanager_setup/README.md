*This readme file was created by AWS Bedrock: anthropic.claude-v2*

# ./src/lambda/aws_auditmanager_setup/app.py

## Overview

This Lambda function sets up AWS Audit Manager by enabling service access and registering the audit account as a delegated administrator.

## Setup

The AuditAccountId parameter must be provided to specify the ID of the audit account. 

## Functions

### lambda_handler

The main handler function that is invoked by Lambda.

- Validates that AWS Service Access is enabled for Audit Manager. If not, it will attempt to enable it.
- Calls auditmanager_register_account to register Audit Manager and establish delegated admin permissions.
- Sends response back to CloudFormation on success/failure.

### auditmanager_register_account

Registers Audit Manager and configures delegated admin access to the provided audit account.

- Parameters:
  - client: Boto3 AuditManager client
  - audit_account_id: ID of the audit account  

- Returns:
  - 1 for success
  - 0 for failure
  - -1 for error

### check_auditmanager_service_access

Checks if AWS Service Access is enabled for Audit Manager using Organizations API.

- Parameter: 
  - client: Boto3 Organizations client

- Returns: 
  - 1 if enabled
  - 0 if disabled
  - -1 for error

### enable_auditmanager_service_access

Enables AWS Service Access for Audit Manager using Organizations API.

- Parameter:
  - client: Boto3 Organizations client
  
- Returns:
  - 1 if successful
  - 0 if failed
  - -1 for error

### Additional helper functions

- check_delegated_administrators
- send

## Testing

No automated testing is included.

## Logging

Uses Python logging to log to CloudWatch.
