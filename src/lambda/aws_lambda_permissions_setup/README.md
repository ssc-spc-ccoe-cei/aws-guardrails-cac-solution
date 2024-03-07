*This readme file was created by AWS Bedrock: anthropic.claude-v2*

# app.py

## Overview

This is a Lambda function to setup permissions for other Lambda functions to be invoked by AWS Config across all accounts in an AWS Organization.

## Functions

### get_accounts

Queries AWS Organizations and returns a List of AWS Accounts.

Returns: List of AWS Accounts

### apply_lambda_permissions

Ensures all GC Guardrail Assessment Lambda Functions can be invoked by all AWS Accounts in the Organization.

Returns: 
- 1 if successful
- 0 if unable to apply permissions
- -1 in case of errors

### send

Sends a response to CloudFormation.

Arguments:

- event - the event variable given in the lambda handler
- context - the context variable given in the lambda handler  
- response_status - the response status to send
- response_data - the response data to send
- physical_resource_id - (optional) physical resource id 
- no_echo - (optional) boolean if response should not be echoed
- reason - (optional) reason string

### lambda_handler

This function is the main entry point for Lambda.

Arguments:

- event - the event variable given in the lambda handler
- context - the context variable given in the lambda handler
