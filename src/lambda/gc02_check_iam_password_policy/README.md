*This readme file was created by AWS Bedrock: anthropic.claude-v2*

# ./src/lambda/gc02_check_iam_password_policy/app.py

## Overview

GC02 - Check IAM Password Policy
https://canada-ca.github.io/cloud-guardrails/EN/02_Management-Admin-Privileges.html

Checks the IAM password policy in the account against configured parameters and reports compliance to AWS Config.

## Functions

### lambda_handler

This is the main handler function, the entry point for the Lambda function.

It loads the rule parameters, gets the relevant AWS clients with assumed roles if configured, checks if this is a scheduled run and runs the compliance check if so, returning evaluation results to AWS Config.

### assess_iam_password_policy

Gets the current IAM password policy for the account and checks it against the configured parameters in PASSWORD_ASSESSMENT_POLICY.

Returns a compliance status and annotation with details on any non-compliant parts.

### build_evaluation

Builds an AWS Config evaluation object from the provided parameters.

### Other functions

* get_client - Gets boto3 clients, using assumed role credentials if configured
* get_assume_role_credentials - Gets temporary credentials from assumed role
* evaluate_parameters - Loads rule parameters into global settings
* is_scheduled_notification - Checks if the lambda run is a scheduled run

## Configuration

The rule is configured via the rule parameters, see evaluate_parameters for details.

The main settings are:

* MinimumPasswordLength 
* MaxPasswordAge
* PasswordReusePrevention
* RequireSymbols
* RequireNumbers
* RequireUppercaseCharacters
* RequireLowercaseCharacters
* AllowUsersToChangePassword
* ExpirePasswords
* HardExpiry

## Deployment

This function runs on AWS Lambda and is deployed via the Serverless Framework and CI/CD pipelines.

The Lambda execution role must have permissions to call AWS Config and IAM.

Cross account access can be enabled by passing the Audit account ID and Execution role name.

## Testing

Testing is done via unit tests and manual invocation.

## Logging

Logging is done via the Python logging library.

The lambda runtime logs are enabled.
