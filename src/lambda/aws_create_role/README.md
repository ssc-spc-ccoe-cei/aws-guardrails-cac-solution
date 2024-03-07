*This readme file was created by AWS Bedrock: anthropic.claude-v2*

# app.py

## Overview

Lambda function used to assume a deployment role in all organizational accounts.

## Functionality

The `lambda_handler` function is the main entry point for the Lambda function.

It performs the following key steps:

- Gets a list of all accounts in the AWS Organization using `get_org_accounts()`
- Creates an IAM session using `boto3`
- Gets the current account ID using `get_account_id()`  
- Loops through each account in the organization
  - Skips the management account
  - Assumes the specified cross-account role using `assume_role()`
  - Creates the specified IAM role using `create_iam_role()`
    - If the role already exists, it detaches policies and deletes it first
  - Loops through the policy documents
    - Creates each IAM policy using `create_iam_policy()` 
      - If the policy exists, it skips creation
    - Attaches the policy to the role using `attach_iam_policy_to_role()`
- On delete requests, it detaches policies, deletes the role, and deletes policies
- Sends a response back to CloudFormation using `send()`

It uses several utility functions:

- `get_org_accounts()` - Gets list of accounts in Org
- `create_iam_policy()` - Creates an IAM policy
- `attach_iam_policy_to_role()` - Attaches a policy to a role  
- `create_iam_role()` - Creates an IAM role
- `delete_role()` - Deletes an IAM role
- `detach_all_policies_from_role()` - Detaches all policies from a role
- `get_account_id()` - Gets the current account ID
- `assume_role()` - Assumes a cross-account role
- `delete_iam_policy()` - Deletes an IAM policy
- `send()` - Sends response back to CloudFormation 

## Testing

Testing is not implemented.

## Logging

Logging is implemented using Python's `logging` module.
