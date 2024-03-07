*This readme file was created by AWS Bedrock: anthropic.claude-v2*

# gc11_check_security_contact

## Overview

This Lambda function is used to check if an AWS account has a configured security contact. It is intended to be used for compliance validation.

The function expects to be invoked on a schedule by AWS Config rules. It will validate if a security contact is configured for the current account.

The main logic is in the `check_security_contact()` function.

## Deployment

The function requires some parameters to be passed in via the Config rule:

- `ExecutionRoleName` - The name of the IAM role that Lambda will assume in the account to check the security contact.
- `AuditAccountID` - The AWS account ID that will run compliance checks across accounts. This Lambda should only perform checks in accounts that are not the Audit account.

The function expects read-only access via the assumed role to the `account` service to call `get_alternate_contact()`.

## Usage

The function is intended to be run on a schedule by AWS Config against multiple accounts.

It will check if an alternate security contact is configured via `get_alternate_contact()`. If one is found with a name, email, and phone number, then the account is compliant. If no security contact is configured, then the account is non-compliant.

The function generates an AWS Config evaluation with the compliance status and a custom annotation with the check details.

## Logging

The function uses Python's logging module to log details about the event and compliance check results. This is useful for tracking execution and debugging issues.
