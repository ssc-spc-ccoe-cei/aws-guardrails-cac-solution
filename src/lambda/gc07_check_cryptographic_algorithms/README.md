# GC07 - Check Cryptographic Algorithms

## Overview

This is a Lambda function that checks to ensure that the Classic Load Balancers Leverage cryptographic algorithms and protocols configurable by the user in accordance with ITSP.40.111 and ITSP.40.062. It is designed to be used by AWS Config to evaluate compliance against a custom Config rule.

The Lambda will:

- Validate the rule parameters
- Assume the Config service role to get credentials
- Check if the S3 object specified in the parameters exists
- Check for custom policies in Classic Load Balancers and ensure that they use the recommended protocols and cipher suites
- Send an evaluation result back to Config:
  - COMPLIANT if the objects are compliant
  - NON_COMPLIANT if an object is non-compliant

## Deployment

The Lambda function needs to be deployed to each account that will be monitored by Config. The execution role `AWSA-GCLambdaExecutionRole` must have permissions to assume the Config service role and access S3.

## Parameters

- `s3ObjectPath` - S3 path to the Emergency Account Management Procedure object (required)
- `ExecutionRoleName` - The role name that the function will assume (default: `AWSA-GCLambdaExecutionRole`)
- `AuditAccountID` - The AWS account ID for the audit account (default: current account)

## Function entry point

The `lambda_handler` function is the entry point called by AWS Lambda. It handles:

- Parsing the input event
- Validating parameters
- Checking if this is a scheduled notification
- Assuming the Config role
- Checking for the S3 object
- Sending evaluations back to Config

## Testing

n/a

## Logging

n/a
