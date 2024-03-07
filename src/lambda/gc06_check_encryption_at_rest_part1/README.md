*This readme file was created by AWS Bedrock: anthropic.claude-v2*

# app.py

## Overview

This is a Lambda function that checks if various AWS resources are encrypted at rest and reports the findings to AWS Config.

## lambda_handler

This is the main entry point for the Lambda function. It performs the following key tasks:

- Sets up logging
- Parses the input event for parameters 
- Gets the relevant AWS clients using assumed roles if needed
- Calls functions to assess encryption status for each service
- Builds evaluation objects with status and annotations
- Submits evaluations to AWS Config in batches

## Service Assessment Functions

The handler calls specific functions to check encryption status for the following services:

- API Gateway
- AWS Backup
- AWS CloudTrail  
- AWS CodeBuild
- Amazon DynamoDB
- Amazon DAX
- Amazon EBS

These functions use the AWS APIs to get the resource details and check if encryption is enabled. 

## Account Assessment

After assessing individual resources, an account-level evaluation is created based on which services were found non-compliant.

## Evaluation Submission

The evaluations are submitted to AWS Config in batches using the put_evaluations API to respect API limits. Failed submissions are retried up to a limit.

## Utilities

There are some common utility functions for:

- Getting assumed role credentials
- Building evaluation objects
- Checking for throttle errors
- Submitting evaluations in batches

## Testing

No automated testing code.

## Logging

Basic logging is configured to log to CloudWatch.
