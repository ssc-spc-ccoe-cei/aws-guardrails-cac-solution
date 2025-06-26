*This readme file was created by AWS Bedrock: anthropic.claude-v2*

# ./src/lambda/aws_bucket_watcher/app.py

## Overview

Lambda function to copy audit data from source s3 bucket to the destination s3 bucket.

## Functions

### lambda_handler

lambda handler to copy audit data from source s3 bucket to the destination s3 bucket.

Args:

- event: lambda event 
- context: lambda context

It logs some information, gets the source bucket and key from the event, constructs the target key using the account ID from the context, and copies the object from the source bucket to the target bucket.

It uses boto3 to interact with S3.

The target bucket is read from the environment variable `target_bucket`.
