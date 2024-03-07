*This readme file was created by AWS Bedrock: anthropic.claude-v2*

# aws_compile_audit_report

## Overview

This Lambda function compiles an audit report from AWS Audit Manager and uploads it to an S3 bucket.

It retrieves assessments, evidence folders, and evidence from Audit Manager for a specified assessment. The evidence is parsed and formatted into a CSV file with relevant metadata. If there is evidence from the past day, the CSV is uploaded to the configured S3 bucket.

## Deployment

This function requires the following environment variables:

- `ORG_ID` - The AWS Organization ID 
- `ASSESSMENT_NAME` - The name of the assessment to compile evidence for
- `ORG_NAME` - The name of the AWS Organization
- `SOURCE_TARGET_BUCKET` - The S3 bucket to upload the compiled CSV 

## Lambda Handler

**lambda_handler** is the main entry point for the function.

It orchestrates:

- Retrieving assessments
- Getting evidence folders for each assessment
- Getting evidence from each folder
- Parsing and formatting evidence into a CSV
- Uploading CSV to S3 if there is evidence from the past day

## Key Functions

**get_assessments**

Retrieves assessments from Audit Manager filtered by the ASSESSMENT_NAME environment variable if provided.

**get_evidence_folders_by_assessment_id** 

Gets evidence folders for a specific assessment ID.

**get_evidence_by_evidence_folders**

Gets evidence from a specific evidence folder.

## Testing

No testing code included.

## Logging

Uses Python logging to log errors and key steps.
