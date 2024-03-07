*This readme file was created by AWS Bedrock: anthropic.claude-v2*

# app.py

This is the main application code for a lambda function to check for encryption at rest for various AWS services.

## Main Entry Point

The main entry point is the `lambda_handler` function. It is invoked by AWS Lambda and passed an `event` and `context`.

## Workflow

The general workflow is:

1. Set up logging 
2. Parse input parameters from the event
3. Get AWS API clients by assuming the IAM role for execution
4. Call functions to assess encryption status for each service
   - EFS
   - EKS
   - ElasticSearch/OpenSearch
   - Kinesis 
   - RDS
   - S3
   - SNS
5. Build an evaluation result for the overall AWS account
6. Submit the evaluations back to AWS Config

## Services Checked

The services that are checked for encryption at rest are:

- EFS
- EKS
- ElasticSearch/OpenSearch
- Kinesis
- RDS 
- S3
- SNS

## Helper Functions

There are helper functions for:

- Getting paginated lists of resources for each service (e.g. `sns_get_topics_list`)
- Assessing the encryption status for each resource (e.g. `assess_sns_encryption_at_rest`) 
- Building an evaluation result
- Submitting evaluations back to AWS Config
- Getting clients for AWS APIs

## IAM Permissions Required

The function needs permissions to call the following APIs:

- config:PutEvaluations
- efs:DescribeFileSystems 
- eks:ListClusters, DescribeCluster
- es/opensearch:ListDomainNames, DescribeDomain  
- kinesis:ListStreams, DescribeStream
- rds:DescribeDBClusters, DescribeDBClusterSnapshots, DescribeDBInstances, DescribeDBSnapshots
- s3:ListBuckets, GetBucketEncryption  
- sns:ListTopics, GetTopicAttributes

It also needs permissions to assume the IAM role defined in the ExecutionRoleName parameter.

## Parameters

The main parameters are:

- ExecutionRoleName - The IAM role to assume to get access to the AWS APIs
- AuditAccountID - The AWS account ID of the audit account
