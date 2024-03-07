*This readme file was created by AWS Bedrock: anthropic.claude-v2*

# app.py

This is the main application code for a GC07 - Check Encryption in Transit AWS Config rule lambda function.

## Functions

### assess_s3_buckets_ssl_enforcement

Finds Amazon S3 resources that do not have a bucket policy restricting SSL access.

### assess_redshift_clusters_ssl_enforcement

Finds Amazon Redshift clusters that do not have a cluster policy restricting SSL access.

### assess_elbv2_ssl_enforcement 

Evaluate whether SSL is enforced on ELBv2.

### assess_rest_api_stages_ssl_enforcement

Evaluates the SSL enforcement on the REST API Stages.

### assess_es_node_to_node_ssl_enforcement

Evaluates the Node to Node SSL Enforcement compliance for the AWS Elasticsearch Service.

### apigw_get_resources_list

Get a list of all the resources in an API Gateway Rest API.

### build_evaluation

Form an evaluation as a dictionary for a resource. Usually suited to report on scheduled rules.

### is_throttling_exception

Returns True if the exception code is one of the throttling exception codes.

### get_client

Return the service boto client using STS assume role if in cross account mode.

### get_assume_role_credentials

Return STS assumed role credentials for cross account access.

### is_scheduled_notification

Check whether the event is a ScheduledNotification. 

### lambda_handler

Main lambda handler function.
