""" Lambda function to copy audit data from source s3 bucke to the destination s3 bucket."""
import logging
import os

import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)
org_id = os.environ['ORG_ID']


def lambda_handler(event, context):
    """lambda handler to copy audit data from source s3 bucke to the destination s3 bucket.
    Args:
        event: lambda event
        context: lambda context
    """
    bucket = event["Records"][0]["s3"]["bucket"]["name"]
    key = event["Records"][0]["s3"]["object"]["key"]
    s3_resource = boto3.resource("s3")
    copy_source = {"Bucket": bucket, "Key": key}

    #print(key)
    
    #Todo: Not sure why this exist, its not being used anywhere? 
    #account_id = context.invoked_function_arn.split(":")[4]
    target_key = f"{org_id}/{key}"
    logger.info("Attempting to copy audit data to GC managed s3 bucket: %s", target_key)

    if key.startswith("chunks/") or key.startswith("state/"):
        pass
    else:
        s3_resource.Bucket(os.environ["target_bucket"]).Object(target_key).copy(
            copy_source, ExtraArgs={"ACL": "bucket-owner-full-control"}
        )
