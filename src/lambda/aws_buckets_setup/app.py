""" Setup S3 Bucket Lambda Function """
import json
import logging
import random
import string
import time

import boto3
import botocore
import urllib3

SUCCESS = "SUCCESS"
FAILED = "FAILED"

# cfnresponse replacement
http = urllib3.PoolManager()

# Logging setup
logger = logging.getLogger()
logger.setLevel(logging.INFO)


def bucket_exists(client=None, bucket_name=None):
    """Check if a bucket exists"""
    b_found = False
    b_retry = True
    b_completed = False
    while b_retry and (not b_completed):
        try:
            response = client.list_buckets()
            for bucket in response.get("Buckets", []):
                if bucket.get("Name") == bucket_name:
                    b_found = True
                    break
            b_completed = True
        except botocore.exceptions.ClientError as error:
            # are we being throttled?
            if error.response["Error"]["Code"] == "TooManyRequestsException":
                logger.warning("API call limit exceeded; backing off and retrying...")
                time.sleep(0.25)
                b_retry = True
            else:
                # no, some other error
                logger.error("Error trying to check if bucket name '%s' exists.", bucket_name)
                logger.error("Error: %s", error)
                b_retry = False
        except (ValueError, TypeError):
            logger.error("Unknown Exception trying to check if bucket name '%s' exists.", bucket_name)
    return b_found


def create_bucket(client=None, bucket_name=None):
    """Create a bucket"""
    if (not client) or (not bucket_name):
        logger.error("Invalid client or bucket_name received")
        return False
    b_retry = True
    b_completed = False
    while b_retry and (not b_completed):
        try:
            if not bucket_exists(client, bucket_name):
                # try to create
                logger.debug("Creating bucket: %s", bucket_name)
                response = client.create_bucket(
                    Bucket=bucket_name,
                    CreateBucketConfiguration={"LocationConstraint": "ca-central-1"},
                )
                if response:
                    logger.info("create_bucket response: %s", response)
                    if response.get("Location"):
                        # success
                        # set bucket policy to restrict access only with SSL/TLS
                        bucket_policy = """
                        {
                            "Version": "2012-10-17",
                            "Id": "SSLOnlyPolicy",
                            "Statement": [
                                {
                                    "Sid": "AllowSSLRequestsOnly",
                                    "Effect": "Deny",
                                    "Principal": "*",
                                    "Action": "s3:*",
                                    "Resource": [
                                        "arn:aws:s3:::{{BUCKET_NAME}}",
                                        "arn:aws:s3:::{{BUCKET_NAME}}/*"
                                    ],
                                    "Condition": {
                                        "Bool": {
                                            "aws:SecureTransport": "false"
                                        }
                                    }
                                }
                            ]
                        }
                        """.replace(
                            "{{BUCKET_NAME}}", bucket_name
                        )
                        logger.debug("Bucket policy RAW: %s", bucket_policy)
                        json_policy = json.loads(bucket_policy)
                        bucket_policy = json.dumps(json_policy, indent=4)
                        logger.debug("Bucket policy JSON: %s", bucket_policy)
                        try:
                            response = client.put_bucket_policy(
                                Bucket=bucket_name,
                                Policy=bucket_policy,
                            )
                            if response:
                                if response.get("ResponseMetadata"):
                                    # success
                                    logger.info("Succesfully set the bucket policy to restrict SSL/TLS only access.  Bucket name %s", bucket_name)
                                else:
                                    logger.error("Empty ResponseMetadata when trying to set the bucket policy to restrict SSL/TLS only access. Bucket name %s", bucket_name)
                            else:
                                logger.error("Empty response when trying to set the bucket policy to restrict SSL/TLS only access. Bucket name %s", bucket_name)
                        except (ValueError, TypeError):
                            logger.error("Failed to put_bucket_policy on bucket %s", bucket_name)
                        if "awsconfig" not in bucket_name:
                            # create folders
                            binary_data = b""
                            folder_names = [
                                "gc-01",
                                "gc-02",
                                "gc-07",
                                "gc-08",
                                "gc-09",
                                "gc-10",
                            ]
                            for folder_name in folder_names:
                                try:
                                    client.put_object(
                                        Body=binary_data,
                                        Bucket=bucket_name,
                                        Key=f"{folder_name}/",
                                    )
                                except (ValueError, TypeError):
                                    logger.error("Failed to create folder %s in bucket %s", folder_name, bucket_name)
                        b_completed = True
                        return True
                    else:
                        logger.error("No Location in create_bucket response")
                else:
                    logger.error("No response to create_bucket call")
            else:
                # bucket already exists
                logger.info("Bucket '%s' already exists.", bucket_name)
                return True
            b_completed = True
        except botocore.exceptions.ClientError as error:
            logger.error("Error trying to create bucket name '%s'", bucket_name)
            logger.error("Error: %s", error)
            return False
    return b_completed


def send(event, context, response_status, response_data, physical_resource_id=None, no_echo=False, reason=None):
    """Sends a response to CloudFormation"""
    response_url = event['ResponseURL']
    logger.info("Response URL: %s", response_url)
    response_body = {
        'Status': response_status,
        'Reason': reason or f"See the details in CloudWatch Log Stream: {context.log_stream_name}",
        'PhysicalResourceId': physical_resource_id or context.log_stream_name,
        'StackId': event['StackId'],
        'RequestId': event['RequestId'],
        'LogicalResourceId': event['LogicalResourceId'],
        'NoEcho': no_echo,
        'Data': response_data
    }
    json_response_body = json.dumps(response_body)
    logger.info("Response body:")
    logger.info(json_response_body)
    headers = {'content-type': '', 'content-length': str(len(json_response_body))}
    try:
        response = http.request('PUT', response_url, headers=headers, body=json_response_body)
        logger.info("Status code: %s", response.status)
    except (ValueError, TypeError, urllib3.exceptions.HTTPError) as err:
        logger.error("send(..) failed executing http.request(..): %s", err)


def lambda_handler(event, context):
    """This function is the main entry point for Lambda.
    Keyword arguments:
    event -- the event variable given in the lambda handler
    context -- the context variable given in the lambda handler
    """
    aws_s3_client = boto3.client("s3")
    logger.info("got event %s", event)
    response_data = {}
    if event["RequestType"] == "Create":
        letters_and_numbers = string.ascii_lowercase + string.digits
        random_suffix = "".join(random.choice(letters_and_numbers) for i in range(10))
        evidence_bucket_name = event["ResourceProperties"].get("EvidenceBucketName", f"gc-evidence-{random_suffix}")
        logger.info("Using '%s' for EVIDENCE_BUCKET_NAME.", evidence_bucket_name)
        awsconfig_bucket_name = event["ResourceProperties"].get("AWSConfigBucketName", f"gc-awsconfigconforms-{random_suffix}")
        logger.info("Using '%s' for AWSCONFIG_BUCKET_NAME.", awsconfig_bucket_name)
        # create the evidence bucket
        if create_bucket(aws_s3_client, evidence_bucket_name):
            response_data["EvidenceBucketName"] = evidence_bucket_name
            # create the AWS Config Conformance Pack bucket
            if create_bucket(aws_s3_client, awsconfig_bucket_name):
                # success
                response_data["AWSConfigBucketName"] = awsconfig_bucket_name
                # Success
                send(event, context, SUCCESS, response_data)
            else:
                # failed to create the AWS Config conformance pack bucket
                response_data["Reason"] = "Failed to create the AWS Config Conformance Pack S3 bucket. Check CloudWatch Logs."
                send(event, context, FAILED, response_data)
        else:
            # failed to create the evidence bucket
            response_data["Reason"] = "Failed to create the evidence S3 bucket. Check CloudWatch Logs."
            send(event, context, FAILED, response_data)
    elif event["RequestType"] == "Update":
        # update - nothing to do at this time
        res = event["PhysicalResourceId"]
        response_data["lower"] = res.lower()
        send(event, context, SUCCESS, response_data)
    elif event["RequestType"] == "Delete":
        # delete - nothing to delete
        res = event["PhysicalResourceId"]
        response_data["lower"] = res.lower()
        send(event, context, SUCCESS, response_data)
    else:  # delete / update
        # something else, need to raise error
        send(event, context, FAILED, response_data, response_data["lower"])
    logger.info("responseData %s", response_data)
