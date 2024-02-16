""" Lambda function to create evidence bucket and AWS Config bucket."""
import json
import logging
import random
import string
import urllib3


SUCCESS = "SUCCESS"
FAILED = "FAILED"

# cfnresponse replacement
http = urllib3.PoolManager()

# Logging setup
logger = logging.getLogger()
logger.setLevel(logging.INFO)


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
    """Lambda function to create evidence bucket and AWS Config bucket."""
    logger.info("got event %s", event)
    response_data = {}
    try:
        if event["RequestType"] == "Create":
            letters_and_numbers = string.ascii_lowercase + string.digits
            random_suffix = "".join(random.choice(letters_and_numbers) for i in range(10))
            response_data["EvidenceBucketName"] = f"gc-evidence-{random_suffix}"
            response_data["AWSConfigBucketName"] = f"gc-awsconfigconforms-{random_suffix}"
            send(event, context, SUCCESS, response_data)
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
        else:
            # delete / update
            # something else, need to raise error
            res = event["PhysicalResourceId"]
            response_data["lower"] = res.lower()
            send(event, context, FAILED, response_data, response_data["lower"])
        logger.info("response_data %s", response_data)
    except (ValueError, TypeError) as err:
        raise err
