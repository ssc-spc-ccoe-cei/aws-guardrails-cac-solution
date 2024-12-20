""" Lambda function used to assume a deployment role in all organizational accounts. """
import json
import logging

import boto3
from botocore.exceptions import ClientError
import urllib3

SUCCESS = "SUCCESS"
FAILED = "FAILED"

# cfnresponse replacement
http = urllib3.PoolManager()

logger = logging.getLogger()
logger.setLevel(logging.INFO)

MAX_RETRIES = 3
RETRY_DELAY = 5
FUNCTION_NAME = "aws_create_role"

def get_org_accounts():
    """
    Returns a list of all active accounts in the organization.
    """
    org_client = boto3.client('organizations')
    active_accounts = []
    paginator = org_client.get_paginator('list_accounts')

    for page in paginator.paginate():
        for account in page['Accounts']:
            if account['Status'] == "ACTIVE":
                logger.info(f"Account added {account}")
                active_accounts.append(account)

    return active_accounts


def create_iam_policy(session, policy_name, policy_document):
    """
    Creates an IAM policy.
    """
    logger.info(f"Create Policy {policy_name} using {policy_document}")
    iam_client = session.client('iam')
    sts_response = iam_client.create_policy(
        PolicyName=policy_name,
        PolicyDocument=policy_document
    )
    return sts_response['Policy']


def attach_iam_policy_to_role(session, role_name, policy_arn):
    """
    Attaches an IAM policy to a role.
    """
    logger.info(f"Attach Policy: {policy_arn} to Role {role_name}")
    iam_client = session.client('iam')
    sts_response = iam_client.attach_role_policy(
        RoleName=role_name,
        PolicyArn=policy_arn
    )
    return sts_response


def create_iam_role(session, role_name, principal):
    """
    Creates an IAM role.
    """
    logger.info(f"Creating Role {role_name}")
    iam_client = session.client('iam')
    assume_role_policy_document = {
        'Version': '2012-10-17',
        'Statement': [
            {
                'Effect': 'Allow',
                'Principal': {
                    'AWS': principal
                },
                'Action': 'sts:AssumeRole'
            }
        ]
    }
    sts_response = iam_client.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(assume_role_policy_document)
    )
    return sts_response['Role']


def delete_role(session, role_name):
    """
    Deletes an IAM role.
    """
    logger.info(f"Deleting Role {role_name}")
    iam_client = session.client('iam')
    sts_response = iam_client.delete_role(
        RoleName=role_name
    )
    return sts_response


def detach_all_policies_from_role(session, role_name):
    """
    Detaches all policies from a role.
    """
    logger.info(f"Detach all policies from {role_name}")
    iam_client = session.client('iam')
    sts_response = iam_client.list_attached_role_policies(
        RoleName=role_name
    )

    logger.info(f"Attached Policies to role {role_name} are {sts_response['AttachedPolicies']}")
    for policy in sts_response['AttachedPolicies']:
        logger.info(f"Deleting Policy: {policy}")
        sts_response = iam_client.detach_role_policy(
        RoleName=role_name,
        PolicyArn=policy['PolicyArn']
        )
        delete_iam_policy(session=session, policy_arn=policy['PolicyArn'])

    sts_response = iam_client.list_role_policies(
        RoleName=role_name
    )
    logger.info(f"Inline Policies attached to role {role_name} are {sts_response['PolicyNames']}")
    for policy_name in sts_response['PolicyNames']:
      logger.info(f"Deleting Policy: {policy_name}")
      sts_response = iam_client.delete_role_policy(
          RoleName=role_name,
          PolicyName=policy_name
      )
    return sts_response


def get_account_id(session):
    """
    Returns the account ID.
    """
    sts_client = session.client('sts')
    return sts_client.get_caller_identity()['Account']


def assume_role(session, account_id, role_name):
    """
    Assumes a role.
    """
    sts_client = session.client('sts')
    sts_response = sts_client.assume_role(
        RoleArn=f"arn:aws:iam::{account_id}:role/{role_name}",
        RoleSessionName=str(account_id)
    )
    sts_session = boto3.Session(aws_access_key_id=sts_response['Credentials']['AccessKeyId'], aws_secret_access_key=sts_response[
                                'Credentials']['SecretAccessKey'], aws_session_token=sts_response['Credentials']['SessionToken'])
    return sts_session


def delete_iam_policy(session, policy_arn):
    """
    Deletes an IAM policy.
    """
    # Check if the policy is an AWS managed policy
    if policy_arn.startswith("arn:aws:iam::aws:policy/"):
        logger.info(f"Skipping deletion of AWS managed policy: {policy_arn}")
        return {"Status": "Skipped", "Reason": "AWS Managed Policy"}
    
    iam_client = session.client('iam')
    # List all versions of the policy
    versions = iam_client.list_policy_versions(PolicyArn=policy_arn)

    # Loop through the versions and delete the non-default versions
    for version in versions['Versions']:
        if not version['IsDefaultVersion']:
            iam_client.delete_policy_version(
                PolicyArn=policy_arn,
                VersionId=version['VersionId']
            )
            logger.info(f"Deleted non-default policy version {version['VersionId']}")

    sts_response = iam_client.delete_policy(
        PolicyArn=policy_arn
    )
    return sts_response


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
    headers = {'content-type': '',
               'content-length': str(len(json_response_body))}
    try:
        response = http.request('PUT', response_url,
                                headers=headers, body=json_response_body)
        logger.info("Status code: %s", response.status)
    except (ValueError, TypeError, urllib3.exceptions.HTTPError) as err:
        logger.error("send(..) failed executing http.request(..): %s", err)


def wait_for_role(iam_client, role_name):
    """
    Check if role is ready (exists). Returns True if found, False otherwise.
    """
    try:
        iam_client.get_role(RoleName=role_name)
        return True
    except iam_client.exceptions.NoSuchEntityException:
        return False


def self_invoke(event):
    """
    Re-invokes the current Lambda function asynchronously with updated retry attempts.
    """
    lambda_client = boto3.client('lambda')
    current_retry = event.get('RetryCount', 0) + 1
    event['RetryCount'] = current_retry
    logger.info(f"Role not ready, re-invoking self with attempt {current_retry}")

    lambda_client.invoke(
        FunctionName=FUNCTION_NAME,
        InvocationType='Event',
        Payload=json.dumps(event)
    )


def lambda_handler(event, context):
    """This function is the main entry point for Lambda.
    Keyword arguments:
    event -- the event variable given in the lambda handler
    context -- the context variable given in the lambda handler
    """
    response_data = {}
    logger.info("Received Event: %s", json.dumps(event, indent=2))
    # Get parameters from event
    trust_principal = event['ResourceProperties']['TrustPrincipal'].split(',')
    switch_role = event['ResourceProperties']['SwitchRole']
    role_name = event['ResourceProperties']['RoleName']
    policy_string = event['ResourceProperties']['PolicyPackage'].replace(
        "'", '"')
    logger.info(f"Policy String: {policy_string}")
    policy_package = json.loads(policy_string, strict=False)
    retry_count = event.get('RetryCount', 0)
    # Get list of Org accounts and the current account_id
    try:
        accounts = get_org_accounts()
    except Exception as err:
        logger.error(f"Error getting accounts: {err}")
        response_data['Error'] = f"Error getting accounts: {err}"
        send(event, context, FAILED, response_data)
        raise err
    try:
        session = boto3.Session()
    except Exception as err:
        logger.error(f"Error getting session: {err}")
        response_data['Error'] = f"Error getting session: {err}"
        send(event, context, FAILED, response_data)
        raise err
    try:
        account_id = get_account_id(session)
    except Exception as err:
        logger.error(f"Error getting account ID: {err}")
        response_data['Error'] = f"Error getting account ID: {err}"
        send(event, context, FAILED, response_data)
        raise err
    if event['RequestType'] == 'Create' or event['RequestType'] == 'Update':
        logger.info(f"CFN {event['RequestType']} request received")
        for account in accounts:
            if account_id in account['Id']:  # Skip the managment account
                continue
            try:
                sts_session = assume_role(
                    session=session, account_id=account['Id'], role_name=switch_role)
                    iam_client = sts_session.client('iam')
                    if not wait_for_role(iam_client, role_name):
                        if retry_count < MAX_RETRIES:
                            self_invoke(event)
                            return
                        else:
                            logger.error(f"Role {role_name} not found after {MAX_RETRIES} retries. Failing.")
                            response_data['Error'] = f"Role {role_name} not ready in account {account['Id']}"
                            send(event, context, FAILED, response_data)
                            return

            except Exception as err:
                logger.error(f"Error assuming role: {err}")
                response_data['Error'] = f"Error assuming role: {err}"
                send(event, context, FAILED, response_data)
                raise err
            try:
                iam_role = create_iam_role(
                    session=sts_session, role_name=role_name, principal=trust_principal)
            except ClientError as e:
                if e.response['Error']['Code'] == 'EntityAlreadyExists':
                    logger.info(f"Existing IAM Role {role_name} found in account {account['Id']}, removing policies and deleting role.")
                    detach_all_policies_from_role(session=sts_session, role_name=role_name)
                    delete_role(session=sts_session, role_name=role_name)
                    iam_role = create_iam_role(session=sts_session, role_name=role_name, principal=trust_principal)
                else:
                    logger.info(f"Exception ocured while creating role {role_name} in {account['Id']}: {e}")
            for policy_doc in policy_package['Docs']:
                logger.info(f"Policy_Doc:{json.dumps(policy_doc)}")
                try:
                    policy = create_iam_policy(
                        session=sts_session, policy_name=policy_doc['Statement'][0]['Sid'], policy_document=json.dumps(policy_doc))
                except ClientError as e:
                    if e.response['Error']['Code'] == 'EntityAlreadyExists':
                        logger.info(f"Existing Policy {policy_doc['Statement'][0]['Sid']} found. Recreating it.")
                        try:  
                            delete_iam_policy(session=sts_session, policy_arn=f"arn:aws:iam::{account['Id']}:policy/{policy_doc['Statement'][0]['Sid']}")
                            policy = create_iam_policy(session=sts_session, policy_name=policy_doc['Statement'][0]['Sid'], policy_document=json.dumps(policy_doc))
                        except Exception as e:
                            logger.info(f"Error recreating {policy_doc['Statement'][0]['Sid']}. Exception: {e}")
                    else:
                        logger.info(f"Exception ocured while creating policy {policy_doc['Statement'][0]['Sid']}: {e}")
                try:
                    attach_iam_policy_to_role(
                        session=sts_session, role_name=iam_role['RoleName'], policy_arn=policy['Arn'])
                except Exception as err:
                    logger.info(
                        f"Error attaching {iam_role['RoleName']} to {policy['Arn']}. Exception: {err}")
        send(event, context, SUCCESS, response_data)

    elif event['RequestType'] == 'Delete':
        logger.info(f"CFN {event['RequestType']} request received")
        for account in accounts:
            if account_id in account['Id']:  # Skip the managment account
                continue
            try:
                sts_session = assume_role(
                    session=session, account_id=account['Id'], role_name=switch_role)
            except Exception as err:
                logger.error(f"Error assuming role: {err}")
                response_data['Error'] = f"Error assuming role: {err}"
                send(event, context, FAILED, response_data)
                raise err
            try:
                detach_all_policies_from_role(
                    session=sts_session, role_name=role_name)
                delete_role(session=sts_session, role_name=role_name)
            except Exception as err:
                logger.info(
                    f"Error deletingrole {role_name}. Exception: {err}")
            for policy_doc in policy_package:
                try:
                    delete_iam_policy(
                        session=sts_session, policy_arn=f"arn:aws:iam::{account['Id']}:policy/{policy_doc['Statement'][0]['Sid']}")
                except Exception as err:
                    logger.info(
                        f"deleting Policy {policy_doc} in {account['Id']} failed. Exception: {err}")
                    policy = {}
            rs = event['PhysicalResourceId']
            response_data['lower'] = rs.lower()
            send(event, context, SUCCESS, response_data)
    else:  # delete / update
        # something else, need to raise error
        send(event, context, FAILED, response_data, response_data['lower'])
