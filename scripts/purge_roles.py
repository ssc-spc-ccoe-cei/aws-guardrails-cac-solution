#!/usr/bin/env python3
# © 2023 Amazon Web Services, Inc. or its affiliates. All Rights Reserved.
# This AWS Content is provided subject to the terms of the AWS Customer Agreement available at
# http://aws.amazon.com/agreement or other written agreement between Customer and either
# Amazon Web Services, Inc. or Amazon Web Services EMEA SARL or both.
""" Lambda script used to purge roles from all accounts """
import json
import logging
import argparse
import boto3

logger = logging.getLogger()
logging.basicConfig(level=logging.INFO, format='%(message)s')

def get_org_accounts():
    """
    Returns a list of all accounts in the organization.
    """
    org_client = boto3.client('organizations')
    sts_response = org_client.list_accounts()
    if 'NextToken' in sts_response:
        while 'NextToken' in sts_response:
            sts_response = org_client.list_accounts(
                NextToken=sts_response['NextToken'])
            sts_response['Accounts'].extend(sts_response['Accounts'])
    return sts_response['Accounts']


def delete_role(session, role_name, account_id):
    """
    Deletes an IAM role.
    """
    logger.info(f"Deleting Role {role_name}")
    try:
      iam_client = session.client('iam')
      sts_response = iam_client.delete_role(
          RoleName=role_name
      )
    except Exception as err:
        logger.error(
            f"deleting Role {role_name} in {account_id} failed. \n \
              A failure here is not expected \n \
              Exception: {err}")
    return sts_response


def detach_all_policies_from_role(session, role_name, account_id):
    """
    Detaches all policies from a role.
    """
    logger.info(f"Detaching policies from {role_name} in {account_id}")
    iam_client = session.client('iam')
    sts_response = iam_client.list_attached_role_policies(
        RoleName=role_name
    )
    for policy in sts_response['AttachedPolicies']:
        logger.info(f"Detching Policy {policy['PolicyArn']}")
        sts_response = iam_client.detach_role_policy(
            RoleName=role_name,
            PolicyArn=policy['PolicyArn']
        )
        try:
            logger.info(f"Deleting Policy: {policy['PolicyArn']} in {account_id}")
            iam_client.delete_iam_policy(
                session=session, policy_arn=policy['PolicyArn'])
        except Exception as err:
            logger.warning(
                f"deleting Policy {policy['PolicyArn']} in {account_id} failed. \n \
                  A failure here is expected if the policy is a managed policy \n \
                  Exception: {err}")
    
    sts_response = iam_client.list_role_policies(
        RoleName=role_name
    )
    logger.info(f"Found inline Policies {sts_response['PolicyNames']}")
    for policy in sts_response['PolicyNames']:
        try:
            logger.info(
                f"Deleting Policy: {policy} in {account_id}")
            iam_client.delete_role_policy(
                 RoleName=role_name, PolicyName=policy)
        except Exception as err:
            logger.warning(
                f"deleting Policy {role_name}:{policy} in {account_id} failed. \n \
                  Exception: {err}")
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
    iam_client = session.client('iam')
    sts_response = iam_client.delete_policy(
        PolicyArn=policy_arn
    )
    return sts_response

parser = argparse.ArgumentParser(
    description='Utility to remove all roles from an organization based on name')
parser.add_argument('--role', help='role to remove',
                    nargs='?', required=True)
parser.add_argument('--assume', help='role name to assume',
                    nargs='?', required=True)
args = parser.parse_args()

logger.info(f"Removing {args.role} from all Organization accounts using {args.assume}")
switch_role = args.assume
role_name = args.role

try:
    session = boto3.Session()
    account_id = get_account_id(session)
except Exception as err:
    logger.error(f"Error getting session: {err}")
    raise err
# Get list of Org accounts and the current account_id
try:
    accounts = get_org_accounts()
except Exception as err:
    logger.error(f"Error getting accounts: {err}")
    raise err
for account in accounts:
    logger.info(f"Deleting {role_name} from {account['Id']}")
    try:
        if account_id != account['Id']:
          sts_session = assume_role(
              session=session, account_id=account['Id'], role_name=switch_role)
    except Exception as err:
        logger.error(f"Error assuming role: {err}")
        raise err
    try:
        detach_all_policies_from_role(
            session=sts_session, role_name=role_name, account_id=account['Id'])
        delete_role(session=sts_session, role_name=role_name, account_id=account_id)
    except Exception as err:
        logger.info(
            f"Error deletingrole {role_name}. Exception: {err}")
        logger.info("Continuing...")


