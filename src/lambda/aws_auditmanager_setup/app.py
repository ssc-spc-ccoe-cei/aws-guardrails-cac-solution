""" Audit Manager Resources Config Setup"""
import json
import logging
import time
import sys

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


def check_delegated_administrators(client=None, service_principal="", audit_account_id=""):
    """Checks if an AWS Account ID has been configured as a delegated administrator for an
    AWS service principal using the AWS Organizations API.
    :param client: boto3 AWS Organizations client
    :param service_principal: service principal to check
    :param audit_account_id: Account ID of the Audit Account (expected delegated admin)
    :return: 1 if delegated administrator found, 0 if not found, or -1 in case of errors
    """
    b_retry = True
    b_completed = False
    while b_retry and (not b_completed):
        try:
            response = client.list_delegated_administrators(ServicePrincipal=service_principal)
            b_more_data = True
            next_token = ""
            delegated_administrators = []
            while b_more_data:
                if response:
                    delegated_administrators.extend(response.get("DelegatedAdministrators"))
                    next_token = response.get("NextToken")
                    if not next_token:
                        b_more_data = False
                        b_completed = True
                    else:
                        # try to avoid Throttling by sleeping for 50ms
                        time.sleep(0.05)
                        response = client.list_delegated_administrators(
                            ServicePrincipal=service_principal,
                            NextToken=next_token
                        )
                else:
                    logger.error("No response when trying to list_delegated_administrators.")
                    b_completed = True
                    b_more_data = False
        except botocore.exceptions.ClientError as error:
            # are we being throttled?
            if error.response["Error"]["Code"] == "TooManyRequestsException":
                logger.warning("API call limit exceeded; backing off and retrying...")
                time.sleep(0.25)
                b_retry = True
            else:
                # no, some other error
                logger.error("boto3 error %s", error)
                b_retry = False
                return -1
        except (ValueError, TypeError):
            logger.error("Unknown exception when trying to list_delegated_administrators")
            b_retry = False
            return -1
    b_result = 0
    for delegated_admin in delegated_administrators:
        if audit_account_id == delegated_admin.get("Id", ""):
            # delegated admin found
            b_result = 1
            break
    return b_result


def check_auditmanager_service_access(client=None):
    """Checks if AWS Audit Manager has been enabled for AWS Service Access
    using the AWS Organizations API.
    :param client: boto3 AWS Organizations client
    :return: 1 if service access is enabled, 0 if disabled, or -1 in case of errors
    """
    b_retry = True
    b_completed = False
    while b_retry and (not b_completed):
        try:
            response = client.list_aws_service_access_for_organization()
            b_more_data = True
            next_token = ""
            enabled_service_principals = []
            while b_more_data:
                if response:
                    enabled_service_principals.extend(response.get("EnabledServicePrincipals"))
                    next_token = response.get("NextToken")
                    if not next_token:
                        b_more_data = False
                        b_completed = True
                    else:
                        # try to avoid Throttling by sleeping for 50ms
                        time.sleep(0.05)
                        response = client.list_aws_service_access_for_organization(NextToken=next_token)
                else:
                    logger.error("No response when trying to list_aws_service_access_for_organization.")
                    b_retry = False
        except botocore.exceptions.ClientError as error:
            # are we being throttled?
            if error.response["Error"]["Code"] == "TooManyRequestsException":
                logger.warning("API call limit exceeded; backing off and retrying...")
                time.sleep(0.25)
                b_retry = True
            else:
                # no, some other error
                logger.error("boto3 error %s", error)
                b_retry = False
                return -1
        except (ValueError, TypeError):
            logger.error("Unknown exception when trying to list_aws_service_access_for_organization")
            b_retry = False
            return -1
    i_result = 0
    for service_principal in enabled_service_principals:
        if "auditmanager.amazonaws.com" == service_principal.get("ServicePrincipal", ""):
            # it's enabled for Audit Manager
            i_result = 1
            break
    return i_result


def enable_auditmanager_service_access(client=None):
    """Enables AWS Service Access for AWS Audit Manager using the AWS Organizations API.
    :param client: boto3 AWS Organizations client
    :return: 1 if successful, 0 if unable to make the change, or -1 in case of errors
    """
    b_retry = True
    b_completed = False
    while b_retry and (not b_completed):
        # Try to Enable AWS Service Access for Audit Manager
        try:
            client.enable_aws_service_access(ServicePrincipal="auditmanager.amazonaws.com")
            b_completed = True
        except botocore.exceptions.ClientError as error:
            # are we being throttled?
            if error.response["Error"]["Code"] == "TooManyRequestsException":
                logger.warning("API call limit exceeded; backing off and retrying...")
                time.sleep(0.25)
                b_retry = True
            elif error.response["Error"]["Code"] == "ConcurrentModificationException":
                logger.warning("ConcurrentModificationException; backing off and retrying...")
                time.sleep(10)
                b_retry = True
            else:
                # no, some other error
                logger.error("Error while trying to enable AWS Service Access for the 'auditmanager.amazonaws.com' service.")
                logger.error("boto3 error %s", error)
                b_retry = False
                return -1
        except (ValueError, TypeError):
            logger.error("Error while trying to enable AWS Service Access for the 'auditmanager.amazonaws.com' service.")
            b_retry = False
            return False
    # check if it's showing up as enabled
    if check_auditmanager_service_access(client=client) == 1:
        # yes, all good.
        logger.info("Successfully enabled AWS Service Access for Audit Manager")
        return 1
    else:
        # not showing up
        logger.info("Failed to enable AWS Service Access for the 'auditmanager.amazonaws.com' service.")
        return 0


def auditmanager_register_account(client=None, audit_account_id=""):
    """Enables AWS Audit Manager and configures the Audit Account as a delegated administrator.
    :param client: boto3 AWS Audit Manager client
    :param audit_account_id: Account ID of the Audit Account (expected delegated admin)
    :return: 1 if successful, 0 if unable to make the change, or -1 in case of errors
    """
    if not client:
        logger.info("Invalid boto3 client provided to 'auditmanager_register_account' function.")
        return -1
    if not audit_account_id:
        logger.info("Invalid audit_account_id provided to 'auditmanager_register_account' function.")
        return -1
    b_retry = True
    b_completed = False
    while b_retry and (not b_completed):
        # Try to enable Audit Manager and establish delegated administration with the Audit Account
        try:
            response = client.register_account(delegatedAdminAccount=audit_account_id)
            status = response.get("status", "")
            b_completed = True
            if status and (status != "INACTIVE"):
                # success
                logger.info("AWS Audit Manager successfully registered with delegated administration to the '%s' account ID.", audit_account_id)
                return 1
            else:
                # fail
                logger.error("Unable to register AWS Audit Manager with delegated administration to the '%s' account ID.", audit_account_id)
                return 0
        except botocore.exceptions.ClientError as error:
            # are we being throttled?
            if (error.response["Error"]["Code"] == "TooManyRequestsException") or (
                error.response["Error"]["Code"] == "ThrottlingException"
            ):
                logger.warning("API call limit exceeded; backing off and retrying...")
                time.sleep(0.25)
                b_retry = True
            elif error.response["Error"]["Code"] == "ConcurrentModificationException":
                logger.warning("ConcurrentModificationException; backing off and retrying...")
                time.sleep(10)
                b_retry = True
            else:
                # no, some other error
                logger.error("Error while trying to enable AWS Audit Manager with delegated administration to the '%s' account ID.", audit_account_id)
                logger.error("boto3 error %s", error)
                b_retry = False
                return -1
        except (ValueError, TypeError):
            logger.error("Error while trying to enable AWS Audit Manager with delegated administration to the %s' account ID.", audit_account_id)
            return -1


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
    aws_organizations_client = boto3.client("organizations")
    aws_auditmanager_client = boto3.client("auditmanager")
    logger.info("got event %s", event)
    response_data = {}
    if event["RequestType"] == "Create":
        audit_account_id = event["ResourceProperties"].get("AuditAccountId", "")
        if audit_account_id:
            # proceed
            b_audit_manager_service_access_enabled = False
            # check if AWS service access for Audit Manager has been enabled
            result = check_auditmanager_service_access(aws_organizations_client)
            if result == -1:
                # error while trying to validate
                logger.info("Error encountered while trying to validate that AWS Service Access has been enabled for Audit Manager")
                send(event, context, FAILED, response_data)
            elif result == 0:
                # it's disabled
                logger.info("AWS Service Access for Audit Manager has not been enabled. Will attempt to enable it.")
                result = enable_auditmanager_service_access(aws_organizations_client)
                if result != 1:
                    # Failed!
                    send(event, context, FAILED, response_data)
                    sys.exit(1)
                elif result == 1:
                    # Success
                    b_audit_manager_service_access_enabled = True
            elif result == 1:
                # it's enabled, no additional action required
                b_audit_manager_service_access_enabled = True
                logger.info("AWS Service Access was already enabled for Audit Manager.")
            if b_audit_manager_service_access_enabled:
                # proceed to Audit Manager registration
                registration_result = auditmanager_register_account(
                    client=aws_auditmanager_client,
                    audit_account_id=audit_account_id
                )
                if registration_result != 1:
                    send(event, context, FAILED, response_data)
                else:
                    send(event, context, SUCCESS, response_data)
        else:
            # no AuditAccountID value received.
            response_data["Error"] = "No AuditAccountID value received. Please fix before continuing."
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
