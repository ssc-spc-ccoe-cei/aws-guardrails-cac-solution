""" Setup AWS COnfig """
import json
import logging
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


def check_delegated_administrators(client=None, service_principal="", audit_account_id=""):
    """Checks if an AWS Account ID has been configured as a delegated administrator for an
    AWS service principal using the AWS Organizations API.
    :param client: boto3 AWS Organizations client
    :param service_principal: service principal to check
    :param audit_account_id: Account ID of the Audit Account (expected delegated admin)
    :return: 1 if delegated administrator found, 0 if not found, or -1 in case of errors
    """
    b_retry = True
    while b_retry:
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
                        b_retry = False
                    else:
                        # try to avoid Throttling by sleeping for 50ms
                        time.sleep(0.05)
                        response = client.list_delegated_administrators(
                            ServicePrincipal=service_principal,
                            NextToken=next_token
                        )
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
            b_retry = False
            return -1
    b_result = 0
    for delegated_admin in delegated_administrators:
        if audit_account_id == delegated_admin.get("Id", ""):
            # delegated admin found
            b_result = 1
            break
    return b_result


def setup_stacksets_service_access(client=None):
    """Enables AWS Service Access for StackSets using the AWS Organizations API.
    :param client: boto3 AWS Organizations client
    :return: 1 if successful or -1 in case of errors
    """
    i_result = 0
    # Try to Enable AWS Service Access
    try:
        client.enable_aws_service_access(
            # ServicePrincipal='stacksets.cloudformation.amazonaws.com'
            ServicePrincipal="member.org.stacksets.cloudformation.amazonaws.com"
        )
        i_result = 1
    except botocore.exceptions.ClientError as error:
        logger.error("Unable to Enable AWS Service Access for the 'stacksets.cloudformation.amazonaws.com' service. Error: %s", error)
        i_result = -1
    return i_result


def setup_config_multiaccountsetup_delegatedadmin(client=None, audit_account_id=""):
    """Enables AWS Service Access for AWS Config (Multi-account) and configures the
    Audit Account as a delegated administrator for AWS Config, using the AWS Organizations API.
    :param client: boto3 AWS Organizations client
    :param audit_account_id: Account ID of the Audit Account (expected delegated admin)
    :return: 1 if successful, 0 if unable to make the change, or -1 in case of errors
    """
    i_result = -1
    # Try to Enable AWS Service Access
    try:
        client.enable_aws_service_access(ServicePrincipal="config-multiaccountsetup.amazonaws.com")
    except botocore.exceptions.ClientError:
        logger.info("Unable to Enable AWS Service Access for the 'config-multiaccountsetup.amazonaws.com' service.")
        return -1
    # Try to Register Delegated Administrator
    try:
        client.register_delegated_administrator(
            AccountId=audit_account_id,
            ServicePrincipal="config-multiaccountsetup.amazonaws.com",
        )
        # check if it's showing up
        if (
            check_delegated_administrators(
                client=client,
                service_principal="config-multiaccountsetup.amazonaws.com",
                audit_account_id=audit_account_id,
            )
            == 1
        ):
            # yes, all good.
            logger.info("Successfully configured Audit Account '%s' as a delegated administrator for the AWS Config multiaccountsetup service.", audit_account_id)
            i_result = 1
        else:
            # not showing up
            logger.info("Unable to configure Audit Account '%s' as a delegated administrator for the AWS Config multiaccountsetup service.", audit_account_id)
            i_result = 0
    except botocore.exceptions.ClientError:
        logger.info("Error while trying to register the Audit account '%s' as the delegated administrator for the config-multiaccountsetup.amazonaws.com service.", audit_account_id)
    return i_result


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
    logger.info("got event %s", event)
    response_data = {}
    if event["RequestType"] == "Create":
        audit_account_id = event["ResourceProperties"].get("AuditAccountId", "")
        if audit_account_id:
            # proceed
            # check if the Audit Account is a delegated administrator for AWS Config
            if (
                check_delegated_administrators(
                    client=aws_organizations_client,
                    service_principal="config.amazonaws.com",
                    audit_account_id=audit_account_id,
                )
                == 1
            ):
                logger.info("Audit Account '%s' is a delegated administrator for the AWS Config service.", audit_account_id)
                # check if the Audit Account is a delegated administrator for
                # AWS Config multi account setup
                if (
                    check_delegated_administrators(
                        client=aws_organizations_client,
                        service_principal="config-multiaccountsetup.amazonaws.com",
                        audit_account_id=audit_account_id,
                    )
                    == 1
                ):
                    logger.info("Audit Account '%s' is a delegated administrator for the AWS Config multiaccountsetup service.", audit_account_id)
                    send(event, context, SUCCESS, response_data)
                else:
                    logger.info("Audit Account '%s' is NOT a delegated administrator for the AWS Config multiaccountsetup service.", audit_account_id)
                    # let's attempt to set it up
                    if (
                        setup_config_multiaccountsetup_delegatedadmin(
                            client=aws_organizations_client,
                            audit_account_id=audit_account_id,
                        )
                        == 1
                    ):
                        logger.info("Audit Account '%sß' successfully configured as a delegated administrator for the AWS Config multiaccountsetup service.", audit_account_id)
                        send(event, context, SUCCESS, response_data)
                    else:
                        logger.info("Unable to configure Audit Account '%s' as a delegated administrator for the AWS Config multiaccountsetup service.", audit_account_id)
                        send(event, context, FAILED, response_data)
            else:
                logger.info("Audit Account '%s' is NOT a delegated administrator for the AWS Config service", audit_account_id)
                response_data["Error"] = f"Audit Account '{audit_account_id}' is NOT a delegated administrator for the AWS Config service. Please fix before continuing."
                send(event, context, FAILED, response_data)
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
