""" Setup Lambda Permissions """
# This needs to be updated to run on a cronjob as well as modified to be used outside of a custom resource, otherwise new account will not
# be able to access the config rules
# Eventbridge rule run every 6 hours
import os
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


def get_accounts():
    """Queries AWS Organizations and returns a List of AWS Accounts
    :return: List of AWS Accounts
    """
    accounts = []
    client = boto3.client("organizations")
    b_retry = True
    b_completed = False
    while b_retry and (not b_completed):
        try:
            response = client.list_accounts()
            if response:
                accounts = response.get("Accounts")
                next_token = response.get("NextToken")
                while next_token:
                    response = client.list_accounts(NextToken=next_token)
                    accounts.extend(response.get("Accounts"))
                    next_token = response.get("NextToken")
            else:
                logger.error("Unable to read account data from AWS - empty response.")
                b_retry = False
            b_completed = True
        except botocore.exceptions.ClientError as error:
            if error.response["Error"]["Code"] == "TooManyRequestsException":
                logger.warning("API call limit exceeded; backing off and retrying...")
                time.sleep(0.25)
                b_retry = True
            else:
                # no, some other error
                logger.error("Unable to list accounts in AWS Organizations. Error:\n %s", error)
                b_retry = False
        except (ValueError, TypeError):
            logger.error("Unknown Exception trying to list accounts in AWS Organizations.")
            b_retry = False
    return accounts


def apply_lambda_permissions():
    """Ensures all GC Guardrail Assessment Lambda Functions can be invoked by all
    AWS Accounts in the Organization.
    :return: 1 if successful, 0 if unable to apply permissions, or -1 in case of errors
    """
    organization_name = os.environ['OrganizationName']
    logger.debug("Organization Name: %s", organization_name)
    i_result = 0
    permissions_validated = 0
    lambda_functions = {
        f"{organization_name}gc01_check_alerts_flag_misuse": ["GC01CheckAlertsFlagMisuseLambda"],
        f"{organization_name}gc01_check_dedicated_admin_account": ["GC01CheckDedicatedAdminAccountLambda"],
        f"{organization_name}gc01_check_federated_users_mfa": ["GC01CheckFederatedUsersMFALambda"],
        f"{organization_name}gc01_check_iam_users_mfa": ["GC01CheckIAMUsersMFALambda"],
        f"{organization_name}gc01_check_mfa_digital_policy": ["GC01CheckMFADigitalPolicy"],
        f"{organization_name}gc01_check_monitoring_and_logging": ["GC01CheckMonitoringAndLoggingLambda"],
        f"{organization_name}gc01_check_root_mfa": ["GC01CheckRootAccountMFAEnabledLambda"],
        f"{organization_name}gc02_check_access_management_attestation": ["GC02CheckAccessManagementAttestationLambda"],
        f"{organization_name}gc02_check_group_access_configuration": ["GC02CheckGroupAccessConfigurationLambda"],
        f"{organization_name}gc02_check_iam_password_policy": ["GC02CheckIAMPasswordPolicyLambda"],
        f"{organization_name}gc02_check_password_protection_mechanisms": ["GC02CheckPasswordProtectionMechanismsLambda"],
        f"{organization_name}gc02_check_privileged_roles_review": ["GC02CheckPrivilegedRolesReviewLambda"],
        f"{organization_name}gc03_check_endpoint_access_config": ["GC03CheckEndpointAccessConfigLambda"],
        f"{organization_name}gc03_check_trusted_devices_admin_access": ["GC03CheckTrustedDevicesAdminAccessLambda"],
        f"{organization_name}gc04_check_alerts_flag_misuse": ["GC04CheckAlertsFlagMisuseLambda"],
        f"{organization_name}gc04_check_enterprise_monitoring": ["GC04CheckEnterpriseMonitoringLambda"],
        f"{organization_name}gc05_check_data_location": ["GC05CheckDataLocationLambda"],
        f"{organization_name}gc06_check_encryption_at_rest_part1": ["GC06CheckEncryptionAtRestPart1Lambda"],
        f"{organization_name}gc06_check_encryption_at_rest_part2": ["GC06CheckEncryptionAtRestPart2Lambda"],
        f"{organization_name}gc07_check_certificate_authorities": ["GC07CheckCertificateAuthoritiesLambda"],
        f"{organization_name}gc07_check_cryptographic_algorithms": ["GC07CheckCryptographicAlgorithmsLambda"],
        f"{organization_name}gc07_check_encryption_in_transit": ["GC07CheckEncryptionInTransitLambda"],
        f"{organization_name}gc07_check_secure_network_transmission_policy": ["GC07CheckSecureNetworkTransmissionPolicyLambda"],
        f"{organization_name}gc08_check_cloud_deployment_guide": ["GC08CheckCloudDeploymentGuideLambda"],
        f"{organization_name}gc08_check_cloud_segmentation_design": ["GC08CheckCloudSegmentationDesignLambda"],
        f"{organization_name}gc08_check_target_network_architecture": ["GC08CheckTargetNetworkArchitectureLambda"],
        f"{organization_name}gc09_check_netsec_architecture": ["GC09CheckNetworkSecurityArchitectureDocumentLambda"],
        f"{organization_name}gc09_check_non_public_storage_accounts": ["GC09CheckNonPublicStorageAccountsLambda"],
        f"{organization_name}gc10_check_cyber_center_sensors": ["GC10CheckCyberCenterSensorsLambda"],
        f"{organization_name}gc11_check_monitoring_all_users": ["GC11CheckMonitoringAllUsersLambda"],
        f"{organization_name}gc11_check_monitoring_use_cases": ["GC11CheckMonitoringUseCasesLambda"],
        f"{organization_name}gc11_check_policy_event_logging": ["GC11CheckPolicyEventLoggingLambda"],
        f"{organization_name}gc11_check_security_contact": ["GC11CheckSecurityContactLambda"],
        f"{organization_name}gc11_check_timezone": ["GC11CheckTimezoneLambda"],
        f"{organization_name}gc11_check_trail_logging": ["GC11CheckTrailLoggingLambda"],
        f"{organization_name}gc12_check_private_marketplace": ["GC12CheckPrivateMarketplacesLambda"],
        f"{organization_name}gc13_check_emergency_account_alerts": ["GC13CheckEmergencyAccountAlertsLambda"],
        f"{organization_name}gc13_check_emergency_account_management": ["GC13CheckEmergencyAccountManagementLambda"],
        f"{organization_name}gc13_check_emergency_account_mgmt_approvals": ["GC13CheckEmergencyAccountMgmtApprovalsLambda"],
        f"{organization_name}gc13_check_emergency_account_testing": ["GC13CheckEmergencyAccountTestingLambda"],
    }
    accounts = get_accounts()
    client = boto3.client("lambda")
    i_requests = 0
    if accounts:
        for lambda_name in lambda_functions:
            # check if any accounts are currently authorized
            authorized_accounts = []
            sids_in_use = []
            b_retry = True
            b_completed = False
            while b_retry and (not b_completed):
                try:
                    response = client.get_policy(FunctionName=lambda_name)
                    i_requests += 1
                    if i_requests % 3 == 0:
                        # backing off the API to avoid throttling
                        time.sleep(0.05)
                    for statement in json.loads(response.get("Policy")).get("Statement"):
                        try:
                            service = statement.get("Principal").get("Service")
                        except AttributeError:
                            service = "*"
                        
                        if (
                            service == "config.amazonaws.com"
                            and statement.get("Action") == "lambda:InvokeFunction"
                            and statement.get("Effect") == "Allow"
                        ):
                            # this is an authorized account
                            try:
                                source_account = (statement.get("Condition").get("StringEquals").get("AWS:SourceAccount"))
                                authorized_accounts.append(source_account)
                            except AttributeError:
                                source_account = ""
                            
                            if statement.get("Sid", ""):
                                sids_in_use.append(statement.get("Sid", ""))
                            
                    b_completed = True
                    

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
                except (ValueError, TypeError):
                    # let's assume the Lambda function permission does not exist
                    logger.error("Unknown Exception trying to get policy for Lambda function '%s'.", lambda_name)
                    b_retry = False
            
            i = 0
            b_throttle = False
            for account in accounts:
                account_id = account["Id"]
                account_status = str(account["Status"]).upper()
                if (account_id in authorized_accounts) or (account_status != "ACTIVE"):
                    # skip this account and go to the next loop iteration
                    i += 1
                    permissions_validated += 1
                    continue
                # we need to add the permission
                compliant_resource_name = f"p{i + 1}"
                # ensure we are using a unique Sid
                while compliant_resource_name in sids_in_use:
                    i += 1
                    compliant_resource_name = f"p{i + 1}"
                b_retry = True
                b_permission_added = False
            
                while b_retry and (not b_permission_added):
                    # if we've been throttled, sleep 50ms every 5 calls
                    if b_throttle and (i_requests % 5 == 0):
                        time.sleep(0.05)
                    try:
                        i_requests += 1
                        
                        response = client.add_permission(
                            Action="lambda:InvokeFunction",
                            FunctionName=lambda_name,
                            Principal="config.amazonaws.com",
                            SourceAccount=account_id,
                            StatementId=compliant_resource_name,
                        )
                    
                        if not response.get("Statement"):
                            # invalid response
                            logger.error("Invalid response adding permission for account '%s' to the '%s'", account_id, lambda_name)
                            i_result = -1
                            b_retry = False
                            break
                        else:
                            # success
                            permissions_validated += 1
                            b_permission_added = True
                    except botocore.exceptions.ClientError as error:
                        # error while trying to add the permission
                        # are we being throttled?
                        if (error.response["Error"]["Code"] == "TooManyRequestsException"):
                            logger.warning("API call limit exceeded; backing off and retrying...")
                            b_throttle = True
                            b_retry = True
                            time.sleep(0.25)
                        else:
                            logger.error("Error while adding permission for account '%s' to the '%s' lambda", account_id, lambda_name)
                            logger.error("Error: {%s}", error)
                            i_result = -1
                            b_retry = False
                i += 1
                if i_result == -1:
                    # we ran into errors, stop the process
                    break
            if i_result != -1 and permissions_validated > 0:
                # success!
                i_result = 1
    else:
        logger.error("No accounts listed - unable to add Lambda permissions to template")
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
    logger.info("Received Event: %s", json.dumps(event, indent=2))
    response_data = {}
    if event["RequestType"] == "Create":
        # try to add the lambda permissions
        result = apply_lambda_permissions()
        if result != 1:
            # we failed
            response_data["Reason"] = "Failed to add the Lambda Permissions. Check CloudWatch Logs."
            send(event, context, FAILED, response_data)
        else:
            # success
            response_data["Reason"] = "Successfully added the Lambda Permissions. Check CloudWatch Logs."
            send(event, context, SUCCESS, response_data)
    elif event["RequestType"] == "Update":
        # try to validate the lambda permissions
        result = apply_lambda_permissions()
        if result != 1:
            # we failed
            response_data["Reason"] = "Failed to update the Lambda Permissions. Check CloudWatch Logs."
            send(event, context, FAILED, response_data)
        else:
            # success
            response_data["Reason"] = "Successfully validated the Lambda Permissions. Check CloudWatch Logs."
            send(event, context, SUCCESS, response_data)
    elif event["RequestType"] == "Delete":
        # delete - review in the future if anything needs to be deleted
        # assuming Lambda Permissions are removed when the function is removed
        res = event["PhysicalResourceId"]
        response_data["lower"] = res.lower()
        send(event, context, SUCCESS, response_data)
    elif event["RequestType"] == "Cron":
        # try to validate the lambda permissions
        result = apply_lambda_permissions()
        if result != 1:
            # we failed
            response_data["Reason"] = "Failed to update the Lambda Permissions. Check CloudWatch Logs."
        else:
            # success
            response_data["Reason"] = "Successfully validated the Lambda Permissions. Check CloudWatch Logs."
    else:  # delete / update
        # something else, need to raise error
        send(event, context, FAILED, response_data, response_data["lower"])
    logger.info("responseData %s", response_data)
