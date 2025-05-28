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
    next_token = None
    while b_retry and (not b_completed):
        try:
            if next_token:
                response = client.list_accounts(NextToken=next_token)
            else:
                response = client.list_accounts()

            if response:
                accounts.extend(response.get("Accounts", []))
                next_token = response.get("NextToken")
                if not next_token:
                    b_completed = True # No more accounts
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
        except (ValueError, TypeError) as e:
            logger.error("Unknown Exception trying to list accounts in AWS Organizations. Error: %s", e)
            b_retry = False
    return accounts


def remove_existing_permissions(client, lambda_name):
    """Removes all existing config.amazonaws.com permissions for a Lambda function.
    :param client: Boto3 Lambda client
    :param lambda_name: Name of the Lambda function
    :return: True if successful, False otherwise
    """
    sids_to_remove = []
    i_requests = 0
    b_retry = True
    while b_retry:
        try:
            response = client.get_policy(FunctionName=lambda_name)
            i_requests += 1
            if i_requests % 3 == 0:
                time.sleep(0.05)

            policy_doc = json.loads(response.get("Policy", "{}"))
            statements = policy_doc.get("Statement", [])

            for statement in statements:
                principal = statement.get("Principal", {})
                if (
                    principal.get("Service") == "config.amazonaws.com"
                    and statement.get("Action") == "lambda:InvokeFunction"
                    and statement.get("Effect") == "Allow"
                    and statement.get("Sid")
                ):
                    sids_to_remove.append(statement.get("Sid"))
            b_retry = False # Success

        except botocore.exceptions.ClientError as error:
            if error.response["Error"]["Code"] == "TooManyRequestsException":
                logger.warning("API call limit exceeded (get_policy); backing off and retrying...")
                time.sleep(0.25)
            elif error.response["Error"]["Code"] == "ResourceNotFoundException":
                logger.info("Policy not found for %s, no SIDs to remove.", lambda_name)
                return True # No policy means no SIDs to remove, so it's a success
            else:
                logger.error("boto3 error getting policy for %s: %s", lambda_name, error)
                return False
        except (ValueError, TypeError, json.JSONDecodeError) as e:
            logger.error("Exception processing policy for %s: %s", lambda_name, e)
            return False

    logger.info("Found %d existing config policies to remove for %s.", len(sids_to_remove), lambda_name)

    # Remove all identified SIDs
    for sid in sids_to_remove:
        b_retry = True
        while b_retry:
            try:
                client.remove_permission(FunctionName=lambda_name, StatementId=sid)
                logger.info("Removed SID %s for %s.", sid, lambda_name)
                i_requests += 1
                if i_requests % 5 == 0:
                    time.sleep(0.05)
                b_retry = False
            except botocore.exceptions.ClientError as error:
                if error.response["Error"]["Code"] == "TooManyRequestsException":
                    logger.warning("API call limit exceeded (remove_permission); backing off and retrying...")
                    time.sleep(0.25)
                elif error.response["Error"]["Code"] == "ResourceNotFoundException":
                    logger.warning("SID %s not found for %s during removal (might have been removed already).", sid, lambda_name)
                    b_retry = False # Ignore if not found
                else:
                    logger.error("Error removing SID %s for %s: %s", sid, lambda_name, error)
                    return False # Error during removal

    logger.info("Successfully removed existing policies for %s.", lambda_name)
    return True


def apply_lambda_permissions():
    """Ensures all GC Guardrail Assessment Lambda Functions can be invoked by all
    AWS Accounts in the Organization.
    :return: 1 if successful, 0 if unable to apply permissions, or -1 in case of errors
    """
    organization_name = os.environ.get('OrganizationName', 'DefaultOrg') # Added default for safety
    logger.debug("Organization Name: %s", organization_name)
    i_result = 0
    lambda_functions = {
        f"{organization_name}gc01_check_alerts_flag_misuse": ["GC01CheckAlertsFlagMisuseLambda"],
        f"{organization_name}gc01_check_attestation_letter": ["GC01CheckAttestationLetterLambda"],
        f"{organization_name}gc01_check_dedicated_admin_account": ["GC01CheckDedicatedAdminAccountLambda"],
        f"{organization_name}gc01_check_federated_users_mfa": ["GC01CheckFederatedUsersMFALambda"],
        f"{organization_name}gc01_check_iam_users_mfa": ["GC01CheckIAMUsersMFALambda"],
        f"{organization_name}gc01_check_mfa_digital_policy": ["GC01CheckMFADigitalPolicy"],
        f"{organization_name}gc01_check_monitoring_and_logging": ["GC01CheckMonitoringAndLoggingLambda"],
        f"{organization_name}gc01_check_root_mfa": ["GC01CheckRootAccountMFAEnabledLambda"],
        f"{organization_name}gc02_check_access_management_attestation": ["GC02CheckAccessManagementAttestationLambda"],
        f"{organization_name}gc02_check_account_mgmt_plan": ["GC02CheckAccountManagementPlanLambda"],
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

    if not accounts:
        logger.error("No accounts listed - unable to add Lambda permissions.")
        return 0 # No accounts isn't a failure, but nothing was done.

    for lambda_name in lambda_functions:
        logger.info("Processing permissions for Lambda: %s", lambda_name)

        # 1. Remove existing permissions
        if not remove_existing_permissions(client, lambda_name):
            logger.error("Failed to remove existing permissions for %s. Aborting.", lambda_name)
            return -1 # Indicate failure

        # 2. Add permissions for all active accounts
        sid_counter = 1
        b_throttle = False
        active_accounts_count = 0

        for account in accounts:
            account_id = account["Id"]
            account_status = str(account["Status"]).upper()
            if account_status != "ACTIVE":
                logger.info("Skipping inactive account %s for %s.", account_id, lambda_name)
                continue

            active_accounts_count += 1
            new_sid = f"p{sid_counter}"

            b_retry = True
            b_permission_added = False
            while b_retry and (not b_permission_added):
                if b_throttle and (i_requests % 5 == 0):
                    time.sleep(0.05)
                try:
                    i_requests += 1
                    response = client.add_permission(
                        Action="lambda:InvokeFunction",
                        FunctionName=lambda_name,
                        Principal="config.amazonaws.com",
                        SourceAccount=account_id,
                        StatementId=new_sid,
                    )
                    if not response.get("Statement"):
                        logger.error("Invalid response adding permission %s for account '%s' to '%s'", new_sid, account_id, lambda_name)
                        i_result = -1
                        b_retry = False
                        break
                    else:
                        logger.info("Added permission %s for account %s to %s.", new_sid, account_id, lambda_name)
                        b_permission_added = True
                        sid_counter += 1 # Increment only on success
                except botocore.exceptions.ClientError as error:
                    if error.response["Error"]["Code"] == "TooManyRequestsException":
                        logger.warning("API call limit exceeded (add_permission); backing off and retrying...")
                        b_throttle = True
                        b_retry = True
                        time.sleep(0.25)
                    elif error.response["Error"]["Code"] == "ResourceConflictException":
                         logger.warning("SID %s already exists for %s. This shouldn't happen after removal. Retrying...", new_sid, lambda_name)
                         b_retry = True
                         time.sleep(0.5) # Wait a bit longer for potential consistency issues
                    else:
                        logger.error("Error adding permission %s for account '%s' to '%s': %s", new_sid, account_id, lambda_name, error)
                        i_result = -1
                        b_retry = False

            if i_result == -1:
                break # Stop adding if an error occurs

        if i_result == -1:
            return -1 # Propagate error upwards

        logger.info("Processed %d active accounts for %s.", active_accounts_count, lambda_name)

    return 1 # If we reached here, all lambdas were processed successfully


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
        response = http.request('PUT', response_url, headers=headers, body=json_response_body.encode('utf-8')) # Added encode
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

    # Determine if this is a CloudFormation event or a scheduled (Cron) event
    is_cloudformation = "RequestType" in event and "ResponseURL" in event
    is_cron = "source" in event and event["source"] == "aws.events" # Example check for EventBridge

    if is_cloudformation:
        request_type = event["RequestType"]
        logger.info("Handling CloudFormation RequestType: %s", request_type)

        if request_type in ["Create", "Update"]:
            result = apply_lambda_permissions()
            if result != 1:
                response_data["Reason"] = f"Failed to {request_type.lower()} the Lambda Permissions. Check CloudWatch Logs."
                send(event, context, FAILED, response_data, reason=response_data["Reason"])
            else:
                response_data["Reason"] = f"Successfully {request_type.lower()}d the Lambda Permissions."
                send(event, context, SUCCESS, response_data)
        elif request_type == "Delete":
            logger.info("Delete request received. No specific cleanup action required for permissions here.")
            send(event, context, SUCCESS, response_data)
        else:
            logger.error("Unknown CloudFormation RequestType: %s", request_type)
            send(event, context, FAILED, response_data, reason="Unknown RequestType")

    # Handle scheduled events (Cron-like)
    # Check if 'RequestType' exists and is 'Cron' (from original code) OR if it's an EventBridge event
    elif event.get("RequestType") == "Cron" or is_cron:
         logger.info("Handling Cron/Scheduled Event.")
         result = apply_lambda_permissions()
         if result != 1:
             logger.error("Cron job failed to update Lambda Permissions.")
             # You might want to raise an exception or send a notification here
         else:
             logger.info("Cron job successfully validated/updated Lambda Permissions.")
             # For cron, we usually don't send CFN responses.
             # If you need to signal success/failure elsewhere, add it here.
    else:
        logger.error("Unknown event type. Event: %s", json.dumps(event, indent=2))
        # If it's a CFN event that failed the initial check, send FAILED
        if is_cloudformation:
             send(event, context, FAILED, response_data, reason="Unknown event structure or RequestType")
        # Otherwise, just log the error.
