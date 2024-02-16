""" Setup Audit Manager Resource Configuration Lambda Function"""
import base64
import json
import logging
import zlib

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


def create_custom_assessment_framework(client=None, framework_data=None, cleanup=True, overwrite_controls=False):
    """Creates or updates a custom assessment framework in Audit Manager
    Parameters:
    :param client: boto3 client for audit manager
    :param framework_data: a dict containing the required fields *** to be described
    :param cleanup: whether to remove ID, ARN and time fields from the response
    :return: the ID of the custom assessment framework after creation
    """
    if framework_data is None:
        framework_data = []
    assessment_framework_id = ""
    if not (client and framework_data):
        logger.error("Empty client or framework_data")
        return "ERROR"
    # check if custom assessment framework already exists
    existing_assessment_framework = get_custom_assessment_framework_by_name(
        client,
        framework_data.get("name", "")
    )
    # Step 1, create or update the controls and structure the control sets
    logger.debug("****** Step 1")
    output_control_sets = []
    input_control_set = {}
    input_control_sets = framework_data.get("controlSets", [])
    for input_control_set in input_control_sets:
        logger.debug("*" * 60)
        logger.debug("input_control_set:\n%s", input_control_set)
        control_id = None
        controls = []
        logger.debug("Starting iteration over controls...")
        for input_control in input_control_set.get("controls", {}):
            logger.debug("input_control:\n%s", input_control)
            control_id = create_custom_control(client, input_control)
            logger.debug("control_id: %s", control_id)
            if not control_id:
                # we were unable to create the custom control
                logger.error("Unable to create/update custom control")
                return "ERROR"
            logger.info(
                "Created/updated custom control with ID: %s", control_id)
            # append the new control ID to our list of controls to be assigned to this controlSet
            controls.append({"id": control_id})
        # put the list of control IDs in the controlSet
        control_set = {"name": input_control_set.get("name", ""), "controls": controls}
        # append this control set to the list of control sets to be
        # assigned to the assessment framework
        output_control_sets.append(control_set)
    # Step 2 create/update the assessment framework
    logger.debug("Assessment framework will be created/updated using the following parameters:\n")
    logger.debug(
        dict(
            name=framework_data.get("name", ""),
            description=framework_data.get("description", ""),
            complianceType=framework_data.get("complianceType", ""),
            controlSets=output_control_sets,
            tags=framework_data.get("tags", {}),
        )
    )
    try:
        if not existing_assessment_framework:
            # create
            response = client.create_assessment_framework(
                name=framework_data.get("name", ""),
                description=framework_data.get("description", ""),
                complianceType=framework_data.get("complianceType", ""),
                controlSets=output_control_sets,
                tags=framework_data.get("tags", {}),
            )
        else:
            # update
            response = client.update_assessment_framework(
                frameworkId=existing_assessment_framework.get("id", ""),
                name=framework_data.get("name", ""),
                description=framework_data.get("description", ""),
                complianceType=framework_data.get("complianceType", ""),
                controlSets=output_control_sets,
            )
    except botocore.exceptions.ClientError as error:
        logger.error("Error creating/updating custom assessment framework: %s", error)
        return "ERROR"
    if response:
        try:
            assessment_framework_id = response.get("framework", {}).get("id", "")
        except ValueError as err:
            logger.error("Error trying to get the framework ID after the create_assessment_framework call. %s", err)
            return "ERROR"
    else:
        logger.error("No response from the create_assessment_framework call")
    # return our assessment framework id
    return assessment_framework_id


def get_custom_assessment_framework_by_name(client=None, target_framework_name=None):
    """Finds a custom assessment framework by name in Audit Manager
    Parameters:
    :param client: boto3 client for audit manager
    :param target_framework_name: a string containing the name of
    the custom assessment framework to be found
    :return: the custom control
    """
    # variables
    result = None
    if not target_framework_name:
        return None
    frameworks = get_custom_assessment_frameworks(client, cleanup=False)
    for framework in frameworks:
        # compare the name
        if target_framework_name == framework.get("name", ""):
            # found it
            result = framework
            break
    return result


def create_custom_control(client=None, control_data=None):
    """Creates/updates a custom control in Audit Manager
    Parameters:
    :param client: boto3 client for audit manager
    :param control_data: a dict containing the required fields *** to be described
    :param cleanup: whether to remove ID, ARN and time fields from the response
    :return: Returns the ID of the custom control
    """
    if control_data is None:
        control_data = []
    result_id = None
    if not (client and control_data):
        logger.error("ERROR: empty client or control_data")
        return None
    # let's first check if the control already exists
    existing_control = get_custom_control_by_name(
        client, control_data.get("name", ""))
    # clean up the source data (remove IDs, ARN, etc.)
    try:
        control_data.pop("arn")
        control_data.pop("id")
        control_data.pop("createdAt")
        control_data.pop("lastUpdatedAt")
        control_data.pop("createdBy")
        control_data.pop("lastUpdatedBy")
        for control_mapping_source in control_data.get("controlMappingSources", []):
            control_mapping_source.pop("sourceId")
    except KeyError:
        # do nothing as we don't need the missing key
        pass
    try:
        if not existing_control:
            # create
            response = client.create_control(
                name=control_data.get("name", ""),
                description=control_data.get("description", ""),
                testingInformation=control_data.get("testingInformation", ""),
                actionPlanTitle=control_data.get("actionPlanTitle", ""),
                actionPlanInstructions=control_data.get("actionPlanInstructions", ""),
                controlMappingSources=control_data.get("controlMappingSources", []),
                tags=control_data.get("tags", {}),
            )
            logger.debug("create_control response:\n%s", response)
        else:
            # update
            response = client.update_control(
                controlId=existing_control.get("id", ""),
                name=control_data.get("name", ""),
                description=control_data.get("description", ""),
                testingInformation=control_data.get("testingInformation", ""),
                actionPlanTitle=control_data.get("actionPlanTitle", ""),
                actionPlanInstructions=control_data.get("actionPlanInstructions", ""),
                controlMappingSources=control_data.get("controlMappingSources", []),
            )
            logger.debug("update_control response:\n%s", response)
    except botocore.exceptions.ClientError as error:
        logger.error('Error creating/updating custom control named "%s"', control_data.get("name", ""))
        logger.error("ERROR: %s", error)
    if response:
        # request was processed, let's check the response
        result_id = response.get("control", {}).get("id", None)
    # return value
    return result_id


def get_custom_assessment_frameworks(client=None, cleanup=True):
    """Gets all custom assessment frameworks defined in Audit Manager
    Parameters:
    :param client: boto3 client for audit manager
    :param cleanup: whether to remove ID, ARN and time fields from the response
    :return: returns a list of dicts containing the assessment frameworks
    """
    custom_frameworks = []
    temp_custom_frameworks = []
    # List all Custom Frameworks
    try:
        response = client.list_assessment_frameworks(frameworkType="Custom")
    except botocore.exceptions.ClientError:
        logger.error("Audit Manager Client - error listing assessment frameworks")
        return None
    if response:
        temp_custom_frameworks = response.get("frameworkMetadataList", [])
        next_token = response.get("nextToken", "")
        # check if the response was paginated
        while next_token != "":
            # yes, the response has been paginated, so request additional frameworks
            try:
                response = client.list_assessment_frameworks(
                    frameworkType="Custom",
                    nextToken=next_token
                )
            except botocore.exceptions.ClientError:
                logger.error("Audit Manager Client- error listing assessment frameworks pagination")
                return None
            if response:
                temp_custom_frameworks.append(response.get("frameworkMetadataList", []))
                next_token = response.get("nextToken", "")
            else:
                next_token = ""
        # now iterate over the framework list to extract the actual content/configuration
        for framework in temp_custom_frameworks:
            target_id = framework.get("id", "")
            if target_id:
                try:
                    response = client.get_assessment_framework(frameworkId=target_id)
                except botocore.exceptions.ClientError:
                    logger.error("Audit Manager Client - error getting assessment framework detail for framework ID %s", target_id)
                    return None
                if response:
                    framework_detail = response.get("framework", {})
                    if framework_detail:
                        # should we clean up and remove unnecessary fields?
                        # (e.g., arn, id, createdAt)
                        if cleanup:
                            try:
                                framework_detail.pop("arn")
                                framework_detail.pop("id")
                                framework_detail.pop("createdAt")
                                framework_detail.pop("lastUpdatedAt")
                                framework_detail.pop("createdBy")
                                framework_detail.pop("lastUpdatedBy")
                                temp_control_sets = []
                                for control_set in framework_detail.get("controlSets", []):
                                    control_set.pop("id")
                                    temp_controls = []
                                    for control in control_set.get("controls", []):
                                        temp_control_mapping_sources = []
                                        for control_mapping_source in control.get("controlMappingSources", []):
                                            control_mapping_source.pop("sourceId")
                                            temp_control_mapping_sources.append(control_mapping_source)
                                        # sort the data sources based on sourceName
                                        temp_control_mapping_sources = sorted(
                                            temp_control_mapping_sources,
                                            key=lambda datasource: datasource["sourceName"],
                                        )
                                        control.update({"controlMappingSources": temp_control_mapping_sources})
                                        control.pop("arn")
                                        control.pop("id")
                                        control.pop("createdAt")
                                        control.pop("lastUpdatedAt")
                                        control.pop("createdBy")
                                        control.pop("lastUpdatedBy")
                                        temp_controls.append(control)
                                    # sort the controls based on name
                                    temp_controls = sorted(
                                        temp_controls,
                                        key=lambda datasource: datasource["name"],
                                    )
                                    control_set.update(
                                        {"controls": temp_controls})
                                    temp_control_sets.append(control_set)
                                framework_detail.update({"controlSets": temp_control_sets})
                            except KeyError:
                                # no need to do anything
                                pass
                        custom_frameworks.append(framework_detail)
        # sort the frameworks based on name
        custom_frameworks = sorted(
            custom_frameworks,
            key=lambda datasource: datasource["name"]
        )
    return custom_frameworks


def get_custom_control_by_name(client=None, target_control_name=None):
    """Finds a custom control by name in Audit Manager
    Parameters:
    :param client: boto3 client for audit manager
    :param target_control_name: a string containing the name of the custom control to be found
    :return: the custom control
    """
    result = None
    # List all Custom Controls
    try:
        response = client.list_controls(controlType="Custom")
    except botocore.exceptions.ClientError as error:
        logger.error(
            "Audit Manager Client - error listing controls: %s", error)
        return None
    if response:
        controls = response.get("controlMetadataList", [])
        next_token = response.get("nextToken", "")
        # check if the response was paginated
        while next_token != "":
            # yes, the response has been paginated, so request additional controls
            try:
                response = client.list_controls(
                    controlType="Custom",
                    nextToken=next_token
                )
            except botocore.exceptions.ClientError as error:
                logger.error("Audit Manager Client - error listing controls during pagination: %s", error)
                return None
            if response:
                controls.append(response.get("controlMetadataList", []))
                next_token = response.get("nextToken", "")
            else:
                next_token = ""
        # Lets iterate over our list of controls
        for control in controls:
            control_id = control.get("id", "")
            control_name = control.get("name", "")
            if control_name == target_control_name:
                # found it, now let's get the entire control configuration
                try:
                    response = client.get_control(controlId=control_id)
                except botocore.exceptions.ClientError as error:
                    logger.error("Audit Manager Client - error getting control id %s: %s", control_id, error)
                    response = None
                if response:
                    # we have a response
                    result = response.get("control", {})
                else:
                    logger.error("Unable to read control ID %s", control_id)
    # return our result
    return result


def get_active_accounts():
    """Queries AWS Organizations and returns a List of ACTIVE AWS Accounts
    :return: List of ACTIVE AWS Accounts
    """
    accounts = []
    parsed_accounts = []
    client = boto3.client("organizations")
    try:
        response = client.list_accounts()
        if response:
            accounts = response.get("Accounts")
            next_token = response.get("NextToken")
            while next_token:
                response = client.list_accounts(NextToken=next_token)
                accounts.append(response.get("Accounts"))
                next_token = response.get("NextToken")
            for account in accounts:
                if account.get("Status", "") == "ACTIVE":
                    parsed_accounts.append(
                        {
                            "id": account.get("Id"),
                            "emailAddress": account.get("Email"),
                            "name": account.get("Name"),
                        }
                    )
                else:
                    logger.info("Skipping account %s as it is not marked as ACTIVE", account.get("Id", ""))
        else:
            logger.error("Unable to read account data from AWS - empty response.")
    except botocore.exceptions.ClientError:
        logger.error("Unable to list accounts in AWS Organizations.")
    return parsed_accounts


def get_aws_services():
    """Provides a list of AWS services for the Audit Manager Assessment scope
    :return: List of dicts in the expected format
    """
    services = []
    try:
        client = boto3.client("auditmanager")
        response = client.get_services_in_scope()
        for service in response.get("serviceMetadata", []):
            if service.get("name"):
                services.append({"serviceName": service.get("name")})
    except botocore.exceptions.ClientError as error:
        logger.error("Error while trying to get_services_in_scope - boto3 Client error - %s", error)
    return services


def create_assessment(framework_id="", bucket_name="", assessment_owner_role_arns=None):
    """Creates the Audit Manager Assessment
    :param framework_id: ID of the custom assessment framework
    :param bucket_name: name of the S3 bucket where to store the evidence
    :param assessment_owner_role_arns: List of ARNs of the IAM roles that will own the assessment
    :return: 1 if successful, 0 if failed, and -1 if errors encountered
    """
    if assessment_owner_role_arns is None:
        assessment_owner_role_arns = []
    result = 0
    aws_services = get_aws_services()
    aws_accounts = get_active_accounts()
    assessment_roles = []
    assessment_name = "GC Guardrails Assessment"
    assessment_description = "Assesses the 12 Government of Canada Guardrails"
    assessment_tags = {"Source": "ProServe Delivery Kit"}
    # get the ASEA pipeline role arn
    asea_pipeline_role_arn = get_asea_pipeline_role_arn(
        role_name="ASEA-PipelineRole")
    if asea_pipeline_role_arn:
        assessment_owner_role_arns.append(asea_pipeline_role_arn)
    for arn in assessment_owner_role_arns:
        # is it an empty string?
        if arn:
            # remove leading and trailing spaces
            arn = arn.strip()
            # make sure it's not empty
            if arn:
                assessment_roles.append({
                    "roleType": "PROCESS_OWNER",
                    "roleArn": arn
                })
    logger.info("create_assessment function:\n framework_id '%s'\n bucket_name '%s'\n assessment_owner_role_arns '%s'", framework_id, bucket_name, assessment_owner_role_arns)
    try:
        client = boto3.client("auditmanager")
        # do we have any active assessments with the same name?
        existing_assessments = get_assessment_by_name(client, assessment_name)
        if existing_assessments:
            # yes, we need to deactivate these
            for assessment in existing_assessments:
                try:
                    response = client.update_assessment_status(
                        assessmentId=assessment.get("id", ""),
                        status="INACTIVE"
                    )
                except botocore.exceptions.ClientError as error:
                    logger.error("Error while trying to update_assessment_status - boto3 Client error - %s", error)
                except ValueError as error:
                    logger.error("Error while trying to update_assessment_status - non-boto3 issue - %s", error)
                if response:
                    logger.info("Successfully deactivated existing '%s' assessment with ID '%s'", assessment_name, assessment.get("id", ""))
        # proceed with the creation of the new assessment
        response = client.create_assessment(
            name=assessment_name,
            description=assessment_description,
            assessmentReportsDestination={
                "destinationType": "S3",
                "destination": f"s3://{bucket_name}",
            },
            scope={
                "awsAccounts": aws_accounts,
                "awsServices": aws_services
            },
            roles=assessment_roles,
            frameworkId=framework_id,
            tags=assessment_tags,
        )
        if response:
            logger.info("response = %s", response)
            if response.get("assessment", None):
                # success!
                logger.info("assessment found in response")
                result = 1
            else:
                # failed!
                logger.info("assessment NOT found in response")
                result = 0
        else:
            logger.info("empty response")
            result = -1
    except botocore.exceptions.ClientError as error:
        logger.error("Error while trying to create the assessment - boto3 Client error - %s", error)
        result = -1
    except ValueError as error:
        logger.error("Error while trying to create the assessment - non-boto3 issue - %s", error)
        result = -1
    return result


def create_auditmanager_resources(bucket_name="", assessment_owner_role_arns=None):
    """Creates the Audit Manager resources
    :param bucket_name: name of the S3 bucket where to store the evidence
    :param assessment_owner_role_arns: List of ARNs of the IAM roles that will own the assessment
    :return: 1 if successful, 0 if failed, and -1 if errors encountered
    """
    if assessment_owner_role_arns is None:
        assessment_owner_role_arns = []
    try:
        # convert the JSON to dict - replace new lines first
        frameworks_data_string = zlib.decompress(
            base64.b64decode(
                "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"
            )
        ).decode("utf-8")
        frameworks_data = json.loads(frameworks_data_string.replace("\n", ""))
    except (ValueError, TypeError, UnicodeDecodeError, zlib.error):
        # failed
        logger.error("Exception trying to convert JSON contents of the framework data.")
        return -1
    if not frameworks_data:
        logger.error("Unable to parse contents of the framework data - Empty Dict.")
        return -1
    # establish connection to AWS
    try:
        client = boto3.client("auditmanager")
    except botocore.exceptions.ClientError as error:
        logger.error("Error establishing boto3 client: %s", error)
        return -1
    # create custom framework - we are expecting an array of dicts as the input,
    # so pick only the first one
    framework_id = ""
    framework = frameworks_data[0]
    framework_id = create_custom_assessment_framework(client, framework)
    if framework_id == "ERROR":
        logger.error("Error during creation of the framework.")
        logger.debug("%s", framework)
        return -1
    # create the assessment
    result = create_assessment(
        framework_id, bucket_name, assessment_owner_role_arns)
    return result


def get_assessment_by_name(client, assessment_name="GC Guardrails Assessment"):
    """Lists all Active Audit Manager assessments and attempts to find one with the name provided"""
    assessments = []
    # List the assessments
    try:
        response = client.list_assessments(status="ACTIVE")
        b_more_data = True
        while b_more_data:
            if response:
                # let's parse
                for assessment in response.get("assessmentMetadata"):
                    if assessment.get("name") == assessment_name:
                        # Found an assessment we're looking for
                        assessments.append(assessment)
                next_token = response.get("nextToken")
                if next_token:
                    response = client.list_assessments(
                        status="ACTIVE",
                        nextToken=next_token
                    )
                else:
                    b_more_data = False
            else:
                logger.error("Failed to list_assessments in get_assessment_by_name")
                b_more_data = False
    except (ValueError, TypeError, botocore.exceptions.ClientError):
        logger.error("Exception trying to list_assessments in get_assessment_by_name")
    return assessments


def delete_assessment_resources(client, assessment_name="GC Guardrails Assessment"):
    """Deletes the custom Assessment, Assessment Framework and underlying controls
    returns 0 if successful, 1 if failed, and -1 if error
    """
    if not client:
        # establish connection to AWS
        try:
            client = boto3.client("auditmanager")
        except botocore.exceptions.ClientError as error:
            logger.error("Error establishing boto3 client: %s", error)
            return -1
    result = 1
    existing_assessments = get_assessment_by_name(client, assessment_name)
    for assessment in existing_assessments:
        assessment_id = assessment.get("id", "")
        logger.info("Assessment '%s' found with ID '%s'.",
                    assessment_name, assessment.get("id", ""))
        try:
            response = client.get_assessment(assessmentId=assessment_id)
        except botocore.exceptions.ClientError as error:
            logger.error("Error when trying to get_assessment: %s", error)
        if response:
            assessment = response.get("assessment")
            if assessment:
                # let's get the framework ID
                framework = assessment.get("framework")
                if framework:
                    framework_id = framework.get("id")
                    logger.debug("Parsing Framework '%s' with ID '%s'", framework.get(
                        "metadata").get("name"), framework_id)
                    for control_set in framework.get("controlSets"):
                        logger.debug("****** Control Set - %s", control_set["id"])
                        for control in control_set.get("controls"):
                            control_name = control.get("name")
                            control_id = control.get("id")
                            try:
                                client.delete_control(controlId=control_id)
                                logger.debug("***** Control '%s' with ID '%s' deleted...", control_name, control_id)
                            except botocore.exceptions.ClientError as error:
                                logger.error("Exception while trying to delete_control ID %s\n%s", control_id, error)
                    # delete the assessment
                    try:
                        response = client.delete_assessment(
                            assessmentId=assessment_id)
                        logger.debug("** Assessment %s with ID %s deleted...", assessment_name, assessment_id)
                    except botocore.exceptions.ClientError as error:
                        logger.error("Exception while trying to delete_assessment ID %s\n%s", assessment_id, error)
                    # delete the framework
                    try:
                        response = client.delete_assessment_framework(frameworkId=framework_id)
                        logger.info("** Framework %s with ID %s deleted...", framework.get("metadata").get("name"), framework_id)
                        logger.info("Done")
                        result = 0
                    except botocore.exceptions.ClientError as error:
                        logger.error("Exception while trying to delete_assessment_framework ID%s \n%s", framework_id, error)
                        result = 1
                else:
                    logger.error("Unable to find Framework data")
                    result = 1
            else:
                logger.error("Assessment data is empty")
                result = 1
        else:
            logger.error("Unable to get_assessment with ID %s", assessment_id)
            return -1
    return result


def get_asea_pipeline_role_arn(role_name="ASEA-PipelineRole"):
    """Looks up the IAM role with the name provided.
    Returns the role ARN if found, otherwise returns None
    """
    if not role_name:
        # if we received a blank role name, exit
        return None
    role_name = role_name.strip()
    role_arn = ""
    response = {}
    try:
        aws_iam_client = boto3.client("iam")
        response = aws_iam_client.list_roles()
    except botocore.exceptions.ClientError as ex:
        logger.error("get_asea_pipeline_role_arn - failed to list_roles - %s", ex)
    except (ValueError, TypeError):
        logger.error("get_asea_pipeline_role_arn - failed to list_roles")
    if response:
        for role in response.get("Roles", []):
            if role.get("RoleName", "") == role_name:
                # found it
                role_arn = role.get("Arn", "")
                logger.info("get_asea_pipeline_role_arn - Found ASEA Pipeline role with Arn %s", role_arn)
                break
    else:
        logger.error("get_asea_pipeline_role_arn - Empty response on list_roles call")
    return role_arn


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
        response = http.request('PUT', response_url,
                                headers=headers, body=json_response_body)
        logger.info("Status code: %s", response.status)
    except (ValueError, TypeError, urllib3.exceptions.HTTPError) as err:
        logger.error("send(..) failed executing http.request(..): %s", err)


def lambda_handler(event, context):
    """This function is the main entry point for Lambda.
    Keyword arguments:
    event -- the event variable given in the lambda handler
    context -- the context variable given in the lambda handler
    """
    logger.info("got event %s", event)
    response_data = {}

    evidence_bucket_name = event["ResourceProperties"].get("EvidenceBucketName", "")
    logger.info("Using '%s' for evidence_bucket_name.", evidence_bucket_name)

    assessment_owner_role_arn = event["ResourceProperties"].get("AssessmentOwnerRoleARN", "")
    logger.info("Using '%s' for assessment_owner_role_arn.", assessment_owner_role_arn)

    lambda_execution_role_arn = event["ResourceProperties"].get("LambdaExecutionRoleARN", "")
    logger.info("Using '%s' for lambda_execution_role_arn.", lambda_execution_role_arn)

    additional_admin_role_arn = event["ResourceProperties"].get("AdditionalAssessmentAdminRoleARN", "")
    logger.info("Using '%s' for additional_admin_role_arn.", additional_admin_role_arn)

    if event["RequestType"] == "Create" or event["RequestType"] == "Update":
        result = create_auditmanager_resources(
            evidence_bucket_name,
            [
                assessment_owner_role_arn,
                lambda_execution_role_arn,
                additional_admin_role_arn,
            ],
        )
        if result == 1:
            # Success
            logger.info("Successfully created the Custom Assessment Framework and the Assessment.")
            send(event, context, SUCCESS, response_data)
        else:
            # creation failed
            response_data["Reason"] = "Failed to Create Audit Manager resources. Please check CloudWatch Logs."
            logger.error(response_data["Reason"])
            send(event, context, FAILED, response_data)
    elif event["RequestType"] == "Delete":
        # delete - for now, do nothing do not remove the assessment
        send(event, context, SUCCESS, response_data)
    else:
        # something else, need to raise error
        send(event, context, FAILED, response_data, response_data["lower"])
    logger.info("responseData %s", response_data)
