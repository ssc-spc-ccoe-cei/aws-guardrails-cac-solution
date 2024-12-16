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
