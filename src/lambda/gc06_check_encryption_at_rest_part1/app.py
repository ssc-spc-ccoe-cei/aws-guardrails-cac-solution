""" GC06 - Check Encryption at Rest - Part 1
    https://canada-ca.github.io/cloud-guardrails/EN/06_Protect-Data-at-Rest.html
"""

import json
import logging
import time

from utils import is_scheduled_notification, check_required_parameters, check_guardrail_requirement_by_cloud_usage_profile, get_cloud_profile_from_tags, GuardrailType, GuardrailRequirementType
from boto_util.organizations import get_account_tags
from boto_util.client import get_client, is_throttling_exception
from boto_util.config import build_evaluation, submit_evaluations
from boto_util.api_gateway import list_all_api_gateway_deployments, list_all_api_gateway_rest_apis
from boto_util.backup import list_all_backup_vaults, list_all_recovery_points_by_backup_vault
from boto_util.code_build import list_all_code_build_projects
from boto_util.dax import describe_all_dax_clusters
from boto_util.dynamo_db import list_all_dynamo_db_tables
from boto_util.ec2 import describe_all_ec2_volumes

import botocore.exceptions

# Logging setup
logger = logging.getLogger()
logger.setLevel(logging.INFO)


############################################################
# AWS API Gateway specific support functions
#  - API_GW_CACHE_ENABLED_AND_ENCRYPTED


def assess_api_gw_encryption_at_rest(api_gw_client, event):
    """
    Finds API Gateway Stages with Cache enabled and not encrypted at rest
    """
    local_evaluations = []
    rest_apis = []
    resource_type = "AWS::ApiGateway::Stage"
    try:
        rest_apis = list_all_api_gateway_rest_apis(api_gw_client, PAGE_SIZE, INTERVAL_BETWEEN_API_CALLS)
    except botocore.exceptions.ClientError as ex:
        logger.error("API Gateway - Error while calling api_gw_get_rest_api_list %s", ex)
        NONCOMPLIANT_SERVICES.add("API Gateway")
    except ValueError:
        logger.error("API Gateway - Error while calling api_gw_get_rest_api_list")
        NONCOMPLIANT_SERVICES.add("API Gateway")
    logger.info("API Gateway - %s REST APIs found.", len(rest_apis))
    for api in rest_apis:
        api_id = api.get("id")
        deployments = []
        try:
            deployments = list_all_api_gateway_deployments(api_gw_client, api_id, PAGE_SIZE, INTERVAL_BETWEEN_API_CALLS)
        except botocore.exceptions.ClientError as ex:
            logger.error("API Gateway - Error while calling api_gw_get_deployments_list %s", ex)
            NONCOMPLIANT_SERVICES.add("API Gateway")
        except ValueError:
            logger.error("API Gateway - Error while calling api_gw_get_deployments_list")
            NONCOMPLIANT_SERVICES.add("API Gateway")
        logger.info("API Gateway - %s deployments found for REST API ID %s.", len(deployments), api_id)
        for deployment in deployments:
            deployment_id = deployment.get("id")
            if not deployment_id:
                logger.error("API Gateway - Invalid deployment for API ID %s\n%s", api_id, deployment)
                NONCOMPLIANT_SERVICES.add("API Gateway")
                continue
            # let's get the stages
            response = {}
            try:
                response = api_gw_client.get_stages(restApiId=api_id, deploymentId=deployment_id)
            except botocore.exceptions.ClientError as ex:
                logger.error("API Gateway - Error while calling get_stages %s", ex)
                NONCOMPLIANT_SERVICES.add("API Gateway")
            except ValueError:
                logger.error(
                    "API Gateway - Error while calling get_stages for API ID %s and Deployment ID %s.",
                    api_id,
                    deployment_id,
                )
                NONCOMPLIANT_SERVICES.add("API Gateway")
            if response:
                stages = response.get("item", [])
                logger.info(
                    "API Gateway - %s stages found in deployment ID %s for REST API ID %s.",
                    len(stages),
                    deployment_id,
                    api_id,
                )
                for stage in stages:
                    compliance_status = "NOT_APPLICABLE"
                    annotation = "Cache is not enabled"
                    stage_name = stage.get("stageName")
                    method_settings = stage.get("methodSettings")
                    if len(method_settings.keys()) < 1:
                        logger.info(
                            "API Gateway - Stage %s in deployment ID %s for REST API ID %s has no methods.",
                            stage_name,
                            deployment_id,
                            api_id,
                        )
                        compliance_status = "COMPLIANT"
                        annotation = "Stage has no methods"
                    else:
                        method = list(method_settings.keys())[0]
                        caching_enabled = method_settings.get(method, {}).get("cachingEnabled", None)
                        cache_data_encrypted = method_settings.get(method, {}).get("cacheDataEncrypted", None)
                        if caching_enabled is False:
                            # Caching is not enabled, therefore NOT_APPLICABLE
                            logger.info(
                                "API Gateway - Stage %s in deployment ID %s for REST API ID %s marked as NOT_APPLICABLE as Caching is Disabled.",
                                stage_name,
                                deployment_id,
                                api_id,
                            )
                        elif cache_data_encrypted:
                            # Caching is enabled, and the data is encrypted
                            compliance_status = "COMPLIANT"
                            annotation = "Cache is enabled and encrypted"
                            logger.info(
                                "API Gateway - Stage %s in deployment ID %s for REST API ID %s marked as COMPLIANT as Caching is enabled and encrypted.",
                                stage_name,
                                deployment_id,
                                api_id,
                            )
                        else:
                            # Caching is enabled, and the data is NOT encrypted
                            compliance_status = "NON_COMPLIANT"
                            annotation = "Cache is not encrypted"
                            logger.info(
                                "API Gateway - Stage %s in deployment ID %s for REST API ID %s marked as NON_COMPLIANT as Caching is enabled but not encrypted.",
                                stage_name,
                                deployment_id,
                                api_id,
                            )
                    # build evaluation
                    local_evaluations.append(
                        build_evaluation(stage_name, compliance_status, event, resource_type, annotation)
                    )
                    if compliance_status == "NON_COMPLIANT":
                        NONCOMPLIANT_SERVICES.add("API Gateway")
            else:
                logger.error(
                    "API Gateway - Empty response while calling get_stages for API ID %s and Deployment ID %s.",
                    api_id,
                    deployment_id,
                )
                NONCOMPLIANT_SERVICES.add("API Gateway")
    logger.info("API Gateway - reporting %s evaluations.", len(local_evaluations))
    return local_evaluations


############################################################
# AWS Backup specific support functions
#   - BACKUP_RECOVERY_POINT_ENCRYPTED


def assess_backup_encryption_at_rest(backup_client, event):
    """
    Finds AWS Backup resources that are not encrypted at rest
    """
    local_evaluations = []
    resource_type = "AWS::Backup::RecoveryPoint"
    try:
        backup_vaults = list_all_backup_vaults(backup_client, PAGE_SIZE, INTERVAL_BETWEEN_API_CALLS)
        logger.info("Backup - %s vaults found.", len(backup_vaults))
        for vault in backup_vaults:
            # back off the API between vaults
            time.sleep(INTERVAL_BETWEEN_API_CALLS * 3)
            vault_name = vault.get("BackupVaultName")
            if not vault_name:
                logger.error("Backup - Faulty structure - %s", vault)
                continue
            try:
                recovery_points = list_all_recovery_points_by_backup_vault(
                    backup_client, vault_name, PAGE_SIZE, INTERVAL_BETWEEN_API_CALLS
                )
                if recovery_points:
                    logger.info("Backup Vault - %s - %s recovery points found.", vault_name, len(recovery_points))
                    for recovery_point in recovery_points:
                        compliance_type = "NON_COMPLIANT"
                        annotation = "Not encrypted at rest"
                        if recovery_point.get("IsEncrypted", "") is True:
                            compliance_type = "COMPLIANT"
                            annotation = "Encrypted at rest"
                        # build evaluation
                        local_evaluations.append(
                            build_evaluation(
                                recovery_point.get("RecoveryPointArn", "INVALID"),
                                compliance_type,
                                event,
                                resource_type,
                                annotation,
                            )
                        )
                else:
                    logger.info("Vault %s has no recovery points.", vault_name)
            except botocore.exceptions.ClientError as ex:
                logger.error("Backup - Error when trying to backup_get_recovery_point_list %s", ex)
    except botocore.exceptions.ClientError as ex:
        if "AccessDenied" in ex.response["Error"]["Code"]:
            logger.error("Backup - AccessDenied when trying to backup_get_vault_list %s", ex)
        else:
            logger.error("Backup - Error while calling backup_get_vault_list %s", ex)
    logger.info("Backup - reporting %s evaluations.", len(local_evaluations))
    return local_evaluations


############################################################
# AWS CloudTrail specific support functions
#   - CLOUD_TRAIL_ENCRYPTION_ENABLED
def assess_cloudtrail_encryption_at_rest(s3_client, AWScloudtrail_client, event):
    """
    Finds AWS CloudTrail trails that are not encrypted at rest using KMS
    """
    local_evaluations = []
    trails = []
    resource_type = "AWS::CloudTrail::Trail"
    try:
        response = AWScloudtrail_client.describe_trails()
        trails = response.get("trailList", [])
    except botocore.exceptions.ClientError as ex:
        logger.error("CloudTrail - Error while calling describe_trails %s", ex)
        NONCOMPLIANT_SERVICES.add("CloudTrail")
    except ValueError:
        logger.error("CloudTrail - Error while calling describe_trails")
        NONCOMPLIANT_SERVICES.add("CloudTrail")
    logger.info("CloudTrail - %s trails found.", len(trails))
    for trail in trails:
        compliance_status = "NON_COMPLIANT"
        annotation = "Not using KMS"
        if trail.get("KmsKeyId", ""):
            compliance_status = "COMPLIANT"
            annotation = "KMS key confirmed"
        else:
            logger.info("### trail doesn't have kms keys %s", trail)
            s3_bucket_name = trail.get("S3BucketName", "")
            if s3_bucket_name:
                bucket_encrypted_flag = check_s3_bucket_encryption(s3_client, s3_bucket_name)
                if bucket_encrypted_flag:
                    logger.info("### trail bucket %s  has encryption", s3_bucket_name)
                    compliance_status = "COMPLIANT"
                    annotation = "Trail bucket has encryption enabled"
                else:
                    logger.info("### trail bucket %s  has no encryption", s3_bucket_name)
                    compliance_status = "NON_COMPLIANT"
                    annotation = "Trail bucket has no encryption enabled"
        
        logger.info(
            "CloudTrail - Trail %s is %s", trail.get("TrailARN", trail.get("Name", "INVALID")), compliance_status
        )
        # build evaluation
        local_evaluations.append(
            build_evaluation(
                trail.get("TrailARN", trail.get("Name", "INVALID")), compliance_status, event, resource_type, annotation
            )
        )
        if compliance_status == "NON_COMPLIANT":
            NONCOMPLIANT_SERVICES.add("CloudTrail")
    logger.info("CloudTrail - reporting %s evaluations.", len(local_evaluations))
    return local_evaluations

def check_s3_bucket_encryption(s3_client, bucket_name):
    """
    Check if S3 bucket has encryption enabled
    :return True if bucket is encrypted, else False
    """
    # s3_client = get_client("s3")

    try:
        response = s3_client.get_bucket_encryption(Bucket=bucket_name)
        encryption_rules = response.get('ServerSideEncryptionConfiguration', {}).get('Rules', [])

        if encryption_rules:
            return True
        return False
    except botocore.exceptions.ClientError as ex:
        logger.error("S3 error while checking bucket encryption for %s: %s", bucket_name, ex)
        return False


############################################################
# AWS CodeBuild specific support functions
#  - CODEBUILD_PROJECT_ARTIFACT_ENCRYPTION
#  - CODEBUILD_PROJECT_S3_LOGS_ENCRYPTED


def assess_codebuild_encryption_at_rest(codebuild_client, event):
    """
    Finds AWS CodeBuild Projects that have builds with artifacts that are not encrypted at rest
    """
    local_evaluations = []
    projects = []
    project_details = []
    resource_type = "AWS::CodeBuild::Project"
    try:
        projects = list_all_code_build_projects(codebuild_client, INTERVAL_BETWEEN_API_CALLS)
        logger.info("CodeBuild - %s projects found.", len(projects))
        if projects:
            project_details = codebuild_get_projects_details_list(codebuild_client, projects)
    except botocore.exceptions.ClientError as ex:
        logger.error(
            "CodeBuild - Error while calling codebuild_get_projects_list or codebuild_get_projects_details_list %s", ex
        )
        NONCOMPLIANT_SERVICES.add("CodeBuild")
    except ValueError:
        logger.error(
            "CodeBuild - Error while calling codebuild_get_projects_list or codebuild_get_projects_details_list"
        )
        NONCOMPLIANT_SERVICES.add("CodeBuild")
        raise
    logger.info("CodeBuild - %s project details found.", len(project_details))
    for project in project_details:
        compliance_status = "NON_COMPLIANT"
        annotation = ""
        b_no_artifacts = True
        b_no_s3_logs = True
        annotation = "No artifacts to encrypt."
        b_artifact_encryption = False
        b_log_encryption = False
        artifacts = project.get("artifacts", {})
        if artifacts:
            if artifacts.get("type", "") != "NO_ARTIFACTS":
                b_no_artifacts = False
                if artifacts.get("encryptionDisabled", "") is False:
                    b_artifact_encryption = True
        else:
            logger.info("CodeBuild - empty artifacts response for project %s", project)
        s3_logs = project.get("logsConfig", {}).get("s3Logs", {})
        if s3_logs:
            b_no_s3_logs = False
            if s3_logs.get("encryptionDisabled", "") is False:
                b_log_encryption = True
        # Scenarios:
        #   1 - No artifacts, No S3 logs to encrypt = COMPLIANT
        #   2 - No artifacts, S3 Logs encrypted = COMPLIANT
        #   3 - No artifacts, S3 Logs not encrypted = NON_COMPLIANT
        #   4 - Artifacts not encrypted, No S3 Logs = NON_COMPLIANT
        #   5 - Artifacts not encrypted, S3 Logs not encrypted = NON_COMPLIANT
        #   6 - Artifacts not encrypted, S3 Logs encrypted = NON_COMPLIANT
        #   7 - Artifacts encrypted, No S3 Logs = COMPLIANT
        #   8 - Artifacts encrypted, S3 Logs not encrypted = NON_COMPLIANT
        #   9 - Artifacts encrypted, S3 Logs encrypted = COMPLIANT
        # Are there NO artifacts?
        if b_no_artifacts:
            # Yes, what about S3 logs?
            if b_no_s3_logs:
                # No S3 logs. Scenario 1
                compliance_status = "COMPLIANT"
                annotation = "No artifacts or S3 logs to encrypt"
            elif b_log_encryption:
                # S3 logs encrypted. Scenario 2
                compliance_status = "COMPLIANT"
                annotation = "No artifacts to encrypt. S3 logs encrypted at rest"
            else:
                # S3 logs not encrypted. Scenario 3
                compliance_status = "NON_COMPLIANT"
                annotation = "No artifacts to encrypt. S3 logs not encrypted at rest"
        else:
            # We have artifacts. Are they not encrypted?
            if not b_artifact_encryption:
                # Artifacts not encrypted, what about S3 logs?
                compliance_status = "NON_COMPLIANT"
                if b_no_s3_logs:
                    # No S3 logs. Scenario 4
                    annotation = "Artifacts not encrypted. No S3 logs to encrypt."
                elif not b_log_encryption:
                    # S3 Logs not encrypted. Scenario 5
                    annotation = "Artifacts and S3 logs not encrypted."
                else:
                    # S3 Logs encrypted. Scenario 6
                    annotation = "Artifacts not encrypted. S3 logs encrypted."
            else:
                # Artifacts encrypted. What about the S3 logs?
                compliance_status = "COMPLIANT"
                if b_no_s3_logs:
                    # No S3 logs. Scenario 7
                    annotation = "Artifacts encrypted. No S3 logs to encrypt."
                elif not b_log_encryption:
                    # S3 Logs not encrypted. Scenario 8
                    compliance_status = "NON_COMPLIANT"
                    annotation = "Artifacts encrypted. S3 logs not encrypted."
                else:
                    # S3 Logs encrypted. Scenario 9
                    annotation = "Artifacts and S3 logs encrypted."
        logger.info(
            "CodeBuild - Project %s is %s", project.get("arn", project.get("name", "INVALID")), compliance_status
        )
        # build evaluation
        local_evaluations.append(
            build_evaluation(
                project.get("arn", project.get("name", "INVALID")), compliance_status, event, resource_type, annotation
            )
        )
        if compliance_status == "NON_COMPLIANT":
            NONCOMPLIANT_SERVICES.add("CodeBuild")
    logger.info("CodeBuild - reporting %s evaluations.", len(local_evaluations))
    return local_evaluations


def codebuild_get_projects_details_list(codebuild_client, project_name_list: list):
    """
    Get the list of projects details from the project name list.
    :param project_name_list: list of project names
    :return: list of projects details
    """
    projects_details_list = []
    max_projects_per_request = 5
    start_index = 0
    end_index = 5
    total_projects = len(project_name_list)
    if total_projects < 1:
        return []
    rounds = (total_projects // max_projects_per_request) + 1
    for rnd in range(rounds):
        start_index = rnd * max_projects_per_request
        end_index = start_index + max_projects_per_request
        if end_index > total_projects:
            end_index = total_projects
        if len(project_name_list[start_index:end_index]) < 1:
            break
        try:
            response = codebuild_client.batch_get_projects(names=project_name_list[start_index:end_index])
            projects = []
            if response:
                projects = response.get("projects", [])
                if projects:
                    projects_details_list.extend(projects)
            if not projects:
                logger.error(
                    "CodeBuild - Empty response while calling batch_get_projects with parameters %s.",
                    project_name_list[start_index:end_index],
                )
                NONCOMPLIANT_SERVICES.add("CodeBuild")
        except botocore.exceptions.ClientError as ex:
            if is_throttling_exception(ex):
                logger.info("CodeBuild - Throttling exception")
                time.sleep(INTERVAL_BETWEEN_API_CALLS * 20)
            else:
                logger.error(
                    "CodeBuild - Error while calling batch_get_projects with parameters %s. Error %s",
                    project_name_list[start_index:end_index],
                    ex,
                )
                NONCOMPLIANT_SERVICES.add("CodeBuild")
        time.sleep(INTERVAL_BETWEEN_API_CALLS)
    return projects_details_list


#################################################################
# DAX specific support functions
#  - DAX_ENCRYPTION_ENABLED


def assess_dax_encryption_at_rest(dax_client, event):
    """
    Finds AWS DAX Clusters that are not encrypted at rest
    """
    local_evaluations = []
    clusters = []
    resource_type = "AWS::DAX::Cluster"
    try:
        clusters = describe_all_dax_clusters(dax_client, PAGE_SIZE, INTERVAL_BETWEEN_API_CALLS)
    except botocore.exceptions.ClientError as ex:
        logger.error("DAX - Error while calling dax_get_clusters_list %s", ex)
        # NONCOMPLIANT_SERVICES.add('DAX')
    except ValueError:
        logger.error("DAX - Error while calling dax_get_clusters_list")
        # NONCOMPLIANT_SERVICES.add('DAX')
    logger.info("DAX - %s clusters found.", len(clusters))
    for cluster in clusters:
        compliance_status = "NON_COMPLIANT"
        annotation = "Unable to assess"
        cluster_arn = cluster.get("ClusterArn", cluster.get("ClusterName", "INVALID"))
        encryption_status = cluster.get("SSEDescription", {}).get("Status", "")
        if encryption_status == "ENABLED":
            compliance_status = "COMPLIANT"
            annotation = "Encrypted at rest"
        else:
            annotation = f"Not encrypted at rest - status is {encryption_status}"
        if compliance_status == "NON_COMPLIANT":
            NONCOMPLIANT_SERVICES.add("DAX")
        # build evaluation
        local_evaluations.append(build_evaluation(cluster_arn, compliance_status, event, resource_type, annotation))
    logger.info("DAX - reporting %s evaluations.", len(local_evaluations))
    return local_evaluations


#################################################################
# # DynamoDB specific support functions
# #  - DYNAMODB_TABLE_ENCRYPTION_ENABLED


# def assess_dynamodb_encryption_at_rest(dynamo_db_client, event):
#     """
#     Finds AWS DynamoDB tables that are not encrypted at rest
#     """
#     local_evaluations = []
#     tables = []
#     resource_type = "AWS::DynamoDB::Table"
#     try:
#         tables = list_all_dynamo_db_tables(dynamo_db_client, PAGE_SIZE, INTERVAL_BETWEEN_API_CALLS)
#     except botocore.exceptions.ClientError as ex:
#         logger.error("DynamoDB - Error while calling dynamodb_get_tables_list %s", ex)
#         NONCOMPLIANT_SERVICES.add("DynamoDB")
#     logger.info("DynamoDB - %s tables found.", len(tables))
#     for table_name in tables:
#         compliance_status = "NON_COMPLIANT"
#         annotation = "Unable to assess"
#         table_id = table_name
#         try:
#             response = dynamo_db_client.describe_table(TableName=table_name)
#             if response:
#                 sse_description = response.get("Table", {}).get("SSEDescription", {})
#                 table_id = response.get("Table", {}).get("TableArn", table_name)
#                 if sse_description.get("Status", "") == "ENABLED":
#                     compliance_status = "COMPLIANT"
#                     annotation = "Encrypted at rest using {}".format(sse_description.get("SSEType", ""))
#                 else:
#                     annotation = "Not encrypted at rest - status is {}".format(sse_description.get("Status", ""))
#         except botocore.exceptions.ClientError as ex:
#             logger.error("DynamoDB - Error while calling describe_table %s", ex)
#         if compliance_status == "NON_COMPLIANT":
#             NONCOMPLIANT_SERVICES.add("DynamoDB")
#         # build evaluation
#         local_evaluations.append(build_evaluation(table_id, compliance_status, event, resource_type, annotation))
#     logger.info("DynamoDB - reporting %s evaluations.", len(local_evaluations))
#     return local_evaluations


#################################################################
# Amazon EBS specific support functions
#  - ENCRYPTED_VOLUMES
#  - EC2_EBS_ENCRYPTION_BY_DEFAULT


def assess_ebs_encryption_at_rest(ec2_client, event):
    """
    Finds Amazon EBS volumes that are not encrypted at rest
    """
    local_evaluations = []
    # Assess EBS Volumes
    resource_type = "AWS::EC2::Volume"
    try:
        ebs_volumes = describe_all_ec2_volumes(ec2_client, PAGE_SIZE, INTERVAL_BETWEEN_API_CALLS)
        logger.info("EBS - %s Volumes found.", len(ebs_volumes))
        for volume in ebs_volumes:
            # let's check the volumes
            if volume.get("Encrypted", "") is True:
                compliance_status = "COMPLIANT"
                annotation = "Encrypted at rest"
            else:
                compliance_status = "NON_COMPLIANT"
                annotation = "Not encrypted at rest"
                NONCOMPLIANT_SERVICES.add("EBS")
            # build evaluation for the instance
            local_evaluations.append(
                build_evaluation(volume.get("VolumeId", "INVALID"), compliance_status, event, resource_type, annotation)
            )
    except botocore.exceptions.ClientError as ex:
        logger.error("EBS - Error while calling ec2_get_volumes_list %s", ex)
        NONCOMPLIANT_SERVICES.add("EBS")
    # check for EBS default volume encryption
    try:
        response = ec2_client.get_ebs_encryption_by_default(DryRun=False)
        if response:
            if response.get("EbsEncryptionByDefault", "") is True:
                logger.info("EBS - EC2 Default Volume Encryption is enabled")
                EBS_ENCRYPTION_AT_REST = True
            else:
                NONCOMPLIANT_SERVICES.add("EBS")
                logger.info("EBS - EC2 Default Volume Encryption is disabled")
        else:
            NONCOMPLIANT_SERVICES.add("EBS")
            logger.error("EBS - Unable to check EC2 Default Volume Encryption")
    except botocore.exceptions.ClientError as ex:
        logger.error("EBS - Error while calling get_ebs_encryption_by_default %s", ex)
    logger.info("EBS - reporting %s evaluations.", len(local_evaluations))
    return local_evaluations


########################################
# Account evaluation result


def get_account_evaluation(aws_account_id, event):
    """
    Returns an evaluation for the account based on whether there were non-compliant services.
    """
    compliance_type = "COMPLIANT"
    annotation = "No issues found"
    if len(NONCOMPLIANT_SERVICES) > 0:
        # check EBS
        annotation = "Non-compliant resources found in: "
        compliance_type = "NON_COMPLIANT"
        if EBS_ENCRYPTION_AT_REST:
            # it's not EBS Default Encryption at rest
            annotation += "{}".format(", ".join(sorted(NONCOMPLIANT_SERVICES)))
        else:
            for service in NONCOMPLIANT_SERVICES:
                if service == "EBS":
                    annotation += "EBS (Default encryption disabled),"
                else:
                    annotation += " {},".format(service)
        annotation.rstrip(", ")

    logger.info(f"{compliance_type}: {annotation}")
    return build_evaluation(aws_account_id, compliance_type, event, annotation=annotation)


def lambda_handler(event, context):
    """
    This function is the main entry point for Lambda.

    Keyword arguments:

    event -- the event variable given in the lambda handler

    context -- the context variable given in the lambda handler
    """
    logger.info("Received Event: %s", json.dumps(event, indent=2))

    invoking_event = json.loads(event["invokingEvent"])
    if not is_scheduled_notification(invoking_event["messageType"]):
        logger.error("Skipping assessments as this is not a scheduled invocation")
        return

    rule_parameters = check_required_parameters(json.loads(event.get("ruleParameters", "{}")), ["ExecutionRoleName"])
    execution_role_name = rule_parameters.get("ExecutionRoleName")
    audit_account_id = rule_parameters.get("AuditAccountID", "")
    aws_account_id = event["accountId"]
    is_not_audit_account = aws_account_id != audit_account_id

    evaluations = []

    # Global variables
    global EBS_ENCRYPTION_AT_REST
    global NONCOMPLIANT_SERVICES
    global PAGE_SIZE
    global INTERVAL_BETWEEN_API_CALLS

    NONCOMPLIANT_SERVICES = set({})
    EBS_ENCRYPTION_AT_REST = False
    PAGE_SIZE = 25
    INTERVAL_BETWEEN_API_CALLS = 0.1

    # establish AWS API clients
    aws_api_gw_client = get_client("apigateway", aws_account_id, execution_role_name, is_not_audit_account)
    aws_backup_client = get_client("backup", aws_account_id, execution_role_name, is_not_audit_account)
    aws_cloudtrail_client = get_client("cloudtrail", aws_account_id, execution_role_name, is_not_audit_account)
    aws_codebuild_client = get_client("codebuild", aws_account_id, execution_role_name, is_not_audit_account)
    aws_config_client = get_client("config", aws_account_id, execution_role_name, is_not_audit_account)
    aws_dax_client = get_client("dax", aws_account_id, execution_role_name, is_not_audit_account)
    #aws_dynamo_db_client = get_client("dynamodb", aws_account_id, execution_role_name, is_not_audit_account)
    aws_ec2_client = get_client("ec2", aws_account_id, execution_role_name, is_not_audit_account)
    aws_s3_client = get_client("s3", aws_account_id, execution_role_name, is_not_audit_account)
    # Check cloud profile
    tags = get_account_tags(get_client("organizations", assume_role=False), aws_account_id)
    cloud_profile = get_cloud_profile_from_tags(tags)
    gr_requirement_type = check_guardrail_requirement_by_cloud_usage_profile(GuardrailType.Guardrail6, cloud_profile)
    
    # If the guardrail is recommended
    if gr_requirement_type == GuardrailRequirementType.Recommended:
        return submit_evaluations(aws_config_client, event, [build_evaluation(
            aws_account_id,
            "COMPLIANT",
            event,
            gr_requirement_type=gr_requirement_type
        )])
    # If the guardrail is not required
    elif gr_requirement_type == GuardrailRequirementType.Not_Required:
        return submit_evaluations(aws_config_client, event, [build_evaluation(
            aws_account_id,
            "NOT_APPLICABLE",
            event,
            gr_requirement_type=gr_requirement_type
        )])
        
    # API Gateway
    evaluations.extend(assess_api_gw_encryption_at_rest(aws_api_gw_client, event))

    # Backup
    evaluations.extend(assess_backup_encryption_at_rest(aws_backup_client, event))

    # CodeBuild
    evaluations.extend(assess_codebuild_encryption_at_rest(aws_codebuild_client, event))

    # CloudTrail
    evaluations.extend(assess_cloudtrail_encryption_at_rest(aws_s3_client, aws_cloudtrail_client, event))

    # DynamoDB
    #evaluations.extend(assess_dynamodb_encryption_at_rest(aws_dynamo_db_client, event))

    # DAX
    evaluations.extend(assess_dax_encryption_at_rest(aws_dax_client, event))

    # EBS
    evaluations.extend(assess_ebs_encryption_at_rest(aws_ec2_client, event))

    # Account - must be the last
    evaluations.append(get_account_evaluation(aws_account_id, event))

    # Submit evaluations to AWS Config
    logger.info("Submitting evaluations %s", evaluations)
    submit_evaluations(aws_config_client, event, evaluations)
