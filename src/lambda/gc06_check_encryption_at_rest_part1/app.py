""" GC06 - Check Encryption at Rest - Part 1
    https://canada-ca.github.io/cloud-guardrails/EN/06_Protect-Data-at-Rest.html
"""
import json
import logging
import time

import boto3
import botocore

# Set to True to get the lambda to assume the Role attached on the Config Service
ASSUME_ROLE_MODE = True
DEFAULT_RESOURCE_TYPE = 'AWS::::Account'

############################################################
# AWS API Gateway specific support functions
#  - API_GW_CACHE_ENABLED_AND_ENCRYPTED


def assess_api_gw_encryption_at_rest(event=None):
    """
    Finds API Gateway Stages with Cache enabled and not encrypted at rest
    """
    local_evaluations = []
    rest_apis = []
    resource_type = 'AWS::ApiGateway::Stage'
    try:
        rest_apis = api_gw_get_rest_api_list()
    except botocore.exceptions.ClientError as ex:
        logger.error('API Gateway - Error while calling api_gw_get_rest_api_list %s', ex)
        NONCOMPLIANT_SERVICES.add('API Gateway')
    except ValueError:
        logger.error('API Gateway - Error while calling api_gw_get_rest_api_list')
        NONCOMPLIANT_SERVICES.add('API Gateway')
    logger.info('API Gateway - %s REST APIs found.', len(rest_apis))
    for api in rest_apis:
        api_id = api.get('id')
        deployments = []
        try:
            deployments = api_gw_get_deployments_list(api_id)
        except botocore.exceptions.ClientError as ex:
            logger.error('API Gateway - Error while calling api_gw_get_deployments_list %s', ex)
            NONCOMPLIANT_SERVICES.add('API Gateway')
        except ValueError:
            logger.error('API Gateway - Error while calling api_gw_get_deployments_list')
            NONCOMPLIANT_SERVICES.add('API Gateway')
        logger.info('API Gateway - %s deployments found for REST API ID %s.', len(deployments), api_id)
        for deployment in deployments:
            deployment_id = deployment.get('id')
            if not deployment_id:
                logger.error('API Gateway - Invalid deployment for API ID %s\n%s', api_id, deployment)
                NONCOMPLIANT_SERVICES.add('API Gateway')
                continue
            # let's get the stages
            response = {}
            try:
                response = AWS_API_GW_CLIENT.get_stages(
                    restApiId=api_id, deploymentId=deployment_id)
            except botocore.exceptions.ClientError as ex:
                logger.error('API Gateway - Error while calling get_stages %s', ex)
                NONCOMPLIANT_SERVICES.add('API Gateway')
            except ValueError:
                logger.error('API Gateway - Error while calling get_stages for API ID %s and Deployment ID %s.', api_id, deployment_id)
                NONCOMPLIANT_SERVICES.add('API Gateway')
            if response:
                stages = response.get('item', [])
                logger.info('API Gateway - %s stages found in deployment ID %s for REST API ID %s.', len(stages), deployment_id, api_id)
                for stage in stages:
                    compliance_status = 'NOT_APPLICABLE'
                    compliance_annotation = 'Cache is not enabled'
                    stage_name = stage.get('stageName')
                    method_settings = stage.get('methodSettings')
                    if len(method_settings.keys()) < 1:
                        logger.info('API Gateway - Stage %s in deployment ID %s for REST API ID %s has no methods.', stage_name, deployment_id, api_id)
                        compliance_status = 'COMPLIANT'
                        compliance_annotation = 'Stage has no methods'
                    else:
                        method = list(method_settings.keys())[0]
                        caching_enabled = method_settings.get(
                            method, {}).get('cachingEnabled', None)
                        cache_data_encrypted = method_settings.get(
                            method, {}).get('cacheDataEncrypted', None)
                        if caching_enabled is False:
                            # Caching is not enabled, therefore NOT_APPLICABLE
                            logger.info('API Gateway - Stage %s in deployment ID %s for REST API ID %s marked as NOT_APPLICABLE as Caching is Disabled.', stage_name, deployment_id, api_id)
                        else:
                            # Caching is enabled, let's confirm if it's encrypted
                            if cache_data_encrypted:
                                compliance_status = 'COMPLIANT'
                                compliance_annotation = 'Cache is enabled and encrypted'
                                logger.info('API Gateway - Stage %s in deployment ID %s for REST API ID %s marked as COMPLIANT as Caching is enabled and encrypted.', stage_name, deployment_id, api_id)
                            else:
                                compliance_status = 'NON_COMPLIANT'
                                compliance_annotation = 'Cache is not encrypted'
                                logger.info('API Gateway - Stage %s in deployment ID %s for REST API ID %s marked as NON_COMPLIANT as Caching is enabled but not encrypted.', stage_name, deployment_id, api_id)
                    # build evaluation
                    local_evaluations.append(
                        build_evaluation(
                            stage_name,
                            compliance_status,
                            event,
                            resource_type,
                            annotation=compliance_annotation
                        )
                    )
                    if compliance_status == 'NON_COMPLIANT':
                        NONCOMPLIANT_SERVICES.add('API Gateway')
            else:
                logger.error('API Gateway - Empty response while calling get_stages for API ID %s and Deployment ID %s.', api_id, deployment_id)
                NONCOMPLIANT_SERVICES.add('API Gateway')
    logger.info('API Gateway - reporting %s evaluations.',
                len(local_evaluations))
    return local_evaluations


def api_gw_get_deployments_list(api_id: str):
    """ Get the list of deployments for a given API ID """
    resource_list = []
    api_gw_paginator = AWS_API_GW_CLIENT.get_paginator('get_deployments')
    api_gw_deployments_page_iterator = api_gw_paginator.paginate(
        restApiId=api_id, PaginationConfig={'limit': PAGE_SIZE})
    for page in api_gw_deployments_page_iterator:
        resource_list.extend(page.get('items', []))
        time.sleep(INTERVAL_BETWEEN_API_CALLS)
    return resource_list


def api_gw_get_rest_api_list():
    """ Get the list of REST APIs """
    resource_list = []
    api_gw_paginator = AWS_API_GW_CLIENT.get_paginator('get_rest_apis')
    api_gw_rest_apis_page_iterator = api_gw_paginator.paginate(PaginationConfig={'limit': PAGE_SIZE})
    for page in api_gw_rest_apis_page_iterator:
        resource_list.extend(page.get('items', []))
        time.sleep(INTERVAL_BETWEEN_API_CALLS)
    return resource_list

############################################################
# AWS Backup specific support functions
#   - BACKUP_RECOVERY_POINT_ENCRYPTED


def assess_backup_encryption_at_rest(event=None):
    """
    Finds AWS Backup resources that are not encrypted at rest
    """
    local_evaluations = []
    resource_type = 'AWS::Backup::RecoveryPoint'
    try:
        backup_vaults = backup_get_vault_list()
        logger.info('Backup - %s vaults found.', len(backup_vaults))
        for vault in backup_vaults:
            # back off the API between vaults
            time.sleep(INTERVAL_BETWEEN_API_CALLS * 3)
            vault_name = vault.get('BackupVaultName')
            if not vault_name:
                logger.error('Backup - Faulty structure - %s', vault)
                continue
            try:
                recovery_points = backup_get_recovery_point_list(vault_name)
                if recovery_points:
                    logger.info('Backup Vault - %s - %s recovery points found.', vault_name, len(recovery_points))
                    for recovery_point in recovery_points:
                        compliance_status = 'NON_COMPLIANT'
                        compliance_annotation = 'Not encrypted at rest'
                        if recovery_point.get('IsEncrypted', '') is True:
                            compliance_status = 'COMPLIANT'
                            compliance_annotation = 'Encrypted at rest'
                        # build evaluation
                        local_evaluations.append(
                            build_evaluation(
                                recovery_point.get('RecoveryPointArn', 'INVALID'),
                                compliance_status,
                                event,
                                resource_type,
                                annotation=compliance_annotation
                            )
                        )
                else:
                    logger.info('Vault %s has no recovery points.', vault_name)
            except botocore.exceptions.ClientError as ex:
                logger.error('Backup - Error when trying to backup_get_recovery_point_list %s', ex)
    except botocore.exceptions.ClientError as ex:
        if 'AccessDenied' in ex.response['Error']['Code']:
            logger.error('Backup - AccessDenied when trying to backup_get_vault_list %s', ex)
        else:
            logger.error('Backup - Error while calling backup_get_vault_list %s', ex)
    logger.info('Backup - reporting %s evaluations.', len(local_evaluations))
    return local_evaluations


def backup_get_vault_list():
    """ Get the list of backup vaults """
    resource_list = []
    backup_paginator = AWS_BACKUP_CLIENT.get_paginator('list_backup_vaults')
    backup_resource_list = backup_paginator.paginate(PaginationConfig={'MaxResults': PAGE_SIZE})
    for page in backup_resource_list:
        resource_list.extend(page['BackupVaultList'])
        time.sleep(INTERVAL_BETWEEN_API_CALLS)
    return resource_list


def backup_get_recovery_point_list(backup_vault_name: str):
    """ Get the list of recovery points for a given backup vault """
    resource_list = []
    backup_paginator = AWS_BACKUP_CLIENT.get_paginator(
        'list_recovery_points_by_backup_vault')
    backup_resource_list = backup_paginator.paginate(
        BackupVaultName=backup_vault_name, PaginationConfig={'MaxResults': PAGE_SIZE})
    for page in backup_resource_list:
        resource_list.extend(page['RecoveryPoints'])
        time.sleep(INTERVAL_BETWEEN_API_CALLS)
    return resource_list


############################################################
# AWS CloudTrail specific support functions
#   - CLOUD_TRAIL_ENCRYPTION_ENABLED
def assess_cloudtrail_encryption_at_rest(event=None):
    """
    Finds AWS CloudTrail trails that are not encrypted at rest using KMS
    """
    local_evaluations = []
    trails = []
    resource_type = 'AWS::CloudTrail::Trail'
    try:
        response = AWS_CLOUDTRAIL_CLIENT.describe_trails()
        trails = response.get('trailList', [])
    except botocore.exceptions.ClientError as ex:
        logger.error('CloudTrail - Error while calling describe_trails %s', ex)
        NONCOMPLIANT_SERVICES.add('CloudTrail')
    except ValueError:
        logger.error('CloudTrail - Error while calling describe_trails')
        NONCOMPLIANT_SERVICES.add('CloudTrail')
    logger.info('CloudTrail - %s trails found.', len(trails))
    for trail in trails:
        compliance_status = 'NON_COMPLIANT'
        compliance_annotation = 'Not using KMS'
        if trail.get('KmsKeyId', ''):
            compliance_status = 'COMPLIANT'
            compliance_annotation = 'KMS key confirmed'
        logger.info('CloudTrail - Trail %s is %s', trail.get('TrailARN', trail.get('Name', 'INVALID')), compliance_status)
        # build evaluation
        local_evaluations.append(
            build_evaluation(
                trail.get('TrailARN', trail.get('Name', 'INVALID')),
                compliance_status,
                event,
                resource_type,
                annotation=compliance_annotation
            )
        )
        if compliance_status == 'NON_COMPLIANT':
            NONCOMPLIANT_SERVICES.add('CloudTrail')
    logger.info('CloudTrail - reporting %s evaluations.', len(local_evaluations))
    return local_evaluations


############################################################
# AWS CodeBuild specific support functions
#  - CODEBUILD_PROJECT_ARTIFACT_ENCRYPTION
#  - CODEBUILD_PROJECT_S3_LOGS_ENCRYPTED

def assess_codebuild_encryption_at_rest(event=None):
    """
    Finds AWS CodeBuild Projects that have builds with artifacts that are not encrypted at rest
    """
    local_evaluations = []
    projects = []
    project_details = []
    resource_type = 'AWS::CodeBuild::Project'
    try:
        projects = codebuild_get_projects_name_list()
        logger.info('CodeBuild - %s projects found.', len(projects))
        if projects:
            project_details = codebuild_get_projects_details_list(projects)
    except botocore.exceptions.ClientError as ex:
        logger.error('CodeBuild - Error while calling codebuild_get_projects_list or codebuild_get_projects_details_list %s', ex)
        NONCOMPLIANT_SERVICES.add('CodeBuild')
    except ValueError:
        logger.error('CodeBuild - Error while calling codebuild_get_projects_list or codebuild_get_projects_details_list')
        NONCOMPLIANT_SERVICES.add('CodeBuild')
        raise
    logger.info('CodeBuild - %s project details found.', len(project_details))
    for project in project_details:
        compliance_status = 'NON_COMPLIANT'
        compliance_annotation = ''
        b_no_artifacts = True
        b_no_s3_logs = True
        compliance_annotation = 'No artifacts to encrypt.'
        b_artifact_encryption = False
        b_log_encryption = False
        artifacts = project.get('artifacts', {})
        if artifacts:
            if artifacts.get('type', '') != 'NO_ARTIFACTS':
                b_no_artifacts = False
                if artifacts.get('encryptionDisabled', '') is False:
                    b_artifact_encryption = True
        else:
            logger.info('CodeBuild - empty artifacts response for project %s', project)
        s3_logs = project.get('logsConfig', {}).get('s3Logs', {})
        if s3_logs:
            b_no_s3_logs = False
            if s3_logs.get('encryptionDisabled', '') is False:
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
                compliance_status = 'COMPLIANT'
                compliance_annotation = 'No artifacts or S3 logs to encrypt'
            elif b_log_encryption:
                # S3 logs encrypted. Scenario 2
                compliance_status = 'COMPLIANT'
                compliance_annotation = 'No artifacts to encrypt. S3 logs encrypted at rest'
            else:
                # S3 logs not encrypted. Scenario 3
                compliance_status = 'NON_COMPLIANT'
                compliance_annotation = 'No artifacts to encrypt. S3 logs not encrypted at rest'
        else:
            # We have artifacts. Are they not encrypted?
            if not b_artifact_encryption:
                # Artifacts not encrypted, what about S3 logs?
                compliance_status = 'NON_COMPLIANT'
                if b_no_s3_logs:
                    # No S3 logs. Scenario 4
                    compliance_annotation = 'Artifacts not encrypted. No S3 logs to encrypt.'
                elif not b_log_encryption:
                    # S3 Logs not encrypted. Scenario 5
                    compliance_annotation = 'Artifacts and S3 logs not encrypted.'
                else:
                    # S3 Logs encrypted. Scenario 6
                    compliance_annotation = 'Artifacts not encrypted. S3 logs encrypted.'
            else:
                # Artifacts encrypted. What about the S3 logs?
                compliance_status = 'COMPLIANT'
                if b_no_s3_logs:
                    # No S3 logs. Scenario 7
                    compliance_annotation = 'Artifacts encrypted. No S3 logs to encrypt.'
                elif not b_log_encryption:
                    # S3 Logs not encrypted. Scenario 8
                    compliance_status = 'NON_COMPLIANT'
                    compliance_annotation = 'Artifacts encrypted. S3 logs not encrypted.'
                else:
                    # S3 Logs encrypted. Scenario 9
                    compliance_annotation = 'Artifacts and S3 logs encrypted.'
        logger.info('CodeBuild - Project %s is %s', project.get('arn', project.get('name', 'INVALID')), compliance_status)
        # build evaluation
        local_evaluations.append(
            build_evaluation(
                project.get('arn', project.get('name', 'INVALID')),
                compliance_status,
                event,
                resource_type,
                annotation=compliance_annotation.strip()
            )
        )
        if compliance_status == 'NON_COMPLIANT':
            NONCOMPLIANT_SERVICES.add('CodeBuild')
    logger.info('CodeBuild - reporting %s evaluations.', len(local_evaluations))
    return local_evaluations


def codebuild_get_projects_details_list(project_name_list: list):
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
            response = AWS_CODEBUILD_CLIENT.batch_get_projects(names=project_name_list[start_index:end_index])
            projects = []
            if response:
                projects = response.get('projects', [])
                if projects:
                    projects_details_list.extend(projects)
            if not projects:
                logger.error('CodeBuild - Empty response while calling batch_get_projects with parameters %s.', project_name_list[start_index:end_index])
                NONCOMPLIANT_SERVICES.add('CodeBuild')
        except botocore.exceptions.ClientError as ex:
            if is_throttling_exception(ex):
                logger.info('CodeBuild - Throttling exception')
                time.sleep(INTERVAL_BETWEEN_API_CALLS * 20)
            else:
                logger.error('CodeBuild - Error while calling batch_get_projects with parameters %s. Error %s', project_name_list[start_index:end_index], ex)
                NONCOMPLIANT_SERVICES.add('CodeBuild')
        time.sleep(INTERVAL_BETWEEN_API_CALLS)
    return projects_details_list


def codebuild_get_projects_name_list():
    """
    Get the list of projects name from the CodeBuild.
    :return: list of projects name
    """
    resource_list = []
    codebuild_paginator = AWS_CODEBUILD_CLIENT.get_paginator('list_projects')
    codebuild_resource_list = codebuild_paginator.paginate()
    for page in codebuild_resource_list:
        resource_list.extend(page['projects'])
        time.sleep(INTERVAL_BETWEEN_API_CALLS)
    return resource_list

#################################################################
# DAX specific support functions
#  - DAX_ENCRYPTION_ENABLED


def assess_dax_encryption_at_rest(event=None):
    """
    Finds AWS DAX Clusters that are not encrypted at rest
    """
    local_evaluations = []
    clusters = []
    resource_type = 'AWS::DAX::Cluster'
    try:
        clusters = dax_get_clusters_list()
    except botocore.exceptions.ClientError as ex:
        logger.error('DAX - Error while calling dax_get_clusters_list %s', ex)
        # NONCOMPLIANT_SERVICES.add('DAX')
    except ValueError:
        logger.error('DAX - Error while calling dax_get_clusters_list')
        # NONCOMPLIANT_SERVICES.add('DAX')
    logger.info('DAX - %s clusters found.', len(clusters))
    for cluster in clusters:
        compliance_status = 'NON_COMPLIANT'
        compliance_annotation = 'Unable to assess'
        cluster_arn = cluster.get('ClusterArn', cluster.get('ClusterName', 'INVALID'))
        encryption_status = cluster.get('SSEDescription', {}).get('Status', '')
        if encryption_status == 'ENABLED':
            compliance_status = 'COMPLIANT'
            compliance_annotation = 'Encrypted at rest'
        else:
            compliance_annotation = f'Not encrypted at rest - status is {encryption_status}'
        if compliance_status == 'NON_COMPLIANT':
            NONCOMPLIANT_SERVICES.add('DAX')
        # build evaluation
        local_evaluations.append(
            build_evaluation(
                cluster_arn,
                compliance_status,
                event,
                resource_type,
                annotation=compliance_annotation
            )
        )
    logger.info('DAX - reporting %s evaluations.', len(local_evaluations))
    return local_evaluations


def dax_get_clusters_list():
    """
    Get the list of DAX clusters from the DAX.
    :return: list of clusters
    """
    resource_list = []
    dax_paginator = AWS_DAX_CLIENT.get_paginator('describe_clusters')
    dax_resource_list = dax_paginator.paginate(PaginationConfig={'MaxResults': PAGE_SIZE})
    for page in dax_resource_list:
        resource_list.extend(page['Clusters'])
        time.sleep(INTERVAL_BETWEEN_API_CALLS)
    return resource_list

#################################################################
# DynamoDB specific support functions
#  - DYNAMODB_TABLE_ENCRYPTION_ENABLED


def assess_dynamodb_encryption_at_rest(event=None):
    """
    Finds AWS DynamoDB tables that are not encrypted at rest
    """
    local_evaluations = []
    tables = []
    resource_type = 'AWS::DynamoDB::Table'
    try:
        tables = dynamodb_get_tables_list()
    except botocore.exceptions.ClientError as ex:
        logger.error('DynamoDB - Error while calling dynamodb_get_tables_list %s', ex)
        NONCOMPLIANT_SERVICES.add('DynamoDB')
    logger.info('DynamoDB - %s tables found.', len(tables))
    for table_name in tables:
        compliance_status = 'NON_COMPLIANT'
        compliance_annotation = 'Unable to assess'
        table_id = table_name
        try:
            response = AWS_DYNAMODB_CLIENT.describe_table(TableName=table_name)
            if response:
                sse_description = response.get('Table', {}).get('SSEDescription', {})
                table_id = response.get('Table', {}).get('TableArn', table_name)
                if sse_description.get('Status', '') == 'ENABLED':
                    compliance_status = 'COMPLIANT'
                    compliance_annotation = 'Encrypted at rest using {}'.format(sse_description.get('SSEType', ''))
                else:
                    compliance_annotation = 'Not encrypted at rest - status is {}'.format(sse_description.get('Status', ''))
        except botocore.exceptions.ClientError as ex:
            logger.error('DynamoDB - Error while calling describe_table %s', ex)
        if compliance_status == 'NON_COMPLIANT':
            NONCOMPLIANT_SERVICES.add('DynamoDB')
        # build evaluation
        local_evaluations.append(
            build_evaluation(
                table_id,
                compliance_status,
                event,
                resource_type,
                annotation=compliance_annotation
            )
        )
    logger.info('DynamoDB - reporting %s evaluations.', len(local_evaluations))
    return local_evaluations


def dynamodb_get_tables_list():
    """ Returns a list of DynamoDB tables """
    resource_list = []
    dynamodb_paginator = AWS_DYNAMODB_CLIENT.get_paginator('list_tables')
    dynamodb_resource_list = dynamodb_paginator.paginate(PaginationConfig={'Limit': PAGE_SIZE})
    for page in dynamodb_resource_list:
        resource_list.extend(page['TableNames'])
        time.sleep(INTERVAL_BETWEEN_API_CALLS)
    return resource_list


#################################################################
# Amazon EBS specific support functions
#  - ENCRYPTED_VOLUMES
#  - EC2_EBS_ENCRYPTION_BY_DEFAULT

def assess_ebs_encryption_at_rest(event=None):
    """
    Finds Amazon EBS volumes that are not encrypted at rest
    """
    local_evaluations = []
    # Assess EBS Volumes
    resource_type = 'AWS::EC2::Volume'
    try:
        ebs_volumes = ebs_get_volumes_list()
        logger.info('EBS - %s Volumes found.', len(ebs_volumes))
        for volume in ebs_volumes:
            # let's check the volumes
            if volume.get('Encrypted', '') is True:
                compliance_status = 'COMPLIANT'
                compliance_annotation = 'Encrypted at rest'
            else:
                compliance_status = 'NON_COMPLIANT'
                compliance_annotation = 'Not encrypted at rest'
                NONCOMPLIANT_SERVICES.add('EBS')
            # build evaluation for the instance
            local_evaluations.append(
                build_evaluation(
                    volume.get('VolumeId', 'INVALID'),
                    compliance_status,
                    event,
                    resource_type,
                    annotation=compliance_annotation
                )
            )
    except botocore.exceptions.ClientError as ex:
        logger.error('EBS - Error while calling ebs_get_volumes_list %s', ex)
        NONCOMPLIANT_SERVICES.add('EBS')
    # check for EBS default volume encryption
    try:
        response = AWS_EC2_CLIENT.get_ebs_encryption_by_default(DryRun=False)
        if response:
            if response.get('EbsEncryptionByDefault', '') is True:
                logger.info('EBS - EC2 Default Volume Encryption is enabled')
                EBS_ENCRYPTION_AT_REST = True
            else:
                NONCOMPLIANT_SERVICES.add('EBS')
                logger.info('EBS - EC2 Default Volume Encryption is disabled')
        else:
            NONCOMPLIANT_SERVICES.add('EBS')
            logger.error('EBS - Unable to check EC2 Default Volume Encryption')
    except botocore.exceptions.ClientError as ex:
        logger.error('EBS - Error while calling get_ebs_encryption_by_default %s', ex)
    logger.info('EBS - reporting %s evaluations.', len(local_evaluations))
    return local_evaluations


def ebs_get_volumes_list():
    """ Returns a list of Amazon EBS volumes """
    resource_list = []
    ebs_paginator = AWS_EC2_CLIENT.get_paginator('describe_volumes')
    ebs_resource_list = ebs_paginator.paginate(PaginationConfig={'MaxResults': PAGE_SIZE})
    for page in ebs_resource_list:
        resource_list.extend(page['Volumes'])
        time.sleep(INTERVAL_BETWEEN_API_CALLS)
    return resource_list


# This generates an evaluation for config
def build_evaluation(resource_id, compliance_type, event, resource_type, annotation=None):
    """Form an evaluation as a dictionary. Usually suited to report on scheduled rules.
    Keyword arguments:
    resource_id -- the unique id of the resource to report
    compliance_type -- either COMPLIANT, NON_COMPLIANT or NOT_APPLICABLE
    event -- the event variable given in the lambda handler
    resource_type -- the CloudFormation resource type (or AWS::::Account) to report on the rule
    annotation -- an annotation to be added to the evaluation (default None)
    """
    eval_cc = {}
    if annotation:
        eval_cc['Annotation'] = annotation
    eval_cc['ComplianceResourceType'] = resource_type
    eval_cc['ComplianceResourceId'] = resource_id
    eval_cc['ComplianceType'] = compliance_type
    eval_cc['OrderingTimestamp'] = str(json.loads(event['invokingEvent'])['notificationCreationTime'])
    return eval_cc


def is_throttling_exception(e):
    """Returns True if the exception code is one of the throttling exception codes we have"""
    b_is_throttling = False
    throttling_exception_codes = [
        'ConcurrentModificationException',
        'InsufficientDeliveryPolicyException',
        'NoAvailableDeliveryChannelException',
        'ConcurrentModifications',
        'LimitExceededException',
        'OperationNotPermittedException',
        'TooManyRequestsException',
        'Throttling',
        'ThrottlingException',
        'InternalErrorException',
        'InternalException',
        'ECONNRESET',
        'EPIPE',
        'ETIMEDOUT',
        'ConcurrentModificationException',
        'InsufficientDeliveryPolicyException',
        'NoAvailableDeliveryChannelException',
        'ConcurrentModifications',
        'LimitExceededException',
        'OperationNotPermittedException',
        'TooManyRequestsException',
        'Throttling',
        'ThrottlingException',
        'InternalErrorException',
        'InternalException',
        'ECONNRESET',
        'EPIPE',
        'ETIMEDOUT'
    ]
    for throttling_code in throttling_exception_codes:
        if throttling_code in e.response['Error']['Code']:
            b_is_throttling = True
            break
    return b_is_throttling

########################################
# Account evaluation result


def get_account_evaluation(event):
    """
    Returns an evaluation for the account based on whether there were non-compliant services.
    """
    compliance_status = 'COMPLIANT'
    compliance_annotation = 'No issues found'
    if len(NONCOMPLIANT_SERVICES) > 0:
        # check EBS
        compliance_annotation = 'Non-compliant resources found in: '
        compliance_status = 'NON_COMPLIANT'
        if EBS_ENCRYPTION_AT_REST:
            # it's not EBS Default Encryption at rest
            compliance_annotation += '{}'.format(', '.join(sorted(NONCOMPLIANT_SERVICES)))
        else:
            for service in NONCOMPLIANT_SERVICES:
                if service == 'EBS':
                    compliance_annotation += 'EBS (Default encryption disabled),'
                else:
                    compliance_annotation += ' {},'.format(service)
        compliance_annotation.rstrip(', ')
    return build_evaluation(
        AWS_ACCOUNT_ID,
        compliance_status,
        event,
        'AWS::::Account',
        annotation=compliance_annotation
    )


def submit_evaluations(evaluations: list, result_token: str, batch_size=50):
    """
    Submits evaluations to AWS Config in batches to respect API limits
    """
    failed_evaluations = []
    temp_failed_evaluations = []
    put_evaluation_retry_limit = 3

    if batch_size > 100:
        batch_size = 100

    start_index = 0
    end_index = batch_size
    total_evaluations = len(evaluations)

    if total_evaluations < 1:
        return []

    rounds = (total_evaluations // batch_size) + 1
    for rnd in range(rounds):
        start_index = rnd * batch_size
        end_index = start_index + batch_size

        if end_index > total_evaluations:
            end_index = total_evaluations

        batch_items = evaluations[start_index:end_index]
        if len(batch_items) < 1:
            break

        b_batch_success = False
        b_batch_failed = False
        batch_attempt = 0
        exception_retry = 0

        while (not b_batch_success) and (not b_batch_failed) and (batch_attempt < put_evaluation_retry_limit) and (exception_retry < MAXIMUM_API_RETRIES):
            try:
                logger.info('Config - put_evaluations - %s', batch_items)
                response = AWS_CONFIG_CLIENT.put_evaluations(Evaluations=batch_items, ResultToken=result_token)
                if response:
                    temp_failed_evaluations = response.get('FailedEvaluations', [])
                    logger.info('Config - put_evaluation - Successful %s Evaluations', len(batch_items) - len(temp_failed_evaluations))
                    if len(temp_failed_evaluations) > 0:
                        # we have some evaluations that failed; let's retry
                        logger.error('Config - put_evaluation - Failed %s Evaluations %s', len(temp_failed_evaluations), temp_failed_evaluations)
                        batch_attempt += 1
                        batch_items = temp_failed_evaluations
                        time.sleep(INTERVAL_BETWEEN_API_CALLS * 20)
                    else:
                        b_batch_success = True
                        time.sleep(INTERVAL_BETWEEN_API_CALLS)
                else:
                    logger.error('Config - Empty response when trying to put_evaluations %s', batch_items)
                    exception_retry += 1
            except botocore.exceptions.ClientError as ex:
                exception_retry += 1
                if is_throttling_exception(ex):
                    logger.info('Config - Throttling exception')
                    time.sleep(INTERVAL_BETWEEN_API_CALLS * 20)
                else:
                    logger.error('Config - Error while calling put_evaluations. Evaluations:\n%s\n\n Error %s', batch_items, ex)
                    b_batch_failed = True
        if b_batch_success:
            # go to next batch
            continue
        else:
            failed_evaluations.extend(temp_failed_evaluations)
    if len(failed_evaluations) > 0:
        logger.error('Config - Unable to put_evaluation for %s evaluations:\n\n%s', len(failed_evaluations), failed_evaluations)
    return failed_evaluations

# This gets the client after assuming the Config service role
# either in the same AWS account or cross-account.


def get_client(service, event, region="ca-central-1"):
    """Return the service boto client. It should be used instead of directly calling the client.
    Keyword arguments:
    service -- the service name used for calling the boto.client()
    event -- the event variable given in the lambda handler
    """
    if not ASSUME_ROLE_MODE or (AWS_ACCOUNT_ID == AUDIT_ACCOUNT_ID):
        return boto3.client(service, region_name=region)
    execution_role_arn = f'arn:aws:iam::{AWS_ACCOUNT_ID}:role/{EXECUTION_ROLE_NAME}'
    credentials = get_assume_role_credentials(execution_role_arn, region)
    return boto3.client(
        service, region_name=region,
        aws_access_key_id=credentials['AccessKeyId'],
        aws_secret_access_key=credentials['SecretAccessKey'],
        aws_session_token=credentials['SessionToken']
    )


def get_assume_role_credentials(role_arn, region="ca-central-1"):
    """Return the service boto client. It should be used instead of directly calling the client.
    Keyword arguments:
    service -- the service name used for calling the boto.client()
    event -- the event variable given in the lambda handler
    """
    sts_client = boto3.client('sts', region_name=region)
    try:
        assume_role_response = sts_client.assume_role(
            RoleArn=role_arn, RoleSessionName="configLambdaExecution")
        return assume_role_response['Credentials']
    except botocore.exceptions.ClientError as ex:
        # Scrub error message for any internal account info leaks
        if 'AccessDenied' in ex.response['Error']['Code']:
            ex.response['Error']['Message'] = "AWS Config does not have permission to assume the IAM role."
        else:
            ex.response['Error']['Message'] = "InternalError"
            ex.response['Error']['Code'] = "InternalError"
        raise ex


def is_scheduled_notification(message_type):
    """Check whether the message is a ScheduledNotification or not.
    Keyword arguments:
    message_type -- the message type
    """
    return message_type == 'ScheduledNotification'


def lambda_handler(event, context):
    """Main Lambda function handler.
    Keyword arguments:
    event -- the event variable given in the lambda handler
    context -- the context variable given in the lambda handler
    """
    # setup logging
    global logger
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)

    # Global variables - AWS API clients
    global AWS_API_GW_CLIENT
    global AWS_BACKUP_CLIENT
    global AWS_CLOUDTRAIL_CLIENT
    global AWS_CODEBUILD_CLIENT
    global AWS_CONFIG_CLIENT
    global AWS_DAX_CLIENT
    global AWS_DYNAMODB_CLIENT
    global AWS_EC2_CLIENT

    # Global variables
    global AWS_ACCOUNT_ID
    global AUDIT_ACCOUNT_ID
    global EXECUTION_ROLE_NAME
    global EBS_ENCRYPTION_AT_REST
    global NONCOMPLIANT_SERVICES
    NONCOMPLIANT_SERVICES = set({})
    EBS_ENCRYPTION_AT_REST = False

    # global constants for API calls
    global MAXIMUM_API_RETRIES
    global PAGE_SIZE
    global INTERVAL_BETWEEN_API_CALLS
    global THROTTLE_BACKOFF

    MAXIMUM_API_RETRIES = 10
    PAGE_SIZE = 25
    INTERVAL_BETWEEN_API_CALLS = 0.1
    THROTTLE_BACKOFF = 2

    evaluations = []
    rule_parameters = {}
    invoking_event = json.loads(event['invokingEvent'])
    logger.info("Received Event: %s", json.dumps(event, indent=2))

    # parse parameters
    AWS_ACCOUNT_ID = event['accountId']
    logger.info('Assessing account %s', AWS_ACCOUNT_ID)
    if 'ruleParameters' in event:
        rule_parameters = json.loads(event['ruleParameters'])

    valid_rule_parameters = rule_parameters

    if 'ExecutionRoleName' in valid_rule_parameters:
        EXECUTION_ROLE_NAME = valid_rule_parameters['ExecutionRoleName']
    else:
        EXECUTION_ROLE_NAME = 'AWSA-GCLambdaExecutionRole2'

    if 'AuditAccountID' in valid_rule_parameters:
        AUDIT_ACCOUNT_ID = valid_rule_parameters['AuditAccountID']
    else:
        AUDIT_ACCOUNT_ID = ''

    # is this a scheduled invocation?
    if not is_scheduled_notification(invoking_event['messageType']):
        logger.error('Skipping assessments as this is not a scheduled invocation')
        return

    # establish AWS API clients
    AWS_API_GW_CLIENT = get_client('apigateway', event)
    AWS_BACKUP_CLIENT = get_client('backup', event)
    AWS_CLOUDTRAIL_CLIENT = get_client('cloudtrail', event)
    AWS_CODEBUILD_CLIENT = get_client('codebuild', event)
    AWS_CONFIG_CLIENT = get_client('config', event)
    AWS_DAX_CLIENT = get_client('dax', event)
    AWS_DYNAMODB_CLIENT = get_client('dynamodb', event)
    AWS_EC2_CLIENT = get_client('ec2', event)

    # API Gateway
    evaluations.extend(assess_api_gw_encryption_at_rest(event))

    # Backup
    evaluations.extend(assess_backup_encryption_at_rest(event))

    # CodeBuild
    evaluations.extend(assess_codebuild_encryption_at_rest(event))

    # CloudTrail
    evaluations.extend(assess_cloudtrail_encryption_at_rest(event))

    # DynamoDB
    evaluations.extend(assess_dynamodb_encryption_at_rest(event))

    # DAX
    evaluations.extend(assess_dax_encryption_at_rest(event))

    # EBS
    evaluations.extend(assess_ebs_encryption_at_rest(event))

    # Account - must be the last
    evaluations.append(get_account_evaluation(event))

    # Submit evaluations to AWS Config
    logger.info('Submitting evaluations %s', evaluations)
    submit_evaluations(evaluations, event['resultToken'], 50)
