""" GC06 - Check Encryption at Rest - Part 2
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
# AWS ElasticSearch and OpenSearch specific support functions
#   - ELASTICSEARCH_ENCRYPTED_AT_REST
#   - OPENSEARCH_ENCRYPTED_AT_REST
def assess_opensearch_encryption_at_rest(event = None):
    """
    Finds OpenSearch and ElasticSearch domains not encrypted at rest
    """
    local_evaluations = []
    domains = []
    # we use a single call to list both OpenSearch and ElasticSearch domains
    try:
        response = AWS_OPENSEARCH_CLIENT.list_domain_names()
        if response:
            domains = response.get('DomainNames', [])
        else:
            # empty response
            logger.error('OpenSearch/ElasticSearch - Empty response while calling list_domain_names')
            NONCOMPLIANT_SERVICES.add('OpenSearch/ElasticSearch')
    except botocore.exceptions.ClientError as ex:
        logger.error('OpenSearch/ElasticSearch - Error while calling list_domain_names %s', ex)
        NONCOMPLIANT_SERVICES.add('OpenSearch/ElasticSearch')
    except ValueError:
        logger.error('OpenSearch/ElasticSearch - Error while calling list_domain_names')
        NONCOMPLIANT_SERVICES.add('OpenSearch/ElasticSearch')
    logger.info('OpenSearch/ElasticSearch - %s Domains found.', len(domains))
    for domain in domains:
        domain_name = domain.get('DomainName', '')
        engine_type = domain.get('EngineType', '')
        compliance_status = 'NON_COMPLIANT'
        compliance_annotation = 'Not encrypted at rest'
        resource_type = 'AWS::OpenSearch::Domain' if engine_type == 'OpenSearch' else 'AWS::Elasticsearch::Domain'
        if not domain_name:
            logger.error('OpenSearch/ElasticSearch - Invalid domain structure %s', domain)
            continue
        try:
            response = AWS_OPENSEARCH_CLIENT.describe_domain(DomainName=domain_name)
            if response:
                domain_status = response.get('DomainStatus', {})
                if domain_status.get('EncryptionAtRestOptions', {}).get('Enabled') is True:
                    # COMPLIANT
                    compliance_status = 'COMPLIANT'
                    compliance_annotation = 'Encrypted at rest'
            else:
                # empty response
                logger.error('OpenSearch/ElasticSearch - Empty response while calling describe_domain')
        except botocore.exceptions.ClientError as ex:
            logger.error('OpenSearch/ElasticSearch - Error while calling describe_domain %s', ex)
        except ValueError:
            logger.error('OpenSearch/ElasticSearch - Error while calling describe_domain')
        if compliance_status == 'NON_COMPLIANT':
            NONCOMPLIANT_SERVICES.add('OpenSearch/ElasticSearch')
        # build evaluation
        local_evaluations.append(
            build_evaluation(
                domain.get('ARN', domain_name),
                compliance_status,
                event,
                resource_type,
                annotation=compliance_annotation
            )
        )
    return local_evaluations


############################################################
# AWS Kinesis specific support functions
#  - KINESIS_STREAM_ENCRYPTED
def assess_kinesis_encryption_at_rest(event = None):
    """
    Finds AWS Kinesis data streams that are not encrypted at rest
    """
    local_evaluations = []
    stream_names = []
    resource_type = 'AWS::Kinesis::Stream'
    try:
        stream_names = kinesis_get_streams_list()
    except botocore.exceptions.ClientError as ex:
        logger.error('Kinesis - Error while calling kinesis_get_streams_list %s', ex)
        NONCOMPLIANT_SERVICES.add('Kinesis')
    except ValueError:
        logger.error('Kinesis - Error while calling kinesis_get_streams_list')
        NONCOMPLIANT_SERVICES.add('Kinesis')
    logger.info('Kinesis - %s streams found.', len(stream_names))
    for stream_name in stream_names:
        compliance_status = 'NON_COMPLIANT'
        compliance_annotation = 'Not encrypted at rest using KMS'
        encryption_type = 'NONE'
        stream_arn = ''
        try:
            response = AWS_KINESIS_CLIENT.describe_stream(StreamName=stream_name, Limit=1)
        except botocore.exceptions.ClientError as ex:
            logger.error('Kinesis - Error while calling describe_stream %s', ex)
        except ValueError:
            logger.error('Kinesis - Error while calling describe_stream')
        if response:
            stream_arn = response.get('StreamDescription', {}).get('StreamARN', '')
            encryption_type = response.get('StreamDescription', {}).get('EncryptionType', 'NONE')
        if encryption_type == 'KMS':
            compliance_status = 'COMPLIANT'
            compliance_annotation = 'Encrypted at rest using KMS'
        logger.info('Kinesis - Stream %s is %s', stream_arn, compliance_status)
        # build evaluation
        local_evaluations.append(
            build_evaluation(
                stream_arn,
                compliance_status,
                event,
                resource_type,
                annotation=compliance_annotation
            )
        )
        if compliance_status == 'NON_COMPLIANT':
            NONCOMPLIANT_SERVICES.add('Kinesis')
    logger.info('Kinesis - reporting %s evaluations.', len(local_evaluations))
    return local_evaluations


def kinesis_get_streams_list():
    """
    Lists all AWS Kinesis data streams
    """
    resource_list = []
    kinesis_paginator = AWS_KINESIS_CLIENT.get_paginator('list_streams')
    kinesis_resource_list = kinesis_paginator.paginate(PaginationConfig={'Limit': PAGE_SIZE})
    for page in kinesis_resource_list:
        resource_list.extend(page.get('StreamNames', []))
        time.sleep(INTERVAL_BETWEEN_API_CALLS)
    return resource_list


#################################################################
# Amazon EFS specific support functions - EFS_ENCRYPTED_CHECK
def assess_efs_encryption_at_rest(event = None):
    """
    Finds Amazon EFS file systems that are not encrypted at rest
    """
    local_evaluations = []
    # Assess File Systems
    resource_type = 'AWS::EFS::FileSystem'
    efs_filesystems = efs_get_filesystem_list()
    logger.info('EFS - %s File systems found.', len(efs_filesystems))
    for filesystem in efs_filesystems:
        if filesystem.get('Encrypted', '') is True:
            compliance_status = 'COMPLIANT'
            compliance_annotation = 'Encrypted at rest'
        else:
            compliance_status = 'NON_COMPLIANT'
            compliance_annotation = 'Not encrypted at rest'
            NONCOMPLIANT_SERVICES.add('EFS')
        # build evaluation for the cluster
        local_evaluations.append(
            build_evaluation(
                filesystem.get('FileSystemArn', filesystem.get('FileSystemId', 'INVALID')),
                compliance_status,
                event,
                resource_type,
                annotation=compliance_annotation
            )
        )
    logger.info('EFS - reporting %s evaluations.', len(local_evaluations))
    return local_evaluations


def efs_get_filesystem_list():
    """
    Lists all AWS EFS file systems
    """
    resource_list = []
    efs_paginator = AWS_EFS_CLIENT.get_paginator('describe_file_systems')
    efs_resource_list = efs_paginator.paginate(PaginationConfig={'MaxItems': PAGE_SIZE})
    for page in efs_resource_list:
        resource_list.extend(page['FileSystems'])
        time.sleep(INTERVAL_BETWEEN_API_CALLS)
    return resource_list

#################################################################
# Amazon EKS specific support functions
#   - EKS_SECRETS_ENCRYPTED


def assess_eks_encryption_at_rest(event = None):
    """
    Finds Amazon EKS resources that are not encrypted at rest
    """
    local_evaluations = []
    # Assess EKS Clusters
    resource_type = 'AWS::EKS::Cluster'
    eks_clusters = eks_get_cluster_list()
    logger.info('EKS - %s clusters found.', len(eks_clusters))
    for cluster in eks_clusters:
        try:
            compliance_status = 'NON_COMPLIANT'
            compliance_annotation = 'Unable to assess'
            response = AWS_EKS_CLIENT.describe_cluster(name=cluster)
            if response:
                encryption_config = response.get('cluster', {}).get('encryptionConfig', [])
                if encryption_config:
                    # check if there are resources of type secrets
                    compliance_status = 'Secrets are not encrypted'
                    for config in encryption_config:
                        if 'secrets' in config.get('resources', []):
                            compliance_status = 'COMPLIANT'
                            compliance_annotation = 'Secrets are encrypted'
                            break
                else:
                    compliance_annotation = 'Empty encryptionConfig'
            if compliance_status == 'NON_COMPLIANT':
                NONCOMPLIANT_SERVICES.add('EKS')
        except botocore.exceptions.ClientError as ex:
            logger.error("EKS - Error trying to describe_cluster %s", ex)
            NONCOMPLIANT_SERVICES.add('EKS')
        # build evaluation for the cluster
        local_evaluations.append(
            build_evaluation(
                response.get('cluster', {}).get('arn', response.get('cluster', {}).get('name', 'INVALID')),
                compliance_status,
                event,
                resource_type,
                annotation=compliance_annotation
            )
        )
    logger.info('EKS - reporting %s evaluations.', len(local_evaluations))
    return local_evaluations


def eks_get_cluster_list():
    """
    Lists all AWS EKS clusters
    """
    resource_list = []
    eks_paginator = AWS_EKS_CLIENT.get_paginator('list_clusters')
    eks_resource_list = eks_paginator.paginate(PaginationConfig={'maxResults': PAGE_SIZE})
    for page in eks_resource_list:
        resource_list.extend(page['clusters'])
        time.sleep(INTERVAL_BETWEEN_API_CALLS)
    return resource_list

############################################################
# RDS specific support functions
#  - RDS_SNAPSHOT_ENCRYPTED
#  - RDS_STORAGE_ENCRYPTED


def assess_rds_encryption_at_rest(event = None):
    """
    Finds Amazon RDS resources that are not encrypted at rest
    """
    local_evaluations = []
    # Assess DB Clusters
    resource_type = 'AWS::RDS::DBCluster'
    db_clusters = rds_get_db_clusters_list()
    logger.info('RDS - %s DB Clusters found.', len(db_clusters))
    for cluster in db_clusters:
        # let's check the cluster storage
        if cluster.get('StorageEncrypted', '') is True:
            compliance_status = 'COMPLIANT'
            compliance_annotation = 'Encrypted at rest'
        else:
            compliance_status = 'NON_COMPLIANT'
            compliance_annotation = 'Not encrypted at rest'
            NONCOMPLIANT_SERVICES.add('RDS')
        # build evaluation for the cluster
        local_evaluations.append(
            build_evaluation(
                cluster.get('DBClusterArn', cluster.get('DBClusterIdentifier', 'INVALID')),
                compliance_status,
                event,
                resource_type,
                annotation=compliance_annotation
            )
        )
    # Assess DB Cluster Snapshots
    resource_type = 'AWS::RDS::DBClusterSnapshot'
    snapshots = rds_get_db_cluster_snapshots_list()
    logger.info('RDS - %s DB Cluster Snapshots found.', len(snapshots))
    for snapshot in snapshots:
        if snapshot.get('StorageEncrypted', '') is True:
            compliance_status = 'COMPLIANT'
            compliance_annotation = 'Encrypted at rest'
        else:
            compliance_status = 'NON_COMPLIANT'
            compliance_annotation = 'Not encrypted at rest'
            NONCOMPLIANT_SERVICES.add('RDS')
        # build evaluation for the snapshot
        local_evaluations.append(
            build_evaluation(
                snapshot.get('DBClusterSnapshotArn', snapshot.get('DBClusterSnapshotIdentifier', 'INVALID')),
                compliance_status,
                event,
                resource_type,
                annotation=compliance_annotation
            )
        )
    # Assess DB Instances
    db_instances = rds_get_db_instances_list()
    resource_type = 'AWS::RDS::DBInstance'
    logger.info('RDS - %s DB Instances found.', len(db_instances))
    for instance in db_instances:
        # let's check the cluster storage
        if instance.get('StorageEncrypted', '') is True:
            compliance_status = 'COMPLIANT'
            compliance_annotation = 'Encrypted at rest'
        else:
            compliance_status = 'NON_COMPLIANT'
            compliance_annotation = 'Not encrypted at rest'
            NONCOMPLIANT_SERVICES.add('RDS')
        # build evaluation for the instance
        local_evaluations.append(
            build_evaluation(
                instance.get('DBInstanceArn', instance.get('DBInstanceIdentifier', 'INVALID')),
                compliance_status,
                event,
                resource_type,
                annotation=compliance_annotation
            )
        )
    # Assess DB Snapshots
    resource_type = 'AWS::RDS::DBSnapshot'
    snapshots = rds_get_db_snapshots_list()
    logger.info('RDS - %s DB Instance Snapshots found.', len(snapshots))
    for snapshot in snapshots:
        if snapshot.get('StorageEncrypted', '') is True:
            compliance_status = 'COMPLIANT'
            compliance_annotation = 'Encrypted at rest'
        else:
            compliance_status = 'NON_COMPLIANT'
            compliance_annotation = 'Not encrypted at rest'
            NONCOMPLIANT_SERVICES.add('RDS')
        # build evaluation for the snapshot
        local_evaluations.append(
            build_evaluation(
                snapshot.get('DBSnapshotArn', snapshot.get('DBSnapshotIdentifier', 'INVALID')),
                compliance_status,
                event,
                resource_type,
                annotation=compliance_annotation
            )
        )
    logger.info('RDS - reporting %s evaluations.', len(local_evaluations))
    return local_evaluations


def rds_get_db_clusters_list():
    """
    Get a list of all the RDS Clusters
    """
    resource_list = []
    rds_paginator = AWS_RDS_CLIENT.get_paginator('describe_db_clusters')
    rds_resource_list = rds_paginator.paginate(PaginationConfig={'MaxRecords': PAGE_SIZE})
    for page in rds_resource_list:
        resource_list.extend(page['DBClusters'])
        time.sleep(INTERVAL_BETWEEN_API_CALLS)
    return resource_list


def rds_get_db_cluster_snapshots_list():
    """
    Get a list of all the RDS Cluster Snapshots
    """
    resource_list = []
    rds_paginator = AWS_RDS_CLIENT.get_paginator('describe_db_cluster_snapshots')
    rds_resource_list = rds_paginator.paginate(PaginationConfig={'MaxRecords': PAGE_SIZE})
    for page in rds_resource_list:
        resource_list.extend(page['DBClusterSnapshots'])
        time.sleep(INTERVAL_BETWEEN_API_CALLS)
    return resource_list


def rds_get_db_instances_list():
    """
    Get a list of all the RDS Instances
    """
    resource_list = []
    rds_paginator = AWS_RDS_CLIENT.get_paginator('describe_db_instances')
    rds_resource_list = rds_paginator.paginate(PaginationConfig={'MaxRecords': PAGE_SIZE})
    for page in rds_resource_list:
        resource_list.extend(page['DBInstances'])
        time.sleep(INTERVAL_BETWEEN_API_CALLS)
    return resource_list


def rds_get_db_snapshots_list():
    """
    Get a list of all the RDS Snapshots
    """
    resource_list = []
    rds_paginator = AWS_RDS_CLIENT.get_paginator('describe_db_snapshots')
    rds_resource_list = rds_paginator.paginate(PaginationConfig={'MaxRecords': PAGE_SIZE})
    for page in rds_resource_list:
        resource_list.extend(page['DBSnapshots'])
        time.sleep(INTERVAL_BETWEEN_API_CALLS)
    return resource_list

############################################################
# S3 specific support functions
#  - S3_BUCKET_SERVER_SIDE_ENCRYPTION_ENABLED


def assess_s3_encryption_at_rest(event = None):
    """
    Finds Amazon S3 resources that do not have a server side encryption enabled
    """
    local_evaluations = []
    # list the buckets
    resource_type = 'AWS::S3::Bucket'
    try:
        response = AWS_S3_CLIENT.list_buckets()
        if response:
            for bucket in response.get('Buckets'):
                bucket_name = bucket.get('Name')
                bucket_arn = f"arn:aws:s3:::{bucket_name}"
                compliance_status = 'NON_COMPLIANT'
                compliance_annotation = 'Unable to assess'
                i_retries = 0
                b_success = False
                while (not b_success) and (i_retries < MAXIMUM_API_RETRIES):
                    try:
                        response2 = AWS_S3_CLIENT.get_bucket_encryption(Bucket=bucket_name)
                        if response2:
                            for rule in response2.get('ServerSideEncryptionConfiguration', {}).get('Rules', []):
                                default_encryption = rule.get('ApplyServerSideEncryptionByDefault', {})
                                if not default_encryption:
                                    continue
                                compliance_status = 'COMPLIANT'
                                compliance_annotation = 'Encryption at rest enforced. Algorithm is {}'.format(default_encryption.get('SSEAlgorithm', ''))
                        else:
                            compliance_annotation = 'Empty response when trying to get_bucket_encryption'
                        if compliance_status == 'NON_COMPLIANT':
                            NONCOMPLIANT_SERVICES.add('S3')
                        b_success = True
                        time.sleep(INTERVAL_BETWEEN_API_CALLS)
                    except botocore.exceptions.ClientError as ex:
                        b_success = True
                        if 'AccessDenied' in ex.response['Error']['Code']:
                            logger.error('AccessDenied when trying to get_bucket_encryption - assess_s3_encryption_at_rest: %s', ex)
                            compliance_annotation = 'Access Denied'
                            NONCOMPLIANT_SERVICES.add('S3')
                        elif 'ServerSideEncryptionConfigurationNotFound' in ex.response['Error']['Code']:
                            logger.info('ServerSideEncryptionConfigurationNotFound when trying to get_bucket_encryption - assess_s3_encryption_at_rest: %s', ex)
                            compliance_annotation = 'Encryption not enforced at rest'
                            NONCOMPLIANT_SERVICES.add('S3')
                        elif is_throttling_exception(ex):
                            i_retries += 1
                            logger.error('S3 - Throttling while calling get_bucket_encryption')
                            time.sleep(THROTTLE_BACKOFF)
                            b_success = False
                        else:
                            logger.error('S3 - Error while calling get_bucket_encryption %s', ex)
                            NONCOMPLIANT_SERVICES.add('S3')
                # build evaluation
                local_evaluations.append(
                    build_evaluation(
                        bucket_arn,
                        compliance_status,
                        event,
                        resource_type,
                        annotation=compliance_annotation
                    )
                )
    except botocore.exceptions.ClientError as ex:
        NONCOMPLIANT_SERVICES.add('S3')
        if 'AccessDenied' in ex.response['Error']['Code']:
            logger.error('AccessDenied when trying to list_buckets - assess_s3_encryption_at_rest: %s', ex)
        else:
            logger.error('S3 - Error while calling list_buckets %s', ex)
    logger.info('S3 - reporting %s evaluations.', len(local_evaluations))
    return local_evaluations


############################################################
# SNS specific support functions
#  -  SNS_ENCRYPTED_KMS
def assess_sns_encryption_at_rest(event = None):
    """
    Finds Amazon SNS resources that are not encrypted at rest
    """
    local_evaluations = []
    resource_type = 'AWS::SNS::Topic'
    try:
        sns_topics = sns_get_topics_list()
        logger.info('SNS - %s topics found.', len(sns_topics))
        for topic in sns_topics:
            # back off the API between vaults
            time.sleep(INTERVAL_BETWEEN_API_CALLS)
            topic_arn = topic.get('TopicArn')
            if not topic_arn:
                logger.error('SNS - Faulty structure - %s', topic)
                continue
            compliance_status = 'NON_COMPLIANT'
            compliance_annotation = 'Unable to assess'
            try:
                response = AWS_SNS_CLIENT.get_topic_attributes(TopicArn=topic_arn)
                if response:
                    if 'KmsMasterKeyId' in response.get('Attributes'):
                        compliance_status = 'COMPLIANT'
                        compliance_annotation = 'Encrypted at rest'
                    else:
                        compliance_annotation = 'Not encrypted at rest'
                else:
                    compliance_annotation = 'Unable to assess - empty attributes'
            except botocore.exceptions.ClientError as ex:
                logger.error('SNS - Error when trying to get_topic_attributes %s', ex)
            # build evaluation
            local_evaluations.append(
                build_evaluation(
                    topic_arn,
                    compliance_status,
                    event,
                    resource_type,
                    annotation=compliance_annotation
                )
            )
            if compliance_status == 'NON_COMPLIANT':
                NONCOMPLIANT_SERVICES.add('SNS')
    except botocore.exceptions.ClientError as ex:
        logger.error('SNS - Error while calling sns_get_topics_list %s', ex)
        NONCOMPLIANT_SERVICES.add('SNS')
    logger.info('SNS - reporting %s evaluations.', len(local_evaluations))
    return local_evaluations


def sns_get_topics_list():
    """
    This function gets a list of all the SNS topics in the account
    """
    resource_list = []
    sns_paginator = AWS_SNS_CLIENT.get_paginator('list_topics')
    sns_resource_list = sns_paginator.paginate()
    for page in sns_resource_list:
        resource_list.extend(page['Topics'])
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
        compliance_annotation = 'Non-compliant resources found in {}'.format(', '.join(sorted(NONCOMPLIANT_SERVICES)))
        compliance_status = 'NON_COMPLIANT'
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

    rounds = (total_evaluations // batch_size)+1

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
        assume_role_response = sts_client.assume_role(RoleArn=role_arn, RoleSessionName="configLambdaExecution")
        return assume_role_response['Credentials']
    except botocore.exceptions.ClientError as ex:
        # Scrub error message for any internal account info leaks
        if 'AccessDenied' in ex.response['Error']['Code']:
            ex.response['Error']['Message'] = "AWS Config does not have permission to assume the IAM role."
        else:
            ex.response['Error']['Message'] = "InternalError"
            ex.response['Error']['Code'] = "InternalError"
        raise ex


# Check whether the message is a ScheduledNotification or not.
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
    global AWS_CONFIG_CLIENT
    global AWS_EFS_CLIENT
    global AWS_EKS_CLIENT
    global AWS_KINESIS_CLIENT
    global AWS_OPENSEARCH_CLIENT
    global AWS_RDS_CLIENT
    global AWS_S3_CLIENT
    global AWS_SNS_CLIENT

    # Global variables
    global AWS_ACCOUNT_ID
    global AUDIT_ACCOUNT_ID
    global EXECUTION_ROLE_NAME
    global NONCOMPLIANT_SERVICES
    NONCOMPLIANT_SERVICES=set({})

    # global constants for API calls
    global MAXIMUM_API_RETRIES
    global PAGE_SIZE
    global INTERVAL_BETWEEN_API_CALLS
    global THROTTLE_BACKOFF
    MAXIMUM_API_RETRIES = 10
    PAGE_SIZE = 25
    INTERVAL_BETWEEN_API_CALLS=0.1
    THROTTLE_BACKOFF=2

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

    if 'EXECUTION_ROLE_NAME' in valid_rule_parameters:
        EXECUTION_ROLE_NAME = valid_rule_parameters['ExecutionRoleName']
    else:
        EXECUTION_ROLE_NAME = 'AWSA-GCLambdaExecutionRole2'

    if 'AuditAccountID' in valid_rule_parameters:
        AUDIT_ACCOUNT_ID = valid_rule_parameters['AuditAccountID']
    else:
        AUDIT_ACCOUNT_ID = ''

    # is this a scheduled invokation?
    if not is_scheduled_notification(invoking_event['messageType']):
        logger.error('Skipping assessments as this is not a scheduled invokation')
        return

    # establish AWS API clients
    AWS_CONFIG_CLIENT = get_client('config', event)
    AWS_EFS_CLIENT = get_client('efs', event)
    AWS_EKS_CLIENT = get_client('eks', event)
    AWS_KINESIS_CLIENT = get_client('kinesis', event)
    AWS_OPENSEARCH_CLIENT = get_client('opensearch', event)
    AWS_RDS_CLIENT = get_client('rds', event)
    AWS_S3_CLIENT = get_client('s3', event)
    AWS_SNS_CLIENT = get_client('sns', event)

    # EFS
    evaluations.extend(assess_efs_encryption_at_rest(event))

    # EKS
    evaluations.extend(assess_eks_encryption_at_rest(event))

    # ElasticSearch/OpenSearch
    evaluations.extend(assess_opensearch_encryption_at_rest(event))

    # Kinesis
    evaluations.extend(assess_kinesis_encryption_at_rest(event))

    # RDS
    evaluations.extend(assess_rds_encryption_at_rest(event))

    # S3
    evaluations.extend(assess_s3_encryption_at_rest(event))

    # SNS
    evaluations.extend(assess_sns_encryption_at_rest(event))

    # Account - must be the last
    evaluations.append(get_account_evaluation(event))

    # Submit evaluations to AWS Config
    logger.info('Submitting evaluations %s', evaluations)
    submit_evaluations(evaluations, event['resultToken'], 50)
