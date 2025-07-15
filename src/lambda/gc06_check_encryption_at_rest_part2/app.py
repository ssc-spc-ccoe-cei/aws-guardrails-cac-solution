""" GC06 - Check Encryption at Rest - Part 2
    https://canada-ca.github.io/cloud-guardrails/EN/06_Protect-Data-at-Rest.html
"""

import json
import logging
import time

from utils import (
    is_scheduled_notification,
    check_required_parameters,
    check_guardrail_requirement_by_cloud_usage_profile,
    get_cloud_profile_from_tags,
    GuardrailType,
    GuardrailRequirementType,
)
from boto_util.organizations import get_account_tags
from boto_util.client import get_client, is_throttling_exception
from boto_util.config import build_evaluation, submit_evaluations
from boto_util.efs import describe_all_efs_file_systems
from boto_util.eks import list_all_eks_clusters
from boto_util.kinesis import list_all_kinesis_streams
from boto_util.rds import (
    describe_all_rds_db_clusters,
    describe_all_rds_db_cluster_snapshots,
    describe_all_rds_db_instances,
    describe_all_rds_db_snapshots,
)
from boto_util.s3 import list_all_s3_buckets
from boto_util.sns import list_all_sns_topics

import botocore.exceptions

# Logging setup
logger = logging.getLogger()
logger.setLevel(logging.INFO)


############################################################
# AWS ElasticSearch and OpenSearch specific support functions
#   - ELASTICSEARCH_ENCRYPTED_AT_REST
#   - OPEN_SEARCH_ENCRYPTED_AT_REST
def assess_open_search_encryption_at_rest(open_search_client, event):
    """
    Finds OpenSearch and ElasticSearch domains not encrypted at rest,
    then marks them COMPLIANT if EncryptionAtRest is enabled.
    """
    local_evaluations = []
    domains = []
    # we use a single call to list both OpenSearch and Elasticsearch domains
    try:
        response = open_search_client.list_domain_names()
        if response:
            domains = response.get("DomainNames", [])
        else:
            # empty response
            logger.error("OpenSearch/ElasticSearch - Empty response while calling list_domain_names")
            NONCOMPLIANT_SERVICES.add("OpenSearch/ElasticSearch")
    except botocore.exceptions.ClientError as ex:
        logger.error("OpenSearch/ElasticSearch - Error while calling list_domain_names %s", ex)
        NONCOMPLIANT_SERVICES.add("OpenSearch/ElasticSearch")
    except ValueError:
        logger.error("OpenSearch/ElasticSearch - Error while calling list_domain_names")
        NONCOMPLIANT_SERVICES.add("OpenSearch/ElasticSearch")

    logger.info("OpenSearch/ElasticSearch - %s Domains found.", len(domains))

    for domain in domains:
        domain_name = domain.get("DomainName", "")
        engine_type = domain.get("EngineType", "")  # "Elasticsearch" or "OpenSearch"
        compliance_status = "NON_COMPLIANT"
        compliance_annotation = "Not encrypted at rest"

        # Fix for AWS Config resource type:
        #   - 'AWS::Elasticsearch::Domain' for ES domains
        #   - 'AWS::OpenSearchService::Domain' for OpenSearch domains
        if engine_type == "OpenSearch":
            resource_type = "AWS::Elasticsearch::Domain"
        else:
            resource_type = "AWS::Elasticsearch::Domain"

        if not domain_name:
            logger.error("OpenSearch/ElasticSearch - Invalid domain structure %s", domain)
            continue

        # Describe domain to get the EncryptionAtRest status and the ARN
        try:
            response = open_search_client.describe_domain(DomainName=domain_name)
            if response:
                domain_status = response.get("DomainStatus", {})
                # Correctly pull out the domain ARN from describe_domain
                domain_arn = domain_status.get("ARN", domain_name)

                if domain_status.get("EncryptionAtRestOptions", {}).get("Enabled") is True:
                    compliance_status = "COMPLIANT"
                    compliance_annotation = "Encrypted at rest"
            else:
                # empty response
                logger.error("OpenSearch/ElasticSearch - Empty response while calling describe_domain")
                domain_arn = domain_name
        except botocore.exceptions.ClientError as ex:
            logger.error("OpenSearch/ElasticSearch - Error while calling describe_domain %s", ex)
            domain_arn = domain_name
        except ValueError:
            logger.error("OpenSearch/ElasticSearch - Error while calling describe_domain")
            domain_arn = domain_name

        if compliance_status == "NON_COMPLIANT":
            NONCOMPLIANT_SERVICES.add("OpenSearch/ElasticSearch")

        local_evaluations.append(
            build_evaluation(
                domain_arn,
                compliance_status,
                event,
                resource_type,
                annotation=compliance_annotation,
            )
        )

    return local_evaluations


############################################################
# AWS Kinesis specific support functions
#  - KINESIS_STREAM_ENCRYPTED
def assess_kinesis_encryption_at_rest(kinesis_client, event):
    """
    Finds AWS Kinesis data streams that are not encrypted at rest
    """
    local_evaluations = []
    stream_names = []
    resource_type = "AWS::Kinesis::Stream"
    try:
        stream_names = list_all_kinesis_streams(kinesis_client, PAGE_SIZE, INTERVAL_BETWEEN_API_CALLS)
    except botocore.exceptions.ClientError as ex:
        logger.error("Kinesis - Error while calling kinesis_get_streams_list %s", ex)
        NONCOMPLIANT_SERVICES.add("Kinesis")
    except ValueError:
        logger.error("Kinesis - Error while calling kinesis_get_streams_list")
        NONCOMPLIANT_SERVICES.add("Kinesis")

    logger.info("Kinesis - %s streams found.", len(stream_names))

    for stream_name in stream_names:
        compliance_status = "NON_COMPLIANT"
        compliance_annotation = "Not encrypted at rest using KMS"
        encryption_type = "NONE"
        stream_arn = ""

        try:
            response = kinesis_client.describe_stream(StreamName=stream_name, Limit=1)
        except botocore.exceptions.ClientError as ex:
            logger.error("Kinesis - Error while calling describe_stream %s", ex)
            response = {}
        except ValueError:
            logger.error("Kinesis - Error while calling describe_stream")
            response = {}

        if response:
            stream_arn = response.get("StreamDescription", {}).get("StreamARN", "")
            encryption_type = response.get("StreamDescription", {}).get("EncryptionType", "NONE")

        if encryption_type == "KMS":
            compliance_status = "COMPLIANT"
            compliance_annotation = "Encrypted at rest using KMS"

        logger.info("Kinesis - Stream %s is %s", stream_arn, compliance_status)

        local_evaluations.append(
            build_evaluation(stream_arn, compliance_status, event, resource_type, annotation=compliance_annotation)
        )
        if compliance_status == "NON_COMPLIANT":
            NONCOMPLIANT_SERVICES.add("Kinesis")

    logger.info("Kinesis - reporting %s evaluations.", len(local_evaluations))
    return local_evaluations


#################################################################
# Amazon EFS specific support functions - EFS_ENCRYPTED_CHECK
def assess_efs_encryption_at_rest(efs_client, event):
    """
    Finds Amazon EFS file systems that are not encrypted at rest
    """
    local_evaluations = []
    # Assess File Systems
    resource_type = "AWS::EFS::FileSystem"

    efs_filesystems = describe_all_efs_file_systems(efs_client, PAGE_SIZE, INTERVAL_BETWEEN_API_CALLS)
    logger.info("EFS - %s File systems found.", len(efs_filesystems))

    for filesystem in efs_filesystems:
        if filesystem.get("Encrypted", "") is True:
            compliance_status = "COMPLIANT"
            annotation = "Encrypted at rest"
        else:
            compliance_status = "NON_COMPLIANT"
            annotation = "Not encrypted at rest"
            NONCOMPLIANT_SERVICES.add("EFS")
        # build evaluation for the cluster
        local_evaluations.append(
            build_evaluation(
                filesystem.get("FileSystemArn", filesystem.get("FileSystemId", "INVALID")),
                compliance_status,
                event,
                resource_type,
                annotation,
            )
        )

    logger.info("EFS - reporting %s evaluations.", len(local_evaluations))
    return local_evaluations


#################################################################
# Amazon EKS specific support functions
#   - EKS_SECRETS_ENCRYPTED
def assess_eks_encryption_at_rest(eks_client, event):
    """
    Finds Amazon EKS clusters that do not have secrets encrypted at rest
    """
    local_evaluations = []
    # Assess EKS Clusters
    resource_type = "AWS::EKS::Cluster"
    eks_clusters = list_all_eks_clusters(eks_client, PAGE_SIZE, INTERVAL_BETWEEN_API_CALLS)
    logger.info("EKS - %s clusters found.", len(eks_clusters))

    for cluster in eks_clusters:
        try:
            compliance_status = "NON_COMPLIANT"
            compliance_annotation = "Unable to assess"
            response = eks_client.describe_cluster(name=cluster)

            if response:
                encryption_config = response.get("cluster", {}).get("encryptionConfig", [])
                if encryption_config:
                    # check if there are resources of type secrets
                    compliance_annotation = "Secrets are not encrypted"
                    for config in encryption_config:
                        if "secrets" in config.get("resources", []):
                            compliance_status = "COMPLIANT"
                            compliance_annotation = "Secrets are encrypted"
                            break
                else:
                    compliance_annotation = "Empty encryptionConfig"

            if compliance_status == "NON_COMPLIANT":
                NONCOMPLIANT_SERVICES.add("EKS")

            cluster_arn = response.get("cluster", {}).get("arn", response.get("cluster", {}).get("name", "INVALID"))
        except botocore.exceptions.ClientError as ex:
            logger.error("EKS - Error trying to describe_cluster %s", ex)
            NONCOMPLIANT_SERVICES.add("EKS")
            cluster_arn = "INVALID"

        local_evaluations.append(
            build_evaluation(
                cluster_arn,
                compliance_status,
                event,
                resource_type,
                annotation=compliance_annotation,
            )
        )

    logger.info("EKS - reporting %s evaluations.", len(local_evaluations))
    return local_evaluations


############################################################
# RDS specific support functions
#  - RDS_SNAPSHOT_ENCRYPTED
#  - RDS_STORAGE_ENCRYPTED
def assess_rds_encryption_at_rest(rds_client, event):
    """
    Finds Amazon RDS resources that are not encrypted at rest
    """
    local_evaluations = []

    # Assess DB Clusters
    resource_type = "AWS::RDS::DBCluster"
    db_clusters = describe_all_rds_db_clusters(rds_client, PAGE_SIZE, INTERVAL_BETWEEN_API_CALLS)
    logger.info("RDS - %s DB Clusters found.", len(db_clusters))

    for cluster in db_clusters:
        # let's check the cluster storage
        if cluster.get("StorageEncrypted", "") is True:
            compliance_status = "COMPLIANT"
            annotation = "Encrypted at rest"
        else:
            compliance_status = "NON_COMPLIANT"
            annotation = "Not encrypted at rest"
            NONCOMPLIANT_SERVICES.add("RDS")
        # build evaluation for the cluster
        local_evaluations.append(
            build_evaluation(
                cluster.get("DBClusterArn", cluster.get("DBClusterIdentifier", "INVALID")),
                compliance_status,
                event,
                resource_type,
                annotation,
            )
        )

    # Assess DB Cluster Snapshots
    resource_type = "AWS::RDS::DBClusterSnapshot"
    snapshots = describe_all_rds_db_cluster_snapshots(rds_client, PAGE_SIZE, INTERVAL_BETWEEN_API_CALLS)
    logger.info("RDS - %s DB Cluster Snapshots found.", len(snapshots))

    for snapshot in snapshots:
        if snapshot.get("StorageEncrypted", "") is True:
            compliance_status = "COMPLIANT"
            annotation = "Encrypted at rest"
        else:
            compliance_status = "NON_COMPLIANT"
            annotation = "Not encrypted at rest"
            NONCOMPLIANT_SERVICES.add("RDS")
        # build evaluation for the snapshot
        local_evaluations.append(
            build_evaluation(
                snapshot.get("DBClusterSnapshotArn", snapshot.get("DBClusterSnapshotIdentifier", "INVALID")),
                compliance_status,
                event,
                resource_type,
                annotation,
            )
        )

    # Assess DB Instances
    db_instances = describe_all_rds_db_instances(rds_client, PAGE_SIZE, INTERVAL_BETWEEN_API_CALLS)
    resource_type = "AWS::RDS::DBInstance"
    logger.info("RDS - %s DB Instances found.", len(db_instances))

    for instance in db_instances:
        # let's check the cluster storage
        if instance.get("StorageEncrypted", "") is True:
            compliance_status = "COMPLIANT"
            annotation = "Encrypted at rest"
        else:
            compliance_status = "NON_COMPLIANT"
            annotation = "Not encrypted at rest"
            NONCOMPLIANT_SERVICES.add("RDS")
        # build evaluation for the instance
        local_evaluations.append(
            build_evaluation(
                instance.get("DBInstanceArn", instance.get("DBInstanceIdentifier", "INVALID")),
                compliance_status,
                event,
                resource_type,
                annotation,
            )
        )

    # Assess DB Snapshots
    resource_type = "AWS::RDS::DBSnapshot"
    snapshots = describe_all_rds_db_snapshots(rds_client, PAGE_SIZE, INTERVAL_BETWEEN_API_CALLS)
    logger.info("RDS - %s DB Instance Snapshots found.", len(snapshots))

    for snapshot in snapshots:
        if snapshot.get("Encrypted", "") is True:
            compliance_status = "COMPLIANT"
            annotation = "Encrypted at rest"
        else:
            compliance_status = "NON_COMPLIANT"
            annotation = "Not encrypted at rest"
            NONCOMPLIANT_SERVICES.add("RDS")
        # build evaluation for the snapshot
        local_evaluations.append(
            build_evaluation(
                snapshot.get("DBSnapshotArn", snapshot.get("DBSnapshotIdentifier", "INVALID")),
                compliance_status,
                event,
                resource_type,
                annotation,
            )
        )

    logger.info("RDS - reporting %s evaluations.", len(local_evaluations))
    return local_evaluations


############################################################
# S3 specific support functions
#  - S3_BUCKET_SERVER_SIDE_ENCRYPTION_ENABLED
def assess_s3_encryption_at_rest(s3_client, event):
    """
    Finds Amazon S3 buckets that do not have server-side encryption enabled
    """
    local_evaluations = []
    resource_type = "AWS::S3::Bucket"

    try:
        buckets = list_all_s3_buckets(s3_client, PAGE_SIZE, INTERVAL_BETWEEN_API_CALLS)
        if buckets:
            for bucket in buckets:
                bucket_name = bucket.get("Name")
                bucket_arn = f"arn:aws:s3:::{bucket_name}"
                compliance_status = "NON_COMPLIANT"
                annotation = "Unable to assess"
                i_retries = 0
                b_success = False

                while (not b_success) and (i_retries < MAXIMUM_API_RETRIES):
                    try:
                        response2 = s3_client.get_bucket_encryption(Bucket=bucket_name)
                        if response2:
                            for rule in response2.get("ServerSideEncryptionConfiguration", {}).get("Rules", []):
                                default_encryption = rule.get("ApplyServerSideEncryptionByDefault", {})
                                if not default_encryption:
                                    continue
                                compliance_status = "COMPLIANT"
                                annotation = "Encryption at rest enforced. Algorithm is {}".format(
                                    default_encryption.get("SSEAlgorithm", "")
                                )
                        else:
                            annotation = "Empty response when trying to get_bucket_encryption"

                        if compliance_status == "NON_COMPLIANT":
                            NONCOMPLIANT_SERVICES.add("S3")

                        b_success = True
                        time.sleep(INTERVAL_BETWEEN_API_CALLS)

                    except botocore.exceptions.ClientError as ex:
                        b_success = True
                        if "AccessDenied" in ex.response["Error"]["Code"]:
                            logger.error(
                                "AccessDenied when trying to get_bucket_encryption - assess_s3_encryption_at_rest: %s",
                                ex,
                            )
                            annotation = "Access Denied"
                            NONCOMPLIANT_SERVICES.add("S3")
                        elif "ServerSideEncryptionConfigurationNotFound" in ex.response["Error"]["Code"]:
                            logger.info(
                                "ServerSideEncryptionConfigurationNotFound when trying to get_bucket_encryption - assess_s3_encryption_at_rest: %s",
                                ex,
                            )
                            annotation = "Encryption not enforced at rest"
                            NONCOMPLIANT_SERVICES.add("S3")
                        elif is_throttling_exception(ex):
                            i_retries += 1
                            logger.error("S3 - Throttling while calling get_bucket_encryption")
                            time.sleep(THROTTLE_BACKOFF)
                            b_success = False
                        else:
                            logger.error("S3 - Error while calling get_bucket_encryption %s", ex)
                            NONCOMPLIANT_SERVICES.add("S3")
                # build evaluation
                local_evaluations.append(
                    build_evaluation(bucket_arn, compliance_status, event, resource_type, annotation)
                )

    except botocore.exceptions.ClientError as ex:
        NONCOMPLIANT_SERVICES.add("S3")
        if "AccessDenied" in ex.response["Error"]["Code"]:
            logger.error("AccessDenied when trying to list_buckets - assess_s3_encryption_at_rest: %s", ex)
        else:
            logger.error("S3 - Error while calling list_buckets %s", ex)

    logger.info("S3 - reporting %s evaluations.", len(local_evaluations))
    return local_evaluations


############################################################
# SNS specific support functions
#  -  SNS_ENCRYPTED_KMS
def assess_sns_encryption_at_rest(sns_client, event):
    """
    Finds Amazon SNS resources that are not encrypted at rest
    """
    local_evaluations = []
    resource_type = "AWS::SNS::Topic"

    try:
        sns_topics = list_all_sns_topics(sns_client, INTERVAL_BETWEEN_API_CALLS)
        logger.info("SNS - %s topics found.", len(sns_topics))

        for topic in sns_topics:
            # back off the API between vaults
            time.sleep(INTERVAL_BETWEEN_API_CALLS)
            topic_arn = topic.get("TopicArn")
            if not topic_arn:
                logger.error("SNS - Faulty structure - %s", topic)
                continue

            compliance_status = "NON_COMPLIANT"
            compliance_annotation = "Unable to assess"

            try:
                response = sns_client.get_topic_attributes(TopicArn=topic_arn)
                if response:
                    if "KmsMasterKeyId" in response.get("Attributes"):
                        compliance_status = "COMPLIANT"
                        compliance_annotation = "Encrypted at rest"
                    else:
                        compliance_annotation = "Not encrypted at rest"
                else:
                    compliance_annotation = "Unable to assess - empty attributes"

            except botocore.exceptions.ClientError as ex:
                logger.error("SNS - Error when trying to get_topic_attributes %s", ex)

            local_evaluations.append(
                build_evaluation(topic_arn, compliance_status, event, resource_type, annotation=compliance_annotation)
            )

            if compliance_status == "NON_COMPLIANT":
                NONCOMPLIANT_SERVICES.add("SNS")

    except botocore.exceptions.ClientError as ex:
        logger.error("SNS - Error while calling sns_get_topics_list %s", ex)
        NONCOMPLIANT_SERVICES.add("SNS")

    logger.info("SNS - reporting %s evaluations.", len(local_evaluations))
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
        annotation = "Non-compliant resources found in {}".format(", ".join(sorted(NONCOMPLIANT_SERVICES)))
        compliance_type = "NON_COMPLIANT"

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
    global NONCOMPLIANT_SERVICES
    global MAXIMUM_API_RETRIES
    global PAGE_SIZE
    global INTERVAL_BETWEEN_API_CALLS
    global THROTTLE_BACKOFF

    NONCOMPLIANT_SERVICES = set({})
    MAXIMUM_API_RETRIES = 10
    PAGE_SIZE = 25
    INTERVAL_BETWEEN_API_CALLS = 0.1
    THROTTLE_BACKOFF = 2

    # establish AWS API clients
    aws_config_client = get_client("config", aws_account_id, execution_role_name, is_not_audit_account)
    aws_efs_client = get_client("efs", aws_account_id, execution_role_name, is_not_audit_account)
    aws_eks_client = get_client("eks", aws_account_id, execution_role_name, is_not_audit_account)
    aws_open_search_client = get_client("opensearch", aws_account_id, execution_role_name, is_not_audit_account)
    aws_kinesis_client = get_client("kinesis", aws_account_id, execution_role_name, is_not_audit_account)
    aws_rds_client = get_client("rds", aws_account_id, execution_role_name, is_not_audit_account)
    #updated to set the flag to true to access buckets not in ca-central-1 region
    aws_s3_client = get_client("s3", aws_account_id, execution_role_name, True)
    aws_sns_client = get_client("sns", aws_account_id, execution_role_name, is_not_audit_account)

    # Check cloud profile
    tags = get_account_tags(get_client("organizations", assume_role=False), aws_account_id)
    cloud_profile = get_cloud_profile_from_tags(tags)
    gr_requirement_type = check_guardrail_requirement_by_cloud_usage_profile(GuardrailType.Guardrail6, cloud_profile)

    # If the guardrail is recommended
    if gr_requirement_type == GuardrailRequirementType.Recommended:
        return submit_evaluations(
            aws_config_client,
            event,
            [
                build_evaluation(
                    aws_account_id,
                    "COMPLIANT",
                    event,
                    gr_requirement_type=gr_requirement_type
                )
            ],
        )

    # If the guardrail is not required
    elif gr_requirement_type == GuardrailRequirementType.Not_Required:
        return submit_evaluations(
            aws_config_client,
            event,
            [
                build_evaluation(
                    aws_account_id,
                    "NOT_APPLICABLE",
                    event,
                    gr_requirement_type=gr_requirement_type
                )
            ],
        )

    # EFS
    evaluations.extend(assess_efs_encryption_at_rest(aws_efs_client, event))

    # EKS
    evaluations.extend(assess_eks_encryption_at_rest(aws_eks_client, event))

    # ElasticSearch/OpenSearch
    evaluations.extend(assess_open_search_encryption_at_rest(aws_open_search_client, event))

    # Kinesis
    evaluations.extend(assess_kinesis_encryption_at_rest(aws_kinesis_client, event))

    # RDS
    evaluations.extend(assess_rds_encryption_at_rest(aws_rds_client, event))

    # S3
    evaluations.extend(assess_s3_encryption_at_rest(aws_s3_client, event))

    # SNS
    evaluations.extend(assess_sns_encryption_at_rest(aws_sns_client, event))

    # Account - must be the last
    evaluations.append(get_account_evaluation(aws_account_id, event))

    # Submit evaluations to AWS Config
    logger.info("Submitting evaluations %s", evaluations)
    submit_evaluations(aws_config_client, event, evaluations)
