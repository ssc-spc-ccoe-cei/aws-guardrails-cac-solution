""" GC05 - Check Data Location
    https://canada-ca.github.io/cloud-guardrails/EN/05_Data-Location.html
"""

import botocore.exceptions
import logging
import json
import os
import re

from utils import (
    is_scheduled_notification,
    check_required_parameters,
    check_guardrail_requirement_by_cloud_usage_profile,
    get_cloud_profile_from_tags,
    GuardrailType,
    GuardrailRequirementType,
)
from boto_util.organizations import get_account_tags
from boto_util.client import get_client
from boto_util.config import build_evaluation, submit_evaluations
from boto_util.ec2 import get_enabled_regions
from boto_util.resource_explorer_2 import resource_explorer_get_indexes

# Logging setup
logger = logging.getLogger()
logger.setLevel(logging.INFO)


def is_allow_listed_resource(resource_name, resource_arn, asea_resource_arns):
    """Assesses whether the resource is to be allow listed
    Returns True if it should be allow listed
    """
    bAllowList = False
    allowlist_regex_rules = [
        ".*asea-.*",
        ".*pbmm-.*",
        "^awscfncli-.+",
        "^awsconfigconforms-.+",
        "^cf-templates.+",
        ".*cdk-.*",
        ".*aws-accelerator-.*",  # rule for Landing Zone Resources (check conventions)
    ]
    allowlist_regex = "(?:%s)" % "|".join(allowlist_regex_rules)

    if re.match(allowlist_regex, resource_name.lower()) or (resource_arn in asea_resource_arns):
        logger.info("Resource '{}' meets requirements for allow listing.".format(resource_name))
        bAllowList = True
    return bAllowList


def parse_resource_explorer_result(
    resources: list,
    service: str,
    unauthorized_resource_types: dict[str, list[str]],
    aws_resource_explorer_to_config_resource_types: dict[str, str],
):
    results = []
    if not resources or not service:
        logger.error("Empty Resources result provided to parse_resource_explorer_result call.")
        return None
    elif not service:
        logger.error("Empty Service name provided to parse_resource_explorer_result call.")
        return None
    service = service.lower()
    if service in unauthorized_resource_types.keys():
        logger.debug("parse_resource_explorer_result - Service '{}' is of interest".format(service))
        for resource in resources:
            resource_arn = resource.get("Arn")
            resource_id = resource.get("Id")
            resource_service = resource.get("Service").lower()
            resource_type = resource.get("ResourceType").lower()
            logger.debug(
                "parse_resource_explorer_result\n  Resource ARN '{}'\n  Service: '{}'\n  Type '{}'".format(
                    resource_arn, resource_service, resource_type
                )
            )
            if resource_type in unauthorized_resource_types.get(service):
                if aws_resource_explorer_to_config_resource_types.get(resource_type, None):
                    logger.debug("*** RESOURCE IS OF UNAUTHORIZED TYPE")
                    results.append(
                        {
                            "Arn": resource_arn,
                            "Id": resource_id,
                            "ResourceType": aws_resource_explorer_to_config_resource_types.get(resource_type, ""),
                        }
                    )
                else:
                    logger.debug(
                        "Ignoring resource {} as it is not a supported AWS Config Resource Type".format(resource_arn)
                    )
            else:
                logger.debug("'{}' not an unauthorized resource type.".format(resource_arn))
    else:
        logger.info("Service '{}' not in the list of NonAuthorizedServices. Returning empty results.")
    return results


def get_qldb_resources(aws_account_id, execution_role_name, RegionName=None, event=None):
    """
    Finds Ledger Database (QLDB) resources in the specified region
    """
    results = []
    aws_qldb_client = get_client("qldb", aws_account_id, execution_role_name, region=RegionName)
    NextToken = ""
    ResourceType = "AWS::QLDB::Ledger"
    try:
        response = aws_qldb_client.list_ledgers()
        while True:
            if response:
                for ledger in response.get("Ledgers"):
                    response2 = aws_qldb_client.describe_ledger(Name=ledger.get("Name"))
                    if response2:
                        results.append(
                            {"Arn": response2.get("Arn"), "Id": response2.get("Name"), "ResourceType": ResourceType}
                        )
                    else:
                        logger.info("Unable to describe_ledger '{}'".format(ledger.get("Name")))
                NextToken = response.get("NextToken")
                if NextToken:
                    response = aws_qldb_client.list_ledgers(NextToken=NextToken)
                else:
                    break
            else:
                break
    except botocore.exceptions.EndpointConnectionError as ex:
        logger.debug("QLDB endpoint not available in the region {}".format(RegionName))
        pass
    except botocore.exceptions.ClientError as ex:
        if "AccessDenied" in ex.response["Error"]["Code"]:
            logger.error("AccessDenied when trying to list_ledgers or describe_ledger - get_qldb_resources")
            pass
        else:
            raise ex
    return results


def s3_has_approved_tags(bucket_tags):
    """Checks if s3 bucket has approved tags attached for location exemption
    Args:
        output from an s3 client get_bucket_tagging(Bucket='bucket_name')

    Returns:
        True if bucket is tagged with approved tag(s)
        False otherwise
    """
    # Tag keys 
    TAG_KEY_DATA_CLASS = "Data classification"
    # Allowed tag values for each key
    ALLOWED_DATA_CLASS_VALUES = ["Protected A", "Unclassified"]

    if bucket_tags == None:
        return False
    elif 'TagSet' in bucket_tags:
        for tag in bucket_tags['TagSet']:
            if tag['Key'] == TAG_KEY_DATA_CLASS and tag['Value'] in ALLOWED_DATA_CLASS_VALUES:
                return True
            else:
                pass        
    return False
    
def get_s3_resources(aws_s3_client, UnauthorizedRegionsList=[]):
    """
    Finds Amazon S3 resources in the specified region
    """
    results = {}
    ResourceType = "AWS::S3::Bucket"
    try:
        response = aws_s3_client.list_buckets()
        if response:
            for bucket in response.get("Buckets"):
                bucket_name = bucket.get("Name")
                bucket_arn = "arn:aws:s3:::{}".format(bucket_name)
                bucket_location = aws_s3_client.get_bucket_location(Bucket=bucket_name)

                # bucket may not have tags
                try:
                    bucket_tags = aws_s3_client.get_bucket_tagging(Bucket=bucket_name)
                except Exception as e:
                    if "NoSuchTagSet" in e.response["Error"]["Code"]:
                        bucket_tags = None
                
                if bucket_location:
                    LocationConstraint = bucket_location.get("LocationConstraint")
                    if LocationConstraint:
                        if LocationConstraint in UnauthorizedRegionsList:
                            # if bucket does not have the proper tags for exemption,
                            # add bucket info to results[LocationConstraint] dict
                            if not s3_has_approved_tags(bucket_tags) and results.get(LocationConstraint):
                                # results[LocationConstraint] exists, then just append
                                results[LocationConstraint].append(
                                    {"Arn": bucket_arn, "Id": bucket.get("Name"), "ResourceType": ResourceType}
                                )
                            elif not s3_has_approved_tags(bucket_tags) and not results.get(LocationConstraint):
                                # results[LocationConstraint] doesn't exist, so start one
                                results[LocationConstraint] = [
                                    {"Arn": bucket_arn, "Id": bucket.get("Name"), "ResourceType": ResourceType}
                                ]
                    else:
                        if not s3_has_approved_tags(bucket_tags) and results.get("global"):
                            # results["global"] exists, then just append
                            results["global"].append(
                                {"Arn": bucket_arn, "Id": bucket.get("Name"), "ResourceType": ResourceType}
                            )
                        elif not s3_has_approved_tags(bucket_tags) and not results.get("global"):
                            # results["global"] doesn't exist, so start one
                            results["global"] = [
                                {"Arn": bucket_arn, "Id": bucket.get("Name"), "ResourceType": ResourceType}
                            ]
                else:
                    logger.info("Unable to get_bucket_location '{}'".format(bucket_name))
        else:
            logger.info("Unable to list buckets")
    except botocore.exceptions.ClientError as ex:
        if "AccessDenied" in ex.response["Error"]["Code"]:
            logger.error("AccessDenied when trying to list_buckets or get_bucket_location - get_s3_resources")
            pass
        else:
            raise ex
    return results


def get_non_authorized_resources_in_region(
    unauthorized_resource_types: dict[str, list[str]],
    aws_resource_explorer_to_config_resource_types: dict[str, str],
    resource_explorer_client,
    aws_account_id,
    execution_role_name,
    RegionName=None,
    event=None,
    interval_between_api_calls=0.05,
    page_size=25,
):
    results = []
    if not RegionName:
        logger.error("Empty region provided for get_non_authorized_resources_in_region call.")
        return None
    bResourceExplorerAvailable = False
    ResourceExplorerIndexRegion = RegionName
    try:
        resource_explorer_indexes = resource_explorer_get_indexes(
            resource_explorer_client, "AGGREGATOR", page_size, interval_between_api_calls
        )
        if resource_explorer_indexes:
            ResourceExplorerIndexRegion = resource_explorer_indexes[0].get("Region", "")
            bResourceExplorerAvailable = True
        else:
            resource_explorer_indexes = resource_explorer_get_indexes(
                resource_explorer_client, None, page_size, interval_between_api_calls
            )
            for index in resource_explorer_indexes:
                if index.get("Region", "") == RegionName:
                    ResourceExplorerIndexRegion == RegionName
                    bResourceExplorerAvailable = True
                    break
    except botocore.exceptions.ClientError as ex:
        logger.error("Error trying to list_indexes for Resource Explorer: {}".format(ex))
        pass
    for service in unauthorized_resource_types.keys():
        query_string = "service:{} region:{}".format(service, ResourceExplorerIndexRegion)
        ResourceList = []
        TempResources = []
        if service == "qldb":
            ResourceList = get_qldb_resources(aws_account_id, execution_role_name, RegionName, event=event)
        elif service == "s3":
            continue
        else:
            if not bResourceExplorerAvailable:
                logger.info(
                    "Skipping service {} in region {} as Resource Explorer is not available.".format(
                        service, RegionName
                    )
                )
                continue
            try:
                response = resource_explorer_client.search(
                    QueryString=query_string,
                )
                if response:
                    if (
                        response.get("Count").get("Complete") == False
                        and response.get("Count").get("TotalResources") == 1000
                    ):
                        logger.error(
                            "Resource Explorer search limit reached when trying to query region '{}' for service '{}'. More than 1000 resources"
                        )
                        TempResources = response.get("Resources")
                        if TempResources:
                            logger.debug("'{}' resources found".format(len(TempResources)))
                            logger.debug(TempResources)
                            ResourceList.extend(
                                parse_resource_explorer_result(
                                    TempResources,
                                    service,
                                    unauthorized_resource_types,
                                    aws_resource_explorer_to_config_resource_types,
                                )
                            )
                        continue
                    else:
                        TempResources = response.get("Resources")
                        if TempResources:
                            logger.debug("'{}' resources found".format(len(TempResources)))
                            logger.debug(TempResources)
                            ResourceList.extend(
                                parse_resource_explorer_result(
                                    TempResources,
                                    service,
                                    unauthorized_resource_types,
                                    aws_resource_explorer_to_config_resource_types,
                                )
                            )
                        NextToken = response.get("NextToken")
                        while NextToken:
                            response = resource_explorer_client.search(QueryString=query_string, NextToken=NextToken)
                            if response:
                                ResourceList.extend(
                                    parse_resource_explorer_result(
                                        response.get("Resources"),
                                        service,
                                        unauthorized_resource_types,
                                        aws_resource_explorer_to_config_resource_types,
                                    )
                                )
                                NextToken = response.get("NextToken")
            except botocore.exceptions.ClientError as ex:
                if "UnauthorizedException" in ex.response["Error"]["Code"]:
                    logger.info(
                        "UnauthorizedException when trying to use Resource Explorer in region '{}'".format(RegionName)
                    )
                    pass
                else:
                    raise ex
        if ResourceList:
            results.extend(ResourceList)
    return results


def get_asea_tagged_resource_arns(
    aws_account_id,
    execution_role_name,
    unauthorized_region_list: list,
    unauthorized_resource_types: dict[str, list[str]],
):
    result = []

    # Tag keys 
    TAG_KEY_ACCELERATOR = "Accelerator"
    TAG_KEY_DATA_CLASS = "Data classification"

    # Allowed tag values for each key
    ALLOWED_ACCELERATOR_VALUES = ["ASEA", "PBMM"]
    ALLOWED_DATA_CLASS_VALUES = ["Protected A", "Unclassified"]

    resource_type_filters = []
    for service in unauthorized_resource_types.keys():
        resource_type_filters.extend(unauthorized_resource_types.get(service))

    # For each unauthorized region, get all resources of the specified types,
    # then in-memory check if they have allowed tags.
    for region in unauthorized_region_list:
        try:
            tagging_client = get_client(
                "resourcegroupstaggingapi", 
                aws_account_id, 
                execution_role_name, 
                region=region
            )

            response = tagging_client.get_resources(
                ResourceTypeFilters=resource_type_filters
            )
            bMoreData = True
            while bMoreData:
                if response:
                    for resource in response.get("ResourceTagMappingList", []):
                        resource_arn = resource.get("ResourceARN")
                        tags_dict = {t["Key"]: t["Value"] for t in resource.get("Tags", [])}

                        # Check if the resource has allowed Accelerator tag or Data Classification tag
                        accel_value = tags_dict.get(TAG_KEY_ACCELERATOR)
                        data_class_value = tags_dict.get(TAG_KEY_DATA_CLASS)

                        if (
                            (accel_value in ALLOWED_ACCELERATOR_VALUES) or
                            (data_class_value in ALLOWED_DATA_CLASS_VALUES)
                        ):
                            result.append(resource_arn)

                    # Handle pagination
                    pagination_token = response.get("PaginationToken")
                    if pagination_token:
                        response = tagging_client.get_resources(
                            ResourceTypeFilters=resource_type_filters,
                            PaginationToken=pagination_token
                        )
                    else:
                        bMoreData = False
        except botocore.exceptions.ClientError as ex:
            logger.error("Failed to get_asea_tagged_resource_arns with exception %s", ex)
            pass

    return result


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

    page_size = 25
    interval_between_api_calls = 0.05
    aws_resource_explorer_to_config_resource_types = {
        "ec2:instance": "AWS::EC2::Instance",
        "ec2:dedicated-host": "AWS::EC2::Host",
        "ec2:volume": "AWS::EC2::Volume",
        "dynamodb:table": "AWS::DynamoDB::Table",
        "ecs:cluster": "AWS::ECS::Cluster",
        "ecs:service": "AWS::ECS::Service",
        "ecs:task-definition": "AWS::ECS::TaskDefinition",
        "lambda:function": "AWS::Lambda::Function",
        "qldb:ledger": "AWS::QLDB::Ledger",
        "rds:cluster": "AWS::RDS::DBCluster",
        "rds:cluster-snapshot": "AWS::RDS::DBClusterSnapshot",
        "rds:db": "AWS::RDS::DBInstance",
        "rds:snapshot": "AWS::RDS::DBSnapshot",
        "redshift:cluster": "AWS::Redshift::Cluster",
        "redshift:snapshot": "AWS::Redshift::ClusterSnapshot",
        "s3:bucket": "AWS::S3::Bucket",
    }
    unauthorized_resource_types = {
        "ec2": ["ec2:instance", "ec2:dedicated-host", "ec2:volume"],
        "dynamodb": ["dynamodb:table"],
        "ecs": ["ecs:cluster", "ecs:service", "ecs:task-definition"],
        "qldb": ["qldb:ledger"],
        "rds": ["rds:cluster", "rds:cluster-snapshot", "rds:db", "rds:snapshot"],
        "redshift": ["redshift:cluster", "redshift:snapshot"],
        "s3": ["s3:bucket"],
    }

    if os.environ.get("ALLOWED_REGIONS"):
        allowed_regions = os.environ.get("ALLOWED_REGIONS").split(",")
        if allowed_regions == [""]:
            allowed_regions == ["ca-central-1", "ca-west-1"]
    else:
        allowed_regions = ["ca-central-1", "ca-west-1"]

    complianceStatus = "NOT_APPLICABLE"
    annotation = ""
    aws_config_client = get_client("config", aws_account_id, execution_role_name)
    aws_ec2_client = get_client("ec2", aws_account_id, execution_role_name)
    aws_resource_explorer_client = get_client("resource-explorer-2", aws_account_id, execution_role_name)
    aws_s3_client = get_client("s3", aws_account_id, execution_role_name)

    # Check cloud profile
    tags = get_account_tags(get_client("organizations", assume_role=False), aws_account_id)
    cloud_profile = get_cloud_profile_from_tags(tags)
    gr_requirement_type = check_guardrail_requirement_by_cloud_usage_profile(GuardrailType.Guardrail5, cloud_profile)

    # If the guardrail is recommended
    if gr_requirement_type == GuardrailRequirementType.Recommended:
        return submit_evaluations(
            aws_config_client,
            event,
            [build_evaluation(aws_account_id, "COMPLIANT", event, gr_requirement_type=gr_requirement_type)],
        )
    # If the guardrail is not required
    elif gr_requirement_type == GuardrailRequirementType.Not_Required:
        return submit_evaluations(
            aws_config_client,
            event,
            [build_evaluation(aws_account_id, "NOT_APPLICABLE", event, gr_requirement_type=gr_requirement_type)],
        )

    EnabledRegionsList = get_enabled_regions(aws_ec2_client)
    logger.info("Regions enabled or that do not require opt-in: {}".format(EnabledRegionsList))
    UnauthorizedRegionsList = []
    for region in EnabledRegionsList:
        if region not in allowed_regions:
            UnauthorizedRegionsList.append(region)
    logger.debug("UnauthorizedRegionsList: {}".format(UnauthorizedRegionsList))
    asea_resource_arns = get_asea_tagged_resource_arns(
        aws_account_id, execution_role_name, UnauthorizedRegionsList, unauthorized_resource_types
    )
    UnauthorizedResourceList = {}
    for region in UnauthorizedRegionsList:
        TempList = []
        TempList = get_non_authorized_resources_in_region(
            unauthorized_resource_types,
            aws_resource_explorer_to_config_resource_types,
            aws_resource_explorer_client,
            aws_account_id,
            execution_role_name,
            region,
            event,
            interval_between_api_calls,
            page_size,
        )
        if TempList:
            UnauthorizedResourceList.update({region: TempList})
    S3UnauthorizedResourceList = get_s3_resources(aws_s3_client, UnauthorizedRegionsList)
    if S3UnauthorizedResourceList:
        for region in S3UnauthorizedResourceList.keys():
            if UnauthorizedResourceList.get(region):
                UnauthorizedResourceList[region].extend(S3UnauthorizedResourceList[region])
            else:
                UnauthorizedResourceList[region] = S3UnauthorizedResourceList[region]
    bOneNonCompliantResourceReported = False
    if UnauthorizedResourceList:
        for region in UnauthorizedResourceList.keys():
            for resource in UnauthorizedResourceList.get(region):
                if is_allow_listed_resource(resource.get("Id", ""), resource.get("Arn", ""), asea_resource_arns):
                    complianceStatus = "COMPLIANT"
                    annotation = "Allow listed resource found in unauthorized region - {}".format(region)
                else:
                    bOneNonCompliantResourceReported = True
                    complianceStatus = "NON_COMPLIANT"
                    annotation = "Resource found in unauthorized region - {}".format(region)
                evaluations.append(
                    build_evaluation(
                        resource.get("Id", resource.get("Arn", "")),
                        complianceStatus,
                        event,
                        resource.get("ResourceType", ""),
                        annotation,
                    )
                )

    if bOneNonCompliantResourceReported:
        complianceStatus = "NON_COMPLIANT"
        annotation = "Resources found in unauthorized regions."
        evaluations.append(build_evaluation(aws_account_id, complianceStatus, event, annotation=annotation))
    else:
        complianceStatus = "COMPLIANT"
        annotation = "No resources found in unauthorized regions."
        evaluations.append(build_evaluation(aws_account_id, complianceStatus, event, annotation=annotation))

    logger.info(f"{complianceStatus}: {annotation}")
    submit_evaluations(aws_config_client, event, evaluations)