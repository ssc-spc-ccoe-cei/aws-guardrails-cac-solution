""" GC05 - Check Data Location
    https://canada-ca.github.io/cloud-guardrails/EN/05_Data-Location.html
"""
import botocore
import boto3
import logging
import json
import os
import sys
import re
import time

os.system("pip3 install --target /tmp boto3")
sys.path.insert(0, '/tmp/')
ASSUME_ROLE_MODE = True
DEFAULT_RESOURCE_TYPE = 'AWS::::Account'


def get_client(service, event, region="ca-central-1"):
    """Return the service boto client. It should be used instead of directly calling the client.
    Keyword arguments:
    service -- the service name used for calling the boto.client()
    event -- the event variable given in the lambda handler
    """
    if not ASSUME_ROLE_MODE:
        return boto3.client(service, region_name=region)
    execution_role_arn = f"arn:aws:iam::{AWS_ACCOUNT_ID}:role/{EXECUTION_ROLE_NAME}"
    credentials = get_assume_role_credentials(execution_role_arn, region)
    return boto3.client(
        service,
        region_name=region,
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


def evaluate_parameters(rule_parameters):
    """Evaluate the rule parameters dictionary.
    Keyword arguments:
    rule_parameters -- the Key/Value dictionary of the Config rule parameters
    """
    return rule_parameters

def get_enabled_regions():
    """Get the list of enabled regions
    Returns:
    List of enabled regions
    """
    result = []
    try:
        response = AWS_EC2_CLIENT.describe_regions(
            DryRun=False,
            AllRegions=True
        )
    except botocore.exceptions.ClientError as ex:
        if 'UnauthorizedOperation' in ex.response['Error']['Code']:
            logger.error('UnauthorizedOperation when trying to describe regions (EC2)')
        logger.error('Unable to describe regions.')
        raise ex
    for region in response.get('Regions'):
        if region.get('OptInStatus') != 'not-opted-in':
            result.append(region.get('RegionName'))
    return result


def is_allow_listed_resource(resourceName, resourceArn):
    """Assesses whether the resource is to be allow listed
    Returns True if it should be allow listed
    """
    bAllowList = False
    ALLOWLIST_REGEX_RULES = [
        ".*asea-.*",
        ".*pbmm-.*",
        "^awscfncli-.+",
        "^awsconfigconforms-.+",
        "^cf-templates.+"
    ]
    ALLOWLIST_REGEX = '(?:% s)' % '|'.join(ALLOWLIST_REGEX_RULES)
    if re.match(ALLOWLIST_REGEX, resourceName.lower()) or (resourceArn in ASEA_RESOURCE_ARNS):
        logger.info("Resource '{}' meets requirements for allow listing.".format(resourceName))
        bAllowList = True
    return bAllowList


def arex_get_indexes(arex_client, index_type=None):
    index_list = []
    arex_paginator = arex_client.get_paginator('list_indexes')
    if not index_type:
        arex_index_list = arex_paginator.paginate(PaginationConfig={'MaxItems': PAGE_SIZE})
    else:
        arex_index_list = arex_paginator.paginate(
            Type=index_type, PaginationConfig={'MaxItems': PAGE_SIZE})
    for page in arex_index_list:
        index_list.extend(page['Indexes'])
        time.sleep(INTERVAL_BETWEEN_API_CALLS)
    return index_list


def parse_resource_explorer_result(Resources=[], Service=''):
    results = []
    if not Resources or not Service:
        logger.error('Empty Resources result provided to parse_resource_explorer_result call.')
        return None
    elif not Service:
        logger.error('Empty Service name provided to parse_resource_explorer_result call.')
        return None
    Service = Service.lower()
    if Service in UNAUTHORIZED_RESOURCE_TYPES.keys():
        logger.debug("parse_resource_explorer_result - Service '{}' is of interest".format(Service))
        for resource in Resources:
            resource_arn = resource.get('Arn')
            resource_id = resource.get('Id')
            resource_service = resource.get('Service').lower()
            resource_type = resource.get('ResourceType').lower()
            logger.debug("parse_resource_explorer_result\n  Resource ARN '{}'\n  Service: '{}'\n  Type '{}'".format(resource_arn, resource_service, resource_type))
            if resource_type in UNAUTHORIZED_RESOURCE_TYPES.get(Service):
                if AWS_RESOURCE_EXPLORER_TO_CONFIG_RESOURCE_TYPES.get(resource_type, None):
                    logger.debug("*** RESOURCE IS OF UNAUTHORIZED TYPE")
                    results.append(
                        {
                            'Arn': resource_arn,
                            'Id': resource_id,
                            'ResourceType': AWS_RESOURCE_EXPLORER_TO_CONFIG_RESOURCE_TYPES.get(resource_type, '')
                        }
                    )
                else:
                    logger.debug('Ignoring resource {} as it is not a supported AWS Config Resource Type'.format(resource_arn))
            else:
                logger.debug("'{}' not an unauthorized resource type.".format(resource_arn))
    else:
        logger.info("Service '{}' not in the list of NonAuthorizedServices. Returning empty results.")
    return results


def get_qldb_resources(RegionName=None, event=None):
    """
    Finds Ledger Database (QLDB) resources in the specified region
    """
    results = []
    AWS_QLDB_CLIENT = get_client('qldb', event, region=RegionName)
    NextToken = ''
    ResourceType = 'AWS::QLDB::Ledger'
    try:
        response = AWS_QLDB_CLIENT.list_ledgers()
        while True:
            if response:
                for ledger in response.get('Ledgers'):
                    response2 = AWS_QLDB_CLIENT.describe_ledger(
                        Name=ledger.get('Name')
                    )
                    if response2:
                        results.append(
                            {
                                'Arn': response2.get('Arn'),
                                'Id': response2.get('Name'),
                                'ResourceType': ResourceType
                            }
                        )
                    else:
                        logger.info("Unable to describe_ledger '{}'".format(ledger.get('Name')))
                NextToken = response.get('NextToken')
                if NextToken:
                    response = AWS_QLDB_CLIENT.list_ledgers(NextToken=NextToken)
                else:
                    break
            else:
                break
    except botocore.exceptions.EndpointConnectionError as ex:
        logger.debug('QLDB endpoint not available in the region {}'.format(RegionName))
        pass
    except botocore.exceptions.ClientError as ex:
        if 'AccessDenied' in ex.response['Error']['Code']:
            logger.error('AccessDenied when trying to list_ledgers or describe_ledger - get_qldb_resources')
            pass
        else:
            raise ex
    return results


def get_s3_resources(event=None, UnauthorizedRegionsList=[]):
    """
    Finds Amazon S3 resources in the specified region
    """
    results = {}
    AWS_S3_CLIENT = get_client('s3', event)
    ResourceType = 'AWS::S3::Bucket'
    try:
        response = AWS_S3_CLIENT.list_buckets()
        if response:
            for bucket in response.get('Buckets'):
                bucket_name = bucket.get('Name')
                bucket_arn = "arn:aws:s3:::{}".format(bucket_name)
                response2 = AWS_S3_CLIENT.get_bucket_location(
                    Bucket=bucket_name)
                if response2:
                    LocationConstraint = response2.get('LocationConstraint')
                    if LocationConstraint:
                        if LocationConstraint in UnauthorizedRegionsList:
                            if results.get(LocationConstraint):
                                results[LocationConstraint].append(
                                    {
                                        'Arn': bucket_arn,
                                        'Id': bucket.get('Name'),
                                        'ResourceType': ResourceType
                                    }
                                )
                            else:
                                results[LocationConstraint] = [
                                    {
                                        'Arn': bucket_arn,
                                        'Id': bucket.get('Name'),
                                        'ResourceType': ResourceType
                                    }
                                ]
                    else:
                        if results.get('global'):
                            results['global'].append(
                                {
                                    'Arn': bucket_arn,
                                    'Id': bucket.get('Name'),
                                    'ResourceType': ResourceType
                                }
                            )
                        else:
                            results['global'] = [
                                {
                                    'Arn': bucket_arn,
                                    'Id': bucket.get('Name'),
                                    'ResourceType': ResourceType
                                }
                            ]
                else:
                    logger.info("Unable to get_bucket_location '{}'".format(bucket_name))
        else:
            logger.info("Unable to list buckets")
    except botocore.exceptions.ClientError as ex:
        if 'AccessDenied' in ex.response['Error']['Code']:
            logger.error('AccessDenied when trying to list_buckets or get_bucket_location - get_s3_resources')
            pass
        else:
            raise ex
    return results


def get_non_authorized_resources_in_region(RegionName=None, event=None):
    results = []
    if not RegionName:
        logger.error(
            'Empty region provided for get_non_authorized_resources_in_region call.')
        return None
    bResourceExplorerAvailable = False
    ResourceExplorerIndexRegion = RegionName
    try:
        resource_explorer_indexes = arex_get_indexes(
            AWS_RESOURCEEXPLORER_CLIENT, "AGGREGATOR")
        if resource_explorer_indexes:
            ResourceExplorerIndexRegion = resource_explorer_indexes[0].get(
                'Region', '')
            bResourceExplorerAvailable = True
        else:
            resource_explorer_indexes = arex_get_indexes(
                AWS_RESOURCEEXPLORER_CLIENT, index_type=None)
            for index in resource_explorer_indexes:
                if index.get('Region', '') == RegionName:
                    ResourceExplorerIndexRegion == RegionName
                    bResourceExplorerAvailable = True
                    break
    except botocore.exceptions.ClientError as ex:
        logger.error('Error trying to list_indexes for Resource Explorer: {}'.format(ex))
        pass
    for service in UNAUTHORIZED_RESOURCE_TYPES.keys():
        query_string = 'service:{} region:{}'.format(
            service, ResourceExplorerIndexRegion)
        ResourceList = []
        TempResources = []
        if service == 'qldb':
            ResourceList = get_qldb_resources(RegionName, event=event)
        elif service == 's3':
            continue
        else:
            if not bResourceExplorerAvailable:
                logger.info('Skipping service {} in region {} as Resource Explorer is not available.'.format(service, RegionName))
                continue
            try:
                response = AWS_RESOURCEEXPLORER_CLIENT.search(
                    QueryString=query_string,
                )
                if response:
                    if response.get('Count').get('Complete') == False and response.get('Count').get('TotalResources') == 1000:
                        logger.error(
                            "Resource Explorer search limit reached when trying to query region '{}' for service '{}'. More than 1000 resources")
                        TempResources = response.get('Resources')
                        if TempResources:
                            logger.debug("'{}' resources found".format(len(TempResources)))
                            logger.debug(TempResources)
                            ResourceList.extend(parse_resource_explorer_result(
                                Resources=TempResources, Service=service))
                        continue
                    else:
                        TempResources = response.get('Resources')
                        if TempResources:
                            logger.debug("'{}' resources found".format(len(TempResources)))
                            logger.debug(TempResources)
                            ResourceList.extend(parse_resource_explorer_result(
                                Resources=TempResources, Service=service))
                        NextToken = response.get('NextToken')
                        while NextToken:
                            response = AWS_RESOURCEEXPLORER_CLIENT.search(
                                QueryString=query_string,
                                NextToken=NextToken
                            )
                            if response:
                                ResourceList.extend(parse_resource_explorer_result(
                                    Resources=response.get('Resources'), Service=service))
                                NextToken = response.get('NextToken')
            except botocore.exceptions.ClientError as ex:
                if 'UnauthorizedException' in ex.response['Error']['Code']:
                    logger.info("UnauthorizedException when trying to use Resource Explorer in region '{}'".format(RegionName))
                    pass
                else:
                    raise ex
        if ResourceList:
            results.extend(ResourceList)
    return results


def build_evaluation(resource_id, compliance_type, event, resource_type=DEFAULT_RESOURCE_TYPE, annotation=None):
    """Form an evaluation as a dictionary. Usually suited to report on scheduled rules.
    Keyword arguments:
    resource_id -- the unique id of the resource to report
    compliance_type -- either COMPLIANT, NON_COMPLIANT or NOT_APPLICABLE
    event -- the event variable given in the lambda handler
    resource_type -- the CloudFormation resource type (or AWS::::Account) to report on the rule (default DEFAULT_RESOURCE_TYPE)
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


def get_asea_tagged_resource_arns(unauthorized_region_list: list, event: dict):
    result = []
    tag_filters = [
        {
            'Key': 'Accelerator',
            'Values': [
                'ASEA',
                'PBMM'
            ]
        }
    ]
    resource_type_filters = []
    for service in UNAUTHORIZED_RESOURCE_TYPES.keys():
        resource_type_filters.extend(UNAUTHORIZED_RESOURCE_TYPES.get(service))
    for region in unauthorized_region_list:
        try:
            AWS_RESOURCEGROUPSTAGGINGAPI_CLIENT = get_client(
                'resourcegroupstaggingapi', event, region)
            response = AWS_RESOURCEGROUPSTAGGINGAPI_CLIENT.get_resources(
                ResourceTypeFilters=resource_type_filters,
                TagFilters=tag_filters,
            )
            bMoreData = True
            while bMoreData:
                if response:
                    for resource in response.get('ResourceTagMappingList'):
                        result.append(resource.get('ResourceARN'))
                    if response.get('PaginationToken'):
                        response = AWS_RESOURCEGROUPSTAGGINGAPI_CLIENT.get_resources(
                            PaginationToken=response.get('PaginationToken'),
                            ResourceTypeFilters=resource_type_filters,
                            TagFilters=tag_filters,
                        )
                    else:
                        bMoreData = False
        except botocore.exceptions.ClientError as ex:
            logger.error('Failed to get_asea_tagged_resource_arns with exception {}'.format(ex))
            pass
    return result


def lambda_handler(event, context):
    global logger
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    global AWS_CONFIG_CLIENT
    global AWS_S3_CLIENT
    global AWS_EC2_CLIENT
    global AWS_RESOURCEEXPLORER_CLIENT
    global ALLOWED_REGIONS
    global UNAUTHORIZED_RESOURCE_TYPES
    global AWS_RESOURCE_EXPLORER_TO_CONFIG_RESOURCE_TYPES
    global AWS_ACCOUNT_ID
    global EXECUTION_ROLE_NAME
    global AUDIT_ACCOUNT_ID
    global ASEA_RESOURCE_ARNS
    global PAGE_SIZE
    global INTERVAL_BETWEEN_API_CALLS
    PAGE_SIZE = 25
    INTERVAL_BETWEEN_API_CALLS = 0.05
    AWS_RESOURCE_EXPLORER_TO_CONFIG_RESOURCE_TYPES = {
        'ec2:instance': 'AWS::EC2::Instance',
        'ec2:dedicated-host': 'AWS::EC2::Host',
        'ec2:volume': 'AWS::EC2::Volume',
        'dynamodb:table': 'AWS::DynamoDB::Table',
        'ecs:cluster': 'AWS::ECS::Cluster',
        'ecs:service': 'AWS::ECS::Service',
        'ecs:task-definition': 'AWS::ECS::TaskDefinition',
        'lambda:function': 'AWS::Lambda::Function',
        'qldb:ledger': 'AWS::QLDB::Ledger',
        'rds:cluster': 'AWS::RDS::DBCluster',
        'rds:cluster-snapshot': 'AWS::RDS::DBClusterSnapshot',
        'rds:db': 'AWS::RDS::DBInstance',
        'rds:snapshot': 'AWS::RDS::DBSnapshot',
        'redshift:cluster': 'AWS::Redshift::Cluster',
        'redshift:snapshot': 'AWS::Redshift::ClusterSnapshot',
        's3:bucket': 'AWS::S3::Bucket',
    }
    UNAUTHORIZED_RESOURCE_TYPES = {
        'ec2': [
            'ec2:instance',
            'ec2:dedicated-host',
            'ec2:volume'
        ],
        'dynamodb': [
            'dynamodb:table'
        ],
        'ecs': [
            'ecs:cluster',
            'ecs:service',
            'ecs:task-definition'
        ],
        'qldb': [
            'qldb:ledger'
        ],
        'rds': [
            'rds:cluster',
            'rds:cluster-snapshot',
            'rds:db',
            'rds:snapshot'
        ],
        'redshift': [
            'redshift:cluster',
            'redshift:snapshot'
        ],
        's3': [
            's3:bucket'
        ]
    }
    if os.environ.get('ALLOWED_REGIONS'):
        ALLOWED_REGIONS = os.environ.get('ALLOWED_REGIONS').split(',')
        if ALLOWED_REGIONS == ['']:
            ALLOWED_REGIONS == ['ca-central-1']
    else:
        ALLOWED_REGIONS = ['ca-central-1']
    evaluations = []
    rule_parameters = {}
    invoking_event = json.loads(event['invokingEvent'])
    AWS_ACCOUNT_ID = event['accountId']
    if 'ruleParameters' in event:
        rule_parameters = json.loads(event['ruleParameters'])
    valid_rule_parameters = evaluate_parameters(rule_parameters)
    if 'ExecutionRoleName' in valid_rule_parameters:
        EXECUTION_ROLE_NAME = valid_rule_parameters['ExecutionRoleName']
    else:
        EXECUTION_ROLE_NAME = 'SSCGCLambdaExecutionRole'
    if 'AuditAccountID' in valid_rule_parameters:
        AUDIT_ACCOUNT_ID = valid_rule_parameters['AuditAccountID']
    else:
        AUDIT_ACCOUNT_ID = ''
    complianceStatus = 'NOT_APPLICABLE'
    complianceAnnotation = ''
    AWS_CONFIG_CLIENT = get_client('config', event)
    AWS_EC2_CLIENT = get_client('ec2', event)
    AWS_RESOURCEEXPLORER_CLIENT = get_client('resource-explorer-2', event)
    if is_scheduled_notification(invoking_event['messageType']):
        EnabledRegionsList = get_enabled_regions()
        logger.info('Regions enabled or that do not require opt-in: {}'.format(EnabledRegionsList))
        UnauthorizedRegionsList = []
        for region in EnabledRegionsList:
            if region not in ALLOWED_REGIONS:
                UnauthorizedRegionsList.append(region)
        logger.debug("UnauthorizedRegionsList: {}".format(UnauthorizedRegionsList))
        ASEA_RESOURCE_ARNS = get_asea_tagged_resource_arns(
            UnauthorizedRegionsList, event)
        UnauthorizedResourceList = {}
        for region in UnauthorizedRegionsList:
            TempList = []
            TempList = get_non_authorized_resources_in_region(
                RegionName=region, event=event)
            if TempList:
                UnauthorizedResourceList.update({
                    region: TempList
                })
        S3UnauthorizedResourceList = get_s3_resources(
            event, UnauthorizedRegionsList)
        if S3UnauthorizedResourceList:
            for region in S3UnauthorizedResourceList.keys():
                if UnauthorizedResourceList.get(region):
                    UnauthorizedResourceList[region].extend(
                        S3UnauthorizedResourceList[region])
                else:
                    UnauthorizedResourceList[region] = S3UnauthorizedResourceList[region]
        if UnauthorizedResourceList:
            bOneNonCompliantResourceReported = False
            for region in UnauthorizedResourceList.keys():
                for resource in UnauthorizedResourceList.get(region):
                    if is_allow_listed_resource(resource.get('Id', ''), resource.get('Arn', '')):
                        complianceStatus = 'COMPLIANT'
                        complianceAnnotation = "Allow listed resource found in unauthorized region - {}".format(region)
                    else:
                        bOneNonCompliantResourceReported = True
                        complianceStatus = 'NON_COMPLIANT'
                        complianceAnnotation = "Resource found in unauthorized region - {}".format(region)
                    evaluations.append(
                        build_evaluation(
                            resource.get('Id', resource.get('Arn', '')),
                            complianceStatus,
                            event,
                            resource.get('ResourceType', ''),
                            annotation=complianceAnnotation
                        )
                    )
            if bOneNonCompliantResourceReported:
                complianceStatus = 'NON_COMPLIANT'
                complianceAnnotation = 'Resources found in unauthorized regions.'
                evaluations.append(
                    build_evaluation(
                        event['accountId'],
                        complianceStatus,
                        event,
                        resource_type=DEFAULT_RESOURCE_TYPE,
                        annotation=complianceAnnotation
                    )
                )
        else:
            complianceStatus = 'COMPLIANT'
            complianceAnnotation = 'No resources found in unauthorized regions.'
            evaluations.append(build_evaluation(event['accountId'], complianceStatus, event, resource_type=DEFAULT_RESOURCE_TYPE, annotation=complianceAnnotation))
        
        number_of_evaluations = len(evaluations)
        if number_of_evaluations > 0:
            MAX_EVALUATIONS_PER_CALL = 100
            rounds = number_of_evaluations // MAX_EVALUATIONS_PER_CALL
            logger.info('Reporting {} evaluations in {} rounds.'.format(number_of_evaluations, rounds+1))
            if number_of_evaluations > MAX_EVALUATIONS_PER_CALL:
                for round in range(rounds):
                    start = round * MAX_EVALUATIONS_PER_CALL
                    end = ((round+1) * MAX_EVALUATIONS_PER_CALL)
                    response = AWS_CONFIG_CLIENT.put_evaluations(Evaluations=evaluations[start:end], ResultToken=event['resultToken'])
                    time.sleep(0.3)
                start = end
                end = number_of_evaluations
                response = AWS_CONFIG_CLIENT.put_evaluations(
                    Evaluations=evaluations[start:end], ResultToken=event['resultToken'])
            else:
                response = AWS_CONFIG_CLIENT.put_evaluations(Evaluations=evaluations, ResultToken=event['resultToken'])
        
    else:
        logger.info('Invokation was not part of schedule. Skipping checks.')
