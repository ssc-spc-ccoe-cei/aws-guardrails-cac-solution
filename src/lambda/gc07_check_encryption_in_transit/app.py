""" GC07 - Check Encryption in Transit
    https://canada-ca.github.io/cloud-guardrails/EN/07_Protect-Data-in-Transit.html
"""
import json
import logging
import time

import boto3
import botocore

ASSUME_ROLE_MODE = True
DEFAULT_RESOURCE_TYPE = "AWS::::Account"


def assess_s3_buckets_ssl_enforcement(event=None):
    """
    Finds Amazon S3 resources that do not have a bucket policy restricting SSL access
    """
    local_evaluations = []
    condition_criteria = {"Bool": {"aws:SecureTransport": "false"}}
    resource_type = "AWS::S3::Bucket"
    try:
        response = AWS_S3_CLIENT.list_buckets()
        if response:
            for bucket in response.get("Buckets"):
                bucket_name = bucket.get("Name")
                bucket_arn = f"arn:aws:s3:::{bucket_name}"
                compliance_status = ""
                compliance_annotation = ""
                b_policy_match = False
                bucket_policy = {}
                i_retries = 0
                b_success = False
                while (not b_success) and (i_retries < MAXIMUM_API_RETRIES):
                    try:
                        response2 = AWS_S3_CLIENT.get_bucket_policy(Bucket=bucket.get("Name"))
                        if response2:
                            bucket_policy = json.loads(response2.get("Policy"))
                        else:
                            logger.info("Unable to get_bucket_policy '%s'", bucket.get("Name"))
                        b_success = True
                        time.sleep(INTERVAL_BETWEEN_API_CALLS)
                    except botocore.exceptions.ClientError as ex:
                        i_retries += 1
                        if "NoSuchBucketPolicy" in ex.response["Error"]["Code"]:
                            logger.info("Bucket %s has no policy", bucket_name)
                            compliance_annotation = "No bucket policy. SSL not enforced."
                            b_success = True
                        elif is_throttling_exception(ex):
                            logger.error("S3 - Throttling while calling get_bucket_policy")
                            time.sleep(THROTTLE_BACKOFF)
                        else:
                            logger.error("S3 - Error while calling get_bucket_policy for bucket %s ---> %s", bucket.get("Name", ""), ex)
                if bucket_policy:
                    for statement in bucket_policy.get("Statement"):
                        statement_condition = statement.get("Condition")
                        statement_effect = statement.get("Effect")
                        statement_principal = statement.get("Principal")
                        statement_action = statement.get("Action")
                        if (
                            (statement_condition == condition_criteria)
                            and (statement_effect == "Deny")
                            and ((statement_principal == "*") or statement_principal.get("AWS") == "*")
                            and (statement_action == "s3:*")
                        ):
                            logger.info("Bucket '%s' has SSL enforced for all S3 actions", bucket_name)
                            b_policy_match = True
                            compliance_status = "COMPLIANT"
                            compliance_annotation = "SSL enforced"
                            break
                if not b_policy_match:
                    compliance_status = "NON_COMPLIANT"
                    if not compliance_annotation:
                        compliance_annotation = "SSL not enforced"
                local_evaluations.append(
                    build_evaluation(
                        bucket_arn,
                        compliance_status,
                        event,
                        resource_type,
                        annotation=compliance_annotation,
                    )
                )
        else:
            logger.info("Unable to list buckets")
    except botocore.exceptions.ClientError as ex:
        if "AccessDenied" in ex.response["Error"]["Code"]:
            logger.error("AccessDenied when trying to list_buckets - get_s3_resources: %s", ex)
        else:
            logger.error("S3 - Error while calling list_buckets %s", ex)
    logger.info("S3 - reporting %s evaluations.", len(local_evaluations))
    return local_evaluations


def assess_redshift_clusters_ssl_enforcement(event=None):
    """
    Finds Amazon Redshift clusters that do not have a cluster policy restricting SSL access
    """
    clusters = []
    local_evaluations = []
    try:
        response = AWS_REDSHIFT_CLIENT.describe_clusters(MaxRecords=PAGE_SIZE)
        b_more_data = True
        i_retries = 0
        while b_more_data and i_retries < MAXIMUM_API_RETRIES:
            if response:
                next_marker = response.get("Marker", "")
                for cluster in response.get("Clusters", []):
                    parameter_group_names = []
                    for parameter_group in cluster.get("ClusterParameterGroups", []):
                        parameter_group_names.append(
                            parameter_group.get("ParameterGroupName")
                        )
                    clusters.append(
                        {
                            "ClusterIdentifier": cluster.get("ClusterIdentifier"),
                            "ClusterParameterGroups": parameter_group_names,
                        }
                    )
                logger.info("%s Redshift clusters found.", len(clusters))
                if next_marker:
                    time.sleep(INTERVAL_BETWEEN_API_CALLS)
                    try:
                        response = AWS_REDSHIFT_CLIENT.describe_clusters(
                            MaxRecords=PAGE_SIZE,
                            Marker=next_marker
                        )
                    except botocore.exceptions.ClientError as ex:
                        i_retries += 1
                        if is_throttling_exception(ex):
                            logger.error("Redshift - Throttling while calling describe_clusters")
                            time.sleep(THROTTLE_BACKOFF)
                        else:
                            logger.error("Redshift - Error while trying to describe_clusters.%s", ex)
                            raise ex
                else:
                    b_more_data = False
            else:
                logger.error("Redshift - Empty response while trying to describe_clusters")
                b_more_data = False
    except botocore.exceptions.ClientError as ex:
        logger.error("Redshift - Error while trying to describe_clusters. %s", ex)
        raise ex
    for cluster in clusters:
        b_require_ssl = False
        for parameter_group_name in cluster.get("ClusterParameterGroups"):
            try:
                next_marker = ""
                response = AWS_REDSHIFT_CLIENT.describe_cluster_parameters(
                    ParameterGroupName=parameter_group_name,
                    MaxRecords=PAGE_SIZE
                )
                b_more_data = True
                i_retries = 0
                while (b_more_data and (i_retries < MAXIMUM_API_RETRIES) and (not b_require_ssl)):
                    if response:
                        next_marker = response.get("Marker", "")
                        for parameter in response.get("Parameters", []):
                            if parameter.get("ParameterName") == "require_ssl":
                                if (parameter.get("ParameterValue", "").lower() == "true"):
                                    b_require_ssl = True
                                    break
                            else:
                                continue
                        if next_marker and (not b_require_ssl):
                            time.sleep(INTERVAL_BETWEEN_API_CALLS)
                            try:
                                response = (
                                    AWS_REDSHIFT_CLIENT.describe_cluster_parameters(
                                        ParameterGroupName=parameter_group_name,
                                        MaxRecords=PAGE_SIZE,
                                        Marker=next_marker,
                                    )
                                )
                            except botocore.exceptions.ClientError as ex:
                                i_retries += 1
                                if is_throttling_exception(ex):
                                    logger.error("Redshift - Throttling while calling describe_cluster_parameters")
                                    time.sleep(THROTTLE_BACKOFF)
                                else:
                                    logger.error("Redshift - Error while trying to describe_cluster_parameters. %s", ex)
                                    raise ex
                        else:
                            b_more_data = False
                    else:
                        logger.error("Redshift - Empty response while trying to describe_cluster_parameters")
                        b_more_data = False
                if b_require_ssl:
                    logger.info("Redshift cluster %s has require_ssl enforced.", cluster.get("ClusterIdentifier", ""))
                    break
            except botocore.exceptions.ClientError as ex:
                logger.error("Redshift - Error while trying to describe_cluster_parameters. %s", ex)
                raise ex
        if b_require_ssl:
            compliance_status = "COMPLIANT"
            compliance_annotation = "SSL required"
        else:
            logger.info("Redshift cluster %s DOES NOT require_ssl.", cluster.get("ClusterIdentifier", ""))
            compliance_status = "NON_COMPLIANT"
            compliance_annotation = "require_ssl not set to true"
        local_evaluations.append(
            build_evaluation(
                cluster.get("ClusterIdentifier", ""),
                compliance_status,
                event,
                "AWS::Redshift::Cluster",
                annotation=compliance_annotation,
            )
        )
    logger.info("Redshift - reporting %s evaluations.", len(local_evaluations))
    return local_evaluations


def assess_elbv2_ssl_enforcement(event=None):
    """
    Evaluate whether SSL is enforced on ELBv2.
    """
    local_evaluations = []
    load_balancers = []
    try:
        response = AWS_ELBV2_CLIENT.describe_load_balancers(PageSize=PAGE_SIZE)
        b_more_data = True
        i_retries = 0
        while b_more_data and i_retries < MAXIMUM_API_RETRIES:
            if response:
                next_marker = response.get("Marker", "")
                for load_balancer in response.get("LoadBalancers", []):
                    load_balancers.append(
                        {
                            "LoadBalancerArn": load_balancer.get("LoadBalancerArn"),
                            "LoadBalancerName": load_balancer.get("LoadBalancerName"),
                        }
                    )
                if next_marker:
                    time.sleep(INTERVAL_BETWEEN_API_CALLS)
                    try:
                        response = AWS_ELBV2_CLIENT.describe_load_balancers(
                            PageSize=PAGE_SIZE, Marker=next_marker
                        )
                    except botocore.exceptions.ClientError as ex:
                        i_retries += 1
                        if is_throttling_exception(ex):
                            logger.error("ELBv2 - Throttling while calling describe_load_balancers")
                            time.sleep(THROTTLE_BACKOFF)
                        else:
                            logger.error("ELBv2 - Error while trying to describe_load_balancers. %s", ex)
                            raise ex
                else:
                    b_more_data = False
            else:
                logger.error("ELBv2 - Empty response while trying to describe_load_balancers")
                b_more_data = False
    except botocore.exceptions.ClientError as ex:
        logger.error("ELBv2 - Error while trying to describe_load_balancers. %s", ex)
        raise ex
    logger.info("%s ELBv2 Load balancers found.", len(load_balancers))
    for load_balancer in load_balancers:
        next_marker = ""
        try:
            response = AWS_ELBV2_CLIENT.describe_listeners(
                LoadBalancerArn=load_balancer.get("LoadBalancerArn", ""),
                PageSize=PAGE_SIZE,
            )
            b_more_data = True
            i_retries = 0
            while b_more_data and (i_retries < MAXIMUM_API_RETRIES):
                if response:
                    next_marker = response.get("Marker", "")
                    for listener in response.get("Listeners", []):
                        listener_compliance = ""
                        listener_annotation = ""
                        listener_protocol = listener.get("Protocol", "")
                        if listener_protocol.lower() not in ["https", "tls"]:
                            listener_compliance = "NON_COMPLIANT"
                            listener_annotation = (
                                "Non HTTPS/TLS listener protocol - %s",
                                listener_protocol,
                            )
                        else:
                            listener_compliance = "COMPLIANT"
                            listener_annotation = "All listeners leverage HTTPS/TLS"
                        local_evaluations.append(
                            build_evaluation(
                                listener.get("ListenerArn", ""),
                                listener_compliance,
                                event,
                                "AWS::ElasticLoadBalancingV2::Listener",
                                annotation=listener_annotation,
                            )
                        )
                    if next_marker:
                        time.sleep(INTERVAL_BETWEEN_API_CALLS)
                        try:
                            response = AWS_ELBV2_CLIENT.describe_listeners(
                                LoadBalancerArn=load_balancer.get("LoadBalancerArn", ""),
                                PageSize=PAGE_SIZE,
                                Marker=next_marker,
                            )
                        except botocore.exceptions.ClientError as ex:
                            i_retries += 1
                            if is_throttling_exception(ex):
                                logger.error("ELBv2 - Throttling while calling describe_listeners")
                                time.sleep(THROTTLE_BACKOFF)
                            else:
                                logger.error("ELBv2 - Error while trying to describe_listeners. %s", ex)
                                raise ex
                    else:
                        b_more_data = False
                else:
                    logger.error("ELBv2 - Empty response on describe_listeners")
        except botocore.exceptions.ClientError as ex:
            i_retries += 1
            if is_throttling_exception(ex):
                logger.error("ELBv2 - Throttling while calling describe_listeners")
                time.sleep(THROTTLE_BACKOFF)
            else:
                logger.error("ELBv2 - Error while trying to describe_listeners. %s", ex)
                raise ex
    logger.info("ELBv2 - reporting %s evaluations.", len(local_evaluations))
    return local_evaluations


def assess_rest_api_stages_ssl_enforcement(event=None):
    """
    This function evaluates the SSL enforcement on the REST API Stages.
    """
    local_evaluations = []
    rest_apis = []
    resource_type = "AWS::ApiGateway::Stage"
    try:
        response = AWS_APIGW_CLIENT.get_rest_apis(limit=PAGE_SIZE)
        b_more_data = True
        i_retries = 0
        while b_more_data and i_retries < MAXIMUM_API_RETRIES:
            if response:
                position = response.get("position", "")
                for api in response.get("items", []):
                    api_id = api.get("id")
                    api_name = api.get("name")
                    if not api_id:
                        logger.error("Skipping Malformed API item %s", api)
                        continue
                    try:
                        api_resource_list = apigw_get_resources_list(
                            AWS_APIGW_CLIENT,
                            api_id
                        )
                    except botocore.exceptions.ClientError as error:
                        if error.response["Error"]["Code"] == "NotFoundException":
                            pass
                    if not api_resource_list:
                        logger.info("Skipping API - %s - as it has no resources.", api_name)
                        continue
                    AWS = False
                    HTTP = False
                    for item in api_resource_list:
                        if "id" in item and "resourceMethods" in item:
                            resource_id = item["id"]
                            method_types = item["resourceMethods"].keys()
                            for method_type in method_types:
                                try:
                                    integration_type = AWS_APIGW_CLIENT.get_integration(
                                        restApiId=api_id,
                                        resourceId=resource_id,
                                        httpMethod=method_type,
                                    )["type"]
                                except botocore.exceptions.ClientError as error:
                                    if (error.response["Error"]["Code"] == "NotFoundException"):
                                        integration_type = "None"
                                    else:
                                        raise error
                                if "HTTP" in integration_type:
                                    HTTP = True
                                if "AWS" in integration_type:
                                    AWS = True
                                time.sleep(THROTTLE_BACKOFF / 2)
                    try:
                        response2 = AWS_APIGW_CLIENT.get_deployments(
                            restApiId=api_id,
                            limit=PAGE_SIZE
                        )
                        i_retries2 = 0
                        b_more_data2 = True
                        while b_more_data2 and i_retries2 < MAXIMUM_API_RETRIES:
                            if response2:
                                position2 = response2.get("position")
                                deployments = response2.get("items", [])
                                if len(deployments) <= 0:
                                    logger.info("APIGW - Skipping API '%s' as it has no deployments", api_name)
                                    continue
                                for deployment in deployments:
                                    deployment_id = deployment.get("id", "")
                                    if not deployment_id:
                                        logger.error("Skipping Malformed Deployment in API %s: %s", api, deployment)
                                        continue
                                    try:
                                        response3 = AWS_APIGW_CLIENT.get_stages(
                                            restApiId=api_id,
                                            deploymentId=deployment_id
                                        )
                                        if response3:
                                            stages = response3.get("item")
                                            if len(stages) <= 0:
                                                logger.error("APIGW - No stages found for API %s and deployment ID %s", api_name, deployment_id)
                                                continue
                                            for stage in stages:
                                                client_certificate_id = stage.get("clientCertificateId", "")
                                                stage_name = stage.get("stageName", "")
                                                stage_resource_id = f"arn:aws:apigateway:ca-central-1::/apis/{api_id}/stages/{stage_name}"
                                                if client_certificate_id:
                                                    if HTTP or (HTTP and AWS):
                                                        compliance_status = "COMPLIANT"
                                                        compliance_annotation = "REST API Stage has a Certificate"
                                                    elif AWS:
                                                        compliance_status = "NOT_APPLICABLE"
                                                        compliance_annotation = "REST API stage has associated client certificate but lambda integration type."
                                                    else:
                                                        compliance_status = "NOT_APPLICABLE"
                                                        compliance_annotation = "REST API stage has an associated client certificate but no integration type."
                                                else:
                                                    if HTTP or (HTTP and AWS):
                                                        compliance_status = "NON_COMPLIANT"
                                                        compliance_annotation = "REST API stage does not have an associated client certificate and an HTTP integration type."
                                                    elif AWS:
                                                        compliance_status = "NOT_APPLICABLE"
                                                        compliance_annotation = "REST API stage does not have an associated client certificate and lambda integration type."
                                                    else:
                                                        compliance_status = "NOT_APPLICABLE"
                                                        compliance_annotation = "REST API stage does not have an associated client certificate or an integration type."
                                                local_evaluations.append(
                                                    build_evaluation(
                                                        stage_resource_id,
                                                        compliance_status,
                                                        event,
                                                        resource_type,
                                                        annotation=compliance_annotation,
                                                    )
                                                )
                                        else:
                                            logger.error("APIGW - Empty response on get_stages for API %s and deployment ID %s", api_name, deployment_id)
                                    except botocore.exceptions.ClientError as ex:
                                        logger.error("APIGW - Error while trying to get_stages for API %s and deployment ID %s.\n%s", api_name, deployment_id, ex)
                                        raise ex
                                if position2:
                                    time.sleep(INTERVAL_BETWEEN_API_CALLS)
                                    try:
                                        response2 = AWS_APIGW_CLIENT.get_deployments(
                                            restApiId=api_id,
                                            position=position2,
                                            limit=PAGE_SIZE,
                                        )
                                    except botocore.exceptions.ClientError as ex:
                                        i_retries2 += 1
                                        if is_throttling_exception(ex):
                                            logger.error("APIGW - Throttling while calling get_deployments")
                                            time.sleep(THROTTLE_BACKOFF)
                                        else:
                                            logger.error("APIGW - Error while trying to get_deployments. %s", ex)
                                            raise ex
                                else:
                                    b_more_data2 = False
                            else:
                                logger.error("APIGW - Empty response on call to get_deployments with API ID '%s'", api_name)
                                b_more_data2 = False
                    except botocore.exceptions.ClientError as ex:
                        i_retries += 1
                        if is_throttling_exception(ex):
                            logger.error("APIGW - Throttling while calling get_deployments")
                            time.sleep(THROTTLE_BACKOFF)
                        else:
                            logger.error("ELBv2 - Error while trying to get_deployments. %s", ex)
                            raise ex
                if position:
                    time.sleep(INTERVAL_BETWEEN_API_CALLS)
                    try:
                        response = AWS_APIGW_CLIENT.get_rest_apis(
                            position=position,
                            limit=PAGE_SIZE
                        )
                    except botocore.exceptions.ClientError as ex:
                        if is_throttling_exception(ex):
                            logger.error("APIGW - Throttling while calling get_rest_apis")
                            time.sleep(THROTTLE_BACKOFF)
                            i_retries += 1
                        else:
                            logger.error("APIGW - Error while trying to get_rest_apis.%s", ex)
                            raise ex
                else:
                    b_more_data = False
            else:
                logger.error("REST API - Empty response from get_rest_apis call")
                b_more_data = False
    except botocore.exceptions.ClientError as ex:
        logger.error("REST API - Error while trying to get_rest_apis - %s", ex)
        raise ex
    logger.info("APIGW - reporting %s evaluations.", len(local_evaluations))
    return local_evaluations


def assess_es_node_to_node_ssl_enforcement(event=None):
    """
    This function evaluates the Node to Node SSL Enforcement compliance
    for the AWS Elasticsearch Service.
    Args:
        event (dict): Lambda event object
    Returns:
        list: List of evaluation objects.
    """
    resource_type = "AWS::Elasticsearch::Domain"
    local_evaluations = []
    try:
        response = AWS_ES_CLIENT.list_domain_names()
        if response:
            for domain in response.get("DomainNames", []):
                time.sleep(INTERVAL_BETWEEN_API_CALLS)
                domain_name = domain.get("DomainName")
                if not domain_name:
                    logger.error("Malformed domain result - %s", domain)
                    continue
                response2 = AWS_ES_CLIENT.describe_elasticsearch_domains(
                    DomainNames=[domain_name]
                )
                if response2:
                    for domain_status in response2.get("DomainStatusList", []):
                        if (domain_status.get("NodeToNodeEncryptionOptions", {}).get("Enabled", "") == "True"):
                            compliance_status = "COMPLIANT"
                            compliance_annotation = "Node to Node Encryption enabled"
                        else:
                            compliance_status = "NON_COMPLIANT"
                            compliance_annotation = "Node to Node Encryption disabled"
                        resource_id = domain_status.get("ARN", "")
                        if not resource_id:
                            resource_id = domain_name
                        local_evaluations.append(
                            build_evaluation(
                                resource_id,
                                compliance_status,
                                event,
                                resource_type,
                                annotation=compliance_annotation,
                            )
                        )
                else:
                    logger.error("ES - Empty response on describe_elasticsearch_domains call.")
        else:
            logger.error("ES - Empty response on list_domain_names call.")
    except botocore.exceptions.ClientError as ex:
        logger.error("ES - Error while trying to list_domain_names or describe_elasticsearch_domains.\n%s", ex)
        raise ex
    logger.info("ElasticSearch - reporting %s evaluations.", len(local_evaluations))
    return local_evaluations


def apigw_get_resources_list(api_client, rest_api_id):
    """Get a list of all the resources in an API Gateway Rest API.
    Keyword arguments:
    api_client -- the API Gateway client object
    rest_api_id -- the ID of the API Gateway Rest API
    """
    resource_list = []
    api_paginator = api_client.get_paginator("get_resources")
    api_resource_list = api_paginator.paginate(
        restApiId=rest_api_id,
        PaginationConfig={"MaxItems": PAGE_SIZE}
    )
    for page in api_resource_list:
        resource_list.extend(page["items"])
        time.sleep(INTERVAL_BETWEEN_API_CALLS)
    return resource_list


def build_evaluation(
    resource_id, compliance_type, event, resource_type, annotation=None
):
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
        eval_cc["Annotation"] = annotation
    eval_cc["ComplianceResourceType"] = resource_type
    eval_cc["ComplianceResourceId"] = resource_id
    eval_cc["ComplianceType"] = compliance_type
    eval_cc["OrderingTimestamp"] = str(
        json.loads(event["invokingEvent"])["notificationCreationTime"]
    )
    return eval_cc


def is_throttling_exception(event):
    """Returns True if the exception code is one of the throttling exception codes we have"""
    b_is_throttling = False
    throttling_exception_codes = [
        "ConcurrentModificationException",
        "InsufficientDeliveryPolicyException",
        "NoAvailableDeliveryChannelException",
        "ConcurrentModifications",
        "LimitExceededException",
        "OperationNotPermittedException",
        "TooManyRequestsException",
        "Throttling",
        "ThrottlingException",
        "InternalErrorException",
        "InternalException",
        "ECONNRESET",
        "EPIPE",
        "ETIMEDOUT",
        "ConcurrentModificationException",
        "InsufficientDeliveryPolicyException",
        "NoAvailableDeliveryChannelException",
        "ConcurrentModifications",
        "LimitExceededException",
        "OperationNotPermittedException",
        "TooManyRequestsException",
        "Throttling",
        "ThrottlingException",
        "InternalErrorException",
        "InternalException",
        "ECONNRESET",
        "EPIPE",
        "ETIMEDOUT",
    ]
    for throttling_code in throttling_exception_codes:
        if throttling_code in event.response["Error"]["Code"]:
            b_is_throttling = True
            break
    return b_is_throttling


def get_client(service, event, region="ca-central-1"):
    """Return the service boto client. It should be used instead of directly calling the client.
    Keyword arguments:
    service -- the service name used for calling the boto.client()
    event -- the event variable given in the lambda handler
    """
    if not ASSUME_ROLE_MODE or (AWS_ACCOUNT_ID == AUDIT_ACCOUNT_ID):
        return boto3.client(service, region_name=region)
    execution_role_arn = f"arn:aws:iam::{AWS_ACCOUNT_ID}:role/{EXECUTION_ROLE_NAME}"
    credentials = get_assume_role_credentials(execution_role_arn, region)
    return boto3.client(
        service,
        region_name=region,
        aws_access_key_id=credentials["AccessKeyId"],
        aws_secret_access_key=credentials["SecretAccessKey"],
        aws_session_token=credentials["SessionToken"],
    )


def get_assume_role_credentials(role_arn, region="ca-central-1"):
    """Return the service boto client. It should be used instead of directly calling the client.
    Keyword arguments:
    service -- the service name used for calling the boto.client()
    event -- the event variable given in the lambda handler
    """
    sts_client = boto3.client("sts", region_name=region)
    try:
        assume_role_response = sts_client.assume_role(
            RoleArn=role_arn,
            RoleSessionName="configLambdaExecution"
        )
        return assume_role_response["Credentials"]
    except botocore.exceptions.ClientError as ex:
        if "AccessDenied" in ex.response["Error"]["Code"]:
            ex.response["Error"]["Message"] = "AWS Config does not have permission to assume the IAM role."
        else:
            ex.response["Error"]["Message"] = "InternalError"
            ex.response["Error"]["Code"] = "InternalError"
        raise ex


def is_scheduled_notification(message_type):
    """Check whether the message is a ScheduledNotification or not.
    Keyword arguments:
    message_type -- the message type
    """
    return message_type == "ScheduledNotification"


def lambda_handler(event, context):
    """Lambda handler to check CloudTrail trails are logging.
    Keyword arguments:
    event -- the event variable given in the lambda handler
    context -- the context variable given in the lambda handler
    """
    global logger
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)

    global MAXIMUM_API_RETRIES
    global PAGE_SIZE
    global INTERVAL_BETWEEN_API_CALLS
    global THROTTLE_BACKOFF

    MAXIMUM_API_RETRIES = 10
    PAGE_SIZE = 25
    INTERVAL_BETWEEN_API_CALLS = 0.25
    THROTTLE_BACKOFF = 2

    global AWS_S3_CLIENT
    global AWS_REDSHIFT_CLIENT
    global AWS_ELBV2_CLIENT
    global AWS_APIGW_CLIENT
    global AWS_ES_CLIENT
    global AWS_CONFIG_CLIENT
    global AWS_ACCOUNT_ID
    global AUDIT_ACCOUNT_ID
    global EXECUTION_ROLE_NAME

    evaluations = []
    rule_parameters = {}
    invoking_event = json.loads(event["invokingEvent"])
    logger.info("Recieved event: %s", json.dumps(event, indent=2))

    AWS_ACCOUNT_ID = event["accountId"]
    logger.info("Assessing account %s", AWS_ACCOUNT_ID)
    if "ruleParameters" in event:
        rule_parameters = json.loads(event["ruleParameters"])

    valid_rule_parameters = rule_parameters

    if "ExecutionRoleName" in valid_rule_parameters:
        EXECUTION_ROLE_NAME = valid_rule_parameters["ExecutionRoleName"]
    else:
        EXECUTION_ROLE_NAME = "AWSA-GCLambdaExecutionRole2"

    if "AuditAccountID" in valid_rule_parameters:
        AUDIT_ACCOUNT_ID = valid_rule_parameters["AuditAccountID"]
    else:
        AUDIT_ACCOUNT_ID = ""

    if not is_scheduled_notification(invoking_event["messageType"]):
        logger.error("Skipping assessments as this is not a scheduled invokation")
        return

    AWS_S3_CLIENT = get_client("s3", event)
    AWS_REDSHIFT_CLIENT = get_client("redshift", event)
    AWS_ELBV2_CLIENT = get_client("elbv2", event)
    AWS_APIGW_CLIENT = get_client("apigateway", event)
    AWS_ES_CLIENT = get_client("es", event)
    AWS_CONFIG_CLIENT = get_client("config", event)

    evaluations.extend(assess_s3_buckets_ssl_enforcement(event))
    evaluations.extend(assess_redshift_clusters_ssl_enforcement(event))
    evaluations.extend(assess_elbv2_ssl_enforcement(event))
    evaluations.extend(assess_rest_api_stages_ssl_enforcement(event))
    evaluations.extend(assess_es_node_to_node_ssl_enforcement(event))

    account_compliance_status = "COMPLIANT"
    account_compliance_annotation = "No non-compliant resources found"

    for evaluation in evaluations:
        if evaluation.get("ComplianceType", "") == "NON_COMPLIANT":
            account_compliance_status = "NON_COMPLIANT"
            account_compliance_annotation = "Non-compliant resources in scope found"
            break
    evaluations.append(
        build_evaluation(
            AWS_ACCOUNT_ID,
            account_compliance_status,
            event,
            "AWS::::Account",
            annotation=account_compliance_annotation,
        )
    )
    number_of_evaluations = len(evaluations)
    if number_of_evaluations > 0:
        max_evaluations_per_call = 100
        rounds = number_of_evaluations // max_evaluations_per_call
        logger.info("Reporting %s evaluations in %s rounds.", number_of_evaluations, rounds + 1)
        if number_of_evaluations > max_evaluations_per_call:
            for rnd in range(rounds):
                start = rnd * max_evaluations_per_call
                end = (rnd + 1) * max_evaluations_per_call
                AWS_CONFIG_CLIENT.put_evaluations(
                    Evaluations=evaluations[start:end],
                    ResultToken=event["resultToken"]
                )
                time.sleep(0.3)
            start = end
            end = number_of_evaluations
            AWS_CONFIG_CLIENT.put_evaluations(
                Evaluations=evaluations[start:end],
                ResultToken=event["resultToken"]
            )
        else:
            AWS_CONFIG_CLIENT.put_evaluations(
                Evaluations=evaluations,
                ResultToken=event["resultToken"]
            )

        AWS_S3_CLIENT = get_client("s3", event)
        AWS_REDSHIFT_CLIENT = get_client("redshift", event)
        AWS_ELBV2_CLIENT = get_client("elbv2", event)
        AWS_APIGW_CLIENT = get_client("apigateway", event)
        AWS_ES_CLIENT = get_client("es", event)
        AWS_CONFIG_CLIENT = get_client("config", event)

        evaluations.extend(assess_s3_buckets_ssl_enforcement(event))
        evaluations.extend(assess_redshift_clusters_ssl_enforcement(event))
        evaluations.extend(assess_elbv2_ssl_enforcement(event))
        evaluations.extend(assess_rest_api_stages_ssl_enforcement(event))
        evaluations.extend(assess_es_node_to_node_ssl_enforcement(event))

        account_compliance_status = "COMPLIANT"
        account_compliance_annotation = "No non-compliant resources found"

        for evaluation in evaluations:
            if evaluation.get("ComplianceType", "") == "NON_COMPLIANT":
                account_compliance_status = "NON_COMPLIANT"
                account_compliance_annotation = "Non-compliant resources in scope found"
                break
        evaluations.append(
            build_evaluation(
                AWS_ACCOUNT_ID,
                account_compliance_status,
                event,
                "AWS::::Account",
                annotation=account_compliance_annotation,
            )
        )
        number_of_evaluations = len(evaluations)
        if number_of_evaluations > 0:
            max_evaluations_per_call = 100
            rounds = number_of_evaluations // max_evaluations_per_call
            logger.info("Reporting %s evaluations in %s rounds.", number_of_evaluations, rounds + 1)
            if number_of_evaluations > max_evaluations_per_call:
                for rnd in range(rounds):
                    start = rnd * max_evaluations_per_call
                    end = (rnd + 1) * max_evaluations_per_call
                    AWS_CONFIG_CLIENT.put_evaluations(
                        Evaluations=evaluations[start:end],
                        ResultToken=event["resultToken"]
                    )
                    time.sleep(0.3)
                start = end
                end = number_of_evaluations
                AWS_CONFIG_CLIENT.put_evaluations(
                    Evaluations=evaluations[start:end],
                    ResultToken=event["resultToken"]
                )
            else:
                AWS_CONFIG_CLIENT.put_evaluations(
                    Evaluations=evaluations,
                    ResultToken=event["resultToken"]
                )
