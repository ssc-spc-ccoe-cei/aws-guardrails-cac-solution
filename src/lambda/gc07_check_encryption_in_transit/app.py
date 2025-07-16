""" GC07 - Check Encryption in Transit
    https://canada-ca.github.io/cloud-guardrails/EN/07_Protect-Data-in-Transit.html
"""

import json
import logging
import time

from utils import is_scheduled_notification, check_required_parameters, check_guardrail_requirement_by_cloud_usage_profile, get_cloud_profile_from_tags, GuardrailType, GuardrailRequirementType
from boto_util.organizations import get_account_tags
from boto_util.client import get_client, is_throttling_exception
from boto_util.config import build_evaluation, submit_evaluations
from boto_util.s3 import list_all_s3_buckets, check_s3_object_exists
from boto_util.api_gateway import list_all_api_gateway_resources
from boto_util.cloud_front import list_all_cloud_front_distributions

import botocore.exceptions


# Logging setup
logger = logging.getLogger()
logger.setLevel(logging.INFO)


def assess_s3_buckets_ssl_enforcement(s3_client, event: dict):
    """
    Finds Amazon S3 resources that do not have a bucket policy restricting SSL access
    """
    local_evaluations = []
    condition_criteria = {"Bool": {"aws:SecureTransport": "false"}}
    resource_type = "AWS::S3::Bucket"
    try:
        buckets = list_all_s3_buckets(s3_client, PAGE_SIZE, INTERVAL_BETWEEN_API_CALLS)
        if buckets:
            for bucket in buckets:
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
                        response = s3_client.get_bucket_policy(Bucket=bucket.get("Name"))
                        if response:
                            bucket_policy = json.loads(response.get("Policy"))
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
                            logger.error(
                                "S3 - Error while calling get_bucket_policy for bucket %s ---> %s",
                                bucket.get("Name", ""),
                                ex,
                            )
                
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
    # logger.info("S3 - reporting %s evaluations.", len(local_evaluations))
    return local_evaluations


def assess_redshift_clusters_ssl_enforcement(redshift_client, event: dict):
    """
    Finds Amazon Redshift clusters that do not have a cluster policy restricting SSL access
    """
    clusters = []
    local_evaluations = []
    try:
        response = redshift_client.describe_clusters(MaxRecords=PAGE_SIZE)
        b_more_data = True
        i_retries = 0
        while b_more_data and i_retries < MAXIMUM_API_RETRIES:
            if response:
                next_marker = response.get("Marker", "")
                for cluster in response.get("Clusters", []):
                    parameter_group_names = []
                    for parameter_group in cluster.get("ClusterParameterGroups", []):
                        parameter_group_names.append(parameter_group.get("ParameterGroupName"))
                    clusters.append(
                        {
                            "ClusterIdentifier": cluster.get("ClusterIdentifier"),
                            "ClusterParameterGroups": parameter_group_names,
                        }
                    )
                # logger.info("%s Redshift clusters found.", len(clusters))
                if next_marker:
                    time.sleep(INTERVAL_BETWEEN_API_CALLS)
                    try:
                        response = redshift_client.describe_clusters(MaxRecords=PAGE_SIZE, Marker=next_marker)
                    except botocore.exceptions.ClientError as ex:
                        i_retries += 1
                        if is_throttling_exception(ex):
                            # logger.error("Redshift - Throttling while calling describe_clusters")
                            time.sleep(THROTTLE_BACKOFF)
                        else:
                            # logger.error("Redshift - Error while trying to describe_clusters.%s", ex)
                            raise ex
                else:
                    b_more_data = False
            else:
                # logger.error("Redshift - Empty response while trying to describe_clusters")
                b_more_data = False
    except botocore.exceptions.ClientError as ex:
        # logger.error("Redshift - Error while trying to describe_clusters. %s", ex)
        raise ex
    for cluster in clusters:
        b_require_ssl = False
        for parameter_group_name in cluster.get("ClusterParameterGroups"):
            try:
                next_marker = ""
                response = redshift_client.describe_cluster_parameters(
                    ParameterGroupName=parameter_group_name, MaxRecords=PAGE_SIZE
                )
                b_more_data = True
                i_retries = 0
                while b_more_data and (i_retries < MAXIMUM_API_RETRIES) and (not b_require_ssl):
                    if response:
                        next_marker = response.get("Marker", "")
                        for parameter in response.get("Parameters", []):
                            if parameter.get("ParameterName") == "require_ssl":
                                if parameter.get("ParameterValue", "").lower() == "true":
                                    b_require_ssl = True
                                    break
                            else:
                                continue
                        if next_marker and (not b_require_ssl):
                            time.sleep(INTERVAL_BETWEEN_API_CALLS)
                            try:
                                response = redshift_client.describe_cluster_parameters(
                                    ParameterGroupName=parameter_group_name,
                                    MaxRecords=PAGE_SIZE,
                                    Marker=next_marker,
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
                    # logger.info("Redshift cluster %s has require_ssl enforced.", cluster.get("ClusterIdentifier", ""))
                    break
            except botocore.exceptions.ClientError as ex:
                logger.error("Redshift - Error while trying to describe_cluster_parameters. %s", ex)
                raise ex
        if b_require_ssl:
            compliance_status = "COMPLIANT"
            compliance_annotation = "SSL required"
        else:
            # logger.info("Redshift cluster %s DOES NOT require_ssl.", cluster.get("ClusterIdentifier", ""))
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
    # logger.info("Redshift - reporting %s evaluations.", len(local_evaluations))
    return local_evaluations


def assess_elb_v2_ssl_enforcement(elb_v2_client, event: dict):
    """
    Evaluate whether SSL is enforced on ELBv2.
    """
    local_evaluations = []
    load_balancers = []
    try:
        response = elb_v2_client.describe_load_balancers(PageSize=PAGE_SIZE)
        b_more_data = True
        i_retries = 0
        while b_more_data and i_retries < MAXIMUM_API_RETRIES:
            if response:
                next_marker = response.get("NextMarker", "")
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
                        response = elb_v2_client.describe_load_balancers(PageSize=PAGE_SIZE, Marker=next_marker)
                    except botocore.exceptions.ClientError as ex:
                        i_retries += 1
                        if is_throttling_exception(ex):
                            # logger.error("ELBv2 - Throttling while calling describe_load_balancers")
                            time.sleep(THROTTLE_BACKOFF)
                        else:
                            # logger.error("ELBv2 - Error while trying to describe_load_balancers. %s", ex)
                            raise ex
                else:
                    b_more_data = False
            else:
                logger.error("ELBv2 - Empty response while trying to describe_load_balancers")
                b_more_data = False
    except botocore.exceptions.ClientError as ex:
        # logger.error("ELBv2 - Error while trying to describe_load_balancers. %s", ex)
        raise ex
    # logger.info("%s ELBv2 Load balancers found.", len(load_balancers))
    for load_balancer in load_balancers:
        next_marker = ""
        try:
            response = elb_v2_client.describe_listeners(
                LoadBalancerArn=load_balancer.get("LoadBalancerArn", ""),
                PageSize=PAGE_SIZE,
            )
            b_more_data = True
            i_retries = 0
            while b_more_data and (i_retries < MAXIMUM_API_RETRIES):
                if response:
                    next_marker = response.get("NextMarker", "")
                    for listener in response.get("Listeners", []):
                        listener_compliance = ""
                        listener_annotation = ""
                        listener_protocol = listener.get("Protocol", "")
                        if listener_protocol.lower() not in ["https", "tls"]:
                            redirect_flag = False
                            for action in listener.get("DefaultActions", []):
                                if (action.get("Type") == "redirect" and action.get("RedirectConfig", {}).get("Protocol") == "HTTPS"):
                                    redirect_flag = True
                                    break

                            if redirect_flag:
                                listener_compliance = "COMPLIANT"
                                listener_annotation = f"HTTP listener with HTTPS redirection - {listener.get("ListenerArn", "")}"
                            else:
                                listener_compliance = "NON_COMPLIANT"
                                listener_annotation = "Non HTTPS/TLS listener protocol - {}".format(listener_protocol)
                        else:
                            listener_compliance = "COMPLIANT"
                            listener_annotation = f"Listener uses HTTPS/TLS - {listener.get("ListenerArn", "")}"
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
                            response = elb_v2_client.describe_listeners(
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
                # logger.error("ELBv2 - Throttling while calling describe_listeners")
                time.sleep(THROTTLE_BACKOFF)
            else:
                # logger.error("ELBv2 - Error while trying to describe_listeners. %s", ex)
                raise ex
    # logger.info("ELBv2 - reporting %s evaluations.", len(local_evaluations))
    return local_evaluations

def assess_elb_v1_ssl_enforcement(elb_client, event: dict):
    """
    Evaluate whether SSL is enforced on Classic Load Balancers (ELB v1).
    """
    local_evaluations = []
    load_balancers = []

    try:
        response = elb_client.describe_load_balancers()
        b_more_data = True
        i_retries = 0
        while b_more_data and i_retries < MAXIMUM_API_RETRIES:
            if response:
                next_marker = response.get("NextMarker", "")
                for load_balancer in response.get("LoadBalancerDescriptions", []):
                    load_balancers.append(
                        {
                            "LoadBalancerName": load_balancer.get("LoadBalancerName"),
                            "DNSName": load_balancer.get("DNSName"),
                            "ListenerDescriptions": load_balancer.get("ListenerDescriptions", []),
                        }
                    )
                if next_marker:
                    time.sleep(INTERVAL_BETWEEN_API_CALLS)
                    try:
                        response = elb_client.describe_load_balancers(Marker=next_marker)
                    except botocore.exceptions.ClientError as ex:
                        i_retries += 1
                        if is_throttling_exception(ex):
                            time.sleep(THROTTLE_BACKOFF)
                        else:
                            raise ex
                else:
                    b_more_data = False
            else:
                logger.error("ELBv1 - Empty response while trying to describe_load_balancers")
                b_more_data = False
    except botocore.exceptions.ClientError as ex:
        raise ex

    #logger.info(f"Found {len(load_balancers)} Classic Load Balancers: {[lb['LoadBalancerName'] for lb in load_balancers]}")

    for load_balancer in load_balancers:
        try:
            for listener in load_balancer.get("ListenerDescriptions", []):
                listener_compliance = ""
                listener_annotation = ""
                listener_port = listener.get("Listener", {}).get("LoadBalancerPort", "")
                listener_protocol = listener.get("Listener", {}).get("Protocol", "")
                
                if listener_protocol.lower() not in ["https", "ssl"]:
                    #Classic Load Balancers don't support HTTP to HTTPS redirection at the load balancer level
                    listener_compliance = "NON_COMPLIANT"
                    listener_annotation = f"Port {listener_port} uses non TLS 1.2 compliant listener protocol {listener_protocol}"
                else:
                    policy_names = listener.get("PolicyNames", [])
                        
                    if not policy_names:  # No policy found for the listener
                        listener_compliance = "NON_COMPLIANT"
                        listener_annotation = f"Port {listener_port} has no TLS 1.2 compliant policy attached for {listener_protocol}"
                    else:

                        for policy_name in policy_names:

                            try:
                                policy_response = elb_client.describe_load_balancer_policies(LoadBalancerName=load_balancer.get('LoadBalancerName'), PolicyNames=[policy_name])
                                listener_security_policy = next(
                                    (attr["AttributeValue"] for attr in policy_response.get("PolicyDescriptions", [{}])[0].get("PolicyAttributeDescriptions", []) 
                                    if attr.get("AttributeName") == "Reference-Security-Policy"), 
                                    None
                                )
                                
                                if listener_security_policy:  # Only log if a value is found
                                    if listener_security_policy == "ELBSecurityPolicy-TLS-1-2-2017-01":
                                        listener_compliance = "COMPLIANT"
                                        listener_annotation = (
                                            f"Port {listener_port} uses TLS 1.2 compliant {listener_protocol} security policy {listener_security_policy}"
                                        )
                                    else:
                                        listener_compliance = "NON_COMPLIANT"
                                        listener_annotation = (
                                            f"Port {listener_port} uses non-TLS 1.2 compliant {listener_protocol} security policy {listener_security_policy}"
                                        )
                                else:
                                    # If Reference-Security-Policy is not found, mark as NON_COMPLIANT
                                    listener_compliance = "NON_COMPLIANT"
                                    listener_annotation = (
                                        f"Port {listener_port} is missing the Reference-Security-Policy: ELBSecurityPolicy-TLS-1-2-2017-01"
                                )
                            except botocore.exceptions.ClientError as ex:
                                logger.error(f"Error retrieving policy details for {policy_name}: {str(ex)}")
                
                local_evaluations.append(
                    build_evaluation(
                        load_balancer.get("DNSName", ""),
                        listener_compliance,
                        event,
                        "AWS::ElasticLoadBalancing::LoadBalancer",
                        annotation=listener_annotation,
                    )
                )
        except botocore.exceptions.ClientError as ex:
            i_retries += 1
            if is_throttling_exception(ex):
                time.sleep(THROTTLE_BACKOFF)
            else:
                raise ex

    return local_evaluations

def assess_rest_api_stages_ssl_enforcement(api_gw_client, event: dict):
    """
    This function evaluates the SSL enforcement on the REST API Stages.
    """
    local_evaluations = []
    resource_type = "AWS::ApiGateway::Stage"
    try:
        response = api_gw_client.get_rest_apis(limit=PAGE_SIZE)
        b_more_data = True
        i_retries = 0
        while b_more_data and i_retries < MAXIMUM_API_RETRIES:
            if response:
                position = response.get("position", "")
                for api in response.get("items", []):
                    api_id = api.get("id")
                    api_name = api.get("name")
                    if not api_id:
                        # logger.error("Skipping Malformed API item %s", api)
                        continue
                    try:
                        api_resource_list = list_all_api_gateway_resources(
                            api_gw_client, api_id, PAGE_SIZE, INTERVAL_BETWEEN_API_CALLS
                        )
                    except botocore.exceptions.ClientError as error:
                        if error.response["Error"]["Code"] == "NotFoundException":
                            pass
                    if not api_resource_list:
                        # logger.info("Skipping API - %s - as it has no resources.", api_name)
                        continue
                    AWS = False
                    HTTP = False
                    for item in api_resource_list:
                        if "id" in item and "resourceMethods" in item:
                            resource_id = item["id"]
                            method_types = item["resourceMethods"].keys()
                            for method_type in method_types:
                                try:
                                    integration_type = api_gw_client.get_integration(
                                        restApiId=api_id,
                                        resourceId=resource_id,
                                        httpMethod=method_type,
                                    )["type"]
                                except botocore.exceptions.ClientError as error:
                                    if error.response["Error"]["Code"] == "NotFoundException":
                                        integration_type = "None"
                                    else:
                                        raise error
                                if "HTTP" in integration_type:
                                    HTTP = True
                                if "AWS" in integration_type:
                                    AWS = True
                                time.sleep(THROTTLE_BACKOFF / 2)
                    try:
                        response2 = api_gw_client.get_deployments(restApiId=api_id, limit=PAGE_SIZE)
                        i_retries2 = 0
                        b_more_data2 = True
                        while b_more_data2 and i_retries2 < MAXIMUM_API_RETRIES:
                            if response2:
                                position2 = response2.get("position")
                                deployments = response2.get("items", [])
                                if len(deployments) <= 0:
                                    # logger.info("APIGW - Skipping API '%s' as it has no deployments", api_name)
                                    break
                                for deployment in deployments:
                                    deployment_id = deployment.get("id", "")
                                    if not deployment_id:
                                        # logger.error("Skipping Malformed Deployment in API %s: %s", api, deployment)
                                        continue
                                    try:
                                        response3 = api_gw_client.get_stages(
                                            restApiId=api_id, deploymentId=deployment_id
                                        )
                                        if response3:
                                            stages = response3.get("item")
                                            if len(stages) <= 0:
                                                logger.error(
                                                    "APIGW - No stages found for API %s and deployment ID %s",
                                                    api_name,
                                                    deployment_id,
                                                )
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
                                            logger.error(
                                                "APIGW - Empty response on get_stages for API %s and deployment ID %s",
                                                api_name,
                                                deployment_id,
                                            )
                                    except botocore.exceptions.ClientError as ex:
                                        logger.error(
                                            "APIGW - Error while trying to get_stages for API %s and deployment ID %s.\n%s",
                                            api_name,
                                            deployment_id,
                                            ex,
                                        )
                                        raise ex
                                if position2:
                                    time.sleep(INTERVAL_BETWEEN_API_CALLS)
                                    try:
                                        response2 = api_gw_client.get_deployments(
                                            restApiId=api_id,
                                            position=position2,
                                            limit=PAGE_SIZE,
                                        )
                                    except botocore.exceptions.ClientError as ex:
                                        i_retries2 += 1
                                        if is_throttling_exception(ex):
                                            # logger.error("APIGW - Throttling while calling get_deployments")
                                            time.sleep(THROTTLE_BACKOFF)
                                        else:
                                            # logger.error("APIGW - Error while trying to get_deployments. %s", ex)
                                            raise ex
                                else:
                                    b_more_data2 = False
                            else:
                                logger.error(
                                    "APIGW - Empty response on call to get_deployments with API ID '%s'", api_name
                                )
                                b_more_data2 = False
                    except botocore.exceptions.ClientError as ex:
                        i_retries += 1
                        if is_throttling_exception(ex):
                            # logger.error("APIGW - Throttling while calling get_deployments")
                            time.sleep(THROTTLE_BACKOFF)
                        else:
                            # logger.error("ELBv2 - Error while trying to get_deployments. %s", ex)
                            raise ex
                if position:
                    time.sleep(INTERVAL_BETWEEN_API_CALLS)
                    try:
                        response = api_gw_client.get_rest_apis(position=position, limit=PAGE_SIZE)
                    except botocore.exceptions.ClientError as ex:
                        if is_throttling_exception(ex):
                            # logger.error("APIGW - Throttling while calling get_rest_apis")
                            time.sleep(THROTTLE_BACKOFF)
                            i_retries += 1
                        else:
                            # logger.error("APIGW - Error while trying to get_rest_apis.%s", ex)
                            raise ex
                else:
                    b_more_data = False
            else:
                # logger.error("REST API - Empty response from get_rest_apis call")
                b_more_data = False
    except botocore.exceptions.ClientError as ex:
        # logger.error("REST API - Error while trying to get_rest_apis - %s", ex)
        raise ex
    # logger.info("APIGW - reporting %s evaluations.", len(local_evaluations))
    return local_evaluations


def assess_open_search_node_to_node_ssl_enforcement(open_search_client, event: dict) -> list[dict]:
    """
    This function evaluates the Node to Node SSL Enforcement compliance
    for the AWS OpenSearch Service.
    Args:
        event (dict): Lambda event object
    Returns:
        list: List of evaluation objects.
    """
    resource_type = "AWS::OpenSearch::Domain"
    local_evaluations = []
    try:
        response = open_search_client.list_domain_names()
        if response:
            for domain in response.get("DomainNames", []):
                time.sleep(INTERVAL_BETWEEN_API_CALLS)
                domain_name = domain.get("DomainName")
                if not domain_name:
                    # logger.error("Malformed domain result - %s", domain)
                    continue
                response2 = open_search_client.describe_domains(DomainNames=[domain_name])
                if response2:
                    for domain_status in response2.get("DomainStatusList", []):
                        if domain_status.get("NodeToNodeEncryptionOptions", {}).get("Enabled", False) == True:
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
                    logger.error("OS - Empty response on describe_domains call.")
        else:
            logger.error("OS - Empty response on list_domain_names call.")
    except botocore.exceptions.ClientError as ex:
        logger.error("OS - Error while trying to list_domain_names or describe_domains.\n%s", ex)
        raise ex
    # logger.info("OpenSearch - reporting %s evaluations.", len(local_evaluations))
    return local_evaluations


def assess_cloud_front_ssl_enforcement(cloud_front_client, event: dict) -> list[dict]:
    resource_type = "AWS::CloudFront::Distribution"
    local_evaluations = []
    distributions = list_all_cloud_front_distributions(cloud_front_client, PAGE_SIZE, INTERVAL_BETWEEN_API_CALLS)
    for distribution in distributions:
        id = distribution["Id"]
        resource_id = distribution.get("ARN", id)
        viewer_certificate = distribution.get("ViewerCertificate", None)

        if not viewer_certificate:
            annotation = "Distribution does not have SSL/TLS enabled."
            local_evaluations.append(build_evaluation(resource_id, "NON_COMPLIANT", event, resource_type, annotation))
            # logger.info(f"{annotation} ({resource_id})")
            continue

        min_protocol_version = viewer_certificate.get("MinimumProtocolVersion", None)
        if min_protocol_version.startswith("TLSv1.2"):
            annotation = f"Distribution has a minimum protocol version of TLS1.2. ({min_protocol_version})"
            local_evaluations.append(build_evaluation(resource_id, "COMPLIANT", event, resource_type, annotation))
        else:
            annotation = f"Distribution does NOT have a minimum protocol version of TLS1.2. ({min_protocol_version})"
            local_evaluations.append(build_evaluation(resource_id, "NON_COMPLIANT", event, resource_type, annotation))
        # logger.info(f"{annotation} ({resource_id})")

    # logger.info("CloudFront - reporting %s evaluations.", len(local_evaluations))
    return local_evaluations


def get_all_compliance_details_by_config_rule(
    config_client, config_rule_name: str, compliance_types: list[str] = None, interval_between_calls: float = 0.05
) -> list[dict]:
    """
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/config/paginator/GetComplianceDetailsByConfigRule.html
    """
    args = {"ConfigRuleName": config_rule_name}
    if compliance_types:
        args["ComplianceTypes"] = compliance_types

    resources: list[dict] = []
    paginator = config_client.get_paginator("get_compliance_details_by_config_rule")
    page_iterator = paginator.paginate(**args)
    for page in page_iterator:
        resources.extend(page.get("EvaluationResults", []))
        time.sleep(interval_between_calls)
    return resources


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

    rule_parameters = check_required_parameters(json.loads(event.get("ruleParameters", "{}")), ["ExecutionRoleName", "S3NonComplianceOptoutFilePath"])
    execution_role_name = rule_parameters.get("ExecutionRoleName")
    audit_account_id = rule_parameters.get("AuditAccountID", "")
    aws_account_id = event["accountId"]
    optout_file_path = rule_parameters.get("S3NonComplianceOptoutFilePath", "")
    logger.info(f"AWS Account ID: {aws_account_id}, Audit Account ID: {audit_account_id}")
    is_not_audit_account = aws_account_id != audit_account_id

    evaluations = []

    global MAXIMUM_API_RETRIES
    global PAGE_SIZE
    global INTERVAL_BETWEEN_API_CALLS
    global THROTTLE_BACKOFF

    MAXIMUM_API_RETRIES = 10
    PAGE_SIZE = 25
    INTERVAL_BETWEEN_API_CALLS = 0.25
    THROTTLE_BACKOFF = 2

    aws_config_client = get_client("config", aws_account_id, execution_role_name, is_not_audit_account)
    aws_cloud_front_client = get_client("cloudfront", aws_account_id, execution_role_name, is_not_audit_account)
    # Updated boolean value to True as in audit account, s3_client was not able to access buckets created outside of ca-central-1 region
    aws_s3_client = get_client("s3", aws_account_id, execution_role_name, True)
    aws_redshift_client = get_client("redshift", aws_account_id, execution_role_name, is_not_audit_account)
    aws_elb_v1_client = get_client("elb", aws_account_id, execution_role_name, is_not_audit_account)
    aws_elb_v2_client = get_client("elbv2", aws_account_id, execution_role_name, is_not_audit_account)
    aws_api_gw_client = get_client("apigateway", aws_account_id, execution_role_name, is_not_audit_account)
    aws_open_search_client = get_client("opensearch", aws_account_id, execution_role_name, is_not_audit_account)
    
    

    compliance_details = get_all_compliance_details_by_config_rule(aws_config_client, event["configRuleName"], ["NON_COMPLIANT"])
    logger.info("compliance_detail = %s", json.dumps([(
            x["EvaluationResultIdentifier"]["EvaluationResultQualifier"]["ResourceId"],
            x["EvaluationResultIdentifier"]["EvaluationResultQualifier"]["ResourceType"],
        ) for x in compliance_details], indent=2))

    # Check cloud profile
    tags = get_account_tags(get_client("organizations", assume_role=False), aws_account_id)
    cloud_profile = get_cloud_profile_from_tags(tags)
    gr_requirement_type = check_guardrail_requirement_by_cloud_usage_profile(GuardrailType.Guardrail7, cloud_profile)
    
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
        
    evaluations.extend(assess_s3_buckets_ssl_enforcement(aws_s3_client, event))
    evaluations.extend(assess_redshift_clusters_ssl_enforcement(aws_redshift_client, event))
    evaluations.extend(assess_elb_v2_ssl_enforcement(aws_elb_v2_client, event))
    evaluations.extend(assess_elb_v1_ssl_enforcement(aws_elb_v1_client, event))
    evaluations.extend(assess_rest_api_stages_ssl_enforcement(aws_api_gw_client, event))
    evaluations.extend(assess_open_search_node_to_node_ssl_enforcement(aws_open_search_client, event))
    evaluations.extend(assess_cloud_front_ssl_enforcement(aws_cloud_front_client, event))

    compliance_type = "COMPLIANT"
    annotation = "No non-compliant resources found"
    # added check for opt out file. if file exists, change the non-compliance to compliant status only for both ELB v1 and v2
    for evaluation in evaluations:
        if evaluation.get("ComplianceType", "") == "NON_COMPLIANT" and (evaluation.get("ComplianceResourceType", "") == "AWS::ElasticLoadBalancingV2::Listener" or evaluation.get("ComplianceResourceType", "") == "AWS::ElasticLoadBalancing::LoadBalancer") :
            # add the check for if file exists in an evidence bucket, 
            # addeded new client to avoid AccessDenied exception
            s3_client = get_client("s3")
            optout_file_exists_flag = check_s3_object_exists(s3_client, optout_file_path)  
            # if file exists, change status to compliant
            if optout_file_exists_flag:
                evaluation["ComplianceType"] = "COMPLIANT"
                evaluation["Annotation"] = "Compliant owing to opt out file found"     
            

    

    for evaluation in evaluations:
        if evaluation.get("ComplianceType", "") == "NON_COMPLIANT":
            compliance_type = "NON_COMPLIANT"
            annotation = "Non-compliant resources in scope found"    
            break

    logger.info(f"{compliance_type}: {annotation}")
    evaluations.append(build_evaluation(aws_account_id, compliance_type, event, annotation=annotation))
    submit_evaluations(aws_config_client, event, evaluations, INTERVAL_BETWEEN_API_CALLS)
