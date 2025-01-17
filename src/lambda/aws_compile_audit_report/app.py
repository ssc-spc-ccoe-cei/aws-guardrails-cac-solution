""" Compile Audit Report """

import csv
import datetime
import io
import json
import logging
import os

import boto3
from utils import get_cloud_profile_from_tags
from boto_util.client import get_client
from boto_util.organizations import get_account_tags

assessment_name = os.environ["ASSESSMENT_NAME"]
cac_version = os.environ["CAC_VERSION"]
org_id = os.environ["ORG_ID"]
org_name = os.environ["ORG_NAME"]
tenant_id = os.environ["TENANT_ID"]
auditManagerClient = boto3.client("auditmanager")
s3 = boto3.client("s3")


def lambda_handler(event, context):
    """This function is the main entry point for Lambda.
    Keyword arguments:
    event -- the event variable given in the lambda handler
    context -- the context variable given in the lambda handler
    """
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.INFO)
    logger.info("start audit manager get assessments")
    logger.info("Received Event: %s", json.dumps(event, indent=2))
    
    header = [
        "accountId",
        "accountCloudProfile",
        "dataSource",
        "guardrail",
        "controlName",
        "timestamp",
        "resourceType",
        "resourceArn",
        "compliance",
        "organizationId",
        "organizationName",
        "tenantId",
        "cacVersion",
    ]
    csv_io = io.StringIO()
    writer = csv.writer(csv_io)
    writer.writerow(header)

    # get list of assessment and we will loop through each one
    assessments = get_assessments(assessment_name)
    if len(assessments) < 1:
        return
    count = 0
    for assessment in assessments:
        assessment_id = assessment["id"]
        evidence_folders = get_evidence_folders_by_assessment_id(assessment_id)
        for folder in evidence_folders:
            control_set_id = folder["controlSetId"]
            folder_id = folder["id"]
            control_id = folder["controlName"]
            evidences = get_evidence_by_evidence_folders(assessment_id, control_set_id, folder_id)
            for item in evidences:
                aws_account_id = item["evidenceAwsAccountId"]
                tags = get_account_tags(get_client("organizations", assume_role=False), aws_account_id)
                cloud_profile = get_cloud_profile_from_tags(tags)
                if item["time"] > (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(1)):
                    rows = []
                    if len(item["resourcesIncluded"]) == 0:
                        rows.append(
                            [
                                aws_account_id,
                                str(cloud_profile.value),
                                item["dataSource"],
                                control_set_id,
                                control_id,
                                item["time"].strftime("%m/%d/%Y %H:%M:%S %Z"),
                                "None",
                                "None",
                                "NOT_APPLICABLE",
                                org_id,
                                org_name,
                                tenant_id,
                                cac_version,
                            ]
                        )
                    elif len(item["resourcesIncluded"]) > 1:
                        for sub_evidence in item["resourcesIncluded"]:
                            rows.append(
                                [
                                    aws_account_id,
                                    str(cloud_profile.value),
                                    item["dataSource"],
                                    control_set_id,
                                    control_id,
                                    item["time"].strftime("%m/%d/%Y %H:%M:%S %Z"),
                                    json.loads(sub_evidence["value"])["complianceResourceType"],
                                    json.loads(sub_evidence["value"])["complianceResourceId"],
                                    json.loads(sub_evidence["value"])["complianceType"],
                                    org_id,
                                    org_name,
                                    tenant_id,
                                    cac_version,
                                ]
                            )
                    else:
                        if "value" not in item["resourcesIncluded"][0]:
                            rows.append(
                                [
                                    aws_account_id,
                                    str(cloud_profile.value),
                                    item["dataSource"],
                                    control_set_id,
                                    control_id,
                                    item["time"].strftime("%m/%d/%Y %H:%M:%S %Z"),
                                    "None",
                                    "None",
                                    "NOT_APPLICABLE",
                                    org_id,
                                    org_name,
                                    tenant_id,
                                    cac_version,
                                ]
                            )
                        else:
                            rows.append(
                                [
                                    aws_account_id,
                                    str(cloud_profile.value),
                                    item["dataSource"],
                                    control_set_id,
                                    control_id,
                                    item["time"].strftime("%m/%d/%Y %H:%M:%S %Z"),
                                    json.loads(item["resourcesIncluded"][0]["value"])["complianceResourceType"],
                                    json.loads(item["resourcesIncluded"][0]["value"])["complianceResourceId"],
                                    json.loads(item["resourcesIncluded"][0]["value"])["complianceType"],
                                    org_id,
                                    org_name,
                                    tenant_id,
                                    cac_version,
                                ]
                            )
                    for row in rows:
                        count += 1
                        writer.writerow(row)
    if count > 0:
        s3.put_object(
            Body=csv_io.getvalue(),
            ContentType="text/csv",
            Bucket=os.environ["source_target_bucket"],
            Key=f'{datetime.datetime.today().strftime("%Y-%m-%d")}.csv',
        )
        csv_io.close()
        return json.dumps("success", default=str)
    else:
        csv_io.close()
        return json.dumps("Nothing to write", default=str)


def get_assessments(filter: str = None) -> list:
    """Get list of all assessments if filter not provided.
    If filter is provided return the single assessment. Filter
    corresponds to assessment name.
    """
    try:
        assessments = auditManagerClient.list_assessments(status="ACTIVE")
    except (ValueError, TypeError) as err:
        logging.error("Error at %s", "list_assessments", exc_info=err)
        results = []
    else:
        results = assessments["assessmentMetadata"]
        print(results)
    if filter is not None and len(results) != 0:
        filtered_results = []
        for item in results:
            if item["name"] == filter:
                filtered_results.append(item)
        return filtered_results
    return results


def get_evidence_folders_by_assessment_id(id: str) -> list:
    """Get list of all evidence folders for an assessment."""
    try:
        response = auditManagerClient.get_evidence_folders_by_assessment(assessmentId=id, maxResults=1000)
    except (ValueError, TypeError) as err:
        logging.error("Error at %s", "get_evidence_folders_by_assessment", exc_info=err)
        results = []
    else:
        results = response["evidenceFolders"]
        return results


def get_evidence_by_evidence_folders(assessment_id: str, control_set_id: str, folder_id: str) -> list:
    """Get list of all evidence for an evidence folder."""
    try:
        response_evidence_folder = auditManagerClient.get_evidence_by_evidence_folder(
            assessmentId=assessment_id, controlSetId=control_set_id, evidenceFolderId=folder_id, maxResults=500
        )
    except (ValueError, TypeError) as err:
        logging.error("Error at %s", "get_evidence_by_evidence_folder", exc_info=err)
        results = []
    else:
        results = response_evidence_folder["evidence"]
        return results
