""" Compile Audit Report """
import csv
import datetime
import io
import json
import logging
import os

import boto3

org_id = os.environ['ORG_ID']
assessment_name = os.environ['ASSESSMENT_NAME']
org_name = os.environ['ORG_NAME']
auditManagerClient = boto3.client('auditmanager')
s3 = boto3.client('s3')


def lambda_handler(event, context):
    """This function is the main entry point for Lambda.
    Keyword arguments:
    event -- the event variable given in the lambda handler
    context -- the context variable given in the lambda handler
    """
    logger = logging.getLogger(__name__)
    logger.info("start audit manager get assessements")

    header = ['accountId', 'dataSource', 'guardrail', 'controlName', 'timestamp',
              "resourceType", "resourceArn", "compliance", "organizationId", "organizationName"]
    csvio = io.StringIO()
    writer = csv.writer(csvio)
    writer.writerow(header)

    # get list of assessment and we will loop through each one
    assessements = get_assessments(assessment_name)
    if len(assessements) < 1:
        return
    count = 0
    for assessement in assessements:
        assessementid = assessement['id']
        evidence_folders = get_evidence_folders_by_assessment_id(assessementid)
        for folder in evidence_folders:
            controlsetid = folder['controlSetId']
            folderid = folder['id']
            controlid = folder['controlName']
            evidences = get_evidence_by_evidence_folders(
                assessementid, controlsetid, folderid)
            for item in evidences:
                if item['time'] > (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(1)):
                    rows = []
                    if len(item['resourcesIncluded']) == 0:
                        rows.append([
                            item['evidenceAwsAccountId'],
                            item['dataSource'],
                            controlsetid,
                            controlid,
                            item['time'].strftime("%m/%d/%Y %H:%M:%S %Z"),
                            'None',
                            'None',
                            'NOT_APPLICABLE',
                            org_id,
                            org_name
                        ])
                    elif len(item['resourcesIncluded']) > 1:
                        for sub_evidence in item['resourcesIncluded']:
                            rows.append([
                                item['evidenceAwsAccountId'],
                                item['dataSource'],
                                controlsetid,
                                controlid,
                                item['time'].strftime("%m/%d/%Y %H:%M:%S %Z"),
                                json.loads(sub_evidence['value'])['complianceResourceType'],
                                json.loads(sub_evidence['value'])['complianceResourceId'],
                                json.loads(sub_evidence['value'])['complianceType'],
                                org_id,
                                org_name
                            ])
                    else:
                        if 'value' not in item['resourcesIncluded'][0]:
                            rows.append([
                                item['evidenceAwsAccountId'],
                                item['dataSource'],
                                controlsetid,
                                controlid,
                                item['time'].strftime("%m/%d/%Y %H:%M:%S %Z"),
                                'None',
                                'None',
                                'NOT_APPLICABLE',
                                org_id,
                                org_name
                            ])
                        else:
                            rows.append([
                                item['evidenceAwsAccountId'],
                                item['dataSource'],
                                controlsetid,
                                controlid,
                                item['time'].strftime("%m/%d/%Y %H:%M:%S %Z"),
                                json.loads(item['resourcesIncluded'][0]['value'])['complianceResourceType'],
                                json.loads(item['resourcesIncluded'][0]['value'])['complianceResourceId'],
                                json.loads(item['resourcesIncluded'][0]['value'])['complianceType'],
                                org_id,
                                org_name
                            ])
                    for row in rows:
                        count += 1
                        writer.writerow(row)
    if count > 0:
        s3.put_object(Body=csvio.getvalue(), ContentType='text/csv',
                      Bucket=os.environ['source_target_bucket'], Key=f'{datetime.datetime.today().strftime("%Y-%m-%d")}.csv')
        csvio.close()
        return json.dumps("success", default=str)
    else:
        csvio.close()
        return json.dumps("Nothing to write", default=str)


def get_assessments(filter: str = None) -> list:
    """Get list of all assessements if filter not provided.
    If filter is provided return the single assessement. Filter
    corresponds to assessment name.
    """
    try:
        assessements = auditManagerClient.list_assessments(status='ACTIVE')
    except (ValueError, TypeError) as err:
        logging.error('Error at %s', 'list_assessments', exc_info=err)
        results = []
    else:
        results = assessements['assessmentMetadata']
        print(results)
    if filter is not None and len(results) != 0:
        filtered_results = []
        for item in results:
            if item['name'] == filter:
                filtered_results.append(item)
        return filtered_results
    return results


def get_evidence_folders_by_assessment_id(id: str) -> list:
    """Get list of all evidence folders for an assessment."""
    try:
        response = auditManagerClient.get_evidence_folders_by_assessment(
            assessmentId=id,
            maxResults=1000
        )
    except (ValueError, TypeError) as err:
        logging.error('Error at %s', 'get_evidence_folders_by_assessment', exc_info=err)
        results = []
    else:
        results = response['evidenceFolders']
        return results


def get_evidence_by_evidence_folders(assessementid: str, controlsetid: str, folderid: str) -> list:
    """Get list of all evidence for an evidence folder."""
    try:
        response_evidence_folder = auditManagerClient.get_evidence_by_evidence_folder(
            assessmentId=assessementid,
            controlSetId=controlsetid,
            evidenceFolderId=folderid,
            maxResults=500
        )
    except (ValueError, TypeError) as err:
        logging.error('Error at %s', 'get_evidence_by_evidence_folder', exc_info=err)
        results = []
    else:
        results = response_evidence_folder['evidence']
        return results
