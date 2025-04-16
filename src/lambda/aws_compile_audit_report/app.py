import csv
import datetime
import io
import json
import logging
import os
import shutil
import time
import uuid
import concurrent.futures

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from utils import get_cloud_profile_from_tags
from boto_util.client import get_client
from boto_util.organizations import get_account_tags

def get_required_env_var(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise EnvironmentError(f"Required environment variable {name} is missing or empty.")
    return value

config = {
    "ASSESSMENT_NAME": get_required_env_var("ASSESSMENT_NAME"),
    "CAC_VERSION": get_required_env_var("CAC_VERSION"),
    "ORG_ID": get_required_env_var("ORG_ID"),
    "ORG_NAME": get_required_env_var("ORG_NAME"),
    "TENANT_ID": get_required_env_var("TENANT_ID"),
    "SOURCE_TARGET_BUCKET": get_required_env_var("source_target_bucket"),
    "MAX_CONCURRENCY": int(os.environ.get("MAX_CONCURRENCY", "10")),
    "TIME_LIMIT_BUFFER_SEC": 30,
    "MAX_RETRIES": 3,
    "CHUNK_FILE_PREFIX": "chunk_",
    "STATE_FILE_NAME": "processing_state.json",
    "DATE_FORMAT": "%Y-%m-%d",
    "STATE_S3_PREFIX": "state/",
    "CHUNK_S3_PREFIX": "chunks/",
}

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

ACCOUNT_TAGS_CACHE = {}

def get_management_account_id(org_client):
    resp = safe_aws_call(
        org_client.describe_organization,
        "describe_organization"
    )
    return resp["Organization"]["MasterAccountId"]

def create_boto3_clients():
    return {
        "auditmanager": boto3.client("auditmanager"),
        "s3": boto3.client("s3"),
        "lambda": boto3.client("lambda"),
        "organizations": get_client("organizations", assume_role=False)
    }


def lambda_handler(event, context):
    logger.info("Lambda invocation started (structured).")
    
    clients = create_boto3_clients()

    # Delete state file before proceeding
    try:
        s3 = boto3.client("s3")
        objects = s3.list_objects_v2(Bucket=config["SOURCE_TARGET_BUCKET"], Prefix="state")
        if 'Contents' in objects:
            for obj in objects['Contents']:
                s3.delete_object(Bucket=config["SOURCE_TARGET_BUCKET"], Key=obj["Key"])
               # logger.info(f"Delete complete{obj}")
    except Exception as e:
        logger.info("Failed to delete S3 states folder: %s", str(e))
 
    # Delete Chunk files before proceeding

    try:
        s3 = boto3.client("s3")
        objects = s3.list_objects_v2(Bucket=config["SOURCE_TARGET_BUCKET"], Prefix="chunks")
        if 'Contents' in objects:
            for obj in objects['Contents']:
                s3.delete_object(Bucket=config["SOURCE_TARGET_BUCKET"], Key=obj["Key"])
               # logger.info(f"Delete complete{obj}")
    except Exception as e:
        logger.info("Failed to delete S3 chunks folder: %s", str(e))

    # Handle concurrency limit
    current_concurrency = event.get("current_concurrency", 1)
    if current_concurrency > config["MAX_CONCURRENCY"]:
        logger.warning("Max concurrency reached (%s). Aborting this branch.", current_concurrency)
        return {"status": "aborted_due_to_max_concurrency"}

    try:
        result = process_assessments(event, context, current_concurrency, clients)
        logger.info("Lambda finished with status: %s", result.get("status"))
        return result
    except Exception as e:
        logger.error("Unexpected error in lambda_handler: %s", str(e), exc_info=True)
        return {"status": "error", "message": str(e)}


def process_assessments(event, context, current_concurrency, clients):
    # Prepare a unique temp directory for this Lambda invocation
    invocation_id = event.get("invocation_id") or str(uuid.uuid4())
    temp_dir = f"/tmp/{invocation_id}"
    os.makedirs(temp_dir, exist_ok=True)

    # Load state from S3
    state = load_state_from_s3(clients["s3"]) or {
        "assessment_name": config["ASSESSMENT_NAME"],
        "assessment_index": 0,
        "folder_index": 0,
        "finished": False,
        "chunks_written": [],
        "assessments_done": False,
        "folders_done": False,
        "current_assessment_id": None,
    }

    logger.info(
        "Starting process with state => assessment_index: %d, folder_index: %d, finished: %s",
        state["assessment_index"],
        state["folder_index"],
        state["finished"]
    )

    if state["finished"]:
        # If state indicates we're done, do final merge check or skip
        return finalize_and_cleanup_if_necessary(temp_dir, state, clients)

    assessment_lists = list(get_all_assessments_paginated(clients["auditmanager"]))
    assessment_list = [assessment for assessment in assessment_lists if assessment['name'] == config["ASSESSMENT_NAME"]]
    logger.info(assessment_list)
    if not assessment_list:
        logger.info("No active assessments found.")
        state["finished"] = True
        save_state_to_s3(clients["s3"], state)
        return finalize_and_cleanup_if_necessary(temp_dir, state, clients)

    # If we've already processed all assessments, mark finished
    if state["assessment_index"] >= len(assessment_list):
        state["finished"] = True
        save_state_to_s3(clients["s3"], state)
        return finalize_and_cleanup_if_necessary(temp_dir, state, clients)

    current_assessment = assessment_list[state["assessment_index"]]
    assessment_id = current_assessment["id"]
    state["current_assessment_id"] = assessment_id
    save_state_to_s3(clients["s3"], state)

    folders = list(get_all_evidence_folders_paginated(clients["auditmanager"], assessment_id))
    if not folders:
        state["assessment_index"] += 1
        state["folder_index"] = 0
        save_state_to_s3(clients["s3"], state)
        if near_time_limit(context, config["TIME_LIMIT_BUFFER_SEC"]):
            return self_invoke(clients["lambda"], event, invocation_id, current_concurrency)
        # Continue to next assessment
        return process_assessments(event, context, current_concurrency, clients)

    while state["folder_index"] < len(folders):
        folder = folders[state["folder_index"]]
        control_set_id = folder["controlSetId"]
        folder_id = folder["id"]
        control_id = folder["controlName"]

        chunk_file_local = os.path.join(temp_dir, f"{config['CHUNK_FILE_PREFIX']}{uuid.uuid4()}.csv")

        try:
            with open(chunk_file_local, "w", newline="") as csvfile:
                writer = csv.writer(csvfile)
                writer.writerow(OUTPUT_HEADER)
                # Log the creation of the chunk file
                logger.info(f"Created chunk file at {chunk_file_local}")


                all_evidence_pages = get_all_evidence_paginated(
                    clients["auditmanager"], assessment_id, control_set_id, folder_id
                )

                with concurrent.futures.ThreadPoolExecutor() as executor:
                    futures = []
                    for evidence_page in all_evidence_pages:
                        futures.append(
                            executor.submit(
                                process_evidence_items,
                                evidence_page,
                                control_set_id,
                                control_id,
                                clients["organizations"]
                            )
                        )
                    for f in concurrent.futures.as_completed(futures):
                        for row in f.result():
                            writer.writerow(row)

            # Upload chunk file to S3, then remove it locally
            if os.path.getsize(chunk_file_local) > 0:
                chunk_s3_key = f'{config["CHUNK_S3_PREFIX"]}{uuid.uuid4()}.csv'
                upload_chunk_to_s3(clients["s3"], chunk_file_local, chunk_s3_key)
                # Track S3 key in state
                state["chunks_written"].append(chunk_s3_key)
            os.remove(chunk_file_local)

        except Exception as e:
            logger.error("Error writing partial CSV for folder %s: %s", folder_id, str(e))

        state["folder_index"] += 1
        save_state_to_s3(clients["s3"], state)

        if near_time_limit(context, config["TIME_LIMIT_BUFFER_SEC"]):
            return self_invoke(clients["lambda"], event, invocation_id, current_concurrency)

    state["assessment_index"] += 1
    state["folder_index"] = 0
    save_state_to_s3(clients["s3"], state)

    if state["assessment_index"] < len(assessment_list):
        if near_time_limit(context, config["TIME_LIMIT_BUFFER_SEC"]):
            return self_invoke(clients["lambda"], event, invocation_id, current_concurrency)
        return process_assessments(event, context, current_concurrency, clients)

    # Mark finished
    state["finished"] = True
    save_state_to_s3(clients["s3"], state)
    return finalize_and_cleanup_if_necessary(temp_dir, state, clients)

def safe_aws_call(fn, context_msg, *args, **kwargs):
    delay = 1
    for attempt in range(1, config["MAX_RETRIES"] + 1):
        try:
            return fn(*args, **kwargs)
        except (BotoCoreError, ClientError) as e:
            logger.warning(
                "[Attempt %s/%s] AWS call failed (%s): %s",
                attempt,
                config["MAX_RETRIES"],
                context_msg,
                str(e)
            )
            if attempt == config["MAX_RETRIES"]:
                logger.error("Max retries reached for %s. Raising exception.", context_msg)
                raise
            time.sleep(delay)
            delay *= 2
def get_all_assessments_paginated(auditmanager_client):
    next_token = None
    while True:
        if not next_token:
            resp = safe_aws_call(
                auditmanager_client.list_assessments,
                "list_assessments",
                status="ACTIVE"
            )
        else:
            resp = safe_aws_call(
                auditmanager_client.list_assessments,
                "list_assessments",
                status="ACTIVE",
                nextToken=next_token
            )

        for assessment in resp.get("assessmentMetadata", []):
            yield assessment

        next_token = resp.get("nextToken")
        if not next_token:
            break

def get_all_evidence_folders_paginated(auditmanager_client, assessment_id):
    """Manually paginate get_evidence_folders_by_assessment."""
    next_token = None
    while True:
        if not next_token:
            resp = safe_aws_call(
                auditmanager_client.get_evidence_folders_by_assessment,
                "get_evidence_folders_by_assessment",
                assessmentId=assessment_id,
                maxResults=1000
            )
        else:
            resp = safe_aws_call(
                auditmanager_client.get_evidence_folders_by_assessment,
                "get_evidence_folders_by_assessment",
                assessmentId=assessment_id,
                maxResults=1000,
                nextToken=next_token
            )

        for folder in resp.get("evidenceFolders", []):
            yield folder

        next_token = resp.get("nextToken")
        if not next_token:
            break

def get_all_evidence_paginated(auditmanager_client, assessment_id, control_set_id, folder_id):
    next_token = None
    while True:
        if not next_token:
            resp = safe_aws_call(
                auditmanager_client.get_evidence_by_evidence_folder,
                "get_evidence_by_evidence_folder",
                assessmentId=assessment_id,
                controlSetId=control_set_id,
                evidenceFolderId=folder_id,
                maxResults=500
            )
        else:
            resp = safe_aws_call(
                auditmanager_client.get_evidence_by_evidence_folder,
                "get_evidence_by_evidence_folder",
                assessmentId=assessment_id,
                controlSetId=control_set_id,
                evidenceFolderId=folder_id,
                maxResults=500,
                nextToken=next_token
            )

        yield resp.get("evidence", [])

        next_token = resp.get("nextToken")
        if not next_token:
            break

OUTPUT_HEADER = [
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
    "azureTenantId",
    "cacVersion",
]

def process_evidence_items(evidence_items, control_set_id, control_id, org_client):
    rows = []
    cutoff = datetime.datetime.now(tz=datetime.timezone.utc) - datetime.timedelta(days=1)

    for item in evidence_items:
        evidence_time = item.get("time")
        if evidence_time and evidence_time > cutoff:
            aws_account_id = item.get("evidenceAwsAccountId", "UNKNOWN")
            tags = get_account_tags_cached(org_client, aws_account_id)
            cloud_profile = get_cloud_profile_from_tags(tags)
            data_source = item.get("dataSource", "UNKNOWN")
            time_str = evidence_time.astimezone(datetime.timezone.utc).isoformat()

            resources = item.get("resourcesIncluded", [])
            if not resources:
                rows.append([
                    aws_account_id,
                    str(cloud_profile.value),
                    data_source,
                    control_set_id,
                    control_id,
                    time_str,
                    "None",
                    "None",
                    "NOT_APPLICABLE",
                    config["ORG_ID"],
                    config["ORG_NAME"],
                    config["TENANT_ID"],
                    config["CAC_VERSION"],
                ])
            else:
                for r in resources:
                    val = r.get("value")
                    if not val:
                        rows.append([
                            aws_account_id,
                            str(cloud_profile.value),
                            data_source,
                            control_set_id,
                            control_id,
                            time_str,
                            "None",
                            "None",
                            "NOT_APPLICABLE",
                            config["ORG_ID"],
                            config["ORG_NAME"],
                            config["TENANT_ID"],
                            config["CAC_VERSION"],
                        ])
                    else:
                        try:
                            val_json = json.loads(val)
                        except json.JSONDecodeError:
                            val_json = {}

                        rows.append([
                            aws_account_id,
                            str(cloud_profile.value),
                            data_source,
                            control_set_id,
                            control_id,
                            time_str,
                            val_json.get("complianceResourceType", "None"),
                            val_json.get("complianceResourceId", "None"),
                            val_json.get("complianceType", "NOT_APPLICABLE"),
                            config["ORG_ID"],
                            config["ORG_NAME"],
                            config["TENANT_ID"],
                            config["CAC_VERSION"],
                        ])
    return rows

def get_account_tags_cached(org_client, aws_account_id):
    if aws_account_id in ACCOUNT_TAGS_CACHE:
        return ACCOUNT_TAGS_CACHE[aws_account_id]
    try:
        tags = get_account_tags(org_client, aws_account_id)
        ACCOUNT_TAGS_CACHE[aws_account_id] = tags
        return tags
    except Exception as e:
        logger.error("Failed to get account tags for %s: %s", aws_account_id, e)
        return {}


def load_state_from_s3(s3_client):
    try:
        resp = s3_client.get_object(Bucket=config["SOURCE_TARGET_BUCKET"],
                                    Key=config["STATE_S3_PREFIX"] + config["STATE_FILE_NAME"])
        body = resp["Body"].read()
        return json.loads(body)
    except s3_client.exceptions.NoSuchKey:
        logger.info("No existing state file in S3 yet.")
        return None
    except (ClientError, json.JSONDecodeError) as e:
        logger.error("Error reading state file from S3: %s", e)
        return None

def save_state_to_s3(s3_client, state):
    try:
        body = json.dumps(state).encode("utf-8")
        safe_aws_call(
            s3_client.put_object,
            "upload_state_json",
            Body=body,
            ContentType="application/json",
            Bucket=config["SOURCE_TARGET_BUCKET"],
            Key=config["STATE_S3_PREFIX"] + config["STATE_FILE_NAME"],
        )
    except Exception as e:
        logger.error("Failed to save state to S3: %s", str(e))


def self_invoke(lambda_client, event, invocation_id, current_concurrency):
    try:
        new_event = {
            **event,
            "invocation_id": invocation_id,
            "current_concurrency": current_concurrency + 1
        }
        lambda_client.invoke(
            FunctionName=os.environ["AWS_LAMBDA_FUNCTION_NAME"],
            InvocationType="Event",
            Payload=json.dumps(new_event),
        )
        logger.info("Self-invoked with concurrency: %d -> %d", current_concurrency, current_concurrency + 1)
        return {"status": "self_invoked", "concurrency": current_concurrency + 1}
    except (BotoCoreError, ClientError) as e:
        logger.error("Error self-invoking Lambda: %s", str(e), exc_info=True)
        return {"status": "error_self_invoke", "message": str(e)}

def near_time_limit(context, buffer_sec):
    return (context.get_remaining_time_in_millis() / 1000.0) < buffer_sec


def upload_chunk_to_s3(s3_client, local_path, s3_key):
    with open(local_path, "rb") as f:
        safe_aws_call(
            s3_client.put_object,
            "upload_chunk",
            Body=f.read(),
            ContentType="text/csv",
            Bucket=config["SOURCE_TARGET_BUCKET"],
            Key=s3_key,
        )
    logger.info(f"Uploaded chunk to s3://{config['SOURCE_TARGET_BUCKET']}/{s3_key}")

def download_chunk_from_s3(s3_client, s3_key, local_path):
    resp = safe_aws_call(
        s3_client.get_object,
        "download_chunk",
        Bucket=config["SOURCE_TARGET_BUCKET"],
        Key=s3_key
    )
    with open(local_path, "wb") as f:
        f.write(resp["Body"].read())


def finalize_and_cleanup_if_necessary(temp_dir, state, clients):
    if not state.get("finished"):
        logger.info("Not finished yet, skipping final merge.")
        return {"status": "in_progress"}

    if not state["chunks_written"]:
        logger.info("No chunk files to merge. Nothing to finalize.")
        cleanup_temp_directory(temp_dir)
        return {"status": "done_no_chunks"}

    logger.info("All tasks done. Performing final CSV merge from S3 chunk objects.")

    mgmt_account_id = get_management_account_id(clients["organizations"])
    merged_csv_local = merge_chunk_files_in_s3(state["chunks_written"], temp_dir, clients["s3"])
    if merged_csv_local:
        final_key = (
            f"{mgmt_account_id}_"
            f"{datetime.datetime.now(tz=datetime.timezone.utc).strftime(config['DATE_FORMAT'])}.csv"
        )
        try:
            with open(merged_csv_local, "rb") as f:
                safe_aws_call(
                    clients["s3"].put_object,
                    "upload_final_csv",
                    Body=f.read(),
                    ContentType="text/csv",
                    Bucket=config["SOURCE_TARGET_BUCKET"],
                    Key=final_key,
                )
            logger.info(f"Merged CSV uploaded to s3://{config['SOURCE_TARGET_BUCKET']}/{final_key}")
        except Exception as e:
            logger.error("Error uploading merged CSV to S3: %s", str(e))

    cleanup_temp_directory(temp_dir)
    return {"status": "success"}

def merge_chunk_files_in_s3(chunk_keys, temp_dir, s3_client):
    if not chunk_keys:
        logger.info("No chunk files to merge.")
        return None

    merged_path = os.path.join(temp_dir, f"merged_{uuid.uuid4()}.csv")
    header_written = False

    try:
        with open(merged_path, "w", newline="") as outfile:
            writer = None

            for s3_key in chunk_keys:
                chunk_local_path = os.path.join(temp_dir, f"chunk_{uuid.uuid4()}.csv")
                download_chunk_from_s3(s3_client, s3_key, chunk_local_path)

                with open(chunk_local_path, "r") as infile:
                    reader = csv.reader(infile)
                    for i, row in enumerate(reader):
                        if i == 0:
                            if not header_written:
                                writer = csv.writer(outfile)
                                writer.writerow(row)
                                header_written = True
                        else:
                            writer.writerow(row)

                os.remove(chunk_local_path)
        return merged_path
    except IOError as e:
        logger.error("Error merging chunk files: %s", str(e))
        return None

def cleanup_temp_directory(temp_dir):
    if os.path.exists(temp_dir):
        shutil.rmtree(temp_dir, ignore_errors=True)
        logger.info("Cleaned up temp directory: %s", temp_dir)
