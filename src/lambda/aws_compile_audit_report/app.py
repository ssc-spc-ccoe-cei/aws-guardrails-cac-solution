""" Compile Audit Report """

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
import botocore.exceptions

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from utils import get_cloud_profile_from_tags
from boto_util.client import get_client
from boto_util.organizations import get_account_tags

# CONFIGURATION
def get_required_env_var(name: str) -> str:
    """Retrieve an environment variable or raise an error if missing."""
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
    "MAX_CONCURRENCY": int(os.environ.get("MAX_CONCURRENCY", "2")),
    "TIME_LIMIT_BUFFER_SEC": 30,
    "MAX_RETRIES": 3,
    "CHUNK_FILE_PREFIX": "chunk_",
    "STATE_FILE_NAME": "processing_state.json",
    "DATE_FORMAT": "%Y-%m-%d",  # For final S3 object naming
}

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

ACCOUNT_TAGS_CACHE = {}

def create_boto3_clients():
    return {
        "auditmanager": boto3.client("auditmanager"),
        "s3": boto3.client("s3"),
        "lambda": boto3.client("lambda"),
        "organizations": get_client("organizations", assume_role=False)
    }


# MAIN LAMBDA HANDLER
def lambda_handler(event, context):
    logger.info("Lambda invocation started (structured).")
    clients = create_boto3_clients()
    # Initialize AWS Organizations client
    org_client = boto3.client("organizations")

    # Fetch Management Account ID
    def get_management_account_id():
        try:
            response = org_client.describe_organization()
            return response["Organization"]["MasterAccountId"]  # Older accounts use "MasterAccountId"
        except Exception as e:
            print(f"Error fetching management account ID: {e}")
            return "unknown"

    # Retrieve Management Account ID
    global management_account_id
    management_account_id = get_management_account_id()

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

# CORE PROCESSING LOGIC
def process_assessments(event, context, current_concurrency, clients):
    # Prepare a unique temp directory for this Lambda invocation
    invocation_id = event.get("invocation_id") or str(uuid.uuid4())
    temp_dir = f"/tmp/{invocation_id}"
    os.makedirs(temp_dir, exist_ok=True)

    # Load or initialize state
    state_path = os.path.join(temp_dir, config["STATE_FILE_NAME"])
    state = load_state(state_path) or {
        "assessment_name": config["ASSESSMENT_NAME"],
        "assessment_index": 0,
        "folder_index": 0,
        "finished": False,
        "chunks_written": [],
        # Paginator positions
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
        finalize_and_cleanup_if_necessary(temp_dir, state, clients["s3"])
        return {"status": "already_finished"}

    assessment_list = list(get_all_assessments_paginated(clients["auditmanager"]))
    if not assessment_list:
        logger.info("No active assessments found.")
        state["finished"] = True
        save_state(state_path, state)
        finalize_and_cleanup_if_necessary(temp_dir, state, clients["s3"])
        return {"status": "no_assessments"}

    if state["assessment_index"] >= len(assessment_list):
        state["finished"] = True
        save_state(state_path, state)
        finalize_and_cleanup_if_necessary(temp_dir, state, clients["s3"])
        return {"status": "done"}

    # Current assessment
    current_assessment = assessment_list[state["assessment_index"]]
    assessment_id = current_assessment["id"]
    state["current_assessment_id"] = assessment_id
    save_state(state_path, state)

    # (2) Get all evidence folders for current assessment with a paginator.
    folders = list(get_all_evidence_folders_paginated(clients["auditmanager"], assessment_id))
    if not folders:
        state["assessment_index"] += 1
        state["folder_index"] = 0
        save_state(state_path, state)
        if near_time_limit(context, config["TIME_LIMIT_BUFFER_SEC"]):
            return self_invoke(clients["lambda"], event, invocation_id, current_concurrency, temp_dir, state_path)
        return process_assessments(event, context, current_concurrency, clients)

    # (3) Process folders starting from the stored folder_index
    while state["folder_index"] < len(folders):
        folder = folders[state["folder_index"]]
        control_set_id = folder["controlSetId"]
        folder_id = folder["id"]
        control_id = folder["controlName"]

        chunk_file = os.path.join(temp_dir, f"{config['CHUNK_FILE_PREFIX']}{uuid.uuid4()}.csv")

        try:
            with open(chunk_file, "w", newline="") as csvfile:
                writer = csv.writer(csvfile)
                writer.writerow(OUTPUT_HEADER)

                all_evidence = get_all_evidence_paginated(
                    clients["auditmanager"], assessment_id, control_set_id, folder_id
                )

                with concurrent.futures.ThreadPoolExecutor() as executor:
                    futures = []
                    for evidence_items in all_evidence:
                        futures.append(
                            executor.submit(
                                process_evidence_items,
                                evidence_items,
                                control_set_id,
                                control_id,
                                clients["organizations"]
                            )
                        )
                    for f in concurrent.futures.as_completed(futures):
                        for row in f.result():
                            writer.writerow(row)

            if os.path.getsize(chunk_file) > 0:
                state["chunks_written"].append(chunk_file)
            else:
                os.remove(chunk_file)

        except Exception as e:
            logger.error("Error writing partial CSV for folder %s: %s", folder_id, str(e))

        state["folder_index"] += 1
        save_state(state_path, state)

        if near_time_limit(context, config["TIME_LIMIT_BUFFER_SEC"]):
            return self_invoke(clients["lambda"], event, invocation_id, current_concurrency, temp_dir, state_path)

    state["assessment_index"] += 1
    state["folder_index"] = 0
    save_state(state_path, state)

    if state["assessment_index"] < len(assessment_list):
        if near_time_limit(context, config["TIME_LIMIT_BUFFER_SEC"]):
            return self_invoke(clients["lambda"], event, invocation_id, current_concurrency, temp_dir, state_path)
        return process_assessments(event, context, current_concurrency, clients)

    state["finished"] = True
    save_state(state_path, state)
    finalize_and_cleanup_if_necessary(temp_dir, state, clients["s3"])
    return {"status": "success"}

def safe_aws_call(fn, context_msg, *args, **kwargs):
    """Wrapper to safely call AWS functions with retries & exponential backoff."""
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
    """
    Yield active assessments via manual pagination
    """
    next_token = None
    while True:
        params = {"status": "ACTIVE"}
        if next_token:
            params["nextToken"] = next_token

        response = safe_aws_call(
            auditmanager_client.list_assessments,
            "list_assessments",
            **params
        )
        for assessment in response.get("assessmentMetadata", []):
            yield assessment

        next_token = response.get("nextToken")
        if not next_token:
            break

def get_all_evidence_folders_paginated(auditmanager_client, assessment_id):
    next_token = None
    while True:
        params = {"assessmentId": assessment_id, "maxResults": 1000}
        if next_token:
            params["nextToken"] = next_token

        response = safe_aws_call(
            auditmanager_client.get_evidence_folders_by_assessment,
            "get_evidence_folders_by_assessment",
            **params
        )
        for folder in response.get("evidenceFolders", []):
            yield folder

        next_token = response.get("nextToken")
        if not next_token:
            break

def get_all_evidence_paginated(auditmanager_client, assessment_id, control_set_id, folder_id):
    """
    Yields pages of evidence via manual pagination
    """
    next_token = None
    while True:
        params = {
            "assessmentId": assessment_id,
            "controlSetId": control_set_id,
            "evidenceFolderId": folder_id,
            "maxResults": 500
        }
        if next_token:
            params["nextToken"] = next_token

        response = safe_aws_call(
            auditmanager_client.get_evidence_by_evidence_folder,
            "get_evidence_by_evidence_folder",
            **params
        )
        yield response.get("evidence", [])

        next_token = response.get("nextToken")
        if not next_token:
            break

# EVIDENCE PROCESSING
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
    """
    Convert AWS evidence items into CSV rows, filtered to last 24 hours.
    """
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
    """Return cached tags for a given account id to reduce repeated lookups."""
    if aws_account_id in ACCOUNT_TAGS_CACHE:
        return ACCOUNT_TAGS_CACHE[aws_account_id]
    try:
        tags = get_account_tags(org_client, aws_account_id)
        ACCOUNT_TAGS_CACHE[aws_account_id] = tags
        return tags
    except Exception as e:
        logger.error("Failed to get account tags for %s: %s", aws_account_id, e)
        return {}


# STATE MANAGEMENT
def load_state(state_path):
    """Load state JSON from local file if it exists."""
    if os.path.exists(state_path):
        try:
            with open(state_path, "r") as f:
                return json.load(f)
        except (IOError, json.JSONDecodeError) as e:
            logger.error("Error loading state file %s: %s", state_path, str(e))
    return None

def save_state(state_path, state):
    """Save state as JSON to local file (atomic)."""
    try:
        with open(state_path, "w") as f:
            json.dump(state, f)
    except IOError as e:
        logger.error("Failed to save state to %s: %s", state_path, str(e))

# SELF-INVOCATION
def self_invoke(lambda_client, event, invocation_id, current_concurrency, temp_dir, state_path):
    """Re-invoke the same Lambda function with updated concurrency."""
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
    """Check if we're within `buffer_sec` seconds of Lambda's time limit."""
    return (context.get_remaining_time_in_millis() / 1000.0) < buffer_sec

# CLEANUP
def finalize_and_cleanup_if_necessary(temp_dir, state, s3_client):
    if state.get("finished"):
        logger.info("State is finished. Merging partial CSV files.")
        merged_csv = merge_chunk_files(state["chunks_written"], temp_dir)
        if merged_csv:
            final_key = f'{management_account_id}_{datetime.datetime.now(tz=datetime.timezone.utc).strftime(config["DATE_FORMAT"])}.csv'
            try:
                with open(merged_csv, "rb") as f:
                    safe_aws_call(
                        s3_client.put_object,
                        "upload_final_csv",
                        Body=f.read(),
                        ContentType="text/csv",
                        Bucket=config["SOURCE_TARGET_BUCKET"],
                        Key=final_key,
                    )
                logger.info(f"Merged CSV uploaded to S3: {final_key}")
            except Exception as e:
                logger.error("Error uploading merged CSV to S3: %s", str(e))
        cleanup_temp_directory(temp_dir)

def merge_chunk_files(chunk_files, temp_dir):
    """Stream-merge all partial CSV chunk files into a single CSV."""
    if not chunk_files:
        logger.info("No chunk files to merge.")
        return None

    merged_path = os.path.join(temp_dir, f"merged_{uuid.uuid4()}.csv")
    header_written = False

    try:
        with open(merged_path, "w", newline="") as outfile:
            writer = None
            for chunk_file in chunk_files:
                if not os.path.exists(chunk_file):
                    continue
                with open(chunk_file, "r") as infile:
                    reader = csv.reader(infile)
                    for i, row in enumerate(reader):
                        if i == 0:
                            if not header_written:
                                writer = csv.writer(outfile)
                                writer.writerow(row)
                                header_written = True
                        else:
                            writer.writerow(row)
    except IOError as e:
        logger.error("Error merging chunk files: %s", str(e))
        return None

    return merged_path

def cleanup_temp_directory(temp_dir):
    """Remove the entire temporary directory.."""
    if os.path.exists(temp_dir):
        shutil.rmtree(temp_dir, ignore_errors=True)
        logger.info("Cleaned up temp directory: %s", temp_dir)