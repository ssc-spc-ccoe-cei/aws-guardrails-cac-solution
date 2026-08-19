"""Daily GC Guardrails compliance report.

Sources compliance data from the organization AWS Config Aggregator
(deployed by ``config-aggregator.yaml``) instead of AWS Audit Manager
(which is being deprecated by AWS). Only Config rules deployed by the
solution's organization conformance pack(s) are included — those rules
are named ``gc<NN>_check_*`` (optionally with a ``_p2``/``_p3`` partition
suffix on the backing Lambda; the rule name itself is stable).

Produces the same CSV shape as the previous Audit Manager-backed
implementation so downstream consumers are unaffected.
"""

import csv
import datetime
import io
import json
import logging
import os
import re
import time
from functools import cache

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from utils import get_cloud_profile_from_tags
from boto_util.client import get_client
from boto_util.organizations import get_account_tags

def _get_cloud_profile_from_tag_str(tag_str):
    tags = json.loads(tag_str)
    return get_cloud_profile_from_tags(tags)

_get_cloud_profile_from_tag_str_cached = cache(_get_cloud_profile_from_tag_str)
_get_account_tags_cached = cache(get_account_tags)

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

def _required_env(name: str) -> str:
    v = os.environ.get(name)
    if not v:
        raise EnvironmentError(f"Required environment variable {name} is missing or empty.")
    return v


CURRENT_DT = datetime.datetime.now(tz=datetime.timezone.utc)

CONFIG = {
    "AGGREGATOR_NAME": _required_env("AGGREGATOR_NAME"),
    "CAC_VERSION": _required_env("CAC_VERSION"),
    "ORG_ID": _required_env("ORG_ID"),
    "ORG_NAME": _required_env("ORG_NAME"),
    "TENANT_ID": _required_env("TENANT_ID"),
    "SOURCE_TARGET_BUCKET": _required_env("source_target_bucket"),
    "MAX_RETRIES": 3,
    "DATE_FORMAT": "%Y-%m-%d",
    "PAGE_LIMIT": 100,  # SelectAggregateResourceConfig max
}


# Guardrail rule names look like ``gc01_check_root_mfa`` (no partition
# suffix — the suffix only exists on the backing Lambda ARN). Anchoring
# strictly to the ``gc\d\d_`` prefix guarantees we only pick up rules
# deployed by the solution's org conformance pack(s).
GUARDRAIL_RULE_RE = re.compile(r"^gc\d{2}_[a-z0-9_\-]+$")

# Maps ``gc<NN>`` prefix to the human-readable control set name used
# historically in the CSV's ``guardrail`` column. Kept in sync with the
# GC Cloud Guardrails framework groupings.
CONTROL_SET_NAMES = {
    "gc01": "01-Protect User Accounts And Identities",
    "gc02": "02-Manage Access",
    "gc03": "03-Secure Endpoints",
    "gc04": "04-Enterprise Monitoring Accounts",
    "gc05": "05-Data Location",
    "gc06": "06-Protection of Data-at-Rest",
    "gc07": "07-Protection of Data-in-Transit",
    "gc08": "08-Segment and Separate",
    "gc09": "09-Network Security Services",
    "gc10": "10-Cyber Defense Services",
    "gc11": "11-Logging and Monitoring",
    "gc12": "12-Configuration of Cloud Marketplaces",
    "gc13": "13-Plan for Continuity",
}


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


def _safe_call(fn, ctx, *args, **kwargs):
    delay = 1
    for attempt in range(1, CONFIG["MAX_RETRIES"] + 1):
        try:
            return fn(*args, **kwargs)
        except (BotoCoreError, ClientError) as e:
            logger.warning("[%s/%s] %s failed: %s", attempt, CONFIG["MAX_RETRIES"], ctx, e)
            if attempt == CONFIG["MAX_RETRIES"]:
                raise
            time.sleep(delay)
            delay *= 2


def _create_clients():
    return {
        "config": boto3.client("config"),
        "s3": boto3.client("s3"),
        "organizations": get_client("organizations", assume_role=False),
    }


def _get_management_account_id(org_client) -> str:
    resp = _safe_call(org_client.describe_organization, "describe_organization")
    return resp["Organization"]["MasterAccountId"]


def _iter_aggregate_compliance(config_client, aggregator_name: str):
    """Yield per-resource compliance rows from the org aggregator.

    Uses ``SelectAggregateResourceConfig`` against the ``AWS::Config::
    ResourceCompliance`` synthetic resource type. Each item's
    ``configuration.configRuleList`` contains one entry per Config rule
    evaluating that resource; we filter to guardrail rules and yield one
    tuple per (resource, rule) pair.
    """
    expression = (
        "SELECT accountId, awsRegion, resourceId, resourceType, "
        "configuration.targetResourceId, configuration.targetResourceType, "
        "configuration.complianceType, configuration.configRuleList "
        "WHERE resourceType = 'AWS::Config::ResourceCompliance'"
    )

    next_token = None
    while True:
        kwargs = {
            "Expression": expression,
            "ConfigurationAggregatorName": aggregator_name,
            "Limit": CONFIG["PAGE_LIMIT"],
        }
        if next_token:
            kwargs["NextToken"] = next_token

        resp = _safe_call(
            config_client.select_aggregate_resource_config,
            "select_aggregate_resource_config",
            **kwargs,
        )

        for raw in resp.get("Results", []):
            try:
                row = json.loads(raw)
            except json.JSONDecodeError:
                logger.warning("Skipping non-JSON aggregator result row.")
                continue

            account_id = row.get("accountId", "UNKNOWN")
            region = row.get("awsRegion", "")
            cfg = row.get("configuration", {}) or {}
            target_resource_id = cfg.get("targetResourceId") or row.get("resourceId") or ""
            target_resource_type = cfg.get("targetResourceType") or ""

            # Prefer per-rule complianceType from the configRuleList; fall
            # back to the top-level complianceType if the list is empty
            # (unlikely for ResourceCompliance items).
            rule_list = cfg.get("configRuleList") or []
            if not rule_list:
                continue

            for rule in rule_list:
                rule_name = rule.get("configRuleName", "")
                if not rule_name or not GUARDRAIL_RULE_RE.match(rule_name):
                    continue
                compliance = rule.get("complianceType") or cfg.get("complianceType") or "NOT_APPLICABLE"
                if compliance == "NOT_APPLICABLE":
                    continue
                yield {
                    "account_id": account_id,
                    "region": region,
                    "rule_name": rule_name,
                    "compliance": compliance,
                    "resource_id": target_resource_id,
                    "resource_type": target_resource_type,
                }

        next_token = resp.get("NextToken")
        if not next_token:
            break


def _row_from_evaluation(ev: dict, org_client, now_iso: str) -> list:
    rule_name = ev["rule_name"]
    control_set = CONTROL_SET_NAMES.get(rule_name[:4], rule_name[:4])
    tags = _get_account_tags_cached(org_client, ev["account_id"])
    cloud_profile = _get_cloud_profile_from_tag_str_cached(json.dumps(tags, sort_keys=True))
    return [
        ev["account_id"],
        str(cloud_profile.value),
        "AWS Config",
        control_set,
        rule_name,
        now_iso,
        ev["resource_type"] or "None",
        ev["resource_id"] or "None",
        ev["compliance"],
        CONFIG["ORG_ID"],
        CONFIG["ORG_NAME"],
        CONFIG["TENANT_ID"],
        CONFIG["CAC_VERSION"],
    ]


def _upload_csv(s3_client, key: str, buf: io.StringIO) -> None:
    _safe_call(
        s3_client.put_object,
        "put_object_report",
        Body=buf.getvalue().encode("utf-8"),
        ContentType="text/csv",
        Bucket=CONFIG["SOURCE_TARGET_BUCKET"],
        Key=key,
    )
    logger.info("Uploaded report to s3://%s/%s", CONFIG["SOURCE_TARGET_BUCKET"], key)


def lambda_handler(event, context):
    logger.info("aws_compile_audit_report started (aggregator=%s).", CONFIG["AGGREGATOR_NAME"])
    clients = _create_clients()

    now_iso = CURRENT_DT.isoformat()
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(OUTPUT_HEADER)

    row_count = 0
    try:
        for ev in _iter_aggregate_compliance(clients["config"], CONFIG["AGGREGATOR_NAME"]):
            writer.writerow(_row_from_evaluation(ev, clients["organizations"], now_iso))
            row_count += 1
    except (BotoCoreError, ClientError) as e:
        logger.error("Aggregator query failed: %s", e, exc_info=True)
        return {"status": "error", "message": str(e)}

    if row_count == 0:
        logger.info("No guardrail compliance rows returned by the aggregator.")

    mgmt_account_id = _get_management_account_id(clients["organizations"])
    final_key = (
        f"{mgmt_account_id}_"
        f"{datetime.datetime.now(tz=datetime.timezone.utc).strftime(CONFIG['DATE_FORMAT'])}.csv"
    )
    try:
        _upload_csv(clients["s3"], final_key, buf)
    except Exception as e:
        logger.error("Failed to upload merged CSV: %s", e, exc_info=True)
        return {"status": "error", "message": str(e)}

    return {"status": "success", "rows": row_count, "key": final_key}
