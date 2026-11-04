""" GC10 - check Cyber Center Sensors

Confirms that the Canadian Centre for Cyber Security (CCCS) Cloud Based Sensor
(CBS) is in place, per GC Guardrail 10 - Cyber Defence Services.

Two assessments are performed:

1. In every account, the CBS reader role is checked for existence, for a trust
   policy that admits a principal from the CBS account, and for its required
   managed policies.

2. In the Log Archive account, every bucket named in the ``S3LogBucketsPath``
   evidence file is checked for an enabled, unfiltered replication rule whose
   destination is owned by the CBS account, along with the permissions of the
   IAM role that replication uses.
"""

import fnmatch
import json
import logging
from urllib.parse import unquote

import botocore.exceptions

from utils import (
    is_scheduled_notification,
    check_required_parameters,
    check_guardrail_requirement_by_cloud_usage_profile,
    get_cloud_profile_from_tags,
    GuardrailType,
    GuardrailRequirementType,
)
from boto_util.organizations import organizations_list_all_accounts, get_account_tags
from boto_util.client import get_client
from boto_util.config import build_evaluation, submit_evaluations
from boto_util.s3 import list_all_s3_buckets, get_lines_from_s3_file, check_s3_object_exists

# Logging setup
logger = logging.getLogger()
logger.setLevel(logging.INFO)


# ---------------------------------------------------------------------------
# Permissions S3 replication requires. Values that vary per deployment (the
# CBS account id, role name and required managed policies) are supplied as
# Config rule parameters and have no defaults here - see the module README.
# ---------------------------------------------------------------------------

# Permissions required on the SOURCE bucket for S3 replication to function.
# Without these, replication silently fails for every object.
SOURCE_REQUIRED_BUCKET_ACTIONS = ["s3:ListBucket", "s3:GetReplicationConfiguration"]
SOURCE_REQUIRED_OBJECT_ACTIONS = ["s3:GetObjectVersionForReplication"]
# Needed only when ACLs / tags / Object Lock are in play. Reported as advisory
# so a working configuration is not failed for permissions it never exercises.
SOURCE_RECOMMENDED_OBJECT_ACTIONS = [
    "s3:GetObjectVersionAcl",
    "s3:GetObjectVersionTagging",
    "s3:GetObjectRetention",
    "s3:GetObjectLegalHold",
]
# Permissions required on the DESTINATION bucket.
DEST_REQUIRED_OBJECT_ACTIONS = ["s3:ReplicateObject", "s3:ReplicateDelete"]
DEST_RECOMMENDED_OBJECT_ACTIONS = [
    "s3:ReplicateTags",
    "s3:ObjectOwnerOverrideToBucketOwner",
]
# KMS grants are only required when the buckets use SSE-KMS. Advisory only -
# we cannot tell from the replication configuration alone whether the source
# or destination is KMS encrypted without access into the CBS account.
RECOMMENDED_KMS_ACTIONS = ["kms:Decrypt", "kms:Encrypt"]


def s3_get_bucket_replication(s3_client, bucket_name) -> tuple[dict, None] | tuple[None, str]:
    try:
        response = s3_client.get_bucket_replication(Bucket=bucket_name)
        return response["ReplicationConfiguration"], None
    except botocore.exceptions.ClientError as e:
        return None, e.response["Error"]["Message"]


def bucket_name_from_arn(bucket_arn: str) -> str:
    """``arn:aws:s3:::my-bucket`` -> ``my-bucket``. Returns "" when unparseable."""
    if not bucket_arn:
        return ""
    return bucket_arn.split(":::")[-1].split("/")[0]


def as_list(value) -> list:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def iam_pattern_matches(pattern: str, value: str, case_sensitive: bool = True) -> bool:
    """Match an IAM pattern (``*`` / ``?`` wildcards) against a value.

    ``fnmatch`` also treats ``[...]`` as a character class, which IAM does not,
    but neither IAM action names nor S3 bucket ARNs contain square brackets so
    the difference is not reachable here.
    """
    if not isinstance(pattern, str) or not isinstance(value, str):
        return False
    if not case_sensitive:
        pattern, value = pattern.lower(), value.lower()
    return fnmatch.fnmatchcase(value, pattern)


def normalize_policy_document(document) -> dict:
    """IAM returns policy documents as dicts or as URL-encoded JSON strings."""
    if isinstance(document, dict):
        return document
    if isinstance(document, str):
        try:
            return json.loads(document)
        except json.JSONDecodeError:
            try:
                return json.loads(unquote(document))
            except (json.JSONDecodeError, TypeError):
                return {}
    return {}


def rule_replicates_everything(rule: dict) -> bool:
    """True when the rule is scoped to the whole bucket rather than a subset.

    Handles both the V1 schema (top level ``Prefix``) and the V2 schema
    (``Filter``). ``Filter: {}`` and ``Filter: {"Prefix": ""}`` are the V2 ways
    of expressing "replicate everything" and must be treated as compliant - the
    previous implementation rejected both, producing false negatives.
    """
    if rule.get("Prefix"):
        return False

    if "Filter" not in rule:
        return True

    rule_filter = rule.get("Filter") or {}
    if not rule_filter:
        return True
    if rule_filter.get("Prefix") or rule_filter.get("Tag"):
        return False
    rule_and = rule_filter.get("And") or {}
    if rule_and.get("Prefix") or rule_and.get("Tags"):
        return False
    return True


def rule_targets_cbs(rule: dict, cbs_account_id: str) -> bool:
    """True when the rule's destination belongs to the Cyber Centre.

    Matches on ``Destination.Account`` - an explicit statement of the
    destination bucket owner - rather than the destination bucket name, which
    is not authoritative.
    """
    destination = rule.get("Destination") or {}
    return destination.get("Account", "") == cbs_account_id


def find_cbs_replication_rule(config: dict, cbs_account_id: str) -> tuple[dict | None, str]:
    """Return the first enabled, unfiltered rule that replicates to CBS.

    The second element is a short reason describing the closest near-miss,
    which is surfaced in the Config annotation so the failure is actionable.
    """
    rules: list[dict] = config.get("Rules", []) or []
    if not rules:
        return None, "the configuration contains no rules"

    reason = "no rule targets the Cyber Centre"
    for rule in rules:
        if not rule_targets_cbs(rule, cbs_account_id):
            continue
        # From here on the rule is aimed at CBS, so its defects are the
        # interesting ones to report.
        if rule.get("Status", "") != "Enabled":
            reason = f"the rule targeting the Cyber Centre is '{rule.get('Status', 'unknown')}', not 'Enabled'"
            continue
        if not rule_replicates_everything(rule):
            reason = "the rule targeting the Cyber Centre is scoped by a prefix or tag filter"
            continue
        return rule, ""

    return None, reason


def get_role_allow_statements(iam_client, role_name: str) -> tuple[list[dict], bool]:
    """Collect Allow statements from a role's inline and attached policies.

    Returns ``(statements, indeterminate)``. ``indeterminate`` is True when a
    statement uses ``NotAction``/``NotResource``, or a policy could not be
    read. In that case the caller must not assert on permissions, because we
    cannot soundly evaluate the role and would risk a false NON_COMPLIANT.
    """
    statements: list[dict] = []
    indeterminate = False
    documents: list[dict] = []

    try:
        paginator = iam_client.get_paginator("list_role_policies")
        for page in paginator.paginate(RoleName=role_name):
            for policy_name in page.get("PolicyNames", []):
                response = iam_client.get_role_policy(RoleName=role_name, PolicyName=policy_name)
                documents.append(normalize_policy_document(response.get("PolicyDocument")))
    except botocore.exceptions.ClientError as e:
        logger.warning("Unable to list inline policies for role '%s': %s", role_name, e)
        indeterminate = True

    try:
        paginator = iam_client.get_paginator("list_attached_role_policies")
        for page in paginator.paginate(RoleName=role_name):
            for policy in page.get("AttachedPolicies", []):
                policy_arn = policy.get("PolicyArn", "")
                try:
                    policy_meta = iam_client.get_policy(PolicyArn=policy_arn)["Policy"]
                    version = iam_client.get_policy_version(
                        PolicyArn=policy_arn, VersionId=policy_meta["DefaultVersionId"]
                    )["PolicyVersion"]
                    documents.append(normalize_policy_document(version.get("Document")))
                except botocore.exceptions.ClientError as e:
                    logger.warning("Unable to read managed policy '%s': %s", policy_arn, e)
                    indeterminate = True
    except botocore.exceptions.ClientError as e:
        logger.warning("Unable to list attached policies for role '%s': %s", role_name, e)
        indeterminate = True

    for document in documents:
        for statement in as_list(document.get("Statement")):
            if not isinstance(statement, dict):
                continue
            if statement.get("Effect") != "Allow":
                continue
            if "NotAction" in statement or "NotResource" in statement:
                indeterminate = True
                continue
            statements.append(statement)

    return statements, indeterminate


def statements_allow(statements: list[dict], action: str, resource_arn: str) -> bool:
    """True when any Allow statement grants ``action`` on ``resource_arn``.

    Deny statements are deliberately ignored: this is a "are the grants
    present" check, not a full policy simulation.
    """
    for statement in statements:
        if not any(iam_pattern_matches(p, action, case_sensitive=False) for p in as_list(statement.get("Action"))):
            continue
        if any(iam_pattern_matches(p, resource_arn) for p in as_list(statement.get("Resource"))):
            return True
    return False


def statements_allow_action(statements: list[dict], action: str) -> bool:
    """True when any Allow statement mentions ``action`` on any resource."""
    return any(
        any(iam_pattern_matches(p, action, case_sensitive=False) for p in as_list(s.get("Action")))
        for s in statements
    )


def missing_actions(statements: list[dict], actions: list[str], resource_arn: str) -> list[str]:
    return [a for a in actions if not statements_allow(statements, a, resource_arn)]


def trust_policy_allows_service(trust_policy: dict, service: str) -> bool:
    for statement in as_list(trust_policy.get("Statement")):
        if not isinstance(statement, dict) or statement.get("Effect") != "Allow":
            continue
        principal = statement.get("Principal") or {}
        if isinstance(principal, str):
            if principal == "*":
                return True
            continue
        if service in as_list(principal.get("Service")):
            return True
    return False


def trust_policy_allows_account(trust_policy: dict, account_id: str) -> bool:
    """True when any Allow statement trusts a principal in ``account_id``."""
    for statement in as_list(trust_policy.get("Statement")):
        if not isinstance(statement, dict) or statement.get("Effect") != "Allow":
            continue
        principal = statement.get("Principal") or {}
        if isinstance(principal, str):
            principal = {"AWS": principal}
        for aws_principal in as_list(principal.get("AWS")):
            # Accepts the bare account id, ``arn:aws:iam::<id>:root`` and any
            # role/user ARN within the account.
            if aws_principal == account_id or f":{account_id}:" in str(aws_principal):
                return True
    return False


def assess_replication_role(
    iam_client, role_arn: str, source_bucket: str, destination_bucket_arn: str
) -> tuple[list[str], list[str]]:
    """Assess the IAM role used by a replication configuration.

    Returns ``(required_problems, advisory_problems)``. Only the first list
    affects compliance; the second is logged so operators can harden a
    configuration that currently works by luck.
    """
    required_problems: list[str] = []
    advisory_problems: list[str] = []

    if not role_arn:
        return ["the replication configuration does not specify an IAM role"], advisory_problems

    role_name = role_arn.split("/")[-1]

    try:
        role = iam_client.get_role(RoleName=role_name)["Role"]
    except botocore.exceptions.ClientError as e:
        if "NoSuchEntity" in e.response["Error"]["Code"]:
            return [f"the replication role '{role_name}' does not exist"], advisory_problems
        logger.warning("Unable to read replication role '%s': %s", role_name, e)
        advisory_problems.append(f"the replication role '{role_name}' could not be read")
        return required_problems, advisory_problems

    # S3 must be able to assume the role, otherwise replication never starts.
    trust_policy = normalize_policy_document(role.get("AssumeRolePolicyDocument"))
    if not trust_policy_allows_service(trust_policy, "s3.amazonaws.com"):
        required_problems.append(f"the replication role '{role_name}' is not assumable by s3.amazonaws.com")

    statements, indeterminate = get_role_allow_statements(iam_client, role_name)
    if indeterminate:
        # Do not assert on permissions we could not soundly evaluate.
        advisory_problems.append(f"the permissions of replication role '{role_name}' could not be fully evaluated")
        return required_problems, advisory_problems

    source_bucket_arn = f"arn:aws:s3:::{source_bucket}"
    source_objects_arn = f"{source_bucket_arn}/an-object"
    destination_objects_arn = f"{destination_bucket_arn}/an-object" if destination_bucket_arn else ""

    missing = missing_actions(statements, SOURCE_REQUIRED_BUCKET_ACTIONS, source_bucket_arn)
    missing += missing_actions(statements, SOURCE_REQUIRED_OBJECT_ACTIONS, source_objects_arn)
    if missing:
        required_problems.append(f"role '{role_name}' is missing {', '.join(sorted(set(missing)))} on the source")

    advisory = missing_actions(statements, SOURCE_RECOMMENDED_OBJECT_ACTIONS, source_objects_arn)

    if destination_objects_arn:
        missing_dest = missing_actions(statements, DEST_REQUIRED_OBJECT_ACTIONS, destination_objects_arn)
        if missing_dest:
            required_problems.append(
                f"role '{role_name}' is missing {', '.join(sorted(set(missing_dest)))} on the destination"
            )
        advisory += missing_actions(statements, DEST_RECOMMENDED_OBJECT_ACTIONS, destination_objects_arn)
    else:
        advisory_problems.append("the replication destination bucket could not be determined")

    # KMS is advisory: we cannot see whether either bucket is SSE-KMS encrypted.
    advisory += [a for a in RECOMMENDED_KMS_ACTIONS if not statements_allow_action(statements, a)]

    if advisory:
        advisory_problems.append(f"role '{role_name}' does not grant {', '.join(sorted(set(advisory)))}")

    return required_problems, advisory_problems


def assess_cbs_reader_role(
    iam_client,
    account_id: str,
    role_name: str,
    cbs_account_id: str,
    required_managed_policy_arns: list[str],
    event: dict,
) -> tuple[dict, bool]:
    """Assess the CBS reader role in the account currently being evaluated."""
    resource_type = "AWS::IAM::Role"
    problems: list[str] = []

    try:
        role = iam_client.get_role(RoleName=role_name)["Role"]
    except botocore.exceptions.ClientError as e:
        if "NoSuchEntity" in e.response["Error"]["Code"]:
            annotation = f"The role '{role_name}' does not exist in account '{account_id}'."
            logger.info("NON_COMPLIANT: %s", annotation)
            return build_evaluation(role_name, "NON_COMPLIANT", event, resource_type, annotation), False
        raise

    trust_policy = normalize_policy_document(role.get("AssumeRolePolicyDocument"))
    if cbs_account_id and not trust_policy_allows_account(trust_policy, cbs_account_id):
        problems.append(f"its trust policy does not admit a principal from Cyber Centre account {cbs_account_id}")

    if required_managed_policy_arns:
        attached_arns = set()
        readable = True
        try:
            paginator = iam_client.get_paginator("list_attached_role_policies")
            for page in paginator.paginate(RoleName=role_name):
                attached_arns.update(p.get("PolicyArn", "") for p in page.get("AttachedPolicies", []))
        except botocore.exceptions.ClientError as e:
            logger.warning("Unable to list attached policies for role '%s': %s", role_name, e)
            readable = False

        if readable:
            missing_policies = [a for a in required_managed_policy_arns if a not in attached_arns]
            if missing_policies:
                problems.append(f"it is missing the policy {', '.join(missing_policies)}")

    if problems:
        annotation = f"The role '{role_name}' in account '{account_id}' is non-compliant: {'; '.join(problems)}."
        logger.info("NON_COMPLIANT: %s", annotation)
        return build_evaluation(role_name, "NON_COMPLIANT", event, resource_type, annotation), False

    annotation = f"The role '{role_name}' in account '{account_id}' is correctly configured."
    logger.info("COMPLIANT: %s", annotation)
    return build_evaluation(role_name, "COMPLIANT", event, resource_type, annotation), True


def assess_bucket_replication_policies(
    s3_client,
    iam_client,
    log_buckets: list[str],
    cbs_account_id: str,
    event: dict,
) -> tuple[list, bool]:
    resource_type = "AWS::S3::Bucket"
    evaluations = []
    all_resources_are_compliant = True

    all_buckets = [x.get("Name") for x in list_all_s3_buckets(s3_client)]
    logger.info("All Buckets: %s", all_buckets)

    for bucket_name in log_buckets:
        error = None
        advisory_problems: list[str] = []

        if bucket_name not in all_buckets:
            compliance_type = "NON_COMPLIANT"
            annotation = f"Bucket '{bucket_name}' does not exist in the log archive account."
        else:
            replication_config, error = s3_get_bucket_replication(s3_client, bucket_name)
            if error:
                compliance_type = "NON_COMPLIANT"
                annotation = f"No readable replication configuration for bucket '{bucket_name}'."
            else:
                rule, reason = find_cbs_replication_rule(replication_config, cbs_account_id)
                if not rule:
                    compliance_type = "NON_COMPLIANT"
                    annotation = f"Bucket '{bucket_name}' does not replicate to the Cyber Centre: {reason}."
                else:
                    destination_bucket_arn = (rule.get("Destination") or {}).get("Bucket", "")
                    required_problems, advisory_problems = assess_replication_role(
                        iam_client,
                        replication_config.get("Role", ""),
                        bucket_name,
                        destination_bucket_arn,
                    )
                    if required_problems:
                        compliance_type = "NON_COMPLIANT"
                        annotation = (
                            f"Bucket '{bucket_name}' replicates to the Cyber Centre but "
                            f"{'; '.join(required_problems)}."
                        )
                    else:
                        compliance_type = "COMPLIANT"
                        annotation = (
                            f"Bucket '{bucket_name}' has an enabled rule replicating all objects to "
                            f"'{bucket_name_from_arn(destination_bucket_arn)}' in the Cyber Centre account."
                        )

        if error:
            logger.info("%s: %s Error: %s", compliance_type, annotation, error)
        else:
            logger.info("%s: %s", compliance_type, annotation)
        if advisory_problems:
            logger.warning("ADVISORY for bucket '%s': %s", bucket_name, "; ".join(advisory_problems))

        evaluations.append(build_evaluation(bucket_name, compliance_type, event, resource_type, annotation))
        if compliance_type == "NON_COMPLIANT":
            all_resources_are_compliant = False

    return evaluations, all_resources_are_compliant


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

    rule_parameters = check_required_parameters(
        json.loads(event.get("ruleParameters", "{}")),
        [
            "ExecutionRoleName",
            "S3LogBucketsPath",
            "LogArchiveAccountName",
            "CBSAccountID",
            "CBSRoleName",
            "CBSRoleManagedPolicyArns",
        ],
    )
    execution_role_name = rule_parameters.get("ExecutionRoleName")
    audit_account_id = rule_parameters.get("AuditAccountID", "")
    aws_account_id = event["accountId"]
    is_not_audit_account = aws_account_id != audit_account_id

    file_param_name = "S3LogBucketsPath"
    log_buckets_s3_path = rule_parameters.get(file_param_name, "")
    log_archive_account_name = rule_parameters["LogArchiveAccountName"]

    # CBS specifics are supplied by the conformance pack, which holds the
    # canonical defaults. A missing value is a deployment error and is raised
    # loudly by check_required_parameters above rather than silently assumed.
    cbs_account_id = rule_parameters["CBSAccountID"].strip()
    cbs_role_name = rule_parameters["CBSRoleName"].strip()
    required_managed_policy_arns = [
        arn.strip() for arn in rule_parameters["CBSRoleManagedPolicyArns"].split(",") if arn.strip()
    ]

    aws_config_client = get_client("config", aws_account_id, execution_role_name, is_not_audit_account)

    # Check cloud profile. The Organizations client is the Audit account's own
    # client (no assume) because Organizations APIs are not callable from an
    # arbitrary member account.
    aws_organizations_client = get_client("organizations", assume_role=False)
    tags = get_account_tags(aws_organizations_client, aws_account_id)
    cloud_profile = get_cloud_profile_from_tags(tags)
    gr_requirement_type = check_guardrail_requirement_by_cloud_usage_profile(GuardrailType.Guardrail10, cloud_profile)

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

    evaluations: list[dict] = []
    all_resources_are_compliant = True

    ###
    # Assert that the log archive account exists
    ###
    accounts = organizations_list_all_accounts(aws_organizations_client)
    log_archive_account = next((x for x in accounts if x.get("Name", "") == log_archive_account_name), None)

    if not log_archive_account:
        annotation = f"A log archive account with name '{log_archive_account_name}' does not exist in the organization."
        logger.info("NON_COMPLIANT: %s", annotation)
        submit_evaluations(
            aws_config_client, event, [build_evaluation(aws_account_id, "NON_COMPLIANT", event, annotation=annotation)]
        )
        return

    logger.info("A log archive account with name '%s' was found: %s", log_archive_account_name, log_archive_account)

    ###
    # Assert that the CBS reader role is correctly deployed in THIS account.
    # The CBS StackSet targets every member account, so every account is
    # assessed - this is what surfaces partial/failed/outdated rollouts.
    ###
    aws_iam_client = get_client("iam", aws_account_id, execution_role_name, is_not_audit_account)
    role_evaluation, role_is_compliant = assess_cbs_reader_role(
        aws_iam_client,
        aws_account_id,
        cbs_role_name,
        cbs_account_id,
        required_managed_policy_arns,
        event,
    )
    evaluations.append(role_evaluation)
    all_resources_are_compliant = all_resources_are_compliant and role_is_compliant

    ###
    # Assert that the log buckets replicate to the Cyber Centre. Only
    # meaningful in the Log Archive account, which is where those buckets live.
    ###
    if aws_account_id == log_archive_account["Id"]:
        # The evidence file lives in the Audit account, where this Lambda runs.
        aws_s3_client_for_audit_account = get_client("s3")

        if not check_s3_object_exists(aws_s3_client_for_audit_account, log_buckets_s3_path):
            annotation = f"No file found for s3 path '{log_buckets_s3_path}' via '{file_param_name}' input parameter."
            logger.info("NON_COMPLIANT: %s", annotation)
            evaluations.append(build_evaluation(aws_account_id, "NON_COMPLIANT", event, annotation=annotation))
            submit_evaluations(aws_config_client, event, evaluations)
            return

        log_buckets = set(get_lines_from_s3_file(aws_s3_client_for_audit_account, log_buckets_s3_path))
        logger.info("log_buckets from the file in s3: %s", log_buckets)

        aws_s3_client_for_log_archive_account = get_client(
            "s3", aws_account_id, execution_role_name, is_not_audit_account
        )

        bucket_evaluations, all_s3_resources_are_compliant = assess_bucket_replication_policies(
            aws_s3_client_for_log_archive_account,
            aws_iam_client,
            log_buckets,
            cbs_account_id,
            event,
        )
        evaluations.extend(bucket_evaluations)
        all_resources_are_compliant = all_resources_are_compliant and all_s3_resources_are_compliant

    ###
    # Create account evaluation and submit evaluations
    ###
    if all_resources_are_compliant:
        compliance_type = "COMPLIANT"
        annotation = "All resources found are compliant."
    else:
        compliance_type = "NON_COMPLIANT"
        annotation = "Non-compliant resources found in scope."

    logger.info("%s: %s", compliance_type, annotation)
    evaluations.append(build_evaluation(aws_account_id, compliance_type, event, annotation=annotation))
    submit_evaluations(aws_config_client, event, evaluations)
