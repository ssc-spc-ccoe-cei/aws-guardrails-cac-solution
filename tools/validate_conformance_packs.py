"""Structural validator for the partitioned ConformancePack rollout."""
import itertools
import re
import sys
import yaml

# Number of partition slots the templates are expected to define. Must
# stay in sync with tools/validate_parts.py, main.yaml's MaxPartitions
# MaxValue, and MAX_PARTITIONS in aws_account_partitioner/app.py.
MAX_PARTITIONS = 4
PARTITIONS = list(range(1, MAX_PARTITIONS + 1))
# Partition 1 uses the base Lambda names (no suffix).
SUFFIXES = {p: ("" if p == 1 else f"_p{p}") for p in PARTITIONS}


class CfnLoader(yaml.SafeLoader):
    pass


def _ctor(tag):
    def _f(loader, node):
        if isinstance(node, yaml.ScalarNode):
            return {tag: loader.construct_scalar(node)}
        if isinstance(node, yaml.SequenceNode):
            return {tag: loader.construct_sequence(node, deep=True)}
        if isinstance(node, yaml.MappingNode):
            return {tag: loader.construct_mapping(node, deep=True)}
        return None
    return _f


for tag in [
    "Sub", "Ref", "GetAtt", "Join", "If", "Equals", "Not", "And", "Or",
    "FindInMap", "Condition", "Base64", "Select", "Split", "ImportValue",
]:
    out = tag if tag in ("Ref", "Condition") else "Fn::" + tag
    CfnLoader.add_constructor("!" + tag, _ctor(out))


ok = True


def load(path):
    with open(path) as f:
        return yaml.load(f, Loader=CfnLoader)


# ---------- ConformancePack.yaml ----------
cp = load("arch/templates/ConformancePack.yaml")
params = cp.get("Parameters", {})
ress = cp.get("Resources", {})

# 1. PartitionSuffix parameter exists with the right allowed values
ps = params.get("PartitionSuffix", {})
expected_suffixes = set(SUFFIXES.values())
if ps.get("Default") != "" or set(ps.get("AllowedValues", [])) != expected_suffixes:
    print(f"*** ConformancePack.yaml: PartitionSuffix param malformed: {ps}")
    print(f"    expected AllowedValues {sorted(expected_suffixes)}")
    ok = False
else:
    print(f"ConformancePack: PartitionSuffix parameter OK ({sorted(expected_suffixes)})")

# 2. Every Config rule must have a literal-string ConfigRuleName (NO
#    intrinsic functions), and a SourceIdentifier that still references
#    ${PartitionSuffix} (Lambda ARNs are per-partition).
#
# Why literal: AWS Config's OrganizationConformancePack template engine
# silently ignores ConfigRuleName values that contain intrinsic
# functions like !Sub, falling back to the CFN logical ID as the
# deployed rule name.  Audit Manager keywords (`Custom_<name>-
# conformance-pack`) then fail to match.  Static literals are the only
# reliable form.  Partition isolation for the rules is already
# guaranteed by ExcludedAccounts in ConformancePackPartitions.yaml.
rules = [(n, r) for n, r in ress.items() if r.get("Type") == "AWS::Config::ConfigRule"]
print(f"ConformancePack: {len(rules)} Config rules found")
bad = 0
for name, r in rules:
    props = r.get("Properties", {})
    rule_name = props.get("ConfigRuleName")
    sid = props.get("Source", {}).get("SourceIdentifier")
    # ConfigRuleName must be a literal string (e.g. "gc01_check_root_mfa")
    if not (isinstance(rule_name, str) and re.match(r"^[a-z0-9_]+$", rule_name)):
        print(f"  *** {name}: ConfigRuleName must be a literal snake_case string, got: {rule_name!r}")
        bad += 1
    # SourceIdentifier must STILL contain ${PartitionSuffix} so that
    # each partition's pack targets its own Lambda clone.
    sid_str = repr(sid)
    if "${PartitionSuffix}" not in sid_str:
        print(f"  *** {name}: SourceIdentifier missing PartitionSuffix")
        bad += 1
if bad:
    ok = False
else:
    print(f"ConformancePack: all {len(rules)} rules have literal ConfigRuleName + partition-aware SourceIdentifier")

# ---------- ConformancePackPartitions.yaml (the new nested stack) ----------
cpp = load("arch/templates/ConformancePackPartitions.yaml")
cpp_params = cpp.get("Parameters", {})
cpp_ress = cpp.get("Resources", {})
cpp_conds = cpp.get("Conditions", {})

required_resources = {f"ConformancePackP{p}" for p in PARTITIONS}
got_resources = set(cpp_ress.keys())
missing = required_resources - got_resources
if missing:
    print(f"*** ConformancePackPartitions: missing resources {missing}")
    ok = False

# Each pack must be conditional on its own HasAccountsInP* condition so a
# partition that has lost all of its accounts cleanly retires its pack
# (rather than leaving an empty pack that excludes the whole org).
expected_resource_conds = {
    f"ConformancePackP{p}": f"HasAccountsInP{p}" for p in PARTITIONS
}
for r_name, expected_cond in expected_resource_conds.items():
    r = cpp_ress.get(r_name, {})
    actual_cond = r.get("Condition")
    if actual_cond != expected_cond:
        print(f"*** ConformancePackPartitions: {r_name} Condition={actual_cond!r} (expected {expected_cond!r})")
        ok = False

# Each pack must carry the correct PartitionSuffix input parameter.
# P1 deliberately omits it and relies on the template's "" default
# (commit 4ec1404 "removed empty partition suffix") — passing an empty
# string explicitly is a no-op and just adds noise.
for p in PARTITIONS[1:]:
    r_name = f"ConformancePackP{p}"
    expected_suffix = SUFFIXES[p]
    r = cpp_ress.get(r_name, {})
    inputs = r.get("Properties", {}).get("ConformancePackInputParameters", [])
    suffix_param = next(
        (q for q in inputs if q.get("ParameterName") == "PartitionSuffix"), None,
    )
    if suffix_param is None:
        print(f"*** {r_name}: PartitionSuffix input missing")
        ok = False
    elif suffix_param.get("ParameterValue") != expected_suffix:
        print(f"*** {r_name}: PartitionSuffix={suffix_param.get('ParameterValue')!r} (expected {expected_suffix!r})")
        ok = False
# P1 must NOT pass PartitionSuffix (relies on template default "").
p1 = cpp_ress.get("ConformancePackP1", {})
p1_inputs = p1.get("Properties", {}).get("ConformancePackInputParameters", [])
if any(q.get("ParameterName") == "PartitionSuffix" for q in p1_inputs):
    print("*** ConformancePackP1: PartitionSuffix input should be omitted (template default is \"\")")
    ok = False

# Every pack must declare an ExcludedAccounts !If ladder — without it an
# account would be targeted by more than one pack.
for p in PARTITIONS:
    r = cpp_ress.get(f"ConformancePackP{p}", {})
    excl = r.get("Properties", {}).get("ExcludedAccounts")
    if not isinstance(excl, dict) or "Fn::If" not in excl:
        print(f"*** ConformancePackP{p}: ExcludedAccounts is not an !If ladder: {excl!r}")
        ok = False
    else:
        # The ladder must never reference the pack's own account list,
        # which would exclude every account the pack is meant to cover.
        if f"AccountsInP{p}" in repr(excl):
            print(f"*** ConformancePackP{p}: ExcludedAccounts references its own AccountsInP{p}")
            ok = False

print(f"ConformancePackPartitions: {len(PARTITIONS)} packs wired with correct PartitionSuffix, "
      "HasAccountsInP* condition and ExcludedAccounts ladder")

# Required empty-string conditions on each partition's account list, plus
# the AND combinations used by the ExcludedAccounts !If ladders. Each
# pack excludes the union of whichever OTHER partitions are populated, so
# every non-empty subset of size >= 2 needs its own condition.
required_conds = [f"HasAccountsInP{p}" for p in PARTITIONS]
for size in range(2, MAX_PARTITIONS):
    for combo in itertools.combinations(PARTITIONS, size):
        required_conds.append("HasAccountsIn" + "And".join(f"P{c}" for c in combo))
for c in required_conds:
    if c not in cpp_conds:
        print(f"*** ConformancePackPartitions: missing Condition {c}")
        ok = False
# Legacy PartitionCount-driven conditions must be gone.
for legacy_cond in ("HasMultiplePartitions", "HasPartition2", "HasPartition3"):
    if legacy_cond in cpp_conds:
        print(f"*** ConformancePackPartitions: legacy Condition {legacy_cond} still present")
        ok = False
print("ConformancePackPartitions: HasAccountsInP* conditions present, legacy conditions gone")

# Mappings block was retired — GC03AlarmList is now a parameter with default.
if "Mappings" in cpp:
    print(f"*** ConformancePackPartitions still has Mappings block: {list(cpp['Mappings'].keys())}")
    ok = False
gc03_param = cpp_params.get("GC03AlarmList", {})
if not gc03_param:
    print("*** ConformancePackPartitions: missing GC03AlarmList parameter")
    ok = False
elif not gc03_param.get("Default"):
    print("*** ConformancePackPartitions: GC03AlarmList parameter has no Default")
    ok = False
else:
    print("ConformancePackPartitions: GC03AlarmList is a String parameter with default (Mappings gone)")

# PartitionCount parameter must be gone (no longer consumed).
if "PartitionCount" in cpp_params:
    print("*** ConformancePackPartitions: PartitionCount parameter still declared (no longer used)")
    ok = False
else:
    print("ConformancePackPartitions: PartitionCount parameter removed")

# ---------- main.yaml ----------
main = load("arch/templates/main.yaml")
main_ress = main.get("Resources", {})

# Logical ID is ConformancePackStack (renamed from the historical
# ConformancePack when the resource type changed from
# AWS::Config::OrganizationConformancePack to a nested stack —
# CloudFormation forbids in-place Type changes on a logical ID).
CP_STACK_ID = "ConformancePackStack"
cp_res = main_ress.get(CP_STACK_ID, {})
if cp_res.get("Type") != "AWS::CloudFormation::Stack":
    print(f"*** main.yaml {CP_STACK_ID} Type={cp_res.get('Type')} (expected AWS::CloudFormation::Stack)")
    ok = False
else:
    print(f"main.yaml: {CP_STACK_ID} is a nested stack")
if "ConformancePack" in main_ress:
    print("*** main.yaml still declares the legacy ConformancePack logical ID")
    ok = False

# Nested stack must reference ConformancePackPartitions.yaml
turl = repr(cp_res.get("Properties", {}).get("TemplateURL", ""))
if "ConformancePackPartitions.yaml" not in turl:
    print(f"*** main.yaml {CP_STACK_ID} TemplateURL missing ConformancePackPartitions.yaml: {turl}")
    ok = False

# Every per-partition account list must be passed in. PartitionCount
# is no longer consumed by ConformancePackPartitions.yaml — whether each
# pack is created is driven by emptiness of AccountsInP* — so it is
# deliberately omitted.
cp_params = cp_res.get("Properties", {}).get("Parameters", {})
required_partitioner_params = {f"AccountsInP{p}" for p in PARTITIONS}
missing_pp = required_partitioner_params - set(cp_params.keys())
if missing_pp:
    print(f"*** main.yaml {CP_STACK_ID} missing partitioner params: {missing_pp}")
    ok = False
else:
    print(f"main.yaml: {len(PARTITIONS)} per-partition account lists wired into {CP_STACK_ID}")
if "PartitionCount" in cp_params:
    print(f"*** main.yaml {CP_STACK_ID} still passes PartitionCount to nested stack (no longer consumed)")
    ok = False

# MaxPartitions must allow every partition slot the templates define,
# otherwise the partitioner would fail closed before the last pack is
# ever created.
max_parts = main.get("Parameters", {}).get("MaxPartitions", {})
if max_parts.get("MaxValue") != MAX_PARTITIONS:
    print(f"*** main.yaml MaxPartitions MaxValue={max_parts.get('MaxValue')} (expected {MAX_PARTITIONS})")
    ok = False
else:
    print(f"main.yaml: MaxPartitions MaxValue={MAX_PARTITIONS} matches the template partition slots")

# Downstream EvidenceCollectionComponents must still DependsOn the pack stack
aam = main_ress.get("EvidenceCollectionComponents", {})
deps = aam.get("DependsOn", [])
if CP_STACK_ID not in deps:
    print(f"*** main.yaml EvidenceCollectionComponents no longer DependsOn {CP_STACK_ID}: {deps}")
    ok = False
else:
    print(f"main.yaml: EvidenceCollectionComponents still DependsOn {CP_STACK_ID}")

# Partitioner Lambda must NOT have AUDIT_ACCOUNT_ID env var — the
# audit-account-first deterministic placement was reverted (the system
# is correct without it, and removing it keeps the partitioner free of
# placement bias that would shift accounts on subsequent runs).
apl = main_ress.get("AccountPartitionerLambda", {})
env_vars = apl.get("Properties", {}).get("Environment", {}).get("Variables", {})
if "AUDIT_ACCOUNT_ID" in env_vars:
    print("*** main.yaml AccountPartitionerLambda still has AUDIT_ACCOUNT_ID env var (should be removed)")
    ok = False
else:
    print("main.yaml: AccountPartitionerLambda has no AUDIT_ACCOUNT_ID env var (reverted, as intended)")

# ---------- audit_manager_custom_framework.py ----------
# Audit Manager has been retired from this solution (deprecated by AWS).
# The daily compile-audit-report Lambda now sources guardrail compliance
# straight from the org AWS Config Aggregator, so the custom framework
# JSON and its keyword mappings no longer exist. Nothing to validate here.

print()
print("OK" if ok else "FAIL")
sys.exit(0 if ok else 1)
