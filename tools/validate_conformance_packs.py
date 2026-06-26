"""Structural validator for the partitioned ConformancePack rollout."""
import re
import sys
import yaml


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
if ps.get("Default") != "" or set(ps.get("AllowedValues", [])) != {"", "_p2", "_p3"}:
    print(f"*** ConformancePack.yaml: PartitionSuffix param malformed: {ps}")
    ok = False
else:
    print("ConformancePack: PartitionSuffix parameter OK")

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

required_resources = {"ConformancePackP1", "ConformancePackP2", "ConformancePackP3"}
got_resources = set(cpp_ress.keys())
missing = required_resources - got_resources
if missing:
    print(f"*** ConformancePackPartitions: missing resources {missing}")
    ok = False

# Each pack must be conditional on its own HasAccountsInP* condition so a
# partition that has lost all of its accounts cleanly retires its pack
# (rather than leaving an empty pack that excludes the whole org).
expected_resource_conds = {
    "ConformancePackP1": "HasAccountsInP1",
    "ConformancePackP2": "HasAccountsInP2",
    "ConformancePackP3": "HasAccountsInP3",
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
for r_name, expected_suffix in [
    ("ConformancePackP2", "_p2"),
    ("ConformancePackP3", "_p3"),
]:
    r = cpp_ress.get(r_name, {})
    inputs = r.get("Properties", {}).get("ConformancePackInputParameters", [])
    suffix_param = next(
        (p for p in inputs if p.get("ParameterName") == "PartitionSuffix"), None,
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
if any(p.get("ParameterName") == "PartitionSuffix" for p in p1_inputs):
    print("*** ConformancePackP1: PartitionSuffix input should be omitted (template default is \"\")")
    ok = False
print("ConformancePackPartitions: 3 packs wired with correct PartitionSuffix and HasAccountsInP* condition")

# Required empty-string conditions on each partition's account list, plus
# the AND combinations used by the ExcludedAccounts !If ladders.
for c in (
    "HasAccountsInP1", "HasAccountsInP2", "HasAccountsInP3",
    "HasAccountsInP2AndP3", "HasAccountsInP1AndP3", "HasAccountsInP1AndP2",
):
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

cp_res = main_ress.get("ConformancePack", {})
if cp_res.get("Type") != "AWS::CloudFormation::Stack":
    print(f"*** main.yaml ConformancePack Type={cp_res.get('Type')} (expected AWS::CloudFormation::Stack)")
    ok = False
else:
    print("main.yaml: ConformancePack is now a nested stack")

# Nested stack must reference ConformancePackPartitions.yaml
turl = repr(cp_res.get("Properties", {}).get("TemplateURL", ""))
if "ConformancePackPartitions.yaml" not in turl:
    print(f"*** main.yaml ConformancePack TemplateURL missing ConformancePackPartitions.yaml: {turl}")
    ok = False

# The 3 per-partition account lists must be passed in. PartitionCount
# is no longer consumed by ConformancePackPartitions.yaml — whether each
# pack is created is driven by emptiness of AccountsInP* — so it is
# deliberately omitted.
cp_params = cp_res.get("Properties", {}).get("Parameters", {})
required_partitioner_params = {"AccountsInP1", "AccountsInP2", "AccountsInP3"}
missing_pp = required_partitioner_params - set(cp_params.keys())
if missing_pp:
    print(f"*** main.yaml ConformancePack missing partitioner params: {missing_pp}")
    ok = False
else:
    print("main.yaml: 3 per-partition account lists wired into ConformancePack")
if "PartitionCount" in cp_params:
    print("*** main.yaml ConformancePack still passes PartitionCount to nested stack (no longer consumed)")
    ok = False

# Downstream AuditAccountAuditManager must still DependsOn ConformancePack
aam = main_ress.get("AuditAccountAuditManager", {})
deps = aam.get("DependsOn", [])
if "ConformancePack" not in deps:
    print(f"*** main.yaml AuditAccountAuditManager no longer DependsOn ConformancePack: {deps}")
    ok = False
else:
    print("main.yaml: AuditAccountAuditManager still DependsOn ConformancePack")

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
from importlib.util import spec_from_file_location, module_from_spec
spec = spec_from_file_location(
    "audit_manager_custom_framework",
    "src/lambda/aws_auditmanager_resources_config_setup/audit_manager_custom_framework.py",
)
mod = module_from_spec(spec)
spec.loader.exec_module(mod)

frameworks = mod.frameworks_data
assert len(frameworks) == 1
controls = []
for cs in frameworks[0]["controlSets"]:
    controls.extend(cs["controls"])

print(f"Audit Manager framework: {len(controls)} controls")
SKIP = {"gc01_check_attestation_letter"}
matched = 0
skipped = 0
bad = 0
for c in controls:
    name = c["name"]
    sources = c.get("controlMappingSources", [])
    if name in SKIP:
        if len(sources) != 1:
            print(f"  *** {name}: expected 1 mapping (no Config rule), got {len(sources)}")
            bad += 1
        else:
            skipped += 1
        continue
    # Every other control maps to a single deployed Config rule named
    # exactly after the control (the partition suffix lives on the
    # Lambda, not the rule), so one keyword covers all 3 packs.
    if len(sources) != 1:
        print(f"  *** {name}: expected 1 mapping, got {len(sources)}")
        bad += 1
        continue
    kv = sources[0]["sourceKeyword"]["keywordValue"]
    expected = f"Custom_{name}-conformance-pack"
    if kv != expected:
        print(f"  *** {name}: keywordValue {kv!r}, expected {expected!r}")
        bad += 1
        continue
    matched += 1
if bad:
    ok = False

print(f"Audit Manager: {matched} controls map to 1 keyword each, "
      f"{skipped} skipped (no Config rule)")

print()
print("OK" if ok else "FAIL")
sys.exit(0 if ok else 1)
