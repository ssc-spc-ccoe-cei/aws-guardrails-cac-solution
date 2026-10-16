"""Validator for the partition-sync nested stack.

Covers the post-factoring layout where the Step Function and EventBridge
rule live in their own template (PartitionSyncStateMachine.yaml) and
main.yaml just references it via a single AWS::CloudFormation::Stack
resource.
"""
import json
import re
import sys

import yaml


class L(yaml.SafeLoader):
    pass


def ctor(tag):
    def f(loader, node):
        if isinstance(node, yaml.ScalarNode):
            return {tag: loader.construct_scalar(node)}
        if isinstance(node, yaml.SequenceNode):
            return {tag: loader.construct_sequence(node, deep=True)}
        if isinstance(node, yaml.MappingNode):
            return {tag: loader.construct_mapping(node, deep=True)}
    return f


for t in ["Sub", "Ref", "GetAtt", "Join", "If", "Equals", "Not", "And", "Or",
          "FindInMap", "Condition", "Base64", "Select", "Split", "ImportValue"]:
    out = t if t in ("Ref", "Condition") else "Fn::" + t
    L.add_constructor("!" + t, ctor(out))


def load(path):
    with open(path) as f:
        return yaml.load(f, Loader=L)


ok = True

# ---------- PartitionSyncStateMachine.yaml (the new nested stack) ----------
psm = load("arch/templates/PartitionSyncStateMachine.yaml")
psm_params = psm.get("Parameters", {})
psm_ress = psm.get("Resources", {})

expected_params = {"OrganizationName", "RootStackName", "AuditAccountID"}
missing_params = expected_params - set(psm_params.keys())
extra_params = set(psm_params.keys()) - expected_params
if missing_params:
    print(f"*** PartitionSyncStateMachine: missing params {missing_params}")
    ok = False
if extra_params:
    print(f"*** PartitionSyncStateMachine: unexpected params {extra_params}")
    ok = False
print(f"PartitionSyncStateMachine: parameters = {sorted(psm_params.keys())}")

expected_resources = [
    "PartitionSyncStateMachineLogGroup",
    "PartitionSyncStateMachineRole",
    "PartitionSyncStateMachine",
    "PartitionSyncScheduleRole",
    "PartitionSyncScheduleRule",
]
missing_res = [r for r in expected_resources if r not in psm_ress]
if missing_res:
    print(f"*** PartitionSyncStateMachine: missing resources {missing_res}")
    ok = False
else:
    print("PartitionSyncStateMachine: all 5 resources present")

# State-machine ASL must parse and every transition must point at a
# state that actually exists.
sm_props = psm_ress["PartitionSyncStateMachine"]["Properties"]
subs = sm_props["DefinitionSubstitutions"]
print("DefinitionSubstitutions keys:", sorted(subs))

defstr = sm_props["DefinitionString"]
try:
    asl = json.loads(defstr)
except json.JSONDecodeError as e:
    print(f"*** ASL is not valid JSON: {e}")
    sys.exit(1)
print(f"ASL StartAt: {asl['StartAt']}, {len(asl['States'])} states:")
for name, s in asl["States"].items():
    if s.get("Next"):
        suffix = f"next={s['Next']}"
    elif s.get("End"):
        suffix = "END"
    elif s["Type"] == "Choice":
        suffix = f"default={s.get('Default','?')}"
    elif s["Type"] == "Fail":
        suffix = "FAIL"
    else:
        suffix = "?"
    print(f"  - {name:24s} type={s['Type']:6s} {suffix}")

placeholders = sorted(set(re.findall(r"\$\{(\w+)\}", defstr)))
print("Placeholders in ASL:", placeholders)
unsupplied = [p for p in placeholders if p not in subs]
if unsupplied:
    print(f"*** Unsupplied placeholders: {unsupplied}")
    ok = False

known = set(asl["States"].keys())
for name, s in asl["States"].items():
    targets = []
    if s.get("Next"):
        targets.append(s["Next"])
    if s.get("Default"):
        targets.append(s["Default"])
    for c in s.get("Choices", []):
        if c.get("Next"):
            targets.append(c["Next"])
    for ct in s.get("Catch", []):
        if ct.get("Next"):
            targets.append(ct["Next"])
    bad = [t for t in targets if t not in known]
    if bad:
        print(f"*** {name}: unknown target state(s) {bad}")
        ok = False

# The membership-change choice must trigger on AccountsChanged. Missing
# that condition causes a real bug: a new account joining an existing
# partition with room leaves PartitionCount unchanged, so without
# AccountsChanged we'd skip the root-stack update, leaving the OTHER
# partitions' ExcludedAccounts lists stale and causing the new account
# to receive multiple Organization Conformance Packs.
#
# PartitionsChanged is returned by the partitioner for observability
# (it surfaces in the execution history) but is intentionally NOT
# tested by the choice — every partition-count change is necessarily
# also a membership change, so branching on both would be redundant.
# We assert it's absent from the Choice expression to catch any
# accidental reintroduction.
choice_state_name = None
for n, s in asl["States"].items():
    if s["Type"] == "Choice" and n in ("MembershipChanged?", "AccountsChanged?"):
        choice_state_name = n
        break
if not choice_state_name:
    print("*** ASL is missing the membership-change Choice state")
    ok = False
else:
    print(f"Membership-change Choice state: {choice_state_name}")
    choice = asl["States"][choice_state_name]
    flat_choice = json.dumps(choice["Choices"])
    if "AccountsChanged" not in flat_choice:
        print("*** Choice does not test AccountsChanged (membership-change bug)")
        ok = False
    if "PartitionsChanged" in flat_choice:
        print("*** Choice tests PartitionsChanged — this is strictly redundant "
              "with AccountsChanged and should be removed (kept only as an "
              "observability field in InvokePartitioner.ResultSelector)")
        ok = False

# InvokePartitioner's ResultSelector must capture both flags from the
# Lambda payload. AccountsChanged is consumed by the Choice; PartitionsChanged
# is kept for observability (surfaces in execution history so operators can
# tell a partition-open run apart from a plain account-add).
invoke = asl["States"].get("InvokePartitioner", {})
rs = invoke.get("ResultSelector", {})
for required in ("PartitionsChanged.$", "AccountsChanged.$"):
    if required not in rs:
        print(f"*** InvokePartitioner.ResultSelector missing {required}")
        ok = False
print("InvokePartitioner ResultSelector keys:", sorted(rs.keys()))

# Schedule sanity
rule = psm_ress["PartitionSyncScheduleRule"]["Properties"]
print(f"EventBridge schedule: {rule['ScheduleExpression']} state={rule['State']}")
target_arn = rule["Targets"][0]["Arn"]
if target_arn != {"Ref": "PartitionSyncStateMachine"}:
    print(f"*** EventBridge target Arn not pointing at state machine: {target_arn}")
    ok = False

# IAM role sanity
sm_role = psm_ress["PartitionSyncStateMachineRole"]["Properties"]
print("State machine role policies:",
      [p["PolicyName"] for p in sm_role["Policies"]])
sched_role = psm_ress["PartitionSyncScheduleRole"]["Properties"]
print("Schedule role policies:",
      [p["PolicyName"] for p in sched_role["Policies"]])

# ---------- main.yaml — must reference the nested stack ----------
main = load("arch/templates/main.yaml")
main_ress = main.get("Resources", {})

stack_res = main_ress.get("PartitionSyncStack")
if not stack_res:
    print("*** main.yaml: missing PartitionSyncStack nested stack resource")
    ok = False
else:
    if stack_res.get("Type") != "AWS::CloudFormation::Stack":
        print(f"*** main.yaml PartitionSyncStack Type={stack_res.get('Type')} "
              f"(expected AWS::CloudFormation::Stack)")
        ok = False
    turl = repr(stack_res.get("Properties", {}).get("TemplateURL", ""))
    if "PartitionSyncStateMachine.yaml" not in turl:
        print(f"*** main.yaml PartitionSyncStack TemplateURL doesn't reference "
              f"PartitionSyncStateMachine.yaml: {turl}")
        ok = False
    fp = stack_res.get("Properties", {}).get("Parameters", {})
    missing_fp = expected_params - set(fp.keys())
    if missing_fp:
        print(f"*** main.yaml PartitionSyncStack missing params {missing_fp}")
        ok = False
    deps = stack_res.get("DependsOn", [])
    # PartitionSyncStack must depend on AccountPartitionerLambda. It must
    # NOT depend on AuditAccountPreRequisitesPartN — that direction is
    # exactly the chicken-and-egg that breaks the deploy: PartN creates
    # an AWS::Lambda::Permission whose Principal is the
    # PartitionSyncStateMachineRole created by THIS stack, and Lambda's
    # AddPermission API rejects ("The provided principal was invalid")
    # principals whose IAM role does not yet exist. So PartN must
    # DependsOn PartitionSyncStack, not the reverse.
    for required_dep in ("AccountPartitionerLambda",):
        if required_dep not in deps:
            print(f"*** main.yaml PartitionSyncStack missing DependsOn: {required_dep}")
            ok = False
    for forbidden_dep in ("AuditAccountPreRequisitesPartN",):
        if forbidden_dep in deps:
            print(f"*** main.yaml PartitionSyncStack has forbidden DependsOn: "
                  f"{forbidden_dep} (would reintroduce 'The provided principal "
                  f"was invalid' deploy failure — PartN must depend on this "
                  f"stack, not the reverse)")
            ok = False
    print(f"main.yaml: PartitionSyncStack OK "
          f"(params={sorted(fp.keys())}, DependsOn={deps})")

# AuditAccountPreRequisitesPartN must DependsOn PartitionSyncStack so
# the PartitionSyncStateMachineRole exists when PartN's audit-account
# StackSet tries to attach LambdaPermissionsLambdaInvokeByStateMachine
# (an AWS::Lambda::Permission whose Principal is that role).
partn_res = main_ress.get("AuditAccountPreRequisitesPartN")
if not partn_res:
    print("*** main.yaml: missing AuditAccountPreRequisitesPartN")
    ok = False
else:
    partn_deps = partn_res.get("DependsOn", [])
    if "PartitionSyncStack" not in partn_deps:
        print("*** main.yaml AuditAccountPreRequisitesPartN missing "
              "DependsOn: PartitionSyncStack (required so the "
              "PartitionSyncStateMachineRole exists before PartN's "
              "LambdaPermissionsLambdaInvokeByStateMachine calls "
              "Lambda's AddPermission API)")
        ok = False
    print(f"main.yaml: AuditAccountPreRequisitesPartN DependsOn={partn_deps}")

# Old inline resources must be GONE from main.yaml.
for r in expected_resources:
    if r in main_ress:
        print(f"*** main.yaml still has inline {r} (should have moved to nested stack)")
        ok = False

# Custom Resource still has InvokeUpdate so the state-machine cascade works.
cr_props = main_ress["InvokeAccountPartitioner"]["Properties"]
print("InvokeAccountPartitioner.InvokeUpdate prop:", cr_props.get("InvokeUpdate"))
if "InvokeUpdate" not in cr_props:
    ok = False

# root.yaml must forward RootStackName.
root = load("arch/templates/root.yaml")
gp = root["Resources"]["GuardRailsStack"]["Properties"]["Parameters"]
print("root.yaml passes RootStackName:", "RootStackName" in gp,
      "->", gp.get("RootStackName"))
if "RootStackName" not in gp:
    ok = False

print()
print("OK" if ok else "FAIL")
sys.exit(0 if ok else 1)
