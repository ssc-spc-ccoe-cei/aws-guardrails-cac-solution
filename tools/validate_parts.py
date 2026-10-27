"""Quick structural validator for the partitioned Part1-8 templates.

Verifies that every guardrail Lambda has exactly one clone per
partition slot (``P2``..``P{MAX_PARTITIONS}``), that each clone carries
the right ``IsAuditAccountAndCreatePartitionN`` condition and ``_pN``
function-name suffix, and that the ``PartitionCount`` parameter and its
conditions are declared.
"""
import yaml
import sys

# Number of partition slots the templates are expected to define.
# Bumping this requires adding the matching conditions + clone resources
# to every AuditAccountPreRequisitesPart*.yaml, and a ConformancePackPN
# resource in ConformancePackPartitions.yaml.
MAX_PARTITIONS = 4
CLONE_SLOTS = list(range(2, MAX_PARTITIONS + 1))
EXPECTED_GUARDRAILS = 37


class CfnLoader(yaml.SafeLoader):
    pass


def cfn_constructor(tag):
    def _ctor(loader, node):
        if isinstance(node, yaml.ScalarNode):
            return {tag: loader.construct_scalar(node)}
        if isinstance(node, yaml.SequenceNode):
            return {tag: loader.construct_sequence(node, deep=True)}
        if isinstance(node, yaml.MappingNode):
            return {tag: loader.construct_mapping(node, deep=True)}
        return None
    return _ctor


for tag in [
    "Sub", "Ref", "GetAtt", "Join", "If", "Equals", "Not", "And", "Or",
    "FindInMap", "Condition", "Base64", "Select", "Split", "ImportValue",
]:
    out = tag if tag in ("Ref", "Condition") else "Fn::" + tag
    CfnLoader.add_constructor("!" + tag, cfn_constructor(out))


def slot_of(resource_name):
    """Returns the partition slot a GC resource belongs to (1 = base)."""
    for p in CLONE_SLOTS:
        if resource_name.endswith(f"P{p}"):
            return p
    return 1


ok = True
totals = {p: 0 for p in range(1, MAX_PARTITIONS + 1)}

for n in [1, 2, 3, 4, 5, 6, 7, 8]:
    path = f"arch/templates/AuditAccountPreRequisitesPart{n}.yaml"
    try:
        with open(path) as f:
            doc = yaml.load(f, Loader=CfnLoader)
    except Exception as e:  # noqa: BLE001 - validator reports and continues
        print(f"Part{n}: PARSE ERROR {e}")
        ok = False
        continue

    params = doc.get("Parameters", {})
    conds = doc.get("Conditions", {})
    ress = doc.get("Resources", {})

    def is_gc(r):
        return r.startswith("GC") and "Check" in r

    counts = {slot: 0 for slot in range(1, MAX_PARTITIONS + 1)}
    for r in ress:
        if is_gc(r):
            counts[slot_of(r)] += 1

    has_pc = "PartitionCount" in params
    missing_conds = [
        c for slot in CLONE_SLOTS
        for c in (f"CreatePartition{slot}", f"IsAuditAccountAndCreatePartition{slot}")
        if c not in conds
    ]

    # PartitionCount must allow every slot, otherwise the StackSet can
    # never be told to create the highest partition's clones.
    allowed = set(params.get("PartitionCount", {}).get("AllowedValues", []))
    expected_allowed = {str(i) for i in range(1, MAX_PARTITIONS + 1)}

    summary = "  ".join(f"P{s}={counts[s]:2d}" for s in sorted(counts))
    print(f"Part{n}: {summary}  PartitionCount={has_pc} allowed={sorted(allowed)}")

    for slot in counts:
        totals[slot] += counts[slot]

    if len(set(counts.values())) != 1:
        print(f"  *** Part{n}: clone counts differ across partitions: {counts} ***")
        ok = False
    if not has_pc:
        print(f"  *** Part{n}: PartitionCount parameter missing ***")
        ok = False
    if missing_conds:
        print(f"  *** Part{n}: missing conditions {missing_conds} ***")
        ok = False
    if allowed != expected_allowed:
        print(
            f"  *** Part{n}: PartitionCount AllowedValues={sorted(allowed)}, "
            f"expected {sorted(expected_allowed)} ***"
        )
        ok = False

    # CreatePartitionN for N < MAX_PARTITIONS must stay true for every
    # higher count too, otherwise raising PartitionCount would DELETE the
    # lower partitions' clones out from under live Config rules.
    for slot in CLONE_SLOTS[:-1]:
        cond_repr = repr(conds.get(f"CreatePartition{slot}"))
        higher = [str(h) for h in range(slot, MAX_PARTITIONS + 1)]
        covers = all(f"'{h}'" in cond_repr for h in higher)
        # CreatePartition2 is expressed as "not 1", which covers all
        # higher counts implicitly.
        if not covers and not (slot == 2 and "Fn::Not" in cond_repr):
            print(
                f"  *** Part{n}: CreatePartition{slot} does not cover counts "
                f"{higher}: {cond_repr} ***"
            )
            ok = False

    # Verify each clone's Condition and FunctionName suffix.
    for r_name, r_def in ress.items():
        if not is_gc(r_name):
            continue
        slot = slot_of(r_name)
        expected_cond = (
            "IsAuditAccount" if slot == 1
            else f"IsAuditAccountAndCreatePartition{slot}"
        )
        cond = r_def.get("Condition")
        if cond != expected_cond:
            print(f"  *** Part{n}.{r_name} Condition={cond}, expected {expected_cond} ***")
            ok = False

        fn = r_def.get("Properties", {}).get("FunctionName", {})
        if isinstance(fn, dict) and "Fn::Sub" in fn:
            s = fn["Fn::Sub"]
            expected_suffix = "" if slot == 1 else f"_p{slot}"
            if expected_suffix and not s.endswith(expected_suffix):
                print(f"  *** Part{n}.{r_name} FunctionName='{s}' missing {expected_suffix} ***")
                ok = False
            if not expected_suffix and any(s.endswith(f"_p{p}") for p in CLONE_SLOTS):
                print(f"  *** Part{n}.{r_name} base FunctionName='{s}' has a partition suffix ***")
                ok = False

print()
print("Totals: " + "  ".join(f"P{s}={totals[s]}" for s in sorted(totals)))
print(f"Expected: {EXPECTED_GUARDRAILS} guardrails in each of {MAX_PARTITIONS} partition(s)")
if any(v != EXPECTED_GUARDRAILS for v in totals.values()):
    print("  *** guardrail totals do not match expectation ***")
    ok = False
print("OK" if ok else "FAIL")
sys.exit(0 if ok else 1)
