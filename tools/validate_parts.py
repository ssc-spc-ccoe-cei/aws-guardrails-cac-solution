"""Quick structural validator for the partitioned Part1-8 templates."""
import yaml
import sys


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


ok = True
total_orig = total_p2 = total_p3 = 0
for n in [1, 2, 3, 4, 5, 6, 7, 8]:
    p = f"arch/templates/AuditAccountPreRequisitesPart{n}.yaml"
    try:
        with open(p) as f:
            doc = yaml.load(f, Loader=CfnLoader)
    except Exception as e:
        print(f"Part{n}: PARSE ERROR {e}")
        ok = False
        continue

    params = doc.get("Parameters", {})
    conds = doc.get("Conditions", {})
    ress = doc.get("Resources", {})

    def is_gc(r): return r.startswith("GC") and "Check" in r
    gc_p2 = sum(1 for r in ress if is_gc(r) and r.endswith("P2"))
    gc_p3 = sum(1 for r in ress if is_gc(r) and r.endswith("P3"))
    gc_orig = sum(
        1 for r in ress
        if is_gc(r) and not r.endswith("P2") and not r.endswith("P3")
    )

    has_pc = "PartitionCount" in params
    has_c2 = "CreatePartition2" in conds
    has_c3 = "CreatePartition3" in conds
    has_iac2 = "IsAuditAccountAndCreatePartition2" in conds
    has_iac3 = "IsAuditAccountAndCreatePartition3" in conds

    print(
        f"Part{n}: GC orig={gc_orig:2d} P2={gc_p2:2d} P3={gc_p3:2d}  "
        f"PC={has_pc} C2={has_c2} C3={has_c3} "
        f"IAC2={has_iac2} IAC3={has_iac3}"
    )

    total_orig += gc_orig
    total_p2 += gc_p2
    total_p3 += gc_p3

    if not (gc_orig == gc_p2 == gc_p3
            and has_pc and has_c2 and has_c3
            and has_iac2 and has_iac3):
        print(f"  *** Part{n} MISMATCH ***")
        ok = False

    # Verify each P2 / P3 has the right Condition
    for r_name, r_def in ress.items():
        if not is_gc(r_name):
            continue
        cond = r_def.get("Condition")
        if r_name.endswith("P2") and cond != "IsAuditAccountAndCreatePartition2":
            print(f"  *** Part{n}.{r_name} Condition={cond}, expected IsAuditAccountAndCreatePartition2 ***")
            ok = False
        elif r_name.endswith("P3") and cond != "IsAuditAccountAndCreatePartition3":
            print(f"  *** Part{n}.{r_name} Condition={cond}, expected IsAuditAccountAndCreatePartition3 ***")
            ok = False
        elif (not r_name.endswith("P2")) and (not r_name.endswith("P3")) and cond != "IsAuditAccount":
            print(f"  *** Part{n}.{r_name} Condition={cond}, expected IsAuditAccount ***")
            ok = False

    # Verify each P2 / P3 FunctionName ends with the right suffix
    for r_name, r_def in ress.items():
        if not is_gc(r_name):
            continue
        props = r_def.get("Properties", {})
        fn = props.get("FunctionName", {})
        if isinstance(fn, dict) and "Fn::Sub" in fn:
            s = fn["Fn::Sub"]
            if r_name.endswith("P2") and not s.endswith("_p2"):
                print(f"  *** Part{n}.{r_name} FunctionName='{s}' missing _p2 ***")
                ok = False
            elif r_name.endswith("P3") and not s.endswith("_p3"):
                print(f"  *** Part{n}.{r_name} FunctionName='{s}' missing _p3 ***")
                ok = False

print()
print(f"Totals: orig={total_orig} p2={total_p2} p3={total_p3}")
print("Expected: orig=37 p2=37 p3=37")
print("OK" if ok else "FAIL")
sys.exit(0 if ok else 1)
