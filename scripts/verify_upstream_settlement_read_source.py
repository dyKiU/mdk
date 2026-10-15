#!/usr/bin/env python3
"""Remote static boundary guard for the private snapshot-only read optimization."""
import hashlib
import json
from pathlib import Path
import re
import subprocess
BASE = "46230f5744139d7f46c1ba266784919361fdcd1d"
CORE = "crates/cgka-engine/src/private_roster_settlement.rs"
SQL = "crates/storage-sqlite/src/private_roster_settlement.rs"
def old(path): return subprocess.check_output(["git", "show", BASE+":"+path], text=True)
core = Path(CORE).read_text()
old_core = old(CORE)
sql = Path(SQL).read_text()
old_sql = old(SQL)
callers = []
for file in Path("crates/cgka-engine/src").rglob("*.rs"):
    for number, line in enumerate(file.read_text().splitlines(), 1):
        if re.search(r"\bcompleted_round_for_tree_in_snapshot\s*\(", line):
            callers.append({"file": str(file), "line": number})
assert len(callers)==1 and callers[0]["file"]==CORE
begin = core.index("    pub fn validated_settled_device_roster(")
end = core.index("    #[cfg(test)]", begin)
getter = core[begin:end]
assert getter.count("completed_round_for_tree_in_snapshot(")==1
assert getter.index("with_read_snapshot(") < getter.index("completed_round_for_tree_in_snapshot(")
general = core[core.index("pub(crate) fn completed_round_for_predecessor_tree"):core.index("fn completed_round_for_tree_in_snapshot")]
assert "store.read_round()?" in general and "loaded_facts: None" in general
assert "read_round_with_loaded_facts" not in general
old_tail = old_core[old_core.index("    if state.phase != PrivateSettlementPhase::Completed", old_core.index("pub(crate) fn completed_round_for_predecessor_tree")):]
new_tail = core[core.index("    if state.phase != PrivateSettlementPhase::Completed", core.index("fn validate_completed_round_read")):]
new_tail = re.sub(r"    let facts = match read.loaded_facts \{\s*Some\(facts\) => facts,\s*None => store.read_facts\(\)\?,\s*\};", "    let facts = store.read_facts()?;", new_tail)
legacy_anchor = old_tail[old_tail.index("    if !crate::private_successor::anchor_matches_actual_tree"):old_tail.index("    let account = ")]
new_tail = re.sub(r"    let anchor_matches = if let Some\(evidence\) = snapshot_evidence \{.*?\n    \};\n    if !anchor_matches\s*\{\s*return Ok\(None\);\s*\}\n", lambda _: legacy_anchor, new_tail, flags=re.S)
assert old_tail == new_tail, "all original validation order and checks must remain exact"
successor_path = "crates/cgka-engine/src/private_successor.rs"
successor = Path(successor_path).read_text()
old_successor = old(successor_path)
old_origin = old_successor[old_successor.index("    let accepted = storage", old_successor.index("pub(crate) fn anchor_matches_actual_tree")):old_successor.index("    let candidate = ", old_successor.index("pub(crate) fn anchor_matches_actual_tree"))]
new_origin = successor[successor.index("    let accepted = storage", successor.index("pub(crate) fn anchor_matches_actual_tree")):successor.index("    Ok(anchor_commitment_matches", successor.index("pub(crate) fn anchor_matches_actual_tree"))]
assert old_origin == new_origin, "all four legacy origin reads, filters, error order and matching must stay exact"
assert "if anchor != evidence.settlement_anchor()" in successor
origin_calls=[]
for file in Path("crates/cgka-engine/src").rglob("*.rs"):
    if file.name.endswith("_tests.rs") or "tests" in file.parts: continue
    for number,line in enumerate(file.read_text().splitlines(),1):
        if re.search(r"\banchor_matches_actual_tree_in_snapshot\s*\(",line):
            origin_calls.append({"file":str(file),"line":number})
assert len(origin_calls)==1 and origin_calls[0]["file"]==CORE
assert re.search(r"loaded_facts:\s*None,\s*\},\s*None,\s*\)",general)
assert "&evidence" in getter and getter.index("validated_private_successor(") < getter.index("MlsGroup::load(") < getter.index("completed_round_for_tree_in_snapshot(")

def read_facts(value): return value[value.index("    fn read_facts(&self)"):value.index("#[cfg(test)]",value.index("    fn read_facts(&self)"))]
assert read_facts(sql)==read_facts(old_sql), "existing read_facts behavior must stay byte-identical"
report={"source":subprocess.check_output(["git","rev-parse","HEAD"],text=True).strip(), "baseline":BASE,
        "sole_optimized_call":callers[0], "pinned_snapshot_in_same_getter":True,
        "general_wrappers_use_legacy_read_order":True, "old_validation_tail_exact":True,
        "existing_read_facts_byte_identical":True,
        "validation_tail_sha256":hashlib.sha256(old_tail.encode()).hexdigest(),
        "sole_optimized_origin_call":origin_calls[0], "legacy_origin_reads_and_errors_exact":True,
        "source_preflight_passed":True,"product_qualification_passed":False}
Path("settlement-read-source.json").write_text(json.dumps(report,indent=2)+"\n")
