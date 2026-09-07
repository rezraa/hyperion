# Copyright (c) 2026 Reza Malik. Licensed under the Apache License, Version 2.0.
"""Hyperion S0 -- blind, stratified, byte-frozen per-stratum baseline.

Council b420a9f0 / m-73ea1894; standard m-55f6d4da (settled -- do not re-litigate).

NORTH STAR: a deterministic, blind, byte-frozen benchmark that measures
Hyperion's CURRENT retrieval per stratum and BLOCKS every later story until each
stratum equals-or-beats its pinned baseline.  THREE strata are graded SEPARATELY
and are NEVER pooled (m-e8ccb163):

  A  THREAT-VECTOR recognition -- threat_vectors.signals (240) + decision_rules
     .structural_signal (55) -> correct vector id, recall@10.
  B  AGENT-THREAT recognition -- agent_threats.detection_signals (64) -> correct
     agent_threat id, recall@10.
  C  scan_code code-detection -- known-vuln corpus examples must FIRE, secure
     examples should stay SILENT; graded by findings coverage, and corpus-pattern
     reachability is measured against the current 29-regex island.

The answer key (ground truth: query -> id) is derived MECHANICALLY from the
frozen corpus -- every signal maps to its own node's id; every decision rule's
structural_signal maps to its recommended_threat.  It is curated blind (no
cherry-picking to flatter or damn the current code) and byte-frozen with a
recorded sha256.  The per-stratum recall floors pinned here (BASELINE_A_*,
BASELINE_B) were measured from the original substring recogniser; that matcher was
deleted at zero callers (S6), so the recall re-run now lives in
test_hyperion_retrofit_s2.py against the production recognition surface
(get_signal_index + hydrate), which imports these frozen floors and must
equals-or-beat each.  Stratum C (scan_code) is measured here directly.

Everything runs from JSON on disk (or a tmp_path copy).  No graph connection, no
live DB.  Firewall: hyperion imports only hyperion.* -- never othrys/coeus/
mnemos/theia/themis.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import sys
from pathlib import Path

import pytest

from hyperion.knowledge.loader import _KNOWLEDGE_DIR, KnowledgeLoader
from hyperion.tools.scan_code import _get_patterns, scan_code

KNOWLEDGE_DIR = Path(_KNOWLEDGE_DIR)

# Top-k for every recall@10 arm.  Named ceiling -- applied where recall is graded.
RECALL_K = 10

# Forbidden imports -- Hyperion is a standalone Titan (firewall).
_FORBIDDEN_ROOTS = ("othrys", "coeus", "mnemos", "theia", "themis")


# ===========================================================================
# Answer key -- ground truth, derived mechanically from the frozen corpus.
# Reused verbatim by S2/S3/S4/S5 so the floor they must beat is this one.
# ===========================================================================

ANSWER_KEY_PATH = Path(__file__).parent / "_hyperion_s0_answer_key.json"
ANSWER_KEY_SHA256 = (
    "58975c63ba467852e8922c8608bea04503b063cfa705ea08181c663e93db323a"
)


def _load_corpus(knowledge_dir: Path) -> tuple[list, list, list]:
    """Load the three graded corpora directly from JSON (the source of truth)."""
    vectors = json.loads(
        (knowledge_dir / "threat_vectors.json").read_text(encoding="utf-8")
    )["vectors"]
    agent_threats = json.loads(
        (knowledge_dir / "agent_threats.json").read_text(encoding="utf-8")
    )["threats"]
    rules = json.loads(
        (knowledge_dir / "decision_rules.json").read_text(encoding="utf-8")
    )["rules"]
    return vectors, agent_threats, rules


def build_answer_key(knowledge_dir: Path) -> dict:
    """Build the deterministic ground-truth answer key from the corpus.

    Every list is sorted so the canonical serialization is byte-stable across
    fresh loaders under PYTHONHASHSEED=0.
    """
    vectors, agent_threats, rules = _load_corpus(knowledge_dir)
    vec_ids = {v["id"] for v in vectors}
    agt_ids = {t["id"] for t in agent_threats}

    # Stratum A ground truth.
    leg1 = sorted(
        [s, v["id"]] for v in vectors for s in v.get("signals", [])
    )
    leg2 = sorted(
        [r["structural_signal"], r["recommended_threat"]]
        for r in rules
        if r.get("structural_signal") and r.get("recommended_threat") in vec_ids
    )

    # Stratum B ground truth.
    leg_b = sorted(
        [s, t["id"]] for t in agent_threats for s in t.get("detection_signals", [])
    )

    # Disjointness: node ids and enumerated signal-text overlap.
    vmap: dict[str, set[str]] = {}
    amap: dict[str, set[str]] = {}
    for v in vectors:
        for s in v.get("signals", []):
            vmap.setdefault(s.lower().strip(), set()).add(v["id"])
    for t in agent_threats:
        for s in t.get("detection_signals", []):
            amap.setdefault(s.lower().strip(), set()).add(t["id"])
    signal_text_overlap = sorted(
        [txt, sorted(vmap[txt]), sorted(amap[txt])]
        for txt in (set(vmap) & set(amap))
    )

    # cwe -> threat_id mapping (the S4 seed).
    cwe_map: dict[str, list[str]] = {}
    for v in vectors:
        for c in v.get("cwe", []):
            cwe_map.setdefault(c, []).append(v["id"])
    cwe_map = {c: sorted(cwe_map[c]) for c in sorted(cwe_map)}

    return {
        "schema_version": "s0-v1",
        "corpus_counts": {
            "threat_vectors": len(vectors),
            "agent_threats": len(agent_threats),
            "decision_rules": len(rules),
            "vector_signals": sum(len(v.get("signals", [])) for v in vectors),
            "structural_signals": sum(
                1 for r in rules if r.get("structural_signal")
            ),
            "agent_detection_signals": sum(
                len(t.get("detection_signals", [])) for t in agent_threats
            ),
            "vector_detection_patterns": sum(
                len(v.get("detection_patterns", [])) for v in vectors
            ),
        },
        "stratum_A": {"leg1_vector_signals": leg1, "leg2_decision_rules": leg2},
        "stratum_B": {"agent_detection_signals": leg_b},
        "disjointness": {
            "node_id_overlap": sorted(vec_ids & agt_ids),
            "signal_text_overlap": signal_text_overlap,
        },
        "cwe_to_threat_ids": cwe_map,
    }


def canonical(obj: dict) -> str:
    """Byte-stable canonical serialization used for the frozen sha256."""
    return json.dumps(obj, sort_keys=True, ensure_ascii=True, separators=(",", ":"))


def stratum_c_coverage(knowledge_dir: Path) -> dict:
    """Measure the CURRENT scanner's findings coverage over corpus examples."""
    vectors, _, _ = _load_corpus(knowledge_dir)
    vuln_firing: set[str] = set()
    secure_firing: set[str] = set()
    vuln_total = secure_total = 0
    for v in vectors:
        examples = v.get("examples") or {}
        vulnerable = examples.get("vulnerable")
        secure = examples.get("secure")
        if vulnerable:
            vuln_total += 1
            if scan_code(vulnerable, "python")["findings"]:
                vuln_firing.add(v["id"])
        if secure:
            secure_total += 1
            if scan_code(secure, "python")["findings"]:
                secure_firing.add(v["id"])
    return {
        "vuln_firing": vuln_firing,
        "vuln_total": vuln_total,
        "secure_firing": secure_firing,
        "secure_total": secure_total,
    }


# ===========================================================================
# Frozen per-stratum baselines -- pinned from CURRENT code.  NEVER pooled.
# A later story passes its stratum only if it equals-or-beats its own floor.
# ===========================================================================

# Stratum A -- threat-vector recall@10.  Reported per leg AND combined so the
# Theia gain-cancels-loss guard (S2) can inspect them independently: leg2 is
# trivially perfect because the substring matcher matches decision_rules against
# themselves, so a gain on leg1 must not be paid for by a collapse of leg2.
BASELINE_A_LEG1 = (18, 240)     # vector.signals -> own vector id
BASELINE_A_LEG2 = (55, 55)      # structural_signal -> recommended vector
BASELINE_A_COMBINED = (73, 295)

# Stratum B -- agent-threat recall@10.  The current code has NO path from a
# natural-language detection_signal to an agent_threat id: the floor is zero.
BASELINE_B = (0, 64)

# Stratum C -- scan_code findings coverage over the corpus's own examples.
BASELINE_C_VULN_FIRING = frozenset({
    "agent_insecure_output", "auth_password_storage", "config_debug_production",
    "crypto_cleartext_transmission", "crypto_hardcoded_secrets",
    "crypto_improper_certificate", "crypto_weak_algorithms",
    "data_api_key_exposure", "data_database_dumps", "injection_command",
    "injection_sql", "input_deserialization",
})
BASELINE_C_SECURE_FIRING = frozenset({"data_database_dumps", "injection_sql"})
BASELINE_C_VULN_TOTAL = 65
BASELINE_C_SECURE_TOTAL = 65
# The doubly-dead corpus bridge: get_detection_patterns(LANGUAGE) keys on
# threat_id, so ZERO of the 316 corpus detection_patterns reach the scanner.
BASELINE_C_CORPUS_PATTERNS_REACHABLE = 0
BASELINE_C_CORPUS_PATTERNS_TOTAL = 316
# patterns_checked reports only the island, excluding the 7 conditional agent
# regexes -- pinned so S5 must report the true post-materialization count.
BASELINE_C_PATTERNS_CHECKED = {"python": 29, "javascript": 25}

# S4 seed -- the inline _REMEDIATIONS island covers 11 CWEs; the corpus covers
# 9 of them.  CWE-95 and CWE-352 are NOT in the corpus: S4 cannot delete the
# island for those two without losing coverage.  Recorded, not chased (S0 scope).
REMEDIATION_ISLAND_CWES = frozenset({
    "CWE-78", "CWE-89", "CWE-79", "CWE-95", "CWE-798", "CWE-502",
    "CWE-327", "CWE-352", "CWE-295", "CWE-74", "CWE-400",
})
CWE_MISSING_FROM_CORPUS = frozenset({"CWE-95", "CWE-352"})


# ===========================================================================
# Fixtures
# ===========================================================================

@pytest.fixture()
def kb() -> KnowledgeLoader:
    return KnowledgeLoader()


@pytest.fixture()
def answer_key() -> dict:
    return build_answer_key(KNOWLEDGE_DIR)


# ===========================================================================
# Answer key -- blind, byte-frozen, deterministic.
# ===========================================================================

def test_answer_key_matches_frozen_sha256(answer_key):
    """The mechanically-derived key hashes to the recorded, frozen sha256."""
    assert hashlib.sha256(canonical(answer_key).encode("utf-8")).hexdigest() == (
        ANSWER_KEY_SHA256
    )


def test_answer_key_byte_identical_to_committed_artifact(answer_key):
    """Regenerating from the corpus is byte-for-byte the committed frozen file.

    If the corpus ever drifts, this fails loud -- that is the block.
    """
    regenerated = canonical(answer_key).encode("utf-8")
    on_disk = ANSWER_KEY_PATH.read_bytes()
    assert regenerated == on_disk
    assert hashlib.sha256(on_disk).hexdigest() == ANSWER_KEY_SHA256


def test_answer_key_deterministic_across_fresh_loaders():
    """Two independent builds under PYTHONHASHSEED=0 are byte-identical."""
    first = canonical(build_answer_key(KNOWLEDGE_DIR))
    second = canonical(build_answer_key(KNOWLEDGE_DIR))
    assert first == second


def test_answer_key_location_independent(tmp_path):
    """Copied to tmp_path, the key is identical -- no hidden live-DB source."""
    dest = tmp_path / "knowledge"
    dest.mkdir()
    for name in (
        "threat_vectors.json", "agent_threats.json",
        "decision_rules.json", "security_tools.json",
    ):
        shutil.copy(KNOWLEDGE_DIR / name, dest / name)
    key = build_answer_key(dest)
    assert hashlib.sha256(canonical(key).encode("utf-8")).hexdigest() == (
        ANSWER_KEY_SHA256
    )
    # And the production loader reads that copy with no DB/graph connection.
    kb = KnowledgeLoader(dest)
    assert len(kb.get_all_threats()) == key["corpus_counts"]["threat_vectors"]


# ===========================================================================
# Strata A & B -- threat-vector / agent-threat recognition, recall@10.
# ===========================================================================
# The pinned floors below (BASELINE_A_*, BASELINE_B) stay frozen and immovable.
# They were originally re-executed here against the substring matcher; that matcher
# was deleted at zero callers (S6), so its live re-execution is retired. The
# per-stratum recall is now re-run against the production recognition surface
# (get_signal_index + hydrate) in test_hyperion_retrofit_s2.py, which imports these
# same frozen constants and asserts the new engine equals-or-beats each one,
# inspected INDEPENDENTLY (never pooled).


# ===========================================================================
# Stratum C -- scan_code code-detection.  Graded ALONE.
# ===========================================================================

def test_stratum_C_findings_coverage_baseline():
    cov = stratum_c_coverage(KNOWLEDGE_DIR)
    assert cov["vuln_total"] == BASELINE_C_VULN_TOTAL
    assert cov["secure_total"] == BASELINE_C_SECURE_TOTAL
    # Freeze the exact firing SETS, not just counts: S5 must cover a superset of
    # the vulnerable ids and add no new secure-example false positive.
    assert cov["vuln_firing"] == BASELINE_C_VULN_FIRING
    assert cov["secure_firing"] == BASELINE_C_SECURE_FIRING


def test_stratum_C_corpus_pattern_bridge_is_dead(kb, answer_key):
    """ZERO of the 316 corpus detection_patterns reach the scanner today.

    scan_code calls get_detection_patterns(LANGUAGE) but the method keys on
    threat_id -- so language lookups return nothing.  Pinned as the floor S5
    must raise by materialising the corpus patterns under a named ceiling.
    """
    assert answer_key["corpus_counts"]["vector_detection_patterns"] == (
        BASELINE_C_CORPUS_PATTERNS_TOTAL
    )
    reachable = sum(
        len(kb.get_detection_patterns(lang))
        for lang in ("python", "javascript", "go", "java", "ruby")
    )
    assert reachable == BASELINE_C_CORPUS_PATTERNS_REACHABLE


def test_stratum_C_patterns_checked_excludes_agent_island():
    assert len(_get_patterns("python")) == BASELINE_C_PATTERNS_CHECKED["python"]
    assert len(_get_patterns("javascript")) == (
        BASELINE_C_PATTERNS_CHECKED["javascript"]
    )


def test_stratum_C_known_vuln_fixtures_fire(
    vulnerable_python_sql_injection,
    vulnerable_python_command_injection,
    vulnerable_python_hardcoded_secrets,
    vulnerable_python_deserialization,
    vulnerable_javascript_xss,
):
    """Curated hard invariant: unambiguous vulnerabilities must produce findings."""
    for code, lang in (
        (vulnerable_python_sql_injection, "python"),
        (vulnerable_python_command_injection, "python"),
        (vulnerable_python_hardcoded_secrets, "python"),
        (vulnerable_python_deserialization, "python"),
        (vulnerable_javascript_xss, "javascript"),
    ):
        assert scan_code(code, lang)["findings"], code


def test_stratum_C_clean_fixture_silent(safe_python_code):
    """Curated hard invariant: obviously-safe code produces zero findings."""
    assert scan_code(safe_python_code, "python")["findings"] == []


# ===========================================================================
# Disjointness -- discharged and standing.
# ===========================================================================

def test_node_ids_disjoint(answer_key):
    """Standing assertion: any threat_vector/agent_threat id collision fails."""
    assert answer_key["disjointness"]["node_id_overlap"] == []


def test_signal_text_overlap_enumerated_and_frozen(answer_key):
    """The 3 shared signal texts are enumerated; a NEW collision fails loud.

    All three sit between the threat_vector ``agent_prompt_injection_direct`` and
    the agent_threat ``prompt_injection_direct`` -- ids are disjoint but the text
    is shared.  This is the Coeus S2 condition: with signal-text overlap present,
    S2 must weigh a tagged single index over two clean views.
    """
    overlap = answer_key["disjointness"]["signal_text_overlap"]
    assert overlap == [
        [
            "input attempts to redefine agent role or persona",
            ["agent_prompt_injection_direct"], ["prompt_injection_direct"],
        ],
        [
            "input contains encoded or obfuscated instructions",
            ["agent_prompt_injection_direct"], ["prompt_injection_direct"],
        ],
        [
            "user input contains instruction override patterns",
            ["agent_prompt_injection_direct"], ["prompt_injection_direct"],
        ],
    ]


# ===========================================================================
# Empty input -> NO_MATCH on every recognition arm.
# ===========================================================================
# These arms exercised the deleted substring matcher and are retired with it (S6).
# The empty/whitespace -> NO_MATCH invariant on the production recognition surface
# is proven in test_hyperion_retrofit_s2.py::test_empty_ids_are_no_match_on_both_views.


# ===========================================================================
# cwe -> threat_id mapping coverage (the S4 seed).
# ===========================================================================

def test_cwe_to_threat_id_mapping_coverage(answer_key):
    cwe_map = answer_key["cwe_to_threat_ids"]
    covered = REMEDIATION_ISLAND_CWES & set(cwe_map)
    missing = REMEDIATION_ISLAND_CWES - set(cwe_map)
    assert len(covered) == 9
    assert missing == CWE_MISSING_FROM_CORPUS
    # Every mapped CWE resolves to at least one real threat_vector id.
    vec_ids = {v["id"] for v in _load_corpus(KNOWLEDGE_DIR)[0]}
    for cwe, ids in cwe_map.items():
        assert ids and all(i in vec_ids for i in ids), cwe


# ===========================================================================
# Grading invariant -- the three strata are NEVER pooled.
# ===========================================================================

def test_strata_graded_separately_never_pooled():
    """Each stratum has its own unit and denominator; there is no shared total.

    Recall@10 over signal->id (A, B) and findings-coverage over code fixtures (C)
    are different measurements; averaging them would be meaningless.  The frozen
    per-stratum denominators encode that separation -- they are three independent
    floors, never a pooled mean.
    """
    denominators = {
        "stratum_A": BASELINE_A_COMBINED[1],
        "stratum_B": BASELINE_B[1],
        "stratum_C": BASELINE_C_VULN_TOTAL,
    }
    assert set(denominators) == {"stratum_A", "stratum_B", "stratum_C"}
    # Denominators differ across strata -- they are not comparable / poolable.
    assert BASELINE_A_COMBINED[1] != BASELINE_B[1] != BASELINE_C_VULN_TOTAL


# ===========================================================================
# Firewall -- Hyperion stands alone.
# ===========================================================================

def test_import_firewall_intact():
    for name in list(sys.modules):
        root = name.split(".", 1)[0]
        assert root not in _FORBIDDEN_ROOTS, name
