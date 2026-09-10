# Copyright (c) 2026 Reza Malik. Licensed under the Apache License, Version 2.0.
"""Hyperion R6 -- grade the ``adjudicate_findings`` judgment layer (council 1fee93f2,
rider b). The empirical proof the reframe is sound.

NORTH STAR: the codified ``adjudicate_findings`` step (scan/SKILL.md step 3) is a
REFINEMENT + RANKING layer on an ALREADY-precise detector -- it must never drop a
real vuln (the conservative floor), and it must earn its keep by removing scan_code's
secure-example false positives. Graded on the corpus's OWN labelled examples, per
label class, NEVER pooled (m-e8ccb163).

CORRECTED FRAMING (council 1fee93f2 overturned the original premise). ``scan_code``
is NOT a wide net over 316 corpus patterns needing rescue. R4 shipped the SAME 29/25
curated-island detectors, now DB-backed, firing BYTE-IDENTICAL to the old islands.
So scan_code is already high-precision: on the corpus's own examples it fires on only
2 secure examples (frozen stratum-C, S0 ``BASELINE_C_SECURE_FIRING``). The obsolete
REJECT criterion "wide-net recall gains nothing over the island" is MOOT -- the design
IS the island. This story grades the JUDGMENT layer, not scan_code's recall.

WHAT ``adjudicate_findings`` CAN AND CANNOT DO. It operates ONLY on scan_code's raw
findings: it can KEEP (rank), DROP (a cited false_positive), but it can NEVER invent a
finding. So its recall on the vulnerable examples is bounded ABOVE by scan_code's --
the 53 vulnerable examples scan_code is silent on are a scan_code COVERAGE GAP (corpus
authoring, out of this arc), not an adjudication failure. Grading the judgment layer
means grading exactly two things:
  * vulnerable examples that FIRED: is the real vuln KEPT? (a dropped real vuln is the
    cardinal failure -- the floor).
  * secure examples that FIRED: is scan_code's false positive correctly DROPPED, with
    a cited reason?

THE CONSERVATIVE FLOOR (the fail-safe, pinned here). On this labelled set, recall on
the vulnerable examples after adjudication EQUALS the scan_code baseline: no real vuln
is lost to adjudication. Structurally guaranteed and asserted below: adjudication DROPS
a finding ONLY on a specific, cited safe-evidence trigger (a comment sink, an
already-parameterised DB-API call); absent such evidence it KEEPS (SKILL.md step 3.1:
"never drop -- the fail-safe is to over-report"). No vulnerable-example finding matches
a safe trigger, so none is dropped.

REPEATABILITY / how the LLM non-determinism is bounded. KEEP-vs-DROP is the only axis
the floor rests on, and it IS deterministic: ``adjudicate_findings`` below codifies
SKILL.md step 3's cited false_positive triggers as a checkable function, re-run live
against scan_code's live findings. The confidence sub-grade (``likely`` vs ``unlikely``
ranking) is the irreducibly-judgment part -- recorded in the frozen ``ADJUDICATION``
oracle with its rationale, bounded by the floor, and NOT required to be reproduced
deterministically. The persona goes live on the user's re-seed; this harness grades the
on-disk skill contract + scan_code, no live DB.

Scope: JSON on disk. Firewall: hyperion imports only hyperion.*.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest

# Repo root on sys.path so ``tests`` imports as a package under any invocation
# (mirrors R3), letting R6 import S0's frozen stratum-C baseline as its ground truth.
_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import json

from hyperion.knowledge.loader import _KNOWLEDGE_DIR
from hyperion.tools.scan_code import scan_code
from tests.test_hyperion_retrofit_s0 import (
    BASELINE_C_SECURE_FIRING,
    BASELINE_C_SECURE_TOTAL,
    BASELINE_C_VULN_FIRING,
    BASELINE_C_VULN_TOTAL,
)

KNOWLEDGE_DIR = Path(_KNOWLEDGE_DIR)

# The whole labelled set is graded as python -- the exact convention S0 stratum-C uses,
# so R6's scan baseline is directly comparable to the frozen BASELINE_C sets.
_GRADE_LANGUAGE = "python"


# ===========================================================================
# Labelled set -- the corpus's own example snippets (the ground truth labels).
# vulnerable == should contain a real vuln (positive); secure == should be clean
# (negative). Loaded LIVE from the corpus so a drift is caught, never re-typed.
# ===========================================================================

def labelled_set() -> list[tuple[str, str, str, str]]:
    """(vector_id, category, kind, code) for every corpus example, in file order.

    ``kind`` is "vulnerable" or "secure". Fresh list per call.
    """
    vectors = json.loads(
        (KNOWLEDGE_DIR / "threat_vectors.json").read_text(encoding="utf-8")
    )["vectors"]
    out: list[tuple[str, str, str, str]] = []
    for v in vectors:
        examples = v.get("examples") or {}
        for kind in ("vulnerable", "secure"):
            code = examples.get(kind)
            if code:
                out.append((v["id"], v["category"], kind, code))
    return out


def scan_baseline() -> dict[str, set[str]]:
    """scan_code's RAW firing over the labelled set: {vuln_firing, secure_firing}.

    A vector id is in a firing set iff scan_code returns >=1 finding on that example.
    The deterministic ground the adjudication grade rests on.
    """
    vuln_firing: set[str] = set()
    secure_firing: set[str] = set()
    for vid, _cat, kind, code in labelled_set():
        if scan_code(code, _GRADE_LANGUAGE)["findings"]:
            (vuln_firing if kind == "vulnerable" else secure_firing).add(vid)
    return {"vuln_firing": vuln_firing, "secure_firing": secure_firing}


# ===========================================================================
# The codified ``adjudicate_findings`` step -- SKILL.md scan step 3, as a checkable
# deterministic function. RAW findings in -> {scan_candidates, dropped, handoff}.
# ===========================================================================
# A finding is DROPPED only on CITED safe evidence (SKILL.md step 3.1). Everything
# else is KEPT (confidence defaulted up to ``likely``: "never drop -- the fail-safe is
# to over-report"). DROP is thus the narrow, evidenced exception, which is what
# structurally pins the conservative floor: no evidence => KEEP => no real vuln lost.
#
# The two safe triggers reachable in THIS labelled set are implemented. The remaining
# step-3.1 triggers (a string-literal / variable-name / test-fixture match) require the
# live persona's judgment and are recorded in ADJUDICATION, not codified here -- no
# example in the set exercises them, so codifying them would be untested speculation
# (Directive 12: report what is deferred, do not fake-cover it).

_SEVERITY_UPPER = {
    "critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM",
    "low": "LOW", "info": "INFO",
}

# Already-parameterised DB-API call: a plain (NON f-string, no .format) query literal
# carrying only a bound placeholder (%s / %(name)s / ? / :name), followed by a comma
# -> the params argument. This is the canonical safe form; the SQL regex fires on the
# %s placeholder, not a live string-format sink. An f-string / .format / concatenated
# query never matches (no leading f-prefix allowed), so a real SQL injection is kept.
_PARAMETERISED_DB_CALL = re.compile(
    r"""(?:execute|query)\s*\(\s*(?:r|b|rb|br)?["'][^"']*"""
    r"""(?:%s|%\(\w+\)s|\?|:\w+)[^"']*["']\s*,"""
)


def _false_positive_reason(finding: dict, code_lines: list[str]) -> str | None:
    """Cited safe evidence that this match never executes as the sink it screens for,
    or None to KEEP (the conservative default). One reason string per trigger."""
    line_no = finding.get("line_number", 0)
    line = code_lines[line_no - 1] if 0 < line_no <= len(code_lines) else ""
    matched = finding.get("matched_text", "")

    # (1) Sink lands INSIDE a comment -> the matched text never executes.
    hash_at = line.find("#")
    sink_at = line.find(matched) if matched else -1
    if hash_at != -1 and sink_at != -1 and sink_at > hash_at:
        return "match lands inside a comment; the sink never executes"

    # (2) Already-parameterised DB-API call -> the regex fired on a bound placeholder.
    if "CWE-89" in (finding.get("cwe") or "") and _PARAMETERISED_DB_CALL.search(line):
        return (
            "already-parameterised DB-API call: the query uses a bound placeholder "
            "with a separate params argument, so the %-match is a placeholder, not a "
            "live string-format injection sink"
        )
    return None


def adjudicate_findings(findings: list[dict]) -> dict:
    """SKILL.md scan step 3, codified. RAW ``scan_code`` findings ->
    {scan_candidates (KEEP, ranked), dropped (false_positive, with reason), handoff}.

    Faithful to the OUTPUT CONTRACT shape. Confidence is ``false_positive`` (dropped)
    or the conservative default ``likely`` (kept); the ``likely`` vs ``unlikely`` split
    is the live persona's ranking judgment (see ADJUDICATION), not codified here.
    """
    scan_candidates: list[dict] = []
    dropped: list[dict] = []
    for f in findings:
        # Each finding carries its own matched line via context; reconstruct the
        # per-finding source line list from line_content (single-line detectors).
        code_lines = [f.get("line_content", "")]
        # _false_positive_reason indexes by line_number, so normalise to a 1-line view.
        line_no = f.get("line_number", 1)
        probe = dict(f, line_number=1)
        reason = _false_positive_reason(probe, code_lines)
        base = f.get("severity", "info")
        det = f.get("pattern", "")
        ident = f"{det}@{line_no}"
        if reason is not None:
            dropped.append({
                "id": ident, "detector": det, "cwe": f.get("cwe"),
                "line_number": line_no, "base_severity": base,
                "confidence": "false_positive", "reason": reason,
            })
            continue
        scan_candidates.append({
            "id": ident, "detector": det, "cwe": f.get("cwe"),
            "line_number": line_no, "matched_text": f.get("matched_text", ""),
            "base_severity": base, "confidence": "likely",
            "contextual_severity": _SEVERITY_UPPER.get(base, "INFO"),
            "remediation_ref": _remediation_ref(f),
        })
    # RANK survivors: contextual_severity desc, then line asc (all here are 'likely').
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    scan_candidates.sort(key=lambda c: (order[c["contextual_severity"]], c["line_number"]))
    for i, c in enumerate(scan_candidates, 1):
        c["rank"] = i
    handoff = [
        c["remediation_ref"] for c in scan_candidates
        if c["contextual_severity"] in ("CRITICAL", "HIGH")
    ]
    return {"scan_candidates": scan_candidates, "dropped": dropped, "handoff": handoff}


def _remediation_ref(finding: dict) -> dict:
    """SKILL.md step 3.5: route by source_vectors[].id when present, else cwe."""
    svs = finding.get("source_vectors") or []
    if svs and svs[0].get("id"):
        return {"threat_id": svs[0]["id"]}
    return {"cwe": finding.get("cwe")}


# ===========================================================================
# The FROZEN GRADE (the oracle) -- Themis's per-example adjudication of every FIRING
# example, applying SKILL.md step 3 as Hyperion would. Recorded so the grade is
# inspectable and the codified adjudicator above is checked against it.
#
# Keyed (vector_id, kind). Two DIFFERENT kinds of value live in each entry, graded
# differently -- a reader must never mistake one for the other:
#
#   VERIFIED (asserted against the codified adjudicator in
#   test_codified_adjudicator_reproduces_frozen_grade):
#     * disposition (KEEP | DROP) -- the axis the conservative floor rests on.
#     * contextual_severity -- on a KEPT finding this is deterministic
#       (_SEVERITY_UPPER[base]) and cross-checked. On a DROP entry it is the severity
#       the finding WOULD have carried (informational: a dropped finding emits none).
#
#   PERSONA JUDGMENT (recorded, NOT reproduced or graded by this harness):
#     * persona_confidence -- the finer band the LIVE persona applies at run time on
#       the user's re-seed. The codified adjudicator emits ONLY a flat
#       confidence="likely" for every KEEP (SKILL.md 3.1's conservative default,
#       "never drop -- over-report") and "false_positive" for every DROP -- it never
#       emits "confirmed" or "unlikely". Those bands, and the rationale prose, are
#       hand-authored narrative for the live run, bounded by the floor. They are
#       labelled persona_confidence precisely so they are never read as a
#       verified/graded result (proven in test_persona_confidence_bands_are_not_codified).
#
# All firing corpus examples produce exactly one finding (verified), so a kept finding
# is trivially rank 1; the multi-finding RANK comparator is exercised separately in
# test_rank_orders_a_multi_finding_report.
# ===========================================================================

ADJUDICATION: dict[tuple[str, str], dict] = {
    # --- VULNERABLE examples that fired: every match lands on a genuine live sink.
    ("injection_sql", "vulnerable"): dict(
        disposition="KEEP", persona_confidence="confirmed", contextual_severity="CRITICAL",
        rationale="f-string SQL built from {user_id} passed to cursor.execute -- a live CWE-89 sink."),
    ("injection_command", "vulnerable"): dict(
        disposition="KEEP", persona_confidence="confirmed", contextual_severity="HIGH",
        rationale="f-string interpolated into os.system -- a live CWE-78 shell sink."),
    ("auth_password_storage", "vulnerable"): dict(
        disposition="KEEP", persona_confidence="confirmed", contextual_severity="HIGH",
        rationale="hashlib.md5 over a password -- a live weak-hash sink (CWE-328)."),
    ("crypto_weak_algorithms", "vulnerable"): dict(
        disposition="KEEP", persona_confidence="confirmed", contextual_severity="HIGH",
        rationale="AES.MODE_ECB selected -- a live weak-cipher-mode sink (CWE-327)."),
    ("crypto_cleartext_transmission", "vulnerable"): dict(
        disposition="KEEP", persona_confidence="confirmed", contextual_severity="HIGH",
        rationale="verify=False on an outbound request -- live TLS-verification-disabled sink."),
    ("crypto_hardcoded_secrets", "vulnerable"): dict(
        disposition="KEEP", persona_confidence="confirmed", contextual_severity="HIGH",
        rationale="API_KEY assigned a literal secret -- a live hardcoded-secret sink (CWE-798)."),
    ("crypto_improper_certificate", "vulnerable"): dict(
        disposition="KEEP", persona_confidence="confirmed", contextual_severity="HIGH",
        rationale="verify=False on an outbound request -- live cert-verification-disabled sink (CWE-295)."),
    ("input_deserialization", "vulnerable"): dict(
        disposition="KEEP", persona_confidence="confirmed", contextual_severity="HIGH",
        rationale="pickle.loads over request.data -- a live untrusted-deserialization sink (CWE-502)."),
    ("config_debug_production", "vulnerable"): dict(
        disposition="KEEP", persona_confidence="confirmed", contextual_severity="HIGH",
        rationale="app.run(debug=True) -- a live debug-in-production sink (CWE-489)."),
    ("data_api_key_exposure", "vulnerable"): dict(
        disposition="KEEP", persona_confidence="confirmed", contextual_severity="HIGH",
        rationale="const API_KEY literal secret -- a live hardcoded-secret sink (CWE-798)."),
    ("data_database_dumps", "vulnerable"): dict(
        disposition="KEEP", persona_confidence="confirmed", contextual_severity="HIGH",
        rationale="os.system f-string writing a dump to a web-accessible path -- live CWE-78 sink."),
    ("agent_insecure_output", "vulnerable"): dict(
        disposition="KEEP", persona_confidence="confirmed", contextual_severity="CRITICAL",
        rationale="exec() over agent-generated code -- a live code-execution sink (CWE-95); "
                  "the matched exec( precedes the trailing comment, so it is the real sink."),
    # --- SECURE examples that fired: scan_code's false positives to triage.
    ("injection_sql", "secure"): dict(
        disposition="DROP", persona_confidence="false_positive", contextual_severity="CRITICAL",
        rationale="parameterised cursor.execute(sql, (user_id,)) with a %s bound "
                  "placeholder -- already safe; the regex fired on the placeholder, "
                  "not a live string-format sink. Correctly removed."),
    ("data_database_dumps", "secure"): dict(
        # KEPT, not dropped: the 'secure' label addresses CWE-540 (the dump is now
        # gpg-encrypted), but os.system(f'...{db}...{date}...') still interpolates into
        # a shell -- a genuine CWE-78 concern the label does not remediate. The
        # conservative fail-safe forbids dropping without safety evidence. Demoted to
        # 'unlikely' (the interpolated values read as internal config, a db name and a
        # date, not an obvious attacker entry point) and ranked last. Residual
        # label-level FP -> corpus-authoring follow-up (use subprocess list form).
        disposition="KEEP", persona_confidence="unlikely", contextual_severity="HIGH",
        rationale="os.system f-string interpolation is a real CWE-78 shell sink the "
                  "CWE-540 'secure' fix does not address; conservatively retained, "
                  "demoted to unlikely, ranked last. Recorded corpus follow-up."),
}

# The conservative floor, stated as the recall bar committed to on this labelled set.
FLOOR = (
    "Recall on the vulnerable examples after adjudication EQUALS the scan_code "
    "baseline: NO real vuln is dropped by adjudication. "
    f"Baseline vulnerable firing = {len(BASELINE_C_VULN_FIRING)}/"
    f"{BASELINE_C_VULN_TOTAL}; all must remain in scan_candidates."
)


# ===========================================================================
# (0) The scan_code baseline is unchanged -- pinned to S0's frozen stratum-C.
# ===========================================================================

def test_scan_baseline_matches_frozen_stratum_c():
    """The live scan over the labelled set equals S0's byte-frozen firing sets.

    R6's whole grade rests on this baseline; if scan_code drifts, the grade is void
    and this fails loud FIRST."""
    base = scan_baseline()
    assert base["vuln_firing"] == set(BASELINE_C_VULN_FIRING)
    assert base["secure_firing"] == set(BASELINE_C_SECURE_FIRING)


def test_labelled_set_counts():
    """The labelled set is exactly the corpus examples: 65 vulnerable + 65 secure."""
    ls = labelled_set()
    vuln = [x for x in ls if x[2] == "vulnerable"]
    secure = [x for x in ls if x[2] == "secure"]
    assert len(vuln) == BASELINE_C_VULN_TOTAL == 65
    assert len(secure) == BASELINE_C_SECURE_TOTAL == 65


# ===========================================================================
# (1) THE CONSERVATIVE FLOOR -- no real vuln is dropped by adjudication.
#     The cardinal failure this story exists to prevent.
# ===========================================================================

def test_conservative_floor_no_real_vuln_dropped():
    """For EVERY vulnerable example scan_code fired on, adjudication KEEPS the finding.

    Recall after adjudication == the scan_code baseline (no real vuln lost). Run LIVE
    through the codified adjudicator, not from the frozen table, so a regression in the
    adjudicator that started dropping a real vuln fails HERE."""
    kept_vuln: set[str] = set()
    dropped_vuln: list[tuple[str, str]] = []
    for vid, _cat, kind, code in labelled_set():
        if kind != "vulnerable":
            continue
        findings = scan_code(code, _GRADE_LANGUAGE)["findings"]
        if not findings:
            continue  # scan_code coverage gap -- not adjudication's to answer
        result = adjudicate_findings(findings)
        if result["scan_candidates"]:
            kept_vuln.add(vid)
        for d in result["dropped"]:
            dropped_vuln.append((vid, d["reason"]))
    # THE FLOOR: nothing dropped, recall preserved at the baseline.
    assert dropped_vuln == [], f"real vuln DROPPED -- floor breached: {dropped_vuln}"
    assert kept_vuln == set(BASELINE_C_VULN_FIRING)


def test_no_vulnerable_finding_matches_a_safe_trigger():
    """Structural proof of the floor: DROP fires only on cited safe evidence, and NO
    vulnerable-example finding carries any. The floor cannot be breached by data."""
    for vid, _cat, kind, code in labelled_set():
        if kind != "vulnerable":
            continue
        for f in scan_code(code, _GRADE_LANGUAGE)["findings"]:
            reason = _false_positive_reason(
                dict(f, line_number=1), [f.get("line_content", "")]
            )
            assert reason is None, (vid, f["pattern"], reason)


# ===========================================================================
# (2) VALUE -- adjudication removes scan_code's secure-example false positives.
# ===========================================================================

def test_secure_fp_the_parameterised_sql_is_dropped():
    """The injection_sql secure example (parameterised %s query) is DROPPED as a
    false_positive with a reason -- adjudication earns its keep."""
    code = _example("injection_sql", "secure")
    result = adjudicate_findings(scan_code(code, _GRADE_LANGUAGE)["findings"])
    assert result["scan_candidates"] == []
    assert len(result["dropped"]) == 1
    assert result["dropped"][0]["confidence"] == "false_positive"
    assert "parameterised" in result["dropped"][0]["reason"]


def test_secure_fp_the_shell_interpolation_is_conservatively_kept():
    """The data_database_dumps secure example (os.system f-string) is KEPT: it is a
    genuine CWE-78 shell-interpolation sink the CWE-540 'secure' fix does not address.
    The conservative fail-safe forbids dropping it -- a retained finding, never a
    silently-dropped one."""
    code = _example("data_database_dumps", "secure")
    result = adjudicate_findings(scan_code(code, _GRADE_LANGUAGE)["findings"])
    assert result["dropped"] == []
    assert len(result["scan_candidates"]) == 1
    assert result["scan_candidates"][0]["detector"] == "os_system"


def test_secure_precision_improves_never_worsens():
    """Net secure-example false positives: 2 (baseline) -> 1 (after adjudication).

    Adjudication provides value (drops 1 of 2) and does NOT worsen precision -- so the
    REJECT criterion 'no value AND worsens secure precision' is NOT met."""
    baseline_secure_fp = 0
    post_adjudication_secure_fp = 0
    for vid, _cat, kind, code in labelled_set():
        if kind != "secure":
            continue
        findings = scan_code(code, _GRADE_LANGUAGE)["findings"]
        if findings:
            baseline_secure_fp += 1
        if adjudicate_findings(findings)["scan_candidates"]:
            post_adjudication_secure_fp += 1
    assert baseline_secure_fp == len(BASELINE_C_SECURE_FIRING) == 2
    assert post_adjudication_secure_fp == 1
    assert post_adjudication_secure_fp < baseline_secure_fp  # strictly improved


# ===========================================================================
# (3) NO-OP on the silent majority -- adjudication invents nothing.
# ===========================================================================

def test_adjudication_is_a_proven_noop_on_silent_examples():
    """The 116 examples scan_code is silent on produce ZERO findings, so adjudication
    is a provable no-op (empty in -> empty out). Nothing here is 'deferred' -- there is
    no finding to judge. This is why the full grade == the 14 firing examples."""
    silent = 0
    for _vid, _cat, _kind, code in labelled_set():
        findings = scan_code(code, _GRADE_LANGUAGE)["findings"]
        if findings:
            continue
        silent += 1
        result = adjudicate_findings(findings)
        assert result == {"scan_candidates": [], "dropped": [], "handoff": []}
    assert silent == 130 - (len(BASELINE_C_VULN_FIRING) + len(BASELINE_C_SECURE_FIRING))
    assert silent == 116


# ===========================================================================
# (4) The codified adjudicator reproduces the frozen grade (oracle agreement).
# ===========================================================================

def test_codified_adjudicator_reproduces_frozen_grade():
    """Every FIRING example is cross-checked against the frozen ADJUDICATION oracle on
    the VERIFIED axes -- and ONLY those:
      * disposition (KEEP/DROP) -- the axis the floor rests on;
      * contextual_severity on a KEPT finding -- deterministic (_SEVERITY_UPPER[base]);
      * the confidence + rank the codified harness ACTUALLY emits -- a FLAT
        confidence="likely" and rank=1 on every KEEP (all firing examples are
        singletons), "false_positive" on every DROP.
    Asserting the emitted confidence + rank pins the table to what the code produces, so
    no unverified value rides it with the weight of a graded result. The oracle's finer
    persona_confidence bands (confirmed / unlikely) are the live persona's judgment and
    are deliberately NOT reproduced here (see test_persona_confidence_bands_are_not_codified)."""
    graded = 0
    for vid, _cat, kind, code in labelled_set():
        findings = scan_code(code, _GRADE_LANGUAGE)["findings"]
        if not findings:
            continue
        graded += 1
        expected = ADJUDICATION[(vid, kind)]
        result = adjudicate_findings(findings)
        got = "KEEP" if result["scan_candidates"] else "DROP"
        assert got == expected["disposition"], (vid, kind, got, expected)
        if got == "KEEP":
            c = result["scan_candidates"][0]
            # What the CODE emits -- a flat 'likely' + rank 1 (singleton), NOT the
            # oracle's persona band.
            assert c["confidence"] == "likely", (vid, kind, c["confidence"])
            assert c["rank"] == 1, (vid, kind, c["rank"])
            # contextual_severity IS deterministic -- it must match the oracle.
            assert c["contextual_severity"] == expected["contextual_severity"], (
                vid, kind, c["contextual_severity"], expected["contextual_severity"])
        else:
            assert result["dropped"][0]["confidence"] == "false_positive", (
                vid, kind, result["dropped"][0]["confidence"])
    # The frozen oracle covers EXACTLY the firing set -- no phantom, no missing entry.
    assert graded == len(ADJUDICATION) == 14


def test_persona_confidence_bands_are_not_codified():
    """The oracle's finer persona_confidence bands are LABELLED persona judgment, not a
    graded value -- and that label is honest: the codified adjudicator emits ONLY
    'likely' (KEEP) or 'false_positive' (DROP), never 'confirmed' or 'unlikely'. So a
    reader can never mistake the hand-authored bands for something this harness verified,
    and a future edit cannot quietly promote one into a 'graded' column undetected."""
    persona_bands = {e["persona_confidence"] for e in ADJUDICATION.values()}
    # The finer bands ARE recorded in the oracle...
    assert {"confirmed", "unlikely"} <= persona_bands
    # ...but are provably ABSENT from everything the codified adjudicator emits.
    codified: set[str] = set()
    for _vid, _cat, _kind, code in labelled_set():
        findings = scan_code(code, _GRADE_LANGUAGE)["findings"]
        if not findings:
            continue
        r = adjudicate_findings(findings)
        codified |= {c["confidence"] for c in r["scan_candidates"]}
        codified |= {d["confidence"] for d in r["dropped"]}
    assert codified == {"likely", "false_positive"}
    assert "confirmed" not in codified and "unlikely" not in codified


def test_frozen_grade_keys_are_exactly_the_firing_set():
    """The oracle's keys equal the live firing set -- the grade tracks the data."""
    base = scan_baseline()
    firing = {(vid, "vulnerable") for vid in base["vuln_firing"]}
    firing |= {(vid, "secure") for vid in base["secure_firing"]}
    assert set(ADJUDICATION) == firing


def test_output_contract_shape_honoured():
    """adjudicate_findings emits exactly the SKILL.md OUTPUT CONTRACT keys, and every
    kept candidate carries a rank, a contextual_severity and a remediation_ref."""
    code = _example("injection_sql", "vulnerable")
    result = adjudicate_findings(scan_code(code, _GRADE_LANGUAGE)["findings"])
    assert set(result) == {"scan_candidates", "dropped", "handoff"}
    c = result["scan_candidates"][0]
    assert c["rank"] == 1
    assert c["contextual_severity"] == "CRITICAL"
    assert ("threat_id" in c["remediation_ref"]) or ("cwe" in c["remediation_ref"])


# ===========================================================================
# (5) RANK -- the multi-finding comparator of the 'ranked, triaged report' north star.
#     Every firing corpus example produces exactly ONE finding, so rank is trivially 1
#     and the sort is never actually ordered. This fixture fires SIX detectors across
#     four severities with two same-severity tie-groups, exercising the sort the
#     singletons never do. The codified comparator orders by contextual_severity DESC,
#     then line ASC -- the two CHECKABLE keys. (SKILL.md step 3 also lists
#     'real before unlikely', but the codified adjudicator emits a flat 'likely' for
#     every KEEP and does not sort by confidence -- that tier is the live persona's, the
#     same persona_confidence axis the oracle records but this harness does not grade.)
# ===========================================================================

# Six DB detectors on distinct lines across four severities, with the CRITICALs placed
# AFTER the HIGH/MEDIUM/LOW lines so a correct report must REORDER them (not echo source
# order). No agent keywords (the agent gate stays shut) and no comment / parameterised-DB
# line, so nothing is dropped -- the whole set survives to be ranked.
_MULTI_FINDING_SNIPPET = "\n".join([
    "hashlib.md5(data)",                    # L1 HIGH     CWE-328 md5_usage
    'api_key = "abcdefghijklmnop1234"',     # L2 HIGH     CWE-798 hardcoded_api_key
    "token = random.randint(0, 9999)",      # L3 MEDIUM   CWE-338 random_not_secure
    'allowed = "127.0.0.1:5432"',           # L4 LOW      CWE-200 hardcoded_ip
    'password = "supersecret123"',          # L5 CRITICAL CWE-798 hardcoded_password
    "eval(expr)",                           # L6 CRITICAL CWE-95  eval_usage
])

# The order a correct report must produce: severity DESC, ties broken by line ASC.
_EXPECTED_RANKING = [
    ("CRITICAL", 5), ("CRITICAL", 6),
    ("HIGH", 1), ("HIGH", 2),
    ("MEDIUM", 3), ("LOW", 4),
]


def test_rank_orders_a_multi_finding_report():
    """scan_code + adjudicate over a six-finding snippet yields a report ranked by
    contextual_severity DESC, ties broken by line ASC -- the 'ranked, triaged report'
    north star, demonstrated on a real multi-finding scan (not a rank==1 singleton).

    The two CRITICALs (L5, L6) rank ahead of the two HIGHs (L1, L2), then the MEDIUM
    (L3), then the LOW (L4); within each severity tie the lower line ranks first."""
    result = adjudicate_findings(
        scan_code(_MULTI_FINDING_SNIPPET, _GRADE_LANGUAGE)["findings"]
    )
    assert result["dropped"] == []  # none is a cited false positive -- all are ranked
    assert [
        (c["contextual_severity"], c["line_number"]) for c in result["scan_candidates"]
    ] == _EXPECTED_RANKING
    # rank is a contiguous 1..n assigned in that sorted order.
    assert [c["rank"] for c in result["scan_candidates"]] == [1, 2, 3, 4, 5, 6]
    # handoff carries exactly the CRITICAL+HIGH remediation refs (MEDIUM/LOW excluded).
    assert len(result["handoff"]) == 4

    # The comparator is load-bearing, not a pass-through of scan_code's own severity
    # sort: fed the SAME findings in REVERSED order, adjudicate re-derives the identical
    # ranking. The tie-break (line ASC) is genuinely exercised -- the reversed input
    # presents each tie-group in descending line order.
    reversed_findings = list(
        reversed(scan_code(_MULTI_FINDING_SNIPPET, _GRADE_LANGUAGE)["findings"])
    )
    reranked = adjudicate_findings(reversed_findings)["scan_candidates"]
    assert [
        (c["contextual_severity"], c["line_number"]) for c in reranked
    ] == _EXPECTED_RANKING


# ===========================================================================
# Grading invariant -- the two label classes are NEVER pooled (m-e8ccb163).
# ===========================================================================

def test_strata_never_pooled():
    """Vulnerable (recall floor) and secure (false-positive removal) are different
    units with different denominators -- there is no shared accuracy. The grade reports
    them apart, exactly as S0 forbids pooling stratum A/B/C."""
    assert BASELINE_C_VULN_TOTAL == BASELINE_C_SECURE_TOTAL == 65
    # ...but the SUCCESS MEASURE differs: vuln is graded by recall preserved, secure by
    # false positives removed. Pooling a recall with an FP count is meaningless.
    assert FLOOR.startswith("Recall on the vulnerable examples")


# ===========================================================================
# Helpers + Firewall.
# ===========================================================================

def _example(vector_id: str, kind: str) -> str:
    for vid, _cat, k, code in labelled_set():
        if vid == vector_id and k == kind:
            return code
    raise AssertionError(f"no {kind} example for {vector_id}")


def test_import_firewall_intact():
    for name in list(sys.modules):
        root = name.split(".", 1)[0]
        assert root not in ("othrys", "coeus", "mnemos", "theia", "themis"), name
