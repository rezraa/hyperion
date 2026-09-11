# Copyright (c) 2026 Reza Malik. Licensed under the Apache License, Version 2.0.
"""MCP tool: grade_detector_batch -- the per-stratum MEASUREMENT arm of the
promotion quality gate (S5).

NORTH STAR (this tool's half): run the CURATED scan_code detector island UNION a
PROPOSED candidate batch over the 65 vulnerable + 65 secure stratum-C corpus
examples IN PROCESS, and return the per-stratum firing COUNTS -- baseline_vuln /
baseline_secure (the shipped island alone) and candidate_vuln / candidate_secure
(island + batch). The generic admission math (``othrys.admission.admit_batch``)
consumes these COUNTS as plain data across the Titan-decoupling firewall; this
tool never decides admission and never imports othrys.

ONE SOURCE OF TRUTH for the measurement. ``stratum_c_coverage`` is the S0
findings-coverage measurement, and ``BASELINE_C_*`` are the S0 frozen per-stratum
floors -- both LIVE HERE (production) and are imported BACK by the S0/R2/R6/S5/S6
test suites, so there is exactly one definition of each. (They were authored in
``tests/test_hyperion_retrofit_s0.py``; a served tool reached through the
summon/TitanSession sandbox may import only ``hyperion.*`` + stdlib -- never
``tests.*`` -- so the shared measurement had to live in the package for the gate's
own integration path to work. The move changes no value and no method: the S0
council's "reuse stratum_c_coverage + BASELINE_C_*, do not re-derive 12/2" holds,
the tests re-import and still assert the frozen sets.)

VERIFY-BEFORE-TRUST (CWE-345): the tool re-measures the baseline island live and
FAILS CLOSED unless it matches the frozen ``BASELINE_C_*`` anchor byte-for-byte
(set membership + totals). A batch is never graded against a floor that has
silently drifted from the record.

Firewall: this module imports only ``hyperion.*`` + stdlib -- never
othrys/coeus/mnemos/theia/themis. Testbed/loader level only: it grades the corpus
on disk in-process; it never opens the live othrys.db and never targets :9876.
"""

from __future__ import annotations

import json
from pathlib import Path

from hyperion.knowledge.loader import _KNOWLEDGE_DIR, KnowledgeLoader
from hyperion.tools._shared import coerce, normalize_kwargs
from hyperion.tools.scan_code import scan_code

# Caller kwarg synonyms remapped to the canonical ``candidate_batch`` param.
_ALIASES = {"batch": "candidate_batch", "candidate_detectors": "candidate_batch"}
_IGNORED: set[str] = set()

# The language every stratum-C example is scanned as. Frozen by S0's measurement
# method (``stratum_c_coverage``): the baseline firing SETS were pinned scanning
# every example as python, so a candidate is graded the SAME way -- a batch that
# would raise recall must apply to the python bucket (``["*"]`` or ``["python"]``)
# to be measured, exactly as the shipped island is.
_SCAN_LANGUAGE = "python"


# ---------------------------------------------------------------------------
# Candidate-batch ceiling -- bounded work over an untrusted proposed batch (CWE-400)
# ---------------------------------------------------------------------------
# grade_detector_batch runs the FULL stratum-C scan (130 examples x the whole detector
# island UNION the batch) in the augmented arm, so that arm's cost grows LINEARLY with
# the batch size over caller-influenceable input -- a 5000-detector batch took ~50s. A
# promotion batch is small by construction (a few dozen detectors), so this NAMED
# ceiling refuses an over-sized batch FAIL-CLOSED at the point the batch is read. It is
# never silently truncated: a truncated grade would certify detectors the grade never
# measured. Sized far above any real promotion batch and far below the DoS range.
_MAX_CANDIDATE_BATCH = 256


# ===========================================================================
# Stratum-C findings-coverage measurement -- the ONE source of truth (from S0).
# ===========================================================================

def _load_vectors(knowledge_dir: Path) -> list[dict]:
    """Load the threat-vector corpus (with its examples) from JSON on disk.

    Reads the same byte-frozen ``threat_vectors.json`` S0 grades, so the examples
    measured here are identical to the ones the frozen ``BASELINE_C_*`` was pinned
    from.
    """
    return json.loads(
        (knowledge_dir / "threat_vectors.json").read_text(encoding="utf-8")
    )["vectors"]


def stratum_c_coverage(
    knowledge_dir: Path | None = None,
    *,
    loader: KnowledgeLoader | None = None,
) -> dict:
    """Measure a scanner's findings coverage over the corpus's own examples.

    For each threat vector, its ``vulnerable`` example SHOULD fire (recall) and its
    ``secure`` example SHOULD stay silent (a firing is a false positive). Returns
    the per-stratum firing SETS + denominators + a partial-scan ledger::

        {vuln_firing, vuln_total, secure_firing, secure_total, incomplete}

    ``incomplete`` is the list of examples whose ``scan_code`` run did NOT complete
    (a per-match ReDoS timeout, an uncompilable detector, or a ceiling truncation).
    scan_code fails OPEN on those -- it DROPS the finding -- so an incomplete example
    cannot be trusted as "not firing"; the ledger lets the grader fail CLOSED rather
    than certify an under-counted stratum (see ``grade_detector_batch``).

    The single source of truth for the stratum-C measurement (S0). ``loader``
    injects the detector set through ``scan_code``'s grading seam: ``None`` grades
    the shipped island (the baseline arm, identical to S0's original call); a
    baseline-plus-candidate ``KnowledgeLoader`` grades the augmented set (the
    candidate arm). Both arms run the SAME ``scan_code`` path, so the two counts are
    directly comparable per stratum -- never pooled.
    """
    kdir = Path(knowledge_dir) if knowledge_dir is not None else _KNOWLEDGE_DIR
    vuln_firing: set[str] = set()
    secure_firing: set[str] = set()
    incomplete: list[dict] = []
    vuln_total = secure_total = 0

    def _scan_example(example: str, vid: str, stratum: str, firing: set[str]) -> None:
        """Scan one example the ONE way; record firing + any partial-scan gap.

        DRY seam for the two strata: both run the identical scan_code path. A scan
        scan_code reports as ``incomplete`` (timed_out / skipped / truncated) dropped
        a finding fail-open, so it is recorded in the ledger -- never silently read as
        "not firing".
        """
        res = scan_code(example, _SCAN_LANGUAGE, kb=loader)
        if res["findings"]:
            firing.add(vid)
        if res.get("incomplete"):
            incomplete.append({
                "id": vid, "stratum": stratum,
                "timed_out": len(res.get("timed_out") or []),
                "skipped": len(res.get("skipped") or []),
                "truncated": bool(res.get("truncated")),
            })

    for v in _load_vectors(kdir):
        examples = v.get("examples") or {}
        vulnerable = examples.get("vulnerable")
        secure = examples.get("secure")
        if vulnerable:
            vuln_total += 1
            _scan_example(vulnerable, v["id"], "vuln", vuln_firing)
        if secure:
            secure_total += 1
            _scan_example(secure, v["id"], "secure", secure_firing)
    return {
        "vuln_firing": vuln_firing,
        "vuln_total": vuln_total,
        "secure_firing": secure_firing,
        "secure_total": secure_total,
        "incomplete": incomplete,
    }


# ===========================================================================
# Frozen per-stratum stratum-C floors (from S0). Immovable; the tamper-evident
# anchor the tool verifies the live baseline against before grading a batch.
# ===========================================================================

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


# ===========================================================================
# Candidate-detector normalisation -- fill the fields scan_code's finding
# projection reads, so a batch need only carry a ``regex`` (+ optional languages).
# ===========================================================================
# scan_code (_scan_detectors) reads these keys off every detector; a candidate
# missing one would raise mid-scan. We default them so the grader is robust to a
# terse proposed batch WITHOUT authoring detector content (out of this story's
# scope) -- the defaults never change WHAT fires (that is the regex alone).
_CANDIDATE_FIELD_DEFAULTS: dict[str, object] = {
    "name": "candidate",
    "base_severity": "info",
    "cwe": "",
    "description": "candidate detector (promotion grading)",
    "remediation": "",
    "languages": ["*"],
    "requires_agent_signals": False,
}


def _normalise_candidate(det: object, index: int) -> dict | None:
    """Normalise one proposed detector, or ``None`` if it carries no regex.

    A candidate must be a dict with a non-empty ``regex`` (the only field that
    governs firing); everything else is defaulted. A synthetic unique ``id`` is
    assigned so an id-less batch cannot collide with the ReDoS-quarantine
    id-exclusion (which keys on ``id``).
    """
    if not isinstance(det, dict):
        return None
    regex = det.get("regex")
    if not (isinstance(regex, str) and regex.strip()):
        return None
    out = dict(_CANDIDATE_FIELD_DEFAULTS)
    for key in ("name", "base_severity", "cwe", "description", "remediation",
                "languages", "requires_agent_signals"):
        if det.get(key) is not None:
            out[key] = det[key]
    out["regex"] = regex
    out["id"] = det.get("id") or f"candidate-{index}"
    out["detector_kind"] = det.get("detector_kind", "code_shape")
    return out


# ===========================================================================
# The grading tool.
# ===========================================================================

@normalize_kwargs
def grade_detector_batch(
    candidate_batch: list | None = None,
    conn: object = None,
) -> dict:
    """Grade a proposed detector batch per stratum over the frozen corpus.

    Args:
        candidate_batch: The PROPOSED detectors (list of dicts, each with at least
            a ``regex``). ``batch`` and ``candidate_detectors`` are accepted
            aliases. An empty/absent batch grades the shipped island alone.
        conn: Accepted for served-mode signature parity; the grade runs on the
            on-disk corpus in-process and does not use it.

    Returns:
        On success, the per-stratum COUNTS the generic admission gate consumes::

            {ok: True, vuln_total, secure_total,
             baseline_vuln, baseline_secure, candidate_vuln, candidate_secure}

        ``baseline_*`` is the shipped island; ``candidate_*`` is island + batch.
        Adding detectors is monotonic, so ``candidate_* >= baseline_*`` always: a
        real gain is ``candidate_vuln > baseline_vuln`` and a false positive is
        ``candidate_secure`` rising above the frozen 2.

        Fails closed with ``{ok: False, reason: ...}`` -- never returning counts --
        in three cases, so a batch that cannot be certified is REFUSED, never
        admitted: (1) the batch exceeds ``_MAX_CANDIDATE_BATCH`` (CWE-400); (2)
        baseline drift (the live island no longer matches the frozen anchor); or
        (3) the augmented scan was incomplete (a candidate timed out / was truncated
        on an example, so its firing count -- especially the false-positive count --
        cannot be trusted).
    """
    batch = coerce(candidate_batch, list) or []
    # CWE-400: refuse an over-ceiling batch FAIL-CLOSED where the untrusted input is
    # read -- never partially grade a truncated batch (that would certify detectors the
    # grade never ran). See _MAX_CANDIDATE_BATCH.
    if len(batch) > _MAX_CANDIDATE_BATCH:
        return {
            "ok": False,
            "reason": (
                f"candidate batch too large: {len(batch)} detectors exceeds the "
                f"_MAX_CANDIDATE_BATCH ceiling of {_MAX_CANDIDATE_BATCH} -- refusing "
                f"to grade (a promotion batch is a few dozen; grading is bounded work)"
            ),
        }
    candidates = [
        c for c in (_normalise_candidate(d, i) for i, d in enumerate(batch))
        if c is not None
    ]

    # Baseline arm -- the shipped island, measured by the ONE source of truth.
    baseline = stratum_c_coverage()

    # VERIFY-BEFORE-TRUST (CWE-345): the live island must equal the frozen anchor
    # (set membership + totals) or the corpus/island has drifted -- fail closed
    # rather than grade a candidate against a floor that no longer matches the tome.
    if (
        baseline["vuln_firing"] != BASELINE_C_VULN_FIRING
        or baseline["secure_firing"] != BASELINE_C_SECURE_FIRING
        or baseline["vuln_total"] != BASELINE_C_VULN_TOTAL
        or baseline["secure_total"] != BASELINE_C_SECURE_TOTAL
    ):
        return {
            "ok": False,
            "reason": (
                "baseline drift: the live stratum-C scan does not match the frozen "
                "BASELINE_C_* anchor -- refusing to grade against a moved floor"
            ),
        }

    # Candidate arm -- island UNION the proposed batch, SAME scan path.
    augmented = stratum_c_coverage(
        loader=KnowledgeLoader(extra_code_detectors=candidates)
    )

    # MEASUREMENT INTEGRITY -- fail closed on an incomplete augmented scan. scan_code
    # fails OPEN on a per-match ReDoS timeout: it DROPS the finding and flags
    # ``incomplete``. A candidate regex that (evading the static quarantine) times out on
    # a SECURE example thus silently drops its false-positive finding, UNDER-counting
    # candidate_secure -- the ONE direction that admits a batch that should be rejected.
    # So an incomplete augmented scan is NOT graded: a timed-out example is never counted
    # as "not firing". The baseline arm is the clean, ReDoS-quarantined island, anchored
    # to the frozen BASELINE_C_* above; only the untrusted candidate batch trips this.
    if augmented["incomplete"]:
        return {
            "ok": False,
            "reason": (
                "grade incomplete: candidate scan timed out (or was truncated/"
                f"skipped) on {len(augmented['incomplete'])} stratum-C example(s) "
                "-- cannot certify the false-positive count; refusing promotion"
            ),
        }

    return {
        "ok": True,
        "vuln_total": baseline["vuln_total"],
        "secure_total": baseline["secure_total"],
        "baseline_vuln": len(baseline["vuln_firing"]),
        "baseline_secure": len(baseline["secure_firing"]),
        "candidate_vuln": len(augmented["vuln_firing"]),
        "candidate_secure": len(augmented["secure_firing"]),
    }
