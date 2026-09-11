# Copyright (c) 2026 Reza Malik. Licensed under the Apache License, Version 2.0.
"""Knowledge loader for Hyperion.

Loads threat_vectors.json, agent_threats.json, decision_rules.json, and
security_tools.json and provides pure retrieval, structural signal matching
(exact substring against decision_rules), and constraint filtering.

No fuzzy keyword matching.  No tokenization.  No Jaccard scoring.
"""

from __future__ import annotations

import hashlib
import heapq
import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path

# The stdlib regex parser (dep-free) exposes the SAME AST re.compile itself builds.
# It moved from ``sre_parse``/``sre_constants`` to ``re._parser``/``re._constants``
# in 3.11; both are stdlib, so the load-time ReDoS quarantine below reuses the one
# real parser (no bespoke regex lexer) and adds NO dependency.
try:  # Python 3.11+
    from re import _constants as _re_constants
    from re import _parser as _re_parser
except ImportError:  # pragma: no cover - Python <= 3.10
    import sre_constants as _re_constants  # type: ignore[no-redef]
    import sre_parse as _re_parser  # type: ignore[no-redef]

_log = logging.getLogger(__name__)

_KNOWLEDGE_DIR = Path(__file__).parent

# ---------------------------------------------------------------------------
# Severity ranking — lower index = more severe.
# ---------------------------------------------------------------------------
_SEVERITY_RANK: dict[str, int] = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
}


# ==========================================================================
# Shape-C retrieval engine — the signal-index hydrate path
# (problem-language signals -> threat vector), a JUSTIFIED MIRROR of the SHIPPED
# mnemos.knowledge.loader / coeus.knowledge.loader / theia.knowledge.loader /
# themis.knowledge.loader ``_SignalEngine`` (council b420a9f0 / m-73ea1894;
# Shape-C standard m-55f6d4da). Hyperion runs standalone: its runtime code MUST
# NOT import othrys.*/coeus.*/mnemos.*/theia.*/themis.* (the titan-decoupling
# firewall, feedback_titan_decoupling_no_othrys_import); the mirror is kept
# faithful by a semantic-parity drift test (tests/test_firewall.py) — the drift
# test IS the enforcement mechanism the firewall's ban on a shared lib requires.
#
# Adapted for the Hyperion corpus: the index source is each THREAT VECTOR's own
# ``signals`` field (with the decision_rules dissolved in at load, S2); the fan-out
# edge is ``alternatives``, materialised at S2 from the rules' recommended_threat/
# alternatives; the node index is a FLAT ``id -> vector`` map (the Coeus/Themis
# shape, no ``(structure_id, pattern)`` tuple).
#
# The engine is PARAMETERIZED over a ``_NamedIndex`` seam — (index source, signal
# field, edge field) — so the SECOND named index over ``agent_threats`` (S2)
# REUSES every primitive below (ceilings, floor, state vocab, ``_signal_id``,
# ``RetrievalResult``, ``deep_freeze``, the facet gate) with ZERO duplicated
# engine code. Both indexes are wired: the threat-vector view and the agent-threat
# view compose the nested two-view ``{threat_signals, agent_threat_signals}``.
#
# Hyperion fail-closed addition (the council's mandatory husk guard,
# b420a9f0-decision-2): the ``_NamedIndex`` carries a ``required_fields`` axis,
# and :meth:`_SignalEngine._resolve_node` treats a node missing any of them as
# unresolved — a FIELD-SHORT node (a husk, e.g. the ``{id, name}`` stub, or the
# empty-description ``matched_rules`` the blind path produced) resolves to
# DANGLING, never a silently-defaulted husk. The reference engines have no such
# axis; adding it does not move the shared primitives or the output contract the
# drift test asserts (a genuine node passes the guard and the contract is
# unchanged).
# ==========================================================================
#
# The four-state retrieval envelope is the single output contract. Every
# retrieval resolves to exactly one state, and abstention is a structural field
# rather than an empty list narrated as an answer (fail closed, never a husk).
HIT = "hit"                        # >=1 vector hydrated at/above the confidence floor
LOW_CONFIDENCE = "low_confidence"  # vectors hydrated, best below the confidence floor
NO_MATCH = "no_match"              # signals recognised but none map to a corpus vector
DANGLING = "dangling"              # signals map only to ids absent/husk in the corpus

# Two named ceilings bound the fan-out's agency, applied where cost is incurred:
_SEED_CAP: int = 64    # max seed vectors admitted to fan-out (bound BEFORE expansion)
_TOPK_CAP: int = 50    # hard ceiling on hydrated results (bound AFTER expansion)

# A hit needs at least this many corroborating votes (direct + propagated); a
# lone single vote is surfaced but flagged low_confidence. Auditable integer,
# not a tuned score.
_CONFIDENCE_FLOOR: int = 2


def _signal_id(text: str) -> str:
    """Deterministic, byte-reproducible id for a signal's text.

    A stable content hash so the corpus-derived index recomputes identically
    across processes (independent of PYTHONHASHSEED) and the LLM/harness can
    refer to a signal by a short id.
    """
    return "sig-" + hashlib.sha1(text.strip().encode("utf-8")).hexdigest()[:12]


# ==========================================================================
# Load-time static ReDoS quarantine (CWE-1333) — council 1fee93f2 / story R3.
#
# A dep-free static guard so an authored/edited ``code_detectors.json`` regex that
# can catastrophically backtrack never enters the active detector set ``scan_code``
# runs on untrusted code (R4 makes ``scan_code`` read detectors from the DB). The
# check is PRECISE: a SINGLE unbounded quantifier (``.*`` / ``.+`` / ``.*?`` /
# ``[^x]+``) is only POLYNOMIAL and is ceiling-bounded by ``scan_code``'s
# ``_MAX_LINE_LENGTH`` (4000), so it is NOT quarantined. Only the two EXPONENTIAL
# shapes are (Hyperion, assess_threat ``input_regex_dos``: "avoid nested
# quantifiers", "alternation with overlapping patterns"):
#   1. a backtracking quantifier over a body holding an AMBIGUOUS inner repeat.
#      The danger is the INNER repeat's AMBIGUITY — min != max, so a single run of
#      input can be split more than one way — NOT its magnitude. ``(a+)+`` and the
#      easily-accidental small-bounded ``(a{1,2})+`` are BOTH exponential; a FIXED
#      inner ``(a{3})+`` (min==max) is deterministic and safe (H3). When the OUTER
#      quantifier is unbounded (or bounded so large it is unbounded-equivalent,
#      ``(a{1,1000}){1,1000}`` — H2) an ambiguous inner is exponential outright;
#      when BOTH are bounded the search space is inner_max ** outer_max, caught only
#      once it exceeds ``_NESTED_SEARCH_CEILING`` so ``(a{1,9}){1,9}`` (387M) is
#      quarantined but ``(a{1,5}){1,5}`` (3125) survives.
#   2. overlapping alternation under a quantifier — ``(a|a)*`` ``(a|ab)+``
# Either shape hidden inside a LOOKAROUND body (``(?=(a+)+$)``, ``(?!(a|a)+z)``) is
# caught too: every walker recurses ASSERT/ASSERT_NOT subpatterns, not only groups
# (H1). The engine reuses the stdlib parser ``re.compile`` itself uses (one source of
# truth, no bespoke lexer) and DFS-walks the AST (Mnemos: DFS preorder, O(n) over
# the pattern length). It FAILS CLOSED: an uncompilable/unparseable regex — or any
# error analysing the untrusted pattern — quarantines. Over-approximation errs the
# same way (a first-char clash under a quantifier quarantines even if the branches
# later diverge), because for a security guard over-quarantine is the safe
# direction. In-memory ONLY: the byte-frozen S0 ``code_detectors.json`` is never
# written.
# ==========================================================================

_MAXREPEAT = _re_constants.MAXREPEAT
_OP_MAX_REPEAT = _re_constants.MAX_REPEAT
_OP_MIN_REPEAT = _re_constants.MIN_REPEAT
_OP_SUBPATTERN = _re_constants.SUBPATTERN
_OP_BRANCH = _re_constants.BRANCH
_OP_LITERAL = _re_constants.LITERAL
_OP_IN = _re_constants.IN
# Lookaround ops: ``(?=...)`` / ``(?<=...)`` parse to ASSERT, ``(?!...)`` /
# ``(?<!...)`` to ASSERT_NOT. Their arg is ``(direction, subpattern)`` — a
# catastrophic quantifier can hide inside a lookaround body (``(?=(a+)+$)``), so
# every walker MUST recurse that subpattern (``av[1]``) exactly as it does a group.
_OP_ASSERT = _re_constants.ASSERT
_OP_ASSERT_NOT = _re_constants.ASSERT_NOT
_ASSERT_OPS = (_OP_ASSERT, _OP_ASSERT_NOT)
# Possessive repeats (3.11+, ``a*+``) cannot backtrack, so a possessive OUTER
# quantifier is never the catastrophic one; only greedy/lazy repeats backtrack.
# Guarded getattr keeps the mirror importable on < 3.11.
_OP_POSSESSIVE_REPEAT = getattr(_re_constants, "POSSESSIVE_REPEAT", None)
_REPEAT_OPS = tuple(
    op for op in (_OP_MAX_REPEAT, _OP_MIN_REPEAT, _OP_POSSESSIVE_REPEAT)
    if op is not None
)
_BACKTRACKING_REPEAT_OPS = (_OP_MAX_REPEAT, _OP_MIN_REPEAT)

# The OUTER-quantifier magnitude gate: a bounded max above this small ceiling makes
# the outer quantifier unbounded-EQUIVALENT, because it can iterate enough times to
# multiply an ambiguous inner into a DoS just as a ``+`` would (``(a{1,1000}){1,1000}``
# backtracks like ``(a+)+`` — H2). It bounds the OUTER only; the INNER repeat's danger
# is keyed on AMBIGUITY, not magnitude (:func:`_is_ambiguous`), so a small-bounded
# ambiguous inner (``(a{1,2})+`` — H3) is not missed. Every real detector's outer
# groups are un-quantified or ``?`` (max 1), far below this, so it never fires on one.
_NESTED_REPEAT_CEILING: int = 10

# The BOTH-BOUNDED search-space ceiling. When neither quantifier is unbounded-equiv
# the nested pair's worst-case backtracking is a bounded constant, inner_max **
# outer_max; below this ceiling it is trivially bounded (``(a{1,5}){1,5}`` = 3125,
# Hyperion measured ~0s) and above it a DoS (``(a{1,9}){1,9}`` = 387,420,489, > 3s).
# WHY this value: at ~10^5 partition attempts per anchored match position the bounded
# blowup stops being trivial and becomes a real DoS multiplier; the named safe/bomb
# controls sit 32x below and ~3900x above it, so both land firmly on the right side.
_NESTED_SEARCH_CEILING: int = 100_000


def _is_unbounded_equiv(maxrep: object) -> bool:
    """True if an OUTER quantifier's max is unbounded, or so large it repeats as if.

    ``maxrep`` is the parser's max-count field: the ``_MAXREPEAT`` sentinel for a
    truly unbounded quantifier (``*`` ``+`` ``{n,}``), otherwise an int. A large
    bounded max is unbounded-equivalent for the OUTER of a nested pair (H2), so a
    ``(a{1,1000}){1,1000}`` bomb is caught the same as ``(a+)+``.
    """
    return maxrep is _MAXREPEAT or maxrep > _NESTED_REPEAT_CEILING


def _is_ambiguous(minrep: object, maxrep: object) -> bool:
    """True if a repeat is AMBIGUOUS: its min and max differ.

    An ambiguous repeat lets a single run of input be consumed by more than one
    iteration count, so an enclosing quantifier can split that run multiple ways —
    the root of catastrophic backtracking (CWE-1333). Covers the unbounded
    ``a+``/``a*``/``a{1,}`` (min != ``_MAXREPEAT``) AND bounded ranges
    ``a{1,2}``/``a{0,n}``; a FIXED ``a{3}`` (min == max) is deterministic and safe.
    """
    return minrep != maxrep


def _iter_inner_repeats(seq):
    """Yield ``(min, max)`` for every BACKTRACKING repeat nested anywhere in *seq*.

    The rule-1 helper: it surfaces the inner repeats an enclosing quantifier could
    multiply. Recurses group, branch, repeat AND lookaround (ASSERT/ASSERT_NOT)
    bodies, so an inner repeat buried in a nested group or a lookahead is found. A
    POSSESSIVE inner (``a*+``) cannot backtrack and so introduces no ambiguity — its
    bounds are not yielded, though its body is still walked for a backtracking repeat
    nested below it.
    """
    for op, av in seq:
        if op in _REPEAT_OPS:
            if op in _BACKTRACKING_REPEAT_OPS:
                yield (av[0], av[1])
            yield from _iter_inner_repeats(av[2])
        elif op is _OP_SUBPATTERN:
            yield from _iter_inner_repeats(av[-1])
        elif op is _OP_BRANCH:
            for sub in av[1]:
                yield from _iter_inner_repeats(sub)
        elif op in _ASSERT_OPS:
            yield from _iter_inner_repeats(av[1])


def _nested_repeat_reason(outer_max: object, body) -> str | None:
    """Why a backtracking outer quantifier over *body* is a nested-repeat bomb.

    Rule 1, keyed on the INNER repeat's ambiguity (:func:`_is_ambiguous`), not its
    magnitude. For each ambiguous inner repeat the outer would multiply:

    * OUTER unbounded-equivalent (:func:`_is_unbounded_equiv`) -> exponential, the
      classic ``(a+)+`` / small-bounded ``(a{1,2})+`` / large-bounded
      ``(a{1,1000}){1,1000}`` (H2) bomb;
    * BOTH bounded -> a constant search space ``inner_max ** outer_max``; a DoS only
      once it exceeds ``_NESTED_SEARCH_CEILING`` (``(a{1,9}){1,9}`` yes,
      ``(a{1,5}){1,5}`` no — H3). A bounded outer over an UNBOUNDED inner
      (``(a+){1,3}``) is polynomial and ceiling-bounded, so it is not flagged here.

    Returns the quarantine reason, or ``None`` when no inner repeat is dangerous.
    """
    outer_unbounded = _is_unbounded_equiv(outer_max)
    for inner_min, inner_max in _iter_inner_repeats(body):
        if not _is_ambiguous(inner_min, inner_max):
            continue
        if outer_unbounded:
            return "nested unbounded quantifier"
        if inner_max is not _MAXREPEAT and inner_max ** outer_max > _NESTED_SEARCH_CEILING:
            return "nested bounded ambiguous quantifier"
    return None


def _first_chars(seq) -> frozenset[int] | None:
    """Code points an alternation branch can START with, or ``None`` = wide.

    ``None`` (an empty/zero-width, wildcard ``.``, negated, ranged, or category
    leading atom) is treated as overlapping every other branch — a branch that
    cannot be PROVEN to start disjointly is assumed to overlap (fail closed).
    """
    if not len(seq):
        return None  # empty branch matches zero-width -> overlaps everything
    op, av = seq[0]
    if op is _OP_LITERAL:
        return frozenset({av})
    if op is _OP_IN:
        chars: set[int] = set()
        for iop, iav in av:
            if iop is _OP_LITERAL:
                chars.add(iav)
            else:  # RANGE / NEGATE / CATEGORY -> not a finite, provable set
                return None
        return frozenset(chars)
    if op is _OP_SUBPATTERN:
        return _first_chars(av[-1])
    if op is _OP_BRANCH:
        acc: set[int] = set()
        for sub in av[1]:
            fc = _first_chars(sub)
            if fc is None:
                return None
            acc |= fc
        return frozenset(acc)
    return None  # ANY / NOT_LITERAL / anchors / groupref / ... -> wide


def _branches_overlap(branches) -> bool:
    """True if any two alternation branches can match a common first character.

    Prefix and equal overlaps surface here too: the parser factors a shared prefix
    out of the branches and leaves an empty (``None`` -> wide) residual branch,
    which overlaps every sibling — so ``(a|a)`` and ``(a|ab)`` are both caught.
    """
    firsts = [_first_chars(b) for b in branches]
    for i in range(len(firsts)):
        for j in range(i + 1, len(firsts)):
            fi, fj = firsts[i], firsts[j]
            if fi is None or fj is None or (fi & fj):
                return True
    return False


def _overlapping_alternation(seq) -> bool:
    """True if a parsed subpattern holds an overlapping alternation (rule-2 helper).

    Scans the WHOLE quantified body: the parser factors common prefixes, so an
    overlapping alternation can sit at any depth — inside a group, a lookaround, or
    inside a bounded repeat that the outer unbounded quantifier still multiplies.
    """
    for op, av in seq:
        if op is _OP_BRANCH:
            if _branches_overlap(av[1]):
                return True
        elif op is _OP_SUBPATTERN:
            if _overlapping_alternation(av[-1]):
                return True
        elif op in _REPEAT_OPS:
            if _overlapping_alternation(av[2]):
                return True
        elif op in _ASSERT_OPS:
            if _overlapping_alternation(av[1]):
                return True
    return False


def _scan_redos(seq) -> str | None:
    """DFS a parsed regex for a catastrophic-backtracking shape; ``None`` if safe.

    At each backtracking quantifier, test its body for a nested ambiguous repeat
    (rule 1, :func:`_nested_repeat_reason` — evaluated for a bounded outer too, so
    the both-bounded ``(a{1,9}){1,9}`` blowup is caught) then, only under an
    unbounded-equivalent outer, for an overlapping alternation (rule 2); recurse
    through groups, branches, repeat AND lookaround (ASSERT/ASSERT_NOT) bodies
    otherwise. A lone unbounded quantifier over a single atom (``.*``) reaches
    neither rule — polynomial, kept.
    """
    for op, av in seq:
        if op in _REPEAT_OPS:
            body = av[2]
            if op in _BACKTRACKING_REPEAT_OPS:
                reason = _nested_repeat_reason(av[1], body)
                if reason:
                    return reason
                if _is_unbounded_equiv(av[1]) and _overlapping_alternation(body):
                    return "overlapping alternation under quantifier"
            reason = _scan_redos(body)
            if reason:
                return reason
        elif op is _OP_SUBPATTERN:
            reason = _scan_redos(av[-1])
            if reason:
                return reason
        elif op is _OP_BRANCH:
            for sub in av[1]:
                reason = _scan_redos(sub)
                if reason:
                    return reason
        elif op in _ASSERT_OPS:
            reason = _scan_redos(av[1])
            if reason:
                return reason
    return None


def static_redos_reason(regex: object) -> str | None:
    """Return WHY *regex* must be quarantined, or ``None`` if it is ReDoS-safe.

    The single source of truth for the load-time quarantine (one pure leaf):
    compile-or-quarantine first (a bomb that will not even compile fails closed),
    then a static AST walk for the exponential shapes. A single unbounded
    quantifier is polynomial and ceiling-bounded, so it is NOT flagged. Any error
    analysing the untrusted pattern fails closed (quarantine).
    """
    if not isinstance(regex, str):
        return "detector has no string regex"
    try:
        re.compile(regex)
    except re.error as exc:
        return f"uncompilable regex: {exc}"
    try:
        return _scan_redos(_re_parser.parse(regex))
    except Exception as exc:  # noqa: BLE001 - untrusted pattern: fail closed on any error
        return f"unparseable regex: {exc}"


@dataclass(frozen=True)
class RetrievalResult:
    """The single retrieval output contract (see the four states above).

    ``patterns`` is the ranked, hydrated result (empty for the abstention
    states — the field name is kept ``patterns`` for cross-titan envelope parity;
    the nodes are Hyperion threat vectors). ``votes`` is the transparent, auditable
    tally used for ranking (vector_id -> integer vote count). ``dangling`` surfaces
    any referenced vector id that did not resolve to a genuine corpus node -- an
    integrity failure is reported, never masked by a husk. ``unmatched_signals``
    records matched signal ids the index did not recognise.
    """

    state: str
    patterns: list[dict] = field(default_factory=list)
    votes: dict[str, int] = field(default_factory=dict)
    dangling: list[str] = field(default_factory=list)
    unmatched_signals: list[str] = field(default_factory=list)
    reason: str = ""


class _FrozenDict(dict):
    """A read-only ``dict``: refuses in-place mutation, serialises as a plain dict.

    Hydrated vectors are deep-frozen through this type so a caller cannot corrupt
    the shared singleton corpus by mutating a returned node (the shallow-copy
    shared-reference hazard: ``{**node}`` copies the top dict but aliases its nested
    lists). It subclasses ``dict`` so ``json.dumps`` and ``["key"]`` reads work
    unchanged; only the mutators are sealed.
    """

    __slots__ = ()

    def _readonly(self, *_a: object, **_k: object) -> None:
        raise TypeError("hydrated vector is read-only")

    __setitem__ = __delitem__ = clear = pop = popitem = setdefault = update = _readonly


def deep_freeze(obj: object) -> object:
    """Recursively copy *obj* into an immutable, JSON-serialisable structure.

    Dicts become :class:`_FrozenDict`, lists/tuples become tuples, scalars pass
    through. The copy severs every shared reference to the source, so this both
    fixes the shared-ref corruption hazard and makes the result tamper-proof.
    """
    if isinstance(obj, dict):
        return _FrozenDict({k: deep_freeze(v) for k, v in obj.items()})
    if isinstance(obj, (list, tuple)):
        return tuple(deep_freeze(v) for v in obj)
    return obj


def _parse_team_range(token: object) -> tuple[float, float] | None:
    """Parse a ``team_size`` token (``"1-5"``, ``"50+"``, ``"3"``) into ``(lo, hi)``.

    Pure string arithmetic — no regex, no eval on caller input. Returns ``None``
    for anything unparseable so the gate can fail OPEN (never demote on a token it
    cannot read). Ported from the shipped mirror as part of the facet gate; DORMANT
    on the Hyperion corpus (no threat vector carries facet dicts), but kept faithful
    so the semantic-parity drift test holds.
    """
    s = str(token).strip()
    if not s:
        return None
    try:
        if s.endswith("+"):
            return (int(s[:-1]), float("inf"))
        if "-" in s:
            lo, hi = s.split("-", 1)
            return (int(lo), int(hi))
        n = int(s)
        return (n, n)
    except (ValueError, TypeError):
        return None


def facet_matches(facet: dict, constraints: dict) -> bool:
    """Does one structured facet hold under the caller's *constraints*?

    The single facet-matching predicate (one source of truth, not one copy per
    reader). A facet is an AND of conditions; it matches only when the constraints
    confirm *every* key: ``team_size`` by numeric range overlap, every other key by
    categorical exact match (case/whitespace-normalised, never substring). Pure
    comparison — no ``eval``/regex on caller input; an unspecified or unreadable
    key yields ``False`` (fail open, never demote on unconfirmed input). Ported
    from the shipped mirror; DORMANT on the Hyperion corpus.
    """
    if not isinstance(facet, dict) or not facet:
        return False
    for key, fval in facet.items():
        cval = constraints.get(key)
        if cval is None:
            return False
        if key == "team_size":
            fr, cr = _parse_team_range(fval), _parse_team_range(cval)
            if fr is None or cr is None:
                return False
            if not (fr[0] <= cr[1] and cr[0] <= fr[1]):
                return False
        elif str(cval).strip().lower() != str(fval).strip().lower():
            return False
    return True


def split_conditions(items: list | None) -> tuple[list[str], list[dict]]:
    """Partition a mixed condition list into its two kinds.

    These lists mix free-text condition strings (for LLM recognition) and
    structured facet dicts (for deterministic gating). Any reader dispatches on
    element type through this one helper. Single pass; tolerates ``None``. Returns
    ``(text_conditions, facet_constraints)``. Ported from the shipped mirror; on
    the Hyperion corpus the facet half is always empty (DORMANT).
    """
    texts: list[str] = []
    facets: list[dict] = []
    for item in items or []:
        (facets if isinstance(item, dict) else texts).append(item)
    return texts, facets


def is_gated(node: dict, constraints: dict) -> bool:
    """Is *node* gated by its OWN ``avoid_when`` facets under *constraints*?

    Reasoning over the node's own field, not a hardcoded detector. Ported from the
    shipped mirror as the deterministic facet gate; DORMANT on the Hyperion corpus
    (no threat vector carries an ``avoid_when`` facet dict), so it always returns
    ``False`` here. The live constraint gate on Hyperion is
    :meth:`KnowledgeLoader.filter_by_constraints`.
    """
    if not constraints:
        return False
    _, facets = split_conditions(node.get("avoid_when"))
    return any(facet_matches(f, constraints) for f in facets)


@dataclass
class _NamedIndex:
    """Descriptor for ONE signal-index corpus the parameterized engine serves.

    The three behavioural axes the council named — (index source, signal field,
    edge field) — are ``node_index`` / ``signal_field`` / ``edge_field``.
    ``id_field`` labels the public view's id-list column for THIS corpus
    (``vector_ids`` at S1; ``agent_threat_ids`` for S2's second index); it rides
    with the index source as a presentation facet, NOT a fourth behavioural axis —
    the ceilings, floor, state vocabulary, ranking and ``_signal_id`` are identical
    across corpora, which is exactly what the drift test asserts. ``required_fields``
    is the Hyperion husk guard (council b420a9f0-decision-2): the fields a genuine,
    tool-reasoned node must carry; a resolved node missing any is treated as a husk
    -> DANGLING (see :meth:`_SignalEngine._resolve_node`). ``name`` identifies the
    corpus. ``signal_index`` (signal_id -> entry) is populated by
    :meth:`_SignalEngine._build_signal_index`.
    """

    name: str
    node_index: dict[str, dict]
    signal_field: str
    edge_field: str
    id_field: str
    required_fields: tuple[str, ...] = ()
    signal_index: dict[str, dict] = field(default_factory=dict)


class _SignalEngine:
    """The Shape-C signal-index retrieval engine — inherited by BOTH loaders and
    PARAMETERIZED over a :class:`_NamedIndex` so one copy serves every corpus.

    :class:`KnowledgeLoader` (JSON) and ``GraphKnowledgeLoader`` (Kuzu, via
    subclassing — Hyperion's graph loader delegates its read path to the JSON
    parent through ``super().__init__()``, so it inherits this engine unchanged)
    build the threat-vector signal index in ``__init__`` and expose the S1-wired
    public bindings that delegate here. Every primitive below reads only its
    ``_NamedIndex`` argument, so there is exactly ONE copy of the engine — no
    duplicate engine code across the two loaders, and none across the S1 index and
    S2's future agent_threats index.
    """

    # ------------------------------------------------------------------
    # Index build (called from the loader's __init__, once per _NamedIndex)
    # ------------------------------------------------------------------

    def _build_signal_index(self, index: _NamedIndex) -> None:
        """Build ``index.signal_index`` from each node's ``index.signal_field``.

        Derived deterministically so the view is byte-reproducible (ids are
        content hashes; id-lists sorted). Fails CLOSED at load on a hash collision
        between two distinct signal texts — a 48-bit clash would silently merge
        two signals, so we refuse to serve a corrupted index rather than mask it.
        """
        index.signal_index = {}
        for node in index.node_index.values():
            nid = node["id"]
            for raw in node.get(index.signal_field, []):
                text = raw.strip()
                if not text:
                    continue
                sid = _signal_id(text)
                entry = index.signal_index.get(sid)
                if entry is None:
                    index.signal_index[sid] = {
                        "signal_id": sid,
                        "signal_text": text,
                        index.id_field: [nid],
                    }
                elif entry["signal_text"] != text:
                    raise ValueError(
                        f"signal_id collision {sid}: "
                        f"{text!r} vs {entry['signal_text']!r}"
                    )
                elif nid not in entry[index.id_field]:
                    entry[index.id_field].append(nid)
        for entry in index.signal_index.values():
            entry[index.id_field].sort()

    # ------------------------------------------------------------------
    # Node-id resolution (retrieval engine)
    # ------------------------------------------------------------------

    def _lookup_node(self, index: _NamedIndex, node_id: str) -> dict | None:
        """Resolve a node id to its stored dict by existence only, fail closed.

        Returns the real stored dict or ``None`` — never a synthesised ``{id, name}``
        husk. The mirror-faithful resolver: the drift test asserts this contract.
        The Hyperion husk guard layers on top in :meth:`_resolve_node`.
        """
        return index.node_index.get(node_id)

    def _resolve_node(self, index: _NamedIndex, node_id: str) -> dict | None:
        """Resolve to a GENUINE node, fail closed on absent OR field-short (husk).

        The Hyperion husk guard (council b420a9f0-decision-2): a node present in the
        index but missing a field a tool will reason over (``index.required_fields``)
        is a husk — the ``{id, name}`` stub, or the empty-description ``matched_rules``
        the blind path produced, is the canonical case. It is treated as unresolved so
        hydrate records it as ``dangling`` and never emits it as a silently-defaulted
        husk. S1 seeds ``required_fields`` with the threat-vector corpus's
        genuine-node marker (``signals`` + ``category``); the S3/S4 tool retrofits may
        tighten it to the exact field set their body reads.
        """
        node = self._lookup_node(index, node_id)
        if node is None:
            return None
        if any(not node.get(f) for f in index.required_fields):
            return None
        return node

    # ------------------------------------------------------------------
    # Signal-index retrieval engine (problem-language -> node)
    # ------------------------------------------------------------------

    def _signal_index_view(self, index: _NamedIndex) -> list[dict]:
        """Return the deterministic, byte-reproducible signal index view.

        Each entry is ``{signal_id, signal_text, <index.id_field>}``; the LLM
        recognises a problem's signals against this view at runtime and passes the
        matched signal ids to :meth:`_hydrate`. Sorted by ``signal_id`` with sorted
        id-lists so two builds serialise identically.
        """
        return [
            {
                "signal_id": e["signal_id"],
                "signal_text": e["signal_text"],
                index.id_field: list(e[index.id_field]),
            }
            for e in sorted(index.signal_index.values(), key=lambda e: e["signal_id"])
        ]

    def _signal_ids_for(self, index: _NamedIndex, node_id: str) -> list[str]:
        """Return the signal ids of *node_id*'s OWN signals.

        The seed-from-node entry point: a tool that already HOLDS a known node id
        recovers that node's own signal ids from the built index — exactly the ids
        :meth:`_hydrate` recognises — and seeds retrieval with them, so the fan-out
        expands over the node's edge without a caller-supplied recognition step.
        Reads only ``index.signal_index`` (the one source of truth for text ->
        signal id), so the JSON and graph loaders derive the IDENTICAL seed; sorted
        for a deterministic, byte-reproducible order. An unknown or signal-less id
        yields ``[]`` (the caller then hydrates to a fail-closed ``no_match``),
        never a fabricated seed.
        """
        return sorted(
            sid for sid, entry in index.signal_index.items()
            if node_id in entry[index.id_field]
        )

    def _hydrate(
        self,
        index: _NamedIndex,
        matched_signal_ids: list[str],
        k: int = 10,
        fan_out: bool = True,
    ) -> RetrievalResult:
        """Hydrate matched signals into ranked nodes, in the four-state envelope.

        End-to-end entry point a harness drives given matched signal ids:

        * maps each signal id -> its owning node(s), tallying a direct vote per
          signal (a seed's weight = number of matched signals mapping to it);
        * one-hop fan-out over ``index.edge_field`` from the capped seed set,
          propagating each seed's weight to its neighbours (when ``fan_out``);
        * selects the top-``k`` via a size-k heap (``heapq.nlargest``, O(n log k))
          over a two-tier composite key: direct-vote tier (a directly-matched seed
          outranks every propagated-only neighbour), then the pre-fan-out
          direct-vote count within the seed tier (accumulated vote score for
          propagated-only neighbours), then node id ascending — deterministic
          throughout.

        Every node is resolved through :meth:`_resolve_node` (the husk guard), so a
        field-short/absent seed does not fan out and a field-short/absent winner is
        recorded ``dangling`` rather than emitted — fail closed, never a husk.
        Bounded by two ceilings: ``_SEED_CAP`` before fan-out and ``_TOPK_CAP``
        after. Votes are transparent integer counts, never a tuned score.
        """
        k = min(max(int(k), 1), _TOPK_CAP)

        # 1. Direct hydration: matched signal -> seed node(s), one vote each.
        unmatched: list[str] = []
        direct_votes: dict[str, int] = {}
        for sid in matched_signal_ids or []:
            entry = index.signal_index.get(sid)
            if entry is None:
                unmatched.append(sid)
                continue
            for nid in entry[index.id_field]:
                direct_votes[nid] = direct_votes.get(nid, 0) + 1

        # Empty leg: recognised signals that hydrate to nothing -> abstain.
        if not direct_votes:
            return RetrievalResult(
                state=NO_MATCH,
                unmatched_signals=sorted(set(unmatched)),
                reason="no matched signal maps to a corpus vector",
            )

        # 2. Seed cap BEFORE fan-out: rank seeds (weight desc, id asc), bound.
        seeds = sorted(direct_votes.items(), key=lambda kv: (-kv[1], kv[0]))[:_SEED_CAP]

        # 3. Vote tally seeded from the capped seeds' direct votes.
        scores: dict[str, int] = dict(seeds)
        dangling: set[str] = set()

        # 4. One-hop fan-out: propagate each seed's weight to its edge neighbours.
        #    A field-short/absent seed (husk) does not fan out; a field-short/absent
        #    neighbour is surfaced dangling, never propagated to.
        if fan_out:
            for nid, weight in seeds:
                seed_node = self._resolve_node(index, nid)
                if seed_node is None:
                    continue
                for neighbour in seed_node.get(index.edge_field, []):
                    if self._resolve_node(index, neighbour) is None:
                        dangling.add(neighbour)   # typed dangling, surfaced loud
                        continue
                    scores[neighbour] = scores.get(neighbour, 0) + weight

        # 5. Top-k via heap-top-k over a TWO-TIER composite key. Pre-order
        #    candidates by id asc so nlargest's stable decoration breaks full ties
        #    by node id ascending — the tertiary key. The key is (direct-vote tier,
        #    then the pre-fan-out direct-vote COUNT within the seed tier, else the
        #    accumulated vote score): a directly-matched seed (tier True) outranks
        #    every propagated-only neighbour (tier False) regardless of score, so no
        #    zero-direct-vote hub can evict a gold seed under the k cap; and seeds
        #    rank by direct-vote count, not accumulated score, so fan-out cannot
        #    re-order the seed tier.
        ordered = sorted(scores.items())
        top = heapq.nlargest(
            k,
            ordered,
            key=lambda kv: (
                kv[0] in direct_votes,
                direct_votes[kv[0]] if kv[0] in direct_votes else kv[1],
            ),
        )

        # 6. Hydrate the winners into the envelope; never emit a husk. Each node is
        #    resolved through the husk guard and deep-frozen at this boundary: a
        #    shallow ``{**node}`` would alias the singleton corpus's nested lists, so
        #    a caller mutating a returned node would corrupt the shared corpus.
        #    deep_freeze severs every reference and seals the copy.
        patterns: list[dict] = []
        votes: dict[str, int] = {}
        for nid, score in top:
            node = self._resolve_node(index, nid)
            if node is None:
                dangling.add(nid)
                continue
            direct = direct_votes.get(nid, 0)
            patterns.append(deep_freeze({
                **node,
                "retrieval": {
                    "score": score,
                    "direct_votes": direct,
                    "propagated_votes": score - direct,
                    "seed": nid in direct_votes,
                },
            }))
            votes[nid] = score

        # 7. Resolve the envelope state (fail closed).
        if not patterns:
            return RetrievalResult(
                state=DANGLING,
                dangling=sorted(dangling),
                unmatched_signals=sorted(set(unmatched)),
                reason="hydrated ids did not resolve to genuine corpus vectors",
            )
        top_score = patterns[0]["retrieval"]["score"]
        if top_score >= _CONFIDENCE_FLOOR:
            state, reason = HIT, ""
        else:
            state = LOW_CONFIDENCE
            reason = f"best score {top_score} below confidence floor {_CONFIDENCE_FLOOR}"
        return RetrievalResult(
            state=state,
            patterns=patterns,
            votes=votes,
            dangling=sorted(dangling),
            unmatched_signals=sorted(set(unmatched)),
            reason=reason,
        )


# The two signal-index corpora the nested two-view is composed from: the threat
# vectors (recognised by their own ``signals``, with decision_rules dissolved in)
# and the agent_threats (recognised by their own ``detection_signals``). Disjoint
# id-spaces; one _SignalEngine serves both via a _NamedIndex each.
_THREAT_INDEX_NAME = "threat_vectors"
_AGENT_THREAT_INDEX_NAME = "agent_threats"


class KnowledgeLoader(_SignalEngine):
    """Loads and queries the Hyperion knowledge base (threat vectors,
    agent threats, decision rules, security tools).

    All matching is structural / exact / data-driven.  No fuzzy keyword overlap.
    Inherits the Shape-C signal-index retrieval engine (:class:`_SignalEngine`).
    """

    # ------------------------------------------------------------------
    # Initialisation
    # ------------------------------------------------------------------

    def __init__(
        self,
        knowledge_dir: Path | None = None,
        *,
        extra_code_detectors: list[dict] | None = None,
    ) -> None:
        # ``extra_code_detectors`` is the promotion-gate GRADING seam (S5): a
        # PROPOSED detector batch is appended to the shipped set below and then runs
        # through the SAME load-time ReDoS quarantine, the SAME per-language index,
        # and the SAME scan path — so a candidate is measured EXACTLY as it would run
        # live, never on a bespoke reduced path. Additive and in-memory only: with no
        # batch the load is byte-identical to before, and ``code_detectors.json`` on
        # disk is never touched, so the byte-frozen S0 benchmark is unaffected.
        self._dir = knowledge_dir or _KNOWLEDGE_DIR

        with open(self._dir / "threat_vectors.json", encoding="utf-8") as f:
            self._threat_vectors_data = json.load(f)

        with open(self._dir / "agent_threats.json", encoding="utf-8") as f:
            self._agent_threats_data = json.load(f)

        with open(self._dir / "decision_rules.json", encoding="utf-8") as f:
            self._decision_rules_data = json.load(f)

        with open(self._dir / "security_tools.json", encoding="utf-8") as f:
            self._security_tools_data = json.load(f)

        with open(self._dir / "code_detectors.json", encoding="utf-8") as f:
            self._code_detectors_data = json.load(f)

        # Build convenience lists.
        self._vectors: list[dict] = self._threat_vectors_data["vectors"]
        self._agent_threats: list[dict] = self._agent_threats_data["threats"]
        self._rules: list[dict] = self._decision_rules_data["rules"]
        self._tools: list[dict] = self._security_tools_data["tools"]
        self._code_detectors: list[dict] = self._code_detectors_data["detectors"]
        if extra_code_detectors:
            # Append the proposed batch so it shares the one quarantine + index +
            # scan path (the grading seam described in __init__).
            self._code_detectors = self._code_detectors + list(extra_code_detectors)

        # Index: vector_id -> vector_dict
        self._vector_index: dict[str, dict] = {
            v["id"]: v for v in self._vectors
        }

        # Index: agent_threat_id -> threat_dict
        self._agent_threat_index: dict[str, dict] = {
            t["id"]: t for t in self._agent_threats
        }

        # Index: tool_id -> tool_dict
        self._tool_index: dict[str, dict] = {
            t["id"]: t for t in self._tools
        }

        # Build OWASP index: owasp_id -> list of vectors
        self._owasp_index: dict[str, list[dict]] = {}
        for v in self._vectors:
            owasp = v.get("owasp", "")
            if owasp:
                self._owasp_index.setdefault(owasp, []).append(v)

        # Build CWE index: cwe -> sorted list of threat vector ids. The S4
        # finding->vector bridge, built from each vector's OWN ``cwe`` list, so it
        # equals the S0-frozen ``cwe_to_threat_ids`` mapping by construction
        # (one-to-many, deterministic). One source of truth for the cwe lookup a
        # finding without a threat_id needs; a cwe absent here is an uncovered CWE
        # (e.g. CWE-95 / CWE-352), which plan_remediation fails closed on (DANGLING).
        self._cwe_index: dict[str, list[str]] = {}
        for v in self._vectors:
            for c in v.get("cwe", []):
                self._cwe_index.setdefault(c, []).append(v["id"])
        for c in self._cwe_index:
            self._cwe_index[c].sort()

        # Load-time static ReDoS quarantine (story R3 / council 1fee93f2): scan
        # EVERY code_detectors regex for a catastrophic-backtracking shape BEFORE it
        # can enter the active detector set. A quarantined detector is EXCLUDED from
        # ``_detectors_by_language`` (below) and surfaced in ``quarantined_detectors``
        # (queryable) and LOGGED at load — never silently dropped. In-memory only:
        # the byte-frozen ``code_detectors.json`` is untouched. Hyperion verified all
        # 41 migrated regexes are ReDoS-safe, so a healthy load quarantines none.
        self.quarantined_detectors: list[dict] = []
        _quarantined_ids: set[str | None] = set()
        for det in self._code_detectors:
            reason = static_redos_reason(det.get("regex"))
            if reason is not None:
                _quarantined_ids.add(det.get("id"))
                self.quarantined_detectors.append({
                    "id": det.get("id"),
                    "name": det.get("name"),
                    "languages": list(det.get("languages", [])),
                    "reason": reason,
                })
        if self.quarantined_detectors:
            _log.warning(
                "code_detectors ReDoS quarantine: %d detector(s) excluded from the "
                "active scan set: %s",
                len(self.quarantined_detectors),
                ", ".join(
                    f"{q['id']} ({q['reason']})" for q in self.quarantined_detectors
                ),
            )

        # Build code-detector index: language -> code-shape detectors. The single
        # source of truth for scan_code's per-language pattern set. Built ONCE here so
        # get_code_detectors is an O(1) dict lookup for a canonical language, never an
        # O(n) rescan per call. A ``["*"]`` universal detector folds into every named
        # language's bucket, prepended in file order (universal-then-language) so the
        # bucket mirrors the scanner's iteration order. The universal set and the
        # per-language named sets are retained separately so get_code_detectors can
        # compose the unknown-language fallback (universal + BOTH import sets) without
        # a rescan. Agent-signal-gated detectors (``requires_agent_signals``) are NOT
        # part of the language scan set — they run only when _has_agent_signals fires —
        # so they are excluded here (and collected into ``_agent_code_detectors`` for
        # the agent path) and the bucket count equals scan_code's ``patterns_checked``
        # (python 29, javascript 25). A ReDoS-quarantined detector enters neither set.
        self._detectors_by_language: dict[str, list[dict]] = {}
        self._universal_code_detectors: list[dict] = []
        self._named_code_detectors: dict[str, list[dict]] = {}
        self._agent_code_detectors: list[dict] = []
        for det in self._code_detectors:
            if det.get("id") in _quarantined_ids:
                continue  # ReDoS-quarantined: never enters any active detector set
            if det.get("requires_agent_signals"):
                self._agent_code_detectors.append(det)  # file order; the agent path
                continue
            langs = det.get("languages", [])
            if "*" in langs:
                self._universal_code_detectors.append(det)
            else:
                for lang in langs:
                    self._named_code_detectors.setdefault(lang, []).append(det)
        for lang, named in self._named_code_detectors.items():
            self._detectors_by_language[lang] = self._universal_code_detectors + named

        # S2 dissolve (council b420a9f0-decision-1): fold the decision_rules'
        # structural_signals onto their recommended_threat vector's OWN ``signals``
        # (content-positive, provenance kept) and materialise the ``alternatives``
        # fan-out edge from the rules' recommended_threat/alternatives, BEFORE the
        # index is built so both feed the one source of truth. In-memory COPY: the
        # ``decision_rules.json`` corpus is never written, so the byte-frozen S0
        # benchmark (which reads the JSON) is untouched.
        self._dissolved_provenance: dict[str, dict[str, list[str]]] = {}
        self._dissolve_decision_rules()

        # Shape-C threat-vector signal index (from each vector's OWN ``signals``
        # field, now including the dissolved structural_signals; fan-out edge
        # ``alternatives``, materialised at S2). Built at load so a hash collision
        # fails CLOSED here, not at first query. The engine is parameterized over
        # this ``_NamedIndex`` seam, so the second index over agent_threats below
        # reuses every primitive (one engine, both corpora — zero duplicated engine
        # code). ``required_fields`` is the council's husk guard: a field-short
        # vector resolves to DANGLING, never a silently-defaulted husk.
        self._threat_signal_index = _NamedIndex(
            name=_THREAT_INDEX_NAME,
            node_index=self._vector_index,
            signal_field="signals",
            edge_field="alternatives",
            id_field="vector_ids",
            required_fields=("signals", "category"),
        )
        self._build_signal_index(self._threat_signal_index)

        # Shape-C agent-threat signal index (S2): the SECOND named index, over each
        # agent_threat's OWN ``detection_signals``. agent_threats carry no
        # ``alternatives`` edge, so this view is EDGELESS / direct-vote-only (the
        # ``edge_field`` resolves to nothing on the corpus — fan-out is a no-op).
        # Disjoint id-space from the vectors, so the nested two-view routes an id to
        # exactly one corpus and a mis-typed id abstains via NO_MATCH. Same husk
        # guard axis (``detection_signals`` + ``category``).
        self._agent_signal_index = _NamedIndex(
            name=_AGENT_THREAT_INDEX_NAME,
            node_index=self._agent_threat_index,
            signal_field="detection_signals",
            edge_field="alternatives",
            id_field="agent_threat_ids",
            required_fields=("detection_signals", "category"),
        )
        self._build_signal_index(self._agent_signal_index)

    # ------------------------------------------------------------------
    # S2 dissolve — decision_rules -> the vectors' own signals + fan-out edge
    # ------------------------------------------------------------------

    def _dissolve_decision_rules(self) -> None:
        """Fold decision_rules onto the threat vectors in memory (council S2).

        Two folds, deterministic and idempotent, over the loaded corpus:

        * each rule's ``structural_signal`` is COPIED onto its ``recommended_threat``
          vector's own ``signals`` where absent (content-positive), so the engine's
          recognition vocabulary is the union of the vectors' own signals and the
          dissolved rule signals — one source of truth the index is built from;
        * each rule's ``(recommended_threat -> alternatives)`` relationship
          materialises the recommended vector's ``alternatives`` fan-out edge (all
          alternative ids resolve to real vectors; a self-edge and any non-vector id
          are dropped).

        Provenance is kept in ``self._dissolved_provenance`` (signal_text ->
        {rules, vectors}); nothing is folded anonymously. The corpus JSON on disk is
        never written — this is a load-time behaviour, so the frozen S0 benchmark
        (which reads the JSON) is untouched and ``decision_rules.json`` stays
        byte-identical on disk.
        """
        alt_edges: dict[str, set[str]] = {}
        for rule in self._rules:
            signal = (rule.get("structural_signal") or "").strip()
            target_id = rule.get("recommended_threat", "")
            target = self._vector_index.get(target_id)
            if target is None:
                continue  # a rule pointing off the vector corpus is not dissolved
            if signal:
                own = target.setdefault("signals", [])
                if signal not in {s.strip() for s in own}:
                    own.append(signal)  # COPY where absent (idempotent)
                prov = self._dissolved_provenance.setdefault(
                    signal, {"rules": [], "vectors": []}
                )
                if rule["id"] not in prov["rules"]:
                    prov["rules"].append(rule["id"])
                if target_id not in prov["vectors"]:
                    prov["vectors"].append(target_id)
            for alt in rule.get("alternatives", []) or []:
                if alt in self._vector_index and alt != target_id:
                    alt_edges.setdefault(target_id, set()).add(alt)
        for vid, alts in alt_edges.items():
            self._vector_index[vid]["alternatives"] = sorted(alts)

    # ------------------------------------------------------------------
    # Signal-index retrieval engine — public API (threat-vector index)
    # ------------------------------------------------------------------
    # Thin bindings of the parameterized :class:`_SignalEngine` primitives to the
    # threat-vector index. The binding is the parameterization seam, not a duplicate
    # source of truth — the engine logic lives once above. These per-view loader
    # bindings are composed into the ONE filed nested accessor at
    # ``hyperion/tools/get_signal_index.py`` — the one recognition surface.

    def get_signal_index(self) -> list[dict]:
        """Return the deterministic threat-vector signal-index view.

        Each entry is ``{signal_id, signal_text, vector_ids}``, sorted by
        ``signal_id`` with sorted ``vector_ids`` so it serialises identically on
        every call. The LLM recognises a problem's signals against this view and
        passes the matched ids to :meth:`hydrate`.
        """
        return self._signal_index_view(self._threat_signal_index)

    def signal_ids_for(self, vector_id: str) -> list[str]:
        """Return the signal ids of *vector_id*'s own signals (seed-from-node)."""
        return self._signal_ids_for(self._threat_signal_index, vector_id)

    def hydrate(
        self,
        matched_signal_ids: list[str],
        k: int = 10,
        fan_out: bool = True,
    ) -> RetrievalResult:
        """Hydrate matched signal ids into ranked threat vectors (four-state envelope)."""
        return self._hydrate(self._threat_signal_index, matched_signal_ids, k, fan_out)

    # ------------------------------------------------------------------
    # Signal-index retrieval engine — S2 agent-threat index (the second view)
    # ------------------------------------------------------------------
    # The same parameterized :class:`_SignalEngine` primitives bound to the
    # agent-threat index. Composed with the threat-vector view above into the ONE
    # nested accessor filed at ``hyperion/tools/get_signal_index.py`` (the single
    # reachable public function; a caller cannot drop one stratum by construction).

    def get_agent_signal_index(self) -> list[dict]:
        """Return the deterministic agent-threat signal-index view.

        Each entry is ``{signal_id, signal_text, agent_threat_ids}``, sorted by
        ``signal_id`` with sorted ``agent_threat_ids`` so it serialises identically
        on every call — the ``agent_threat_signals`` half of the nested two-view.
        """
        return self._signal_index_view(self._agent_signal_index)

    def agent_signal_ids_for(self, agent_threat_id: str) -> list[str]:
        """Return the signal ids of *agent_threat_id*'s own detection_signals."""
        return self._signal_ids_for(self._agent_signal_index, agent_threat_id)

    def hydrate_agent(
        self,
        matched_signal_ids: list[str],
        k: int = 10,
        fan_out: bool = True,
    ) -> RetrievalResult:
        """Hydrate matched signal ids into ranked agent threats (four-state envelope).

        The agent index is edgeless (agent_threats carry no ``alternatives``), so
        retrieval is direct-vote-only regardless of *fan_out*.
        """
        return self._hydrate(self._agent_signal_index, matched_signal_ids, k, fan_out)

    # ------------------------------------------------------------------
    # Pure retrieval — threat vectors
    # ------------------------------------------------------------------

    def get_threat(self, threat_id: str) -> dict | None:
        """Get a threat vector by ID."""
        return self._vector_index.get(threat_id)

    def get_threats_by_ids(self, ids: list[str]) -> list[dict]:
        """Batch retrieval of threat vectors by ID."""
        results: list[dict] = []
        for tid in ids:
            t = self._vector_index.get(tid)
            if t is not None:
                results.append(t)
        return results

    def get_all_threats(self) -> list[dict]:
        """Get all threat vectors."""
        return list(self._vectors)

    def get_threats_by_category(self, category: str) -> list[dict]:
        """Get all threat vectors in a given category."""
        return [v for v in self._vectors if v.get("category") == category]

    def get_threats_by_severity(self, severity: str) -> list[dict]:
        """Get all threat vectors at a given severity level."""
        return [v for v in self._vectors if v.get("severity") == severity]

    def get_threats_by_owasp(self, owasp_id: str) -> list[dict]:
        """Get all threat vectors mapped to a specific OWASP category."""
        return list(self._owasp_index.get(owasp_id, []))

    # ------------------------------------------------------------------
    # Pure retrieval — agent threats
    # ------------------------------------------------------------------

    def get_agent_threat(self, threat_id: str) -> dict | None:
        """Get an agent-specific threat by ID."""
        return self._agent_threat_index.get(threat_id)

    def get_all_agent_threats(self) -> list[dict]:
        """Get all agent-specific threats."""
        return list(self._agent_threats)

    def get_agent_threats_by_category(self, category: str) -> list[dict]:
        """Get agent threats filtered by category."""
        return [t for t in self._agent_threats if t.get("category") == category]

    def get_agent_threats_by_severity(self, severity: str) -> list[dict]:
        """Get agent threats filtered by severity."""
        return [t for t in self._agent_threats if t.get("severity") == severity]

    # ------------------------------------------------------------------
    # Pure retrieval — security tools
    # ------------------------------------------------------------------

    def get_tool(self, tool_id: str) -> dict | None:
        """Get a security tool by ID."""
        return self._tool_index.get(tool_id)

    def get_all_tools(self) -> list[dict]:
        """Get all security tools."""
        return list(self._tools)

    def get_tools_by_category(self, category: str) -> list[dict]:
        """Get security tools by category (sast, dast, sca,
        secret_scanning, container, network, agent_security)."""
        return [t for t in self._tools if t.get("category") == category]

    def get_tools_by_language(self, language: str) -> list[dict]:
        """Get security tools that support a given language."""
        return [
            t for t in self._tools
            if language in t.get("languages", [])
            or "any" in t.get("languages", [])
        ]

    def get_tools_with_agent_support(self) -> list[dict]:
        """Get security tools with native or plugin agent security support."""
        return [
            t for t in self._tools
            if t.get("agent_security_support") in ("native", "plugin")
        ]

    def get_open_source_tools(self) -> list[dict]:
        """Get all open source security tools."""
        return [t for t in self._tools if t.get("open_source") is True]

    # ------------------------------------------------------------------
    # Detection patterns
    # ------------------------------------------------------------------

    def get_detection_patterns(self, threat_id: str) -> list[str]:
        """Get regex detection patterns for a given threat vector.

        Returns a list of regex pattern strings suitable for code scanning.
        """
        threat = self._vector_index.get(threat_id)
        if threat is None:
            return []
        return list(threat.get("detection_patterns", []))

    # Language aliases scan_code resolves to a canonical detector bucket — the single
    # source of truth for the mapping the deleted in-code islands did by hand.
    _LANGUAGE_ALIASES: dict[str, str] = {
        "py": "python",
        "js": "javascript",
        "ts": "javascript",
        "typescript": "javascript",
    }

    def get_code_detectors(self, language: str) -> list[dict]:
        """Return the code-shape detectors that apply to *language*.

        The single source of truth for scan_code's per-language pattern set, with the
        alias + fallback resolution folded in (the resolution the deleted in-code
        islands did by hand):

        * ``language`` is lower-cased, then aliases resolve (py -> python;
          js / ts / typescript -> javascript);
        * a canonical language (python / javascript) is an O(1) lookup against the
          ``_detectors_by_language`` index built once at load — the ``["*"]`` universal
          detectors folded ahead of the language's own, in universal-then-language
          order;
        * an unknown language falls back to the universal detectors + BOTH the python
          and javascript import sets, in universal-then-python-then-js order.

        Agent-signal-gated detectors are excluded (they run only when
        _has_agent_signals fires), so the count equals scan_code's ``patterns_checked``
        — 29 for python, 25 for javascript, 34 for an unknown language. Returns a fresh
        list so a caller cannot mutate the shared index.
        """
        lang = language.lower()
        lang = self._LANGUAGE_ALIASES.get(lang, lang)
        if lang in self._detectors_by_language:
            return list(self._detectors_by_language[lang])
        return list(
            self._universal_code_detectors
            + self._named_code_detectors.get("python", [])
            + self._named_code_detectors.get("javascript", [])
        )

    def get_agent_code_detectors(self) -> list[dict]:
        """Return the agent-signal-gated code detectors, in file order.

        The single source of truth for scan_code's agent path: the
        ``requires_agent_signals`` detectors from the FILTERED (non-quarantined) active
        set, in the corpus file order. These run only when ``_has_agent_signals`` fires,
        so they are held apart from the per-language scan set. Returns a fresh list so a
        caller cannot mutate the shared index.
        """
        return list(self._agent_code_detectors)

    def get_quarantined_detectors(self) -> list[dict]:
        """Return the code detectors excluded by the load-time ReDoS quarantine.

        Each entry is ``{id, name, languages, reason}``. Empty when every detector
        is ReDoS-safe (the healthy state; all 41 migrated detectors pass). A
        catastrophic-backtracking regex is surfaced here rather than silently
        dropped. Returns a fresh list so a caller cannot mutate the loader's record.
        """
        return [dict(q) for q in self.quarantined_detectors]

    # ------------------------------------------------------------------
    # Remediation
    # ------------------------------------------------------------------

    def get_remediation(self, threat_id: str) -> str | None:
        """Get the remediation guidance for a threat vector."""
        threat = self._vector_index.get(threat_id)
        if threat is None:
            return None
        return threat.get("remediation")

    def get_examples(self, threat_id: str) -> dict | None:
        """Get vulnerable and secure code examples for a threat vector."""
        threat = self._vector_index.get(threat_id)
        if threat is None:
            return None
        return threat.get("examples")

    def cwe_to_threat_ids(self) -> dict[str, list[str]]:
        """Return the corpus-built ``{cwe: sorted[threat_vector_id]}`` mapping.

        The S4 finding->vector bridge: a finding that carries only a CWE resolves to
        its threat vector(s) through this map. Built from each vector's OWN ``cwe``
        list, so it equals the S0-frozen ``cwe_to_threat_ids`` by construction
        (one-to-many, deterministic). A cwe the corpus does not cover is simply
        absent — the caller fails closed (DANGLING), never a generic husk. Returns a
        fresh copy so a caller cannot mutate the built index.
        """
        return {c: list(ids) for c, ids in self._cwe_index.items()}

    # ------------------------------------------------------------------
    # Compact index
    # ------------------------------------------------------------------

    def get_compact_index(self) -> list[dict]:
        """Return id + name + category + severity + signals only, for each
        threat vector.

        Useful for the agent to scan available threats without pulling
        full details.
        """
        results: list[dict] = []
        for v in self._vectors:
            results.append({
                "id": v["id"],
                "name": v.get("name", v["id"]),
                "category": v.get("category", ""),
                "severity": v.get("severity", ""),
                "signals": v.get("signals", []),
            })
        return results

    def get_compact_agent_index(self) -> list[dict]:
        """Return id + name + category + severity for each agent threat.

        Compact representation for scanning without full details.
        """
        results: list[dict] = []
        for t in self._agent_threats:
            results.append({
                "id": t["id"],
                "name": t.get("name", t["id"]),
                "category": t.get("category", ""),
                "severity": t.get("severity", ""),
            })
        return results

    # ------------------------------------------------------------------
    # Constraint filtering — data-driven from threat metadata
    # ------------------------------------------------------------------

    def filter_by_constraints(
        self,
        threats: list[dict],
        constraints: dict,
    ) -> tuple[list[dict], list[dict]]:
        """Filter threats by constraints.

        Args:
            threats: List of threat dicts.
            constraints: Dict with optional keys:
                - ``language`` (str): filter by attack surface relevance
                - ``category`` (str): target category
                - ``severity`` (str): minimum severity ("critical"/"high"/"medium"/"low")
                - ``owasp`` (str): filter by OWASP category

        Returns:
            (surviving, filtered_out) where each filtered_out entry has
            a ``filter_reason`` key explaining why it was removed.
        """
        category = constraints.get("category")
        min_severity = constraints.get("severity")
        owasp = constraints.get("owasp")

        surviving: list[dict] = []
        filtered_out: list[dict] = []

        for threat in threats:
            reason = None

            # --- category filter ---
            if category and threat.get("category") != category:
                reason = f"category '{threat.get('category')}' != '{category}'"

            # --- severity filter ---
            if reason is None and min_severity:
                threat_sev = threat.get("severity", "low")
                if _SEVERITY_RANK.get(threat_sev, 3) > _SEVERITY_RANK.get(min_severity, 3):
                    reason = f"severity '{threat_sev}' below minimum '{min_severity}'"

            # --- OWASP filter ---
            if reason is None and owasp:
                if threat.get("owasp") != owasp:
                    reason = f"owasp '{threat.get('owasp')}' != '{owasp}'"

            if reason:
                entry = dict(threat)
                entry["filter_reason"] = reason
                filtered_out.append(entry)
            else:
                surviving.append(threat)

        return surviving, filtered_out
