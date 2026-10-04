"""Tests for the third evidence layer added to avscan/explain.py: real PE
structure re-parsed independently of the EMBER vector (named sections/entropy,
named suspicious-API co-occurrences), and the prompt rules that keep that new
evidence grounded as a structural fact rather than a behavioural claim.
"""
import numpy as np
import pytest

from avscan import config, explain


def _zero_vector():
    return np.zeros(config.EXPECTED_DIM, dtype=np.float64)


# ─────────────────────────────────────────────────────────────────────────────
# extract_pe_detail() — never raises, real facts only
# ─────────────────────────────────────────────────────────────────────────────
def test_extract_pe_detail_never_raises_on_garbage():
    assert explain.extract_pe_detail(b"") == {}
    assert explain.extract_pe_detail(b"not a pe file at all") == {}
    assert explain.extract_pe_detail(b"MZ" + b"\x00" * 50) == {}


def test_extract_pe_detail_real_file(benign_exes):
    data = benign_exes[0].read_bytes()
    detail = explain.extract_pe_detail(data)
    assert "sections" in detail
    assert "matched_categories" in detail
    assert isinstance(detail["sections"], list)
    for s in detail["sections"]:
        assert set(s.keys()) == {"name", "size", "entropy"}
        assert isinstance(s["name"], str)
        assert 0.0 <= s["entropy"] <= 8.0 + 1e-6


def test_matched_categories_respect_min_match():
    """A category only fires when >= min_match names from THAT category are
    present — a single incidental import must never trigger it."""
    import avscan.explain as ex

    class FakeEntry:
        def __init__(self, name):
            self.name = name

    class FakeImport:
        def __init__(self, names):
            self.entries = [FakeEntry(n) for n in names]

    class FakeBinary:
        def __init__(self, imported_names, sections=()):
            self.imports = [FakeImport(imported_names)]
            self.sections = sections

    import lief

    # process_injection requires min_match=2; give it only 1 -> must not fire.
    fake = FakeBinary(["WriteProcessMemory", "SomeUnrelatedFunc"])
    orig_parse = lief.PE.parse
    try:
        lief.PE.parse = lambda data: fake
        detail = ex.extract_pe_detail(b"irrelevant")
        assert "process_injection" not in detail["matched_categories"]

        # Give it 2 -> must fire, and must return exactly the matched names.
        fake.imports = [FakeImport(["WriteProcessMemory", "VirtualAllocEx"])]
        detail = ex.extract_pe_detail(b"irrelevant")
        assert detail["matched_categories"]["process_injection"] == \
            sorted(["WriteProcessMemory", "VirtualAllocEx"])
    finally:
        lief.PE.parse = orig_parse


def test_extract_pe_detail_swallows_parse_exception():
    import avscan.explain as ex
    import lief

    orig_parse = lief.PE.parse
    try:
        def boom(data):
            raise RuntimeError("simulated parser crash")
        lief.PE.parse = boom
        assert ex.extract_pe_detail(b"anything") == {}
    finally:
        lief.PE.parse = orig_parse


# ─────────────────────────────────────────────────────────────────────────────
# extract_evidence() integration — named API categories become evidence items
# ─────────────────────────────────────────────────────────────────────────────
def test_evidence_includes_named_api_category(monkeypatch):
    monkeypatch.setattr(
        explain, "extract_pe_detail",
        lambda data: {"sections": [],
                      "matched_categories": {
                          "process_injection": ["VirtualAllocEx", "WriteProcessMemory"]}})
    v = _zero_vector()
    ev = explain.extract_evidence(v, data=b"x" * 64)
    item = next(e for e in ev if e["key"] == "api_process_injection")
    assert item["suspicious"] is True
    assert item["group"] == "imported functions / DLLs"
    # Both real function names must appear verbatim, in both languages.
    assert "VirtualAllocEx" in item["he"] and "WriteProcessMemory" in item["he"]
    assert "VirtualAllocEx" in item["en"] and "WriteProcessMemory" in item["en"]
    # Structural phrasing only — never a behavioural claim.
    assert "the file imports" in item["en"]
    assert "מייבא" in item["he"]


def test_evidence_no_api_category_when_none_matched(monkeypatch):
    monkeypatch.setattr(
        explain, "extract_pe_detail",
        lambda data: {"sections": [], "matched_categories": {}})
    v = _zero_vector()
    ev = explain.extract_evidence(v, data=b"x" * 64)
    assert not any(e["key"].startswith("api_") for e in ev)


def test_evidence_named_sections_appear_in_layout_fact(monkeypatch):
    monkeypatch.setattr(
        explain, "extract_pe_detail",
        lambda data: {"sections": [{"name": ".text", "size": 100, "entropy": 1.0},
                                   {"name": ".rsrc", "size": 50, "entropy": 2.0}],
                      "matched_categories": {}})
    v = _zero_vector()
    v[explain.I_NUM_SECTIONS] = 2
    ev = explain.extract_evidence(v, data=b"x" * 64)
    sec = next(e for e in ev if e["key"] == "sections")
    assert ".text" in sec["en"] and ".rsrc" in sec["en"]
    assert ".text" in sec["he"] and ".rsrc" in sec["he"]


def test_evidence_packer_section_name_flags_odd_layout(monkeypatch):
    monkeypatch.setattr(
        explain, "extract_pe_detail",
        lambda data: {"sections": [{"name": "UPX0", "size": 100, "entropy": 7.9},
                                   {"name": "UPX1", "size": 50, "entropy": 7.8}],
                      "matched_categories": {}})
    v = _zero_vector()
    v[explain.I_NUM_SECTIONS] = 2
    ev = explain.extract_evidence(v, data=b"x" * 64)
    sec = next(e for e in ev if e["key"] == "sections")
    assert sec["suspicious"] is True
    assert "UPX0" in sec["en"]


def test_evidence_localized_packing_flags_hot_section(monkeypatch):
    """A single named region far more compressed than the whole file must be
    surfaced even when whole-file entropy looks unremarkable."""
    low_entropy_data = b"\x00" * 5000  # whole-file entropy ~= 0
    monkeypatch.setattr(
        explain, "extract_pe_detail",
        lambda data: {"sections": [{"name": ".packed", "size": 100, "entropy": 7.9}],
                      "matched_categories": {}})
    v = _zero_vector()
    v[explain.I_NUM_SECTIONS] = 1
    ev = explain.extract_evidence(v, data=low_entropy_data)
    hot = next(e for e in ev if e["key"] == "section_entropy")
    assert hot["suspicious"] is True
    assert ".packed" in hot["en"] and ".packed" in hot["he"]


def test_evidence_no_localized_packing_when_uniform(monkeypatch):
    monkeypatch.setattr(
        explain, "extract_pe_detail",
        lambda data: {"sections": [{"name": ".text", "size": 100, "entropy": 6.0}],
                      "matched_categories": {}})
    v = _zero_vector()
    v[explain.I_NUM_SECTIONS] = 1
    ev = explain.extract_evidence(v, data=b"\x00" * 5000)
    assert not any(e["key"] == "section_entropy" for e in ev)


def test_extract_evidence_still_works_with_no_data():
    """data=None must not crash extract_evidence (pe_detail degrades to {})."""
    v = _zero_vector()
    ev = explain.extract_evidence(v, data=None)
    assert isinstance(ev, list)
    assert not any(e["key"].startswith("api_") for e in ev)
    assert not any(e["key"] == "section_entropy" for e in ev)


def test_extract_evidence_bad_vector_shape_returns_empty():
    ev = explain.extract_evidence(np.zeros(10), data=b"irrelevant")
    assert ev == []


# ─────────────────────────────────────────────────────────────────────────────
# build_prompt() — new grounding rule for named API imports
# ─────────────────────────────────────────────────────────────────────────────
def test_build_prompt_contains_rule_3a_both_languages():
    prompt_he = explain.build_prompt("MALWARE", 0.9, [], language="he", evidence=[])
    prompt_en = explain.build_prompt("MALWARE", 0.9, [], language="en", evidence=[])
    assert "3א." in prompt_he
    assert "מייבא פונקציות שמשמשות בדרך כלל" in prompt_he
    assert "3a." in prompt_en
    assert "imports functions commonly used for" in prompt_en


def test_build_prompt_includes_named_api_evidence_verbatim():
    evidence = [{"key": "api_process_injection",
                "he": "הקובץ מייבא פונקציות Windows שמשמשות יחד בדרך כלל להזרקת קוד: VirtualAllocEx, WriteProcessMemory",
                "en": "the file imports Windows functions commonly used together for "
                      "code-injection into another running process: VirtualAllocEx, WriteProcessMemory",
                "suspicious": True, "group": "imported functions / DLLs"}]
    prompt = explain.build_prompt("MALWARE", 0.9, [], language="en", evidence=evidence)
    assert "VirtualAllocEx" in prompt and "WriteProcessMemory" in prompt
    assert "the file imports Windows functions" in prompt


def test_build_prompt_rule_7_allows_quoting_function_names():
    prompt_en = explain.build_prompt("MALWARE", 0.9, [], language="en", evidence=[])
    assert "WriteProcessMemory" in prompt_en  # cited as an allowed exception in rule 7
    prompt_he = explain.build_prompt("MALWARE", 0.9, [], language="he", evidence=[])
    assert "WriteProcessMemory" in prompt_he


# ─────────────────────────────────────────────────────────────────────────────
# format_all_evidence() — the full raw evidence list shown to the user
# (GUI ExplainDialog + quickscan popup), not just the AI's curated summary.
# ─────────────────────────────────────────────────────────────────────────────
def test_format_all_evidence_splits_suspicious_from_background():
    evidence = [
        {"key": "entropy", "he": "רמת ערבול גבוהה", "en": "high entropy",
         "suspicious": True, "group": "byte-entropy patterns"},
        {"key": "size", "he": "גודל הקובץ: 10 KB", "en": "file size: 10 KB",
         "suspicious": False, "group": "general file info"},
    ]
    out_he = explain.format_all_evidence(evidence, [], "he")
    assert "מאפיינים חריגים" in out_he
    assert "רמת ערבול גבוהה" in out_he
    assert "נתוני רקע" in out_he
    assert "גודל הקובץ: 10 KB" in out_he
    # suspicious item must appear before the background one
    assert out_he.index("רמת ערבול גבוהה") < out_he.index("גודל הקובץ")

    out_en = explain.format_all_evidence(evidence, [], "en")
    assert "Unusual properties" in out_en
    assert "high entropy" in out_en
    assert "Background facts" in out_en
    assert "file size: 10 KB" in out_en


def test_format_all_evidence_empty_returns_placeholder_not_crash():
    assert explain.format_all_evidence([], [], "he")
    assert explain.format_all_evidence([], [], "en")
    assert "measurable data" in explain.format_all_evidence([], [], "en").lower()


def test_format_all_evidence_all_suspicious_no_background_heading():
    evidence = [{"key": "entropy", "he": "רמת ערבול גבוהה", "en": "high entropy",
                "suspicious": True, "group": "byte-entropy patterns"}]
    out = explain.format_all_evidence(evidence, [], "he")
    assert "מאפיינים חריגים" in out
    assert "נתוני רקע" not in out


# ─────────────────────────────────────────────────────────────────────────────
# format_raw_vector() — the full 2381-number vector, grouped by EMBER group
# ─────────────────────────────────────────────────────────────────────────────
def test_format_raw_vector_groups_by_feature_group():
    vector = [0.0] * config.EXPECTED_DIM
    vector[0] = 1.5           # first value of byte-value distribution
    vector[943] = 2.5         # first value of imported functions / DLLs
    out = explain.format_raw_vector(vector, "he")
    # Hebrew plain-language group labels, not raw internal names, are used.
    assert "הרכב התוכן הגולמי" in out          # byte-value distribution
    assert "הפעולות שהקובץ מבקש" in out         # imported functions / DLLs
    assert "[0:256]" in out
    assert "[943:2223]" in out
    assert "1.5000" in out
    assert "2.5000" in out


def test_format_raw_vector_english_labels():
    vector = [0.0] * config.EXPECTED_DIM
    out = explain.format_raw_vector(vector, "en")
    assert "byte-value distribution" in out or "raw make-up" in out.lower()
    assert "[0:256]" in out


def test_format_raw_vector_empty_or_none_never_crashes():
    assert explain.format_raw_vector(None, "he")
    assert explain.format_raw_vector([], "he")
    assert explain.format_raw_vector(None, "en")


def test_format_raw_vector_covers_all_2381_values():
    vector = list(range(config.EXPECTED_DIM))
    out = explain.format_raw_vector(vector, "he")
    # last value (index 2380) must appear somewhere, proving nothing was truncated
    assert "2380.0000" in out


# ─────────────────────────────────────────────────────────────────────────────
# Concise wording — the summary a worried user actually reads must stay SHORT
# without becoming less true (see explain.add()'s docstring).
# ─────────────────────────────────────────────────────────────────────────────
def _unsigned_multi_section_vector():
    """A vector shaped like the real report that triggered the 'too long,
    too complicated' complaint: unsigned, 11 regions (2 empty), TLS present."""
    v = _zero_vector()
    v[explain.I_HAS_SIGNATURE] = 0
    v[explain.I_IMPORTS] = 40
    v[explain.I_NUM_SECTIONS] = 11
    v[explain.I_ZERO_SIZE_SECTIONS] = 2
    v[explain.I_HAS_TLS] = 1
    v[explain.I_SIZE] = 2_200_000
    return v


def test_every_evidence_item_has_short_wording():
    evidence = explain.extract_evidence(_unsigned_multi_section_vector(), None)
    assert evidence
    for item in evidence:
        assert item["short_he"] and item["short_en"]
        # The point of the short form: it must not be longer than the full one.
        assert len(item["short_he"]) <= len(item["he"])


def test_short_signature_wording_keeps_the_not_proof_caveat():
    """EMBER's has_signature only sees an EMBEDDED cert, so the short form must
    never read as a bare 'unsigned' claim - the caveat travels with the fact."""
    evidence = explain.extract_evidence(_unsigned_multi_section_vector(), None)
    sig = next(e for e in evidence if e["key"] == "signature")
    assert "לא הוכחה" in sig["short_he"]
    assert "not proof" in sig["short_en"]


def test_local_summary_is_short_and_capped_at_three_bullets():
    evidence = explain.extract_evidence(_unsigned_multi_section_vector(), None)
    out = explain.local_feature_summary([], "he", evidence, "MALWARE", 0.999,
                                        "UNSIGNED", None, quarantined=True)
    assert out.count("•") <= 3
    assert len(out.split()) <= 80
    assert "22" in out or "%" in out          # the measured score survives
    assert "מה כדאי לעשות" in out


def test_local_summary_wording_follows_the_action_actually_taken():
    """A flagged-but-not-quarantined file must never be described as blocked."""
    evidence = explain.extract_evidence(_unsigned_multi_section_vector(), None)
    flagged = explain.local_feature_summary([], "he", evidence, "POTENTIAL_ZERODAY",
                                            0.5, "UNSIGNED", None, quarantined=False)
    assert "נחסם" not in flagged
    assert "סומן" in flagged
    blocked = explain.local_feature_summary([], "he", evidence, "MALWARE", 0.999,
                                            "UNSIGNED", None, quarantined=True)
    assert "נחסם" in blocked


def test_local_summary_leads_with_a_trusted_signature():
    evidence = explain.extract_evidence(_unsigned_multi_section_vector(), None)
    out = explain.local_feature_summary([], "he", evidence, "MALWARE", 0.99,
                                        "TRUSTED", "Acme Ltd", quarantined=False)
    assert out.splitlines()[0].startswith("כנראה אזעקת שווא")
    assert "Acme Ltd" in out


def test_local_summary_survives_evidence_without_short_wording():
    """Callers building their own evidence dicts must not render empty bullets."""
    legacy = [{"key": "x", "he": "עובדה מלאה", "en": "full fact",
               "suspicious": True, "group": "general file info"}]
    out = explain.local_feature_summary([], "he", legacy, "MALWARE", 0.9)
    assert "עובדה מלאה" in out


def test_build_prompt_keeps_false_alarm_honesty_under_the_word_limit():
    """Tightening the length must not let the model drop rule 5's caveat."""
    prompt_he = explain.build_prompt("MALWARE", 0.9, [], language="he", evidence=[])
    prompt_en = explain.build_prompt("MALWARE", 0.9, [], language="en", evidence=[])
    assert "אזעקת שווא" in prompt_he and "60 מילים" in prompt_he
    assert "false alarm" in prompt_en and "60 words" in prompt_en
