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
