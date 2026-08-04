"""Tests for the Authenticode layer (avscan/signature.py) and the way the
orchestrator uses it to gate the quarantine ACTION without ever touching the
ML verdict.
"""
import os
import sys

import pytest

from avscan import orchestrator as orch
from avscan import signature
from avscan.engine import MALWARE

WINDOWS_ONLY = pytest.mark.skipif(not sys.platform.startswith("win"),
                                  reason="Authenticode verification requires Windows")

# A file Windows ships that carries an EMBEDDED Authenticode signature.
SIGNED_SYSTEM_FILE = r"C:\Windows\System32\kernel32.dll"


@WINDOWS_ONLY
def test_verify_trusted_system_binary():
    if not os.path.isfile(SIGNED_SYSTEM_FILE):
        pytest.skip("kernel32.dll not present")
    res = signature.verify(SIGNED_SYSTEM_FILE)
    assert res.status == signature.TRUSTED
    assert res.trusted is True
    assert res.signer          # a publisher name was recovered
    assert res.detail is None


@WINDOWS_ONLY
def test_verify_unsigned_file(tmp_path):
    """A plain file has no embedded signature -> UNSIGNED, never TRUSTED."""
    p = tmp_path / "not_a_signed_binary.txt"
    p.write_text("hello", encoding="utf-8")
    res = signature.verify(str(p))
    assert res.status == signature.UNSIGNED
    assert res.trusted is False


def test_verify_missing_file_never_raises(tmp_path):
    """Robustness: the layer must degrade, never crash a scan."""
    res = signature.verify(str(tmp_path / "does_not_exist.exe"))
    assert res.status in (signature.UNSIGNED, signature.UNTRUSTED,
                          signature.UNKNOWN)
    assert res.trusted is False


def test_unknown_is_never_trusted():
    """UNKNOWN must fail closed — an undeterminable signature grants nothing."""
    assert signature.SignatureResult(signature.UNKNOWN).trusted is False
    assert signature.SignatureResult(signature.UNTRUSTED).trusted is False
    assert signature.SignatureResult(signature.UNSIGNED).trusted is False
    assert signature.SignatureResult(signature.TRUSTED).trusted is True


def test_describe_mentions_signer_when_trusted():
    r = signature.SignatureResult(signature.TRUSTED, "Anthropic, PBC")
    assert "Anthropic, PBC" in signature.describe(r, "he")
    assert "Anthropic, PBC" in signature.describe(r, "en")


def test_display_verdict_green_only_for_trusted_signature():
    dv = signature.display_verdict
    # Validly signed + not a known sample -> shown green.
    assert dv("MALWARE", signature.TRUSTED, "NOT_IN_DB") == signature.SIGNED_SAFE
    # Anything less than a trusted signature stays as the model said.
    assert dv("MALWARE", signature.UNSIGNED, "NOT_IN_DB") == "MALWARE"
    assert dv("MALWARE", signature.UNTRUSTED, "NOT_IN_DB") == "MALWARE"
    assert dv("MALWARE", signature.UNKNOWN, "NOT_IN_DB") == "MALWARE"
    assert dv("MALWARE", None, None) == "MALWARE"


def test_display_verdict_known_malware_hash_always_wins():
    """The safety carve-out: signed malware is real (stolen certificates), so an
    exact known-sample match must never be masked by a valid signature."""
    assert signature.display_verdict(
        "MALWARE", signature.TRUSTED, "KNOWN_MALWARE") == "MALWARE"


def test_display_verdict_respects_trust_signed_toggle():
    assert signature.display_verdict(
        "MALWARE", signature.TRUSTED, "NOT_IN_DB", trust_signed=False) == "MALWARE"


def test_display_verdict_never_downgrades_a_clean_file():
    """It may only soften a flagged verdict, never turn SAFE/ERROR into something else."""
    assert signature.display_verdict("SAFE", signature.TRUSTED, "NOT_IN_DB") == "SAFE"
    assert signature.display_verdict("ERROR", signature.TRUSTED, "NOT_IN_DB") == "ERROR"
    assert signature.display_verdict("SAFE", signature.UNSIGNED, None) == "SAFE"


def test_unsigned_malware_is_still_quarantined(mixed_folder, engine):
    """The safety net must not be weakened: an UNSIGNED MALWARE file is still
    handed to the quarantine callback."""
    moved = []

    def on_malware(fr):
        moved.append(fr.name)
        return True, "/fake/quarantine/path"

    res = orch.scan_folder(mixed_folder, engine=engine, hash_compare=False,
                           on_malware=on_malware, check_signature=True,
                           trust_signed=True)
    junk = next(r for r in res.results if r.name == "junk.exe")
    assert junk.ml_verdict == MALWARE
    assert junk.signature_status != signature.TRUSTED
    assert "junk.exe" in moved
    assert junk.quarantine_skipped_reason is None


def test_trusted_signature_skips_quarantine_but_keeps_verdict(
        mixed_folder, engine, monkeypatch):
    """A validly signed MALWARE file is reported but NOT auto-quarantined —
    and its ML verdict is unchanged (build rule: the signature layer never
    alters classification, only the action)."""
    monkeypatch.setattr(
        signature, "verify",
        lambda path: signature.SignatureResult(signature.TRUSTED, "Test Publisher"))
    moved = []

    def on_malware(fr):
        moved.append(fr.name)
        return True, "/fake/quarantine/path"

    res = orch.scan_folder(mixed_folder, engine=engine, hash_compare=False,
                           on_malware=on_malware, check_signature=True,
                           trust_signed=True)
    junk = next(r for r in res.results if r.name == "junk.exe")
    assert junk.ml_verdict == MALWARE            # verdict untouched
    assert junk.signature_status == signature.TRUSTED
    assert junk.quarantined is False
    assert "Test Publisher" in junk.quarantine_skipped_reason
    assert moved == []                           # never handed to quarantine


def test_trust_signed_off_quarantines_signed_file(mixed_folder, engine, monkeypatch):
    """With trust_signed=False the override still quarantines a signed file."""
    monkeypatch.setattr(
        signature, "verify",
        lambda path: signature.SignatureResult(signature.TRUSTED, "Test Publisher"))
    moved = []

    def on_malware(fr):
        moved.append(fr.name)
        return True, "/fake/quarantine/path"

    res = orch.scan_folder(mixed_folder, engine=engine, hash_compare=False,
                           on_malware=on_malware, check_signature=True,
                           trust_signed=False)
    junk = next(r for r in res.results if r.name == "junk.exe")
    assert junk.ml_verdict == MALWARE
    assert "junk.exe" in moved
    assert junk.quarantine_skipped_reason is None


def test_check_signature_off_records_nothing(mixed_folder, engine):
    res = orch.scan_folder(mixed_folder, engine=engine, hash_compare=False,
                           check_signature=False)
    for r in res.results:
        assert r.signature_status is None
