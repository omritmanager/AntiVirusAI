"""Quarantine tests (spec §13): round-trip SHA-256 preservation, safe ordering."""
from pathlib import Path

import pytest

from avscan.engine import sha256_file
from avscan.quarantine import Quarantine, QuarantineError, xor_bytes


@pytest.mark.parametrize("use_xor", [True, False])
def test_quarantine_restore_roundtrip_preserves_sha(tmp_path, benign_exes, use_xor):
    victim = tmp_path / "evil.exe"
    victim.write_bytes(benign_exes[0].read_bytes())
    original_sha = sha256_file(victim)

    qdir = tmp_path / "q"
    q = Quarantine(quarantine_dir=qdir, manifest_path=qdir / "manifest.json",
                   use_xor=use_xor, xor_key=0x55)
    entry = q.quarantine_file(victim, sha256=original_sha, lgbm_prob=0.99)

    assert not victim.exists()                       # original moved
    stored = Path(entry["quarantine_path"])
    assert stored.exists()
    if use_xor:                                      # neutralized: not a live PE
        assert stored.read_bytes()[:2] != b"MZ"

    restored = q.restore(original_sha)
    assert len(restored) == 1
    assert victim.exists()
    assert sha256_file(victim) == original_sha        # round-trip preserved
    assert q.entries() == []                          # manifest cleared


def test_xor_is_reversible():
    data = b"\x00\x01\x02MZ hello world" * 10
    assert xor_bytes(xor_bytes(data, 0x55), 0x55) == data


def test_stale_hash_keeps_original(tmp_path, benign_exes):
    victim = tmp_path / "evil.exe"
    victim.write_bytes(benign_exes[0].read_bytes())
    qdir = tmp_path / "q"
    q = Quarantine(quarantine_dir=qdir, manifest_path=qdir / "manifest.json")
    with pytest.raises(QuarantineError):
        q.quarantine_file(victim, sha256="0" * 64)   # wrong hash -> refuse
    assert victim.exists()                            # original untouched
    assert q.entries() == []


def test_quarantine_for_result_never_raises(tmp_path):
    qdir = tmp_path / "q"
    q = Quarantine(quarantine_dir=qdir, manifest_path=qdir / "manifest.json")

    class FR:  # minimal stand-in for orchestrator.FileResult
        path = str(tmp_path / "missing.exe")
        sha256 = "a" * 64
        lgbm_prob = 0.5

    ok, where = q.quarantine_for_result(FR())
    assert ok is False and where is None
