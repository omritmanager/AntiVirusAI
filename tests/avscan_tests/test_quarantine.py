"""Quarantine tests (spec §13): round-trip SHA-256 preservation, safe ordering."""
from pathlib import Path

import pytest

from avscan import config
from avscan.engine import sha256_file
from avscan.quarantine import Quarantine, QuarantineError, _resolve_writable_dir, xor_bytes


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


def test_explicit_quarantine_dir_never_falls_back(tmp_path):
    """An explicitly-passed dir (e.g. from tests, or a caller with a known-good
    path) is honored as-is -- no silent redirect to the local fallback."""
    qdir = tmp_path / "q"
    q = Quarantine(quarantine_dir=qdir, manifest_path=qdir / "manifest.json")
    assert q.dir == qdir
    assert q.used_local_fallback is False


def test_resolve_writable_dir_prefers_writable_preferred(tmp_path):
    preferred = tmp_path / "writable"
    resolved, used_fallback = _resolve_writable_dir(preferred)
    assert resolved == preferred
    assert used_fallback is False
    assert preferred.exists()


def test_resolve_writable_dir_falls_back_on_permission_error(tmp_path, monkeypatch):
    """Simulate the real failure mode: the project's quarantine dir sits on an
    unwritable location (e.g. a read-only network share) -- mkdir raises, and
    the resolver must fall back to the local per-user directory instead of
    propagating the error."""
    unwritable = tmp_path / "no_access"

    class FakePath(type(unwritable)):
        def mkdir(self, *a, **kw):
            raise PermissionError("simulated: no permission for this folder")

    fake = FakePath(str(unwritable))
    local_fallback = tmp_path / "local_fallback"
    monkeypatch.setattr("avscan.quarantine.LOCAL_FALLBACK_QUARANTINE_DIR", local_fallback)

    resolved, used_fallback = _resolve_writable_dir(fake)
    assert used_fallback is True
    assert resolved == local_fallback
    assert local_fallback.exists()


def test_quarantine_default_dir_falls_back_when_project_dir_unwritable(tmp_path, monkeypatch):
    """End-to-end: constructing Quarantine() with no explicit dir must not crash
    even when config.QUARANTINE_DIR is unwritable -- it should transparently use
    the local fallback and still be fully functional (quarantine + restore)."""
    import pathlib

    fake_unwritable = tmp_path / "project_on_share" / "quarantine"
    local_fallback = tmp_path / "local_fallback"
    monkeypatch.setattr(config, "QUARANTINE_DIR", fake_unwritable)
    monkeypatch.setattr("avscan.quarantine.LOCAL_FALLBACK_QUARANTINE_DIR", local_fallback)

    real_mkdir = pathlib.Path.mkdir

    def selective_mkdir(self, *a, **kw):
        # Only the "project on an unwritable share" path fails -- everything
        # else (including the fallback dir itself) uses the real mkdir.
        if self == fake_unwritable:
            raise PermissionError("simulated: no permission for FINAL PROJECT folder")
        return real_mkdir(self, *a, **kw)

    monkeypatch.setattr(pathlib.Path, "mkdir", selective_mkdir)

    q = Quarantine()
    assert q.used_local_fallback is True
    assert q.dir == local_fallback
    assert q.manifest_path == local_fallback / "manifest.json"
