"""Report-writer tests: the writable-location fallback and honest model naming.

Both exist because the app is routinely run from a network share (a VM reaching
the host over \\\\host\\Final Project) where the project directory is not
writable -- a completed scan must still produce a report, and that report must
name the model that actually ran.
"""
import json

import pytest

from avscan import config
from avscan import report as report_mod


@pytest.fixture
def scan_result(mixed_folder, engine):
    from avscan import orchestrator as orch
    return orch.scan_folder(mixed_folder, engine=engine, hash_compare=False)


def test_write_report_normal_path(scan_result, tmp_path):
    out = tmp_path / "report.json"
    written = report_mod.write_report(scan_result, output_path=out)
    assert written == out
    assert out.exists()
    json.loads(out.read_text(encoding="utf-8"))     # valid JSON


def test_write_report_falls_back_when_dir_unwritable(scan_result, tmp_path, monkeypatch):
    """The real failure mode: PermissionError writing into the project dir on a
    read-only share. The report must land locally instead of the scan crashing,
    and the RETURNED path must be where it actually landed."""
    import pathlib

    unwritable = tmp_path / "share" / "evaluation"
    fallback = tmp_path / "local_eval"
    monkeypatch.setattr(config, "EVALUATION_DIR", unwritable)
    monkeypatch.setattr(report_mod, "LOCAL_FALLBACK_EVALUATION_DIR", fallback)

    real_mkdir = pathlib.Path.mkdir

    def selective_mkdir(self, *a, **kw):
        if self == unwritable:
            raise PermissionError("simulated: read-only network share")
        return real_mkdir(self, *a, **kw)

    monkeypatch.setattr(pathlib.Path, "mkdir", selective_mkdir)

    written = report_mod.write_report(scan_result)
    assert written.parent == fallback
    assert written.exists()
    assert json.loads(written.read_text(encoding="utf-8"))


def test_report_names_the_model_actually_loaded(scan_result, tmp_path, monkeypatch):
    """Under an AVSCAN_MODEL override the report must not claim the production
    model produced it."""
    fake = config.MODELS_DIR / "lgbm_v7_correct_candidate.pkl"
    monkeypatch.setattr(config, "LGBM_PATH", fake)
    out = tmp_path / "r.json"
    report_mod.write_report(scan_result, output_path=out)
    data = json.loads(out.read_text(encoding="utf-8"))
    blob = json.dumps(data)
    assert "lgbm_v7_correct_candidate.pkl" in blob


def test_explicit_model_name_still_wins(scan_result, tmp_path):
    out = tmp_path / "r.json"
    report_mod.write_report(scan_result, output_path=out, model_name="explicit.pkl")
    assert "explicit.pkl" in json.dumps(json.loads(out.read_text(encoding="utf-8")))
