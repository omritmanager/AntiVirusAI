"""
report.py — JSON scan report writer (spec §8).

Produces a single detailed JSON file per scan, including the `hash_comparison`
block that captures the SHA-256-vs-ML experiment. The `environment` block records
the ACTUAL installed versions so a report is self-documenting evidence that the
scan ran under the locked environment.
"""
from __future__ import annotations

import importlib
import json
from pathlib import Path

from . import config
from .orchestrator import ScanResult


def gather_environment() -> dict:
    """Record the actual installed versions (evidence of the locked env)."""
    env = {}
    for label, import_name in [("lief", "lief"), ("sklearn", "sklearn"),
                               ("lightgbm", "lightgbm"), ("numpy", "numpy")]:
        try:
            env[label] = getattr(importlib.import_module(import_name), "__version__", "?")
        except Exception as e:
            env[label] = f"<not importable: {e}>"
    return env


def _result_to_dict(r) -> dict:
    return {
        "path": r.path,
        "name": r.name,
        "sha256": r.sha256,
        "size": r.size,
        "ml_verdict": r.ml_verdict,
        "hash_verdict": r.hash_verdict,
        "comparison_tag": r.comparison_tag,
        "lgbm_prob": r.lgbm_prob,
        "if_score": r.if_score,
        "error": r.error,
        "quarantined": r.quarantined,
        "quarantine_path": r.quarantine_path,
        # Authenticode layer — recorded side by side with the ML verdict, which
        # it never changes. quarantine_skipped_reason explains a MALWARE verdict
        # that was deliberately left in place (validly signed).
        "signature_status": getattr(r, "signature_status", None),
        "signature_signer": getattr(r, "signature_signer", None),
        "quarantine_skipped_reason": getattr(r, "quarantine_skipped_reason", None),
        "explanation": getattr(r, "explanation", None),
    }


def build_report_dict(scan: ScanResult, *, model_name: str = "lgbm_v7_correct.pkl") -> dict:
    opts = scan.options or {}
    hash_db_path = None
    if scan.hash_comparison:
        hash_db_path = scan.hash_comparison.get("db_path")

    report = {
        "scan_id": scan.scan_id,
        "started_at": scan.started_at,
        "finished_at": scan.finished_at,
        "duration_seconds": scan.duration_seconds,
        "config": {
            "folder": scan.folder,
            "lgbm_threshold": config.LGBM_THRESHOLD,
            "if_enabled": bool(opts.get("use_if", False)),
            "if_threshold": config.IF_THRESHOLD,
            "whitelist_enabled": bool(opts.get("whitelist_enabled", True)),
            "hash_db": hash_db_path,
            "hash_compare_enabled": bool(opts.get("hash_compare", False)),
            "signature_check_enabled": bool(opts.get("check_signature", False)),
            "trust_signed": bool(opts.get("trust_signed", False)),
            "model": model_name,
        },
        "environment": gather_environment(),
        "summary": {
            "total_files_seen": scan.summary.total_files_seen,
            "scanned": scan.summary.scanned,
            "skipped_system": scan.summary.skipped_system,
            "errors": scan.summary.errors,
            "malware": scan.summary.malware,
            "potential_zeroday": scan.summary.potential_zeroday,
            "safe": scan.summary.safe,
            "flagged_pct": scan.summary.flagged_pct,
        },
        "hash_comparison": scan.hash_comparison,
        "results": [_result_to_dict(r) for r in scan.results],
    }
    return report


def default_report_path(scan: ScanResult) -> Path:
    safe_id = scan.scan_id.replace(":", "-")
    return config.EVALUATION_DIR / f"scan_{safe_id}.json"


def write_report(scan: ScanResult, output_path=None,
                 model_name: str = "lgbm_v7_correct.pkl") -> Path:
    """Write the JSON report and return its path."""
    out = Path(output_path) if output_path else default_report_path(scan)
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w", encoding="utf-8") as f:
        json.dump(build_report_dict(scan, model_name=model_name), f, indent=2)
    return out
