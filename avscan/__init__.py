"""
AntivirusAI V7 — desktop malware scanner around a frozen, validated ML pipeline.

This package wraps an already-trained LightGBM (+ optional Isolation Forest)
model operating on EMBER v2 PE feature vectors. The inference math is frozen and
validated; this package is the application layer (orchestration, hash-lookup
comparison, quarantine, reporting, CLI, GUI) built around it.

The single most important defense is `selfcheck.py`, which verifies the locked
environment before any scan runs. See AntivirusAI_V7_SPECIFICATION.md.
"""

__version__ = "7.0.0"
