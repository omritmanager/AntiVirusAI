"""
cli.py — Command-line interface (spec §10).

Commands:
  avscan scan <folder> [--no-whitelist] [--quarantine|--report-only]
                       [--hash-db <path>] [--hash-compare|--no-hash-compare]
                       [--output <path.json>] [--skip-selfcheck]
  avscan demo-zeroday <folder> [--hash-db <path>] [--skip-selfcheck]
  avscan restore <sha256|all>
  avscan selfcheck
  avscan list-quarantine

Exit codes: 0 = clean, 1 = malware found, 2 = scan error / self-check failed.

Every scan runs the startup self-check first (spec §9). --skip-selfcheck is an
escape hatch that warns loudly.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import config
from .selfcheck import run_selfcheck

EXIT_CLEAN = 0
EXIT_MALWARE = 1
EXIT_ERROR = 2


# ── progress (tqdm if available, else plain) ─────────────────────────────────
class _Progress:
    def __init__(self, enabled: bool = True):
        self.enabled = enabled
        self.bar = None
        self._tqdm = None
        if enabled:
            try:
                from tqdm import tqdm
                self._tqdm = tqdm
            except Exception:
                self._tqdm = None

    def __call__(self, i: int, total: int, path: Path) -> None:
        if not self.enabled:
            return
        if self._tqdm is not None:
            if self.bar is None:
                self.bar = self._tqdm(total=total, unit="file", desc="scanning")
            self.bar.n = i
            self.bar.refresh()
        elif total and (i == 1 or i == total or i % 50 == 0):
            pct = 100.0 * i / total
            print(f"\r  scanning {i}/{total} ({pct:5.1f}%) ", end="", flush=True)

    def close(self) -> None:
        if self.bar is not None:
            self.bar.close()
        elif self.enabled and self._tqdm is None:
            print()


def _print_flagged(fr) -> None:
    tag = f"[{fr.comparison_tag}]" if fr.comparison_tag else ""
    if fr.ml_verdict == "MALWARE":
        print(f"  MALWARE           {fr.name:<45} p={fr.lgbm_prob:.3f} {tag}")
    elif fr.ml_verdict == "ERROR":
        # Treated as flagged under the fail-closed policy (couldn't be read or
        # parsed, so we don't get to assume it's safe) — still surfaced here so
        # a quarantined ERROR file isn't silently invisible in the CLI output.
        print(f"  ERROR (treated as MALWARE) {fr.name:<30} {fr.error or 'unknown error'}")
    # Surface the signature counter-signal right where the user sees the alarm,
    # so a likely false positive on a signed program is obvious immediately.
    if fr.signature_status == "TRUSTED":
        print(f"                    -> signed by {fr.signature_signer or 'a trusted publisher'}"
              f"{' (NOT quarantined)' if fr.quarantine_skipped_reason else ''}")


def _ensure_selfcheck(skip: bool) -> bool:
    """Run the self-check (spec §9). Returns True if scanning may proceed."""
    if skip:
        print("!" * 64)
        print("WARNING: --skip-selfcheck set. The environment-parity guarantee")
        print("         is DISABLED. Predictions may be silently wrong if any")
        print("         locked library version differs. Use only for debugging.")
        print("!" * 64)
        return True
    result = run_selfcheck(run_regression=True, verbose=True)
    if not result.ok:
        print("\nABORTING: self-check failed. Fix the environment "
              "(python setup_environment.py) before scanning.")
    return result.ok


# ── commands ─────────────────────────────────────────────────────────────────
def cmd_selfcheck(args) -> int:
    result = run_selfcheck(run_regression=True, verbose=True)
    return EXIT_CLEAN if result.ok else EXIT_ERROR


def cmd_scan(args) -> int:
    from .orchestrator import scan_folder
    from .hashdb import HashDB
    from .quarantine import Quarantine
    from . import report as report_mod

    if not _ensure_selfcheck(args.skip_selfcheck):
        return EXIT_ERROR

    folder = Path(args.folder)
    if not folder.exists():
        print(f"ERROR: folder not found: {folder}")
        return EXIT_ERROR

    hash_compare = not args.no_hash_compare
    hash_db = None
    if hash_compare:
        db_path = Path(args.hash_db) if args.hash_db else config.BASELINE_SQLITE
        hash_db = HashDB(db_path)
        if not hash_db.available:
            print(f"NOTE: hash DB unavailable ({db_path}); scanning ML-only.")

    do_quarantine = not args.report_only
    quarantine = Quarantine(use_xor=config.load_settings().get("xor_quarantine", True),
                            xor_key=config.load_settings().get("xor_key", config.XOR_KEY_DEFAULT)) \
        if do_quarantine else None
    on_malware = quarantine.quarantine_for_result if quarantine else None

    settings = config.load_settings()
    check_signature = settings.get("check_signature", True) and not args.no_signature
    trust_signed = settings.get("trust_signed", True) and not args.no_trust_signed

    print(f"\nScanning: {folder}")
    print(f"  whitelist: {not args.no_whitelist} | "
          f"hash-compare: {hash_compare} | action: "
          f"{'quarantine' if do_quarantine else 'report-only'}")
    print(f"  signature check: {check_signature} | "
          f"skip quarantine for signed: {trust_signed}\n")

    progress = _Progress(enabled=True)
    scan = scan_folder(
        folder,
        whitelist_enabled=not args.no_whitelist,
        hash_db=hash_db,
        hash_compare=hash_compare,
        progress_cb=progress,
        flagged_cb=_print_flagged,
        error_cb=lambda e: None,
        on_malware=on_malware,
        check_signature=check_signature,
        trust_signed=trust_signed,
    )
    progress.close()
    if hash_db:
        hash_db.close()

    if getattr(args, "explain", False):
        _attach_explanations(scan)

    out = report_mod.write_report(scan, output_path=args.output)
    _print_summary(scan, out)

    flagged = scan.summary.malware
    return EXIT_MALWARE if flagged > 0 else EXIT_CLEAN


def _attach_explanations(scan, cap: int = 10) -> None:
    """Fill FileResult.explanation for flagged files via Gemini (needs a key).
    Bounded by `cap` to limit API cost. Never raises."""
    from .engine import get_engine, MLResult, MALWARE
    from . import explain

    settings = config.load_settings()
    if not settings.get("explain_enabled", True) or not config.get_gemini_api_key():
        print("\nNOTE: --explain requested but no Gemini API key is set (or it is "
              "disabled). Set GEMINI_API_KEY to enable explanations.")
        return
    flagged = [r for r in scan.results if r.ml_verdict == MALWARE]
    if not flagged:
        return
    engine = get_engine()
    n = min(len(flagged), cap)
    print(f"\nGenerating explanations for {n} flagged file(s) (Gemini)...")
    for r in flagged[:cap]:
        try:
            with open(r.path, "rb") as f:
                data = f.read()
            ml = MLResult(r.ml_verdict, lgbm_prob=r.lgbm_prob)
            out = explain.explain_bytes(engine, data, ml, settings=settings,
                                        hash_verdict=r.hash_verdict,
                                        quarantined=r.quarantined,
                                        signature_status=r.signature_status,
                                        signature_signer=r.signature_signer)
            r.explanation = out.get("summary")
            print(f"  {r.name}: {(r.explanation or '')[:110]}...")
        except Exception:
            continue


def cmd_quickscan(args) -> int:
    from . import quickscan as qs
    from .engine import ERROR, MALWARE

    res = qs.quick_scan(args.file, do_explain=not args.no_explain)
    if args.text:
        qs._print_text(res)
    else:
        qs.show_popup(res)
    return EXIT_MALWARE if res["ml_verdict"] in (MALWARE, ERROR) else EXIT_CLEAN


def cmd_demo_zeroday(args) -> int:
    from .orchestrator import scan_folder
    from .hashdb import HashDB

    if not _ensure_selfcheck(args.skip_selfcheck):
        return EXIT_ERROR

    folder = Path(args.folder)
    if not folder.exists():
        print(f"ERROR: folder not found: {folder}")
        return EXIT_ERROR

    # Load the withheld simulated-zero-day hashes for the headline metric.
    zeroday = set()
    if config.SIMULATED_ZERODAY_TXT.exists():
        zeroday = {h.strip().lower() for h in
                   config.SIMULATED_ZERODAY_TXT.read_text().split() if h.strip()}
    else:
        print(f"NOTE: {config.SIMULATED_ZERODAY_TXT} not found; "
              "run build_hash_db.py first. Headline will be over scanned files only.")

    db_path = Path(args.hash_db) if args.hash_db else config.BASELINE_SQLITE
    hash_db = HashDB(db_path)

    print(f"\nDemo (SHA-256 vs ML) on: {folder}\n")
    progress = _Progress(enabled=True)
    scan = scan_folder(
        folder, whitelist_enabled=False,
        hash_db=hash_db, hash_compare=True,
        zeroday_hashes=zeroday if zeroday else None,
        progress_cb=progress,
    )
    progress.close()
    hash_db.close()

    _print_demo_table(scan)
    return EXIT_CLEAN


def cmd_restore(args) -> int:
    from .quarantine import Quarantine, QuarantineError

    q = Quarantine()
    try:
        restored = q.restore(args.target)
    except QuarantineError as e:
        print(f"Restore failed: {e}")
        return EXIT_ERROR
    print(f"Restored {len(restored)} file(s):")
    for p in restored:
        print(f"  {p}")
    return EXIT_CLEAN


def cmd_list_quarantine(args) -> int:
    from .quarantine import Quarantine

    q = Quarantine()
    entries = q.entries()
    if not entries:
        print("Quarantine is empty.")
        return EXIT_CLEAN
    print(f"Quarantine manifest ({len(entries)} entr{'y' if len(entries)==1 else 'ies'}):")
    print("-" * 78)
    for e in entries:
        prob = e.get("lgbm_prob")
        print(f"  sha256 : {e.get('sha256','?')}")
        print(f"  origin : {e.get('original_path','?')}")
        print(f"  stored : {e.get('quarantine_path','?')}")
        print(f"  when   : {e.get('timestamp','?')}  prob={prob}  xored={e.get('xored')}")
        print("-" * 78)
    return EXIT_CLEAN


# ── pretty printers ──────────────────────────────────────────────────────────
def _print_summary(scan, out_path) -> None:
    s = scan.summary
    print("\n" + "=" * 64)
    print("SCAN RESULTS")
    print("=" * 64)
    print(f"  Files seen (PE):   {s.total_files_seen}")
    print(f"  Scanned:           {s.scanned}")
    print(f"  Skipped (system):  {s.skipped_system}")
    print(f"  MALWARE:           {s.malware}")
    print(f"  SAFE:              {s.safe}")
    print(f"  Errors:            {s.errors}")
    print(f"  Flagged:           {s.flagged_pct:.2f}%")
    if scan.hash_comparison and scan.hash_comparison.get("db_available"):
        hc = scan.hash_comparison
        files = hc["files"]
        print("\n  SHA-256 vs ML comparison:")
        print(f"    Known hashes in DB:  {hc['known_hashes_in_db']}")
        print(f"    BOTH_CAUGHT:         {files['BOTH_CAUGHT']}")
        print(f"    ML_ONLY_CATCH:       {files['ML_ONLY_CATCH']}   "
              f"<- ML caught what signatures missed")
        print(f"    HASH_ONLY_CATCH:     {files['HASH_ONLY_CATCH']}")
        print(f"    BOTH_CLEAR:          {files['BOTH_CLEAR']}")
    qn = sum(1 for r in scan.results if r.quarantined)
    if qn:
        print(f"\n  Quarantined: {qn} file(s)")
    print(f"\n  Report saved: {out_path}")


def _print_demo_table(scan) -> None:
    hc = scan.hash_comparison or {}
    head = hc.get("headline")
    print("\n" + "=" * 64)
    print("SIGNATURE (SHA-256) vs ML - simulated zero-day folder")
    print("=" * 64)
    if head and head["simulated_zeroday_scanned"] > 0:
        n = head["simulated_zeroday_scanned"]
        ch = head["caught_by_hash"]
        cm = head["caught_by_ml"]
        print(f"  Files scanned:            {n}")
        print(f"  Caught by SHA-256 lookup: {ch:>3}   ({100*ch/n:5.1f}%)   "
              f"<- signatures are blind to new malware")
        print(f"  Caught by ML model:       {cm:>3}   ({100*cm/n:5.1f}%)   "
              f"<- model generalizes")
    else:
        files = hc.get("files", {})
        flagged = scan.summary.malware
        print(f"  Files scanned:            {scan.summary.scanned}")
        print(f"  (No files matched the withheld zero-day hash set.)")
        print(f"  ML flagged:               {flagged}")
        print(f"  ML_ONLY_CATCH:            {files.get('ML_ONLY_CATCH', 0)}")


# ── argparse wiring ──────────────────────────────────────────────────────────
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="avscan",
                                description="AntivirusAI V7 - ML malware scanner.")
    sub = p.add_subparsers(dest="command", required=True)

    sc = sub.add_parser("scan", help="scan a folder")
    sc.add_argument("folder")
    sc.add_argument("--no-whitelist", action="store_true", help="do not skip system files")
    g = sc.add_mutually_exclusive_group()
    g.add_argument("--quarantine", action="store_true", help="quarantine MALWARE (default)")
    g.add_argument("--report-only", action="store_true", help="report without moving files")
    sc.add_argument("--hash-db", default=None, help="path to baseline SQLite DB")
    sc.add_argument("--hash-compare", action="store_true", help="(default on) include comparison")
    sc.add_argument("--no-hash-compare", action="store_true", help="disable hash comparison")
    sc.add_argument("--no-signature", action="store_true",
                    help="skip Authenticode verification of flagged files")
    sc.add_argument("--no-trust-signed", action="store_true",
                    help="quarantine flagged MALWARE even if validly signed")
    sc.add_argument("--output", default=None, help="report JSON path")
    sc.add_argument("--explain", action="store_true",
                    help="add a Gemini 'why' to flagged files (needs GEMINI_API_KEY)")
    sc.add_argument("--skip-selfcheck", action="store_true", help="skip startup self-check (warns)")
    sc.set_defaults(func=cmd_scan)

    qs = sub.add_parser("quickscan", help="scan ONE file and show a popup verdict + 'why'")
    qs.add_argument("file", help="path to the file to scan")
    qs.add_argument("--text", action="store_true", help="print result instead of a popup")
    qs.add_argument("--no-explain", action="store_true", help="skip the Gemini explanation")
    qs.set_defaults(func=cmd_quickscan)

    dz = sub.add_parser("demo-zeroday", help="SHA-256 vs ML headline table")
    dz.add_argument("folder")
    dz.add_argument("--hash-db", default=None)
    dz.add_argument("--skip-selfcheck", action="store_true")
    dz.set_defaults(func=cmd_demo_zeroday)

    rs = sub.add_parser("restore", help="restore from quarantine")
    rs.add_argument("target", help="a SHA-256, or 'all'")
    rs.set_defaults(func=cmd_restore)

    sub.add_parser("selfcheck", help="run environment + regression check").set_defaults(func=cmd_selfcheck)
    sub.add_parser("list-quarantine", help="show the quarantine manifest").set_defaults(func=cmd_list_quarantine)
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        print("\nInterrupted.")
        return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
