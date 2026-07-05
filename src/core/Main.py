"""
AntivirusAI - Application Entry Point
מפעיל את ה-GUI; במידה והקובץ gui.py עדיין לא קיים, נופל אוטומטית למצב CLI.
"""

import argparse
from engine import ScanEngine, ScanStatus

# === Configuration ===
DB_PATH = r"C:\Users\omri9\Desktop\School\Final Project\data\hashes\malware_hashes.db"
MODEL_PATH = r"C:\Users\omri9\Desktop\School\Final Project\models\AntivirusAI_V6_Balanced.txt"
ENGINE_VERSION = "V6_Balanced"
DEFAULT_TARGET = r"C:\\"


def run_cli(target_dir: str):
    """מצב CLI - ל-debug, ל-benchmarks או להפעלה דרך scheduled task."""
    print("=" * 60)
    print("  🛡️  AntivirusAI - CLI Mode")
    print("=" * 60)

    engine = ScanEngine(DB_PATH, MODEL_PATH, ENGINE_VERSION)

    def on_status_change(status):
        if status == ScanStatus.LOADING:
            print("🔄 Loading model & database...")
        elif status == ScanStatus.SCANNING:
            print(f"🔍 Scanning: {target_dir}")
            print("-" * 60)
        elif status == ScanStatus.STOPPING:
            print("\n⏳ Flushing database writes...")

    def on_progress(p):
        display = (p.current_file[:75] + '..') if len(p.current_file) > 75 \
                  else p.current_file
        print(f"   🔎 [{p.scanned}] {display:<80}", end="\r")

    def on_threat(threat):
        symbol = "🛑" if threat.classification == "MALWARE" else "⚠️"
        print(f"\n   {symbol} [{threat.source}] {threat.classification}: "
              f"{threat.filename} ({threat.threat_score:.2f}%)")

    def on_error(msg):
        print(f"\n   ❌ {msg}")

    def on_finished(summary):
        print("\n" + "=" * 60)
        print("📋 SCAN SUMMARY")
        print(f"   📂 Scanned:           {summary.scanned}")
        print(f"   ⚡ Cached:            {summary.cached}")
        print(f"   🛑 Local DB hits:     {summary.db_hits}")
        print(f"   🧠 AI hits:           {summary.ai_hits}")
        print(f"   ❌ Errors:            {summary.errors}")
        print(f"   ⏱️  Duration:          {summary.duration_seconds:.1f}s")
        print("=" * 60)

    engine.on_status_change = on_status_change
    engine.on_progress = on_progress
    engine.on_threat = on_threat
    engine.on_error = on_error
    engine.on_finished = on_finished

    engine.start(target_dir)

    try:
        engine.wait()
    except KeyboardInterrupt:
        print("\n\n🛑 Interrupted - stopping engine, please wait...")
        engine.stop()
        engine.wait()


def run_gui():
    """מצב GUI - הממשק הגרפי הראשי."""
    try:
        from gui import launch
    except ImportError:
        print("⚠️  GUI module (gui.py) not found yet.")
        print("    Falling back to CLI mode on default target.\n")
        run_cli(DEFAULT_TARGET)
        return

    launch(db_path=DB_PATH, model_path=MODEL_PATH, engine_version=ENGINE_VERSION)


def main():
    parser = argparse.ArgumentParser(description="AntivirusAI - Enterprise scanner")
    parser.add_argument("--cli", action="store_true",
                        help="Run in headless CLI mode (no GUI)")
    parser.add_argument("--target", default=DEFAULT_TARGET,
                        help=f"Directory to scan (default: {DEFAULT_TARGET})")
    args = parser.parse_args()

    if args.cli:
        run_cli(args.target)
    else:
        run_gui()


if __name__ == "__main__":
    main()