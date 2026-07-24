"""
quickscan.py — Scan ONE file and show a popup verdict (for the right-click menu).

Flow: light self-check -> classify (LightGBM engine) -> SHA-256 hash lookup ->
(if flagged) ask Gemini for a short "why" -> show a color-coded popup.

Runs as a standalone script (the Explorer right-click entry points here) OR as
`python -m avscan.quickscan <file>`. Use --text for a headless (no-window) run,
which is what the tests use.

The popup is Tkinter (Python stdlib) so it needs no extra GUI dependency and
runs under the locked venv (Python 3.11) that already has the ML stack.
"""
from __future__ import annotations

import os
import sys

# Under pythonw.exe (the right-click entry) there is NO console: sys.stdout and
# sys.stderr are None. A single stray print or library warning to a None stream
# would crash the process before any window appears (looks like "nothing
# happens"). Route both to a throwaway sink so imports/warnings can never do that.
if sys.stdout is None or sys.stderr is None:
    _sink = open(os.devnull, "w")
    if sys.stdout is None:
        sys.stdout = _sink
    if sys.stderr is None:
        sys.stderr = _sink

# Allow running as a plain script: `python avscan/quickscan.py <file>`
if __package__ in (None, ""):
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from avscan import config, explain  # noqa: E402
from avscan.engine import get_engine, MALWARE, POTENTIAL_ZERODAY, SAFE, ERROR  # noqa: E402
from avscan.hashdb import HashDB, KNOWN_MALWARE  # noqa: E402
from avscan.selfcheck import run_selfcheck  # noqa: E402


def quick_scan(path: str, *, use_if: bool = True, do_explain: bool = True) -> dict:
    """Scan a single file. Returns a result dict; never raises."""
    res = {
        "path": path, "name": os.path.basename(path), "sha256": None, "size": 0,
        "ml_verdict": None, "lgbm_prob": None, "if_score": None,
        "hash_verdict": None, "explanation": None, "explain_status": None,
        "error": None, "selfcheck_ok": True, "selfcheck_failed": [],
    }

    # Light self-check (versions + EMBER patch + assets) — skip the slow F1
    # regression so a right-click scan stays fast, but still refuse if the
    # environment is broken (the whole point of the project).
    try:
        sc = run_selfcheck(run_regression=False, verbose=False)
        if not sc.ok:
            res["selfcheck_ok"] = False
            res["selfcheck_failed"] = [c.name for c in sc.checks if not c.passed]
            res["error"] = "environment self-check failed"
            return res
    except Exception as e:
        res["selfcheck_ok"] = False
        res["error"] = f"self-check error: {e}"
        return res

    if not os.path.isfile(path):
        res["error"] = "file not found"
        return res

    try:
        engine = get_engine(load_if=True)
        with open(path, "rb") as f:
            data = f.read()
        ml, sha, size = engine.classify_file(path, use_if=use_if)
        res.update(sha256=sha, size=size, ml_verdict=ml.ml_verdict,
                   lgbm_prob=ml.lgbm_prob, if_score=ml.if_score, error=ml.error)

        # Independent SHA-256 signature lookup (never changes the ML verdict).
        try:
            with HashDB(config.BASELINE_SQLITE) as db:
                if db.available and sha:
                    res["hash_verdict"] = db.verdict(sha)
        except Exception:
            pass

        # Explanation only for flagged files (saves API cost on clean files).
        if do_explain and ml.ml_verdict in (MALWARE, POTENTIAL_ZERODAY):
            out = explain.explain_bytes(engine, data, ml)
            res["explanation"] = out.get("summary") or None
            res["explain_status"] = out.get("status")
    except Exception as e:
        res["error"] = f"scan failed: {e}"
    return res


# ── text output (headless / tests) ───────────────────────────────────────────
def _print_text(res: dict) -> None:
    import io
    out = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")
    out.write("=" * 56 + "\n")
    out.write(f"AntivirusAI quick scan: {res['name']}\n")
    out.write("=" * 56 + "\n")
    if not res["selfcheck_ok"]:
        out.write("ENVIRONMENT CHECK FAILED: " + ", ".join(res["selfcheck_failed"]) + "\n")
    if res["error"] and res["ml_verdict"] is None:
        out.write(f"ERROR: {res['error']}\n"); out.flush(); return
    out.write(f"Verdict:     {res['ml_verdict']}\n")
    if res["lgbm_prob"] is not None:
        out.write(f"Probability: {res['lgbm_prob'] * 100:.1f}%\n")
    if res["hash_verdict"]:
        out.write(f"Signature:   {res['hash_verdict']}\n")
    if res["explanation"]:
        out.write("\nWhy:\n" + res["explanation"] + "\n")
        if res["explain_status"]:
            out.write("[" + explain.status_message(res["explain_status"], "en") + "]\n")
    out.flush()


# ── popup (Tkinter) ───────────────────────────────────────────────────────────
_STYLE = {
    MALWARE:           ("#b00020", "white",   "⛔  זדוני / נוזקה"),
    POTENTIAL_ZERODAY: ("#a06a00", "white",   "⚠  חשוד (זירו-דיי אפשרי)"),
    SAFE:              ("#137333", "white",   "✓  נקי"),
    ERROR:             ("#5f6368", "white",   "שגיאה בסריקה"),
}


def _clear(widget) -> None:
    for c in widget.winfo_children():
        c.destroy()


def _center(root) -> None:
    """Resize the window to fit its content (so nothing is clipped) and center it."""
    root.geometry("")               # drop any fixed size -> auto-fit to content
    root.update_idletasks()
    w = max(root.winfo_reqwidth(), 470)
    h = root.winfo_reqheight()
    x = (root.winfo_screenwidth() - w) // 2
    y = (root.winfo_screenheight() - h) // 3
    root.geometry(f"{w}x{h}+{x}+{y}")


def _render_scanning(root, name: str):
    """The immediate 'scanning…' screen (shown before the slow work).

    The bar is driven by a self-scheduled `after` loop (not Progressbar.start),
    which — together with the low thread-switch interval set in run_popup — keeps
    it moving smoothly even while the worker thread is busy importing/loading.
    """
    import tkinter as tk
    from tkinter import ttk

    _clear(root)
    tk.Label(root, text=name, font=("Segoe UI", 12, "bold"), bg="#f4f6f8",
             anchor="e", justify="right").pack(fill="x", padx=16, pady=(14, 4))
    tk.Label(root, text="🔄  סורק את הקובץ…", font=("Segoe UI", 15, "bold"),
             bg="#1a73e8", fg="white", padx=14, pady=12).pack(fill="x", padx=16, pady=8)
    pb = ttk.Progressbar(root, mode="indeterminate", length=390)
    pb.pack(fill="x", padx=16, pady=(4, 6))
    tk.Label(root, text="בדיקת סביבה, חילוץ מאפיינים, סיווג, השוואת חתימות והסבר AI…",
             font=("Segoe UI", 9), fg="#666", bg="#f4f6f8", anchor="e",
             justify="right", wraplength=390).pack(fill="x", padx=16, pady=(0, 14))

    def _tick():
        if not pb.winfo_exists():   # stops itself once the results view replaces it
            return
        pb.step(5)
        root.after(20, _tick)

    root.after(20, _tick)
    root.update_idletasks()


def _render_results(root, res: dict):
    """Build the results view into `root` (root is cleared first)."""
    import tkinter as tk
    from tkinter import scrolledtext

    _clear(root)
    pad = {"padx": 16, "pady": 6}
    tk.Label(root, text=res["name"], font=("Segoe UI", 12, "bold"),
             bg="#f4f6f8", anchor="e", justify="right").pack(fill="x", **pad)

    if not res["selfcheck_ok"]:
        bg, fg, label = "#5f6368", "white", "בדיקת סביבה נכשלה — לא ניתן לסרוק בבטחה"
    else:
        bg, fg, label = _STYLE.get(res["ml_verdict"], _STYLE[ERROR])
    tk.Label(root, text=label, font=("Segoe UI", 16, "bold"), bg=bg, fg=fg,
             padx=14, pady=12).pack(fill="x", padx=16, pady=(2, 8))

    info = tk.Frame(root, bg="#f4f6f8")
    info.pack(fill="x", **pad)
    lines = []
    if res["lgbm_prob"] is not None:
        lines.append(f"הסתברות (LightGBM): {res['lgbm_prob'] * 100:.1f}%")
    if res["hash_verdict"]:
        hv = "נמצא במאגר החתימות (KNOWN_MALWARE)" if res["hash_verdict"] == KNOWN_MALWARE \
            else "לא נמצא במאגר החתימות (NOT_IN_DB)"
        lines.append(f"התאמת חתימה SHA-256: {hv}")
    if res["sha256"]:
        lines.append(f"SHA-256: {res['sha256'][:32]}…")
    if not res["selfcheck_ok"]:
        lines.append("נכשל: " + ", ".join(res["selfcheck_failed"]))
    if res["error"] and res["ml_verdict"] in (None, ERROR):
        lines.append(f"שגיאה: {res['error']}")
    tk.Label(info, text="\n".join(lines), font=("Segoe UI", 10), bg="#f4f6f8",
             anchor="e", justify="right").pack(fill="x")

    if res["explanation"]:
        tk.Label(root, text="למה המערכת חושבת כך:", font=("Segoe UI", 10, "bold"),
                 bg="#f4f6f8", anchor="e", justify="right").pack(fill="x", padx=16)
        box = scrolledtext.ScrolledText(root, height=8, width=54, wrap="word",
                                        font=("Segoe UI", 10))
        box.pack(fill="both", expand=True, padx=16, pady=(2, 4))
        box.tag_configure("rtl", justify="right")
        box.insert("1.0", res["explanation"], "rtl")
        box.configure(state="disabled")
        if res["explain_status"] and res["explain_status"] != "ok":
            tk.Label(root, text=explain.status_message(res["explain_status"], "he"),
                     font=("Segoe UI", 8), fg="#777", bg="#f4f6f8",
                     anchor="e", justify="right", wraplength=440).pack(fill="x", padx=16)

    btnbar = tk.Frame(root, bg="#f4f6f8")
    btnbar.pack(pady=(6, 12))
    if (res["selfcheck_ok"] and res["ml_verdict"] in (MALWARE, POTENTIAL_ZERODAY)
            and res.get("path") and res.get("sha256") and os.path.isfile(res["path"])):
        qbtn = tk.Button(btnbar, text="🛡  העבר להסגר", bg="#a06a00", fg="white",
                         font=("Segoe UI", 10, "bold"), width=16)
        qbtn.configure(command=lambda: _send_to_quarantine(root, res, qbtn))
        qbtn.pack(side="left", padx=6)
    tk.Button(btnbar, text="סגור", width=12, command=root.destroy).pack(side="left", padx=6)
    _center(root)


def _send_to_quarantine(root, res: dict, btn) -> None:
    """Move a flagged file to quarantine (XOR-neutralized, verified). Confirms
    first, since this removes the file from its current location (restorable)."""
    import tkinter.messagebox as mb
    from avscan.quarantine import Quarantine, QuarantineError

    if not mb.askyesno(
            "העברה להסגר",
            f"להעביר את '{res['name']}' להסגר?\n\n"
            "הקובץ יינטרל (XOR) ויוסר ממיקומו הנוכחי. ניתן לשחזר אותו בהמשך.",
            icon="warning", parent=root):
        return
    try:
        entry = Quarantine().quarantine_file(
            res["path"], sha256=res["sha256"], lgbm_prob=res.get("lgbm_prob"))
        btn.configure(text="✓ בהסגר", state="disabled", bg="#137333")
        mb.showinfo(
            "הסגר",
            "הקובץ הועבר להסגר בהצלחה.\n\n"
            f"מיקום ההסגר:\n{entry['quarantine_path']}\n\n"
            f"לשחזור מאוחר יותר:\n  python -m avscan restore {res['sha256']}",
            parent=root)
    except QuarantineError as e:
        mb.showerror("שגיאת הסגר", f"לא ניתן היה להעביר להסגר:\n{e}", parent=root)
    except Exception as e:
        mb.showerror("שגיאה", str(e), parent=root)


def show_popup(res: dict, _for_test: bool = False):
    """Show a results-only popup for an already-computed result (tests / fallback)."""
    import tkinter as tk

    root = tk.Tk()
    root.title("AntivirusAI — סריקה מהירה")
    root.configure(bg="#f4f6f8")
    if _for_test:
        root.withdraw()
    elif True:
        try:
            root.attributes("-topmost", True)
        except Exception:
            pass
    _render_results(root, res)
    if _for_test:
        root.update()
        root.destroy()
        return
    root.mainloop()


def run_popup(path: str, *, use_if: bool = True, do_explain: bool = True) -> int:
    """Show a 'scanning…' window IMMEDIATELY, run the scan on a background thread,
    then swap in the results in the same window. Returns the exit code."""
    import queue
    import threading
    import tkinter as tk

    # Let the worker thread yield the GIL to the UI thread very frequently, so the
    # progress animation stays smooth during the heavy (import/model-load) phase.
    try:
        sys.setswitchinterval(0.0005)
    except Exception:
        pass

    holder: dict = {"res": None}
    root = tk.Tk()
    root.title("AntivirusAI — סריקה מהירה")
    root.configure(bg="#f4f6f8")
    try:
        root.attributes("-topmost", True)
    except Exception:
        pass
    _render_scanning(root, os.path.basename(path))
    _center(root)

    q: "queue.Queue" = queue.Queue()

    def worker():
        try:
            r = quick_scan(path, use_if=use_if, do_explain=do_explain)
        except Exception as e:  # never let the worker die silently under pythonw
            r = {"path": path, "name": os.path.basename(path), "sha256": None, "size": 0,
                 "ml_verdict": ERROR, "lgbm_prob": None, "if_score": None,
                 "hash_verdict": None, "explanation": None, "explain_status": None,
                 "error": f"{type(e).__name__}: {e}", "selfcheck_ok": True,
                 "selfcheck_failed": []}
        q.put(r)

    threading.Thread(target=worker, daemon=True).start()

    def poll():
        try:
            res = q.get_nowait()
        except queue.Empty:
            root.after(120, poll)
            return
        holder["res"] = res
        _render_results(root, res)

    root.after(150, poll)
    root.mainloop()

    res = holder["res"] or {}
    return 1 if res.get("ml_verdict") in (MALWARE, POTENTIAL_ZERODAY) else 0


# ── entry point ───────────────────────────────────────────────────────────────
def main(argv=None) -> int:
    import argparse
    ap = argparse.ArgumentParser(prog="avscan quickscan",
                                 description="Scan one file and show a popup verdict.")
    ap.add_argument("file", help="path to the file to scan")
    ap.add_argument("--text", action="store_true", help="print result instead of a popup")
    ap.add_argument("--no-explain", action="store_true", help="skip the Gemini explanation")
    ap.add_argument("--no-if", action="store_true", help="disable the Isolation Forest layer")
    args = ap.parse_args(argv)

    if args.text:
        res = quick_scan(args.file, use_if=not args.no_if, do_explain=not args.no_explain)
        _print_text(res)
        return 1 if res["ml_verdict"] in (MALWARE, POTENTIAL_ZERODAY) else 0

    # GUI: show a "scanning…" window immediately, scan on a worker thread, then
    # render the results in the same window.
    try:
        return run_popup(args.file, use_if=not args.no_if, do_explain=not args.no_explain)
    except Exception as e:
        # Last-resort fallback if Tk can't start at all.
        res = quick_scan(args.file, use_if=not args.no_if, do_explain=not args.no_explain)
        try:
            import tkinter.messagebox as mb
            mb.showinfo("AntivirusAI", f"{res['name']}: {res['ml_verdict']}")
        except Exception:
            print(f"{res['name']}: {res['ml_verdict']} ({e})")
        return 1 if res["ml_verdict"] in (MALWARE, POTENTIAL_ZERODAY) else 0


if __name__ == "__main__":
    sys.exit(main())
