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

from avscan import config, explain, signature, theme  # noqa: E402
from avscan.engine import get_engine, MALWARE, SAFE, ERROR  # noqa: E402
from avscan.hashdb import HashDB, KNOWN_MALWARE  # noqa: E402
from avscan.selfcheck import run_selfcheck  # noqa: E402


def quick_scan(path: str, *, do_explain: bool = True) -> dict:
    """Scan a single file. Returns a result dict; never raises."""
    res = {
        "path": path, "name": os.path.basename(path), "sha256": None, "size": 0,
        "ml_verdict": None, "lgbm_prob": None,
        "hash_verdict": None, "explanation": None, "explain_status": None,
        "error": None, "selfcheck_ok": True, "selfcheck_failed": [],
        "signature_status": None, "signature_signer": None, "signature_detail": None,
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
        engine = get_engine()
        with open(path, "rb") as f:
            data = f.read()
        ml, sha, size = engine.classify_file(path)
        res.update(sha256=sha, size=size, ml_verdict=ml.ml_verdict,
                   lgbm_prob=ml.lgbm_prob, error=ml.error)

        # Independent SHA-256 signature lookup (never changes the ML verdict).
        try:
            with HashDB(config.BASELINE_SQLITE) as db:
                if db.available and sha:
                    res["hash_verdict"] = db.verdict(sha)
        except Exception:
            pass

        # Authenticode layer (independent) — never changes the ML verdict, but a
        # valid signature is the strongest offline counter-signal to a false
        # positive, so it is checked for anything flagged.
        if ml.ml_verdict == MALWARE:
            sig = signature.verify(path)
            res["signature_status"] = sig.status
            res["signature_signer"] = sig.signer
            res["signature_detail"] = sig.detail

        # Explanation only for flagged files (saves API cost on clean files).
        if do_explain and ml.ml_verdict == MALWARE:
            out = explain.explain_bytes(engine, data, ml,
                                        hash_verdict=res.get("hash_verdict"),
                                        signature_status=res.get("signature_status"),
                                        signature_signer=res.get("signature_signer"))
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
    shown = signature.display_verdict(res["ml_verdict"], res.get("signature_status"),
                                      res.get("hash_verdict"))
    if shown == signature.SIGNED_SAFE:
        out.write(f"Verdict:     CLEAN (validly signed"
                  + (f" by {res['signature_signer']}" if res.get("signature_signer") else "")
                  + f") [ML said {res['ml_verdict']}]\n")
    else:
        out.write(f"Verdict:     {res['ml_verdict']}\n")
    if res["lgbm_prob"] is not None:
        out.write(f"Probability: {res['lgbm_prob'] * 100:.1f}%\n")
    if res["hash_verdict"]:
        out.write(f"Signature:   {res['hash_verdict']}\n")
    if res.get("signature_status"):
        signer = res.get("signature_signer")
        out.write(f"Authenticode:{res['signature_status']}"
                  + (f" ({signer})" if signer else "") + "\n")
    if res["explanation"]:
        out.write("\nWhy:\n" + res["explanation"] + "\n")
        if res["explain_status"]:
            out.write("[" + explain.status_message(res["explain_status"], "en") + "]\n")
    out.flush()


# ── popup (Tkinter) ───────────────────────────────────────────────────────────
# Colours come from theme.py so the popup and the PySide6 main window cannot
# drift apart. Tk has no rounded corners or real styling, so the modern feel
# here is carried by the palette, generous spacing and type hierarchy instead.
P = theme.palette("dark")

_STYLE = {
    MALWARE:           ("danger",  "⛔", "זדוני / נוזקה"),
    SAFE:              ("success", "✓",  "נקי"),
    ERROR:             ("neutral", "•",  "שגיאה בסריקה"),
    # Green: flagged by the model, but validly signed by a trusted publisher.
    signature.SIGNED_SAFE: ("success", "✓", "נקי — חתום דיגיטלית"),
}


def _verdict_style(shown):
    """(accent, bg, icon, text) for a display verdict."""
    key, icon, text = _STYLE.get(shown, _STYLE[ERROR])
    return P[key], P[f"{key}_bg"], icon, text


def _row(parent, label: str, value: str, accent: str = None):
    """One right-aligned label/value line in the details card."""
    import tkinter as tk
    line = tk.Frame(parent, bg=P["surface"])
    line.pack(fill="x", pady=2)
    tk.Label(line, text=value, font=("Segoe UI", 9),
             fg=accent or P["text"], bg=P["surface"],
             anchor="e", justify="right").pack(side="right")
    tk.Label(line, text=f"{label}:  ", font=("Segoe UI", 9),
             fg=P["text_muted"], bg=P["surface"],
             anchor="e", justify="right").pack(side="right")
    return line


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
    root.configure(bg=P["bg"])

    header = tk.Frame(root, bg=P["surface"])
    header.pack(fill="x")
    inner = tk.Frame(header, bg=P["surface"])
    inner.pack(fill="x", padx=18, pady=(13, 12))
    tk.Label(inner, text="AntivirusAI", font=("Segoe UI", 9, "bold"),
             fg=P["accent"], bg=P["surface"]).pack(side="left")
    tk.Label(inner, text=name, font=("Segoe UI", 12, "bold"), fg=P["text"],
             bg=P["surface"], anchor="e", justify="right").pack(side="right")
    tk.Frame(root, bg=P["border"], height=1).pack(fill="x")

    banner = tk.Frame(root, bg=P["neutral_bg"])
    banner.pack(fill="x", padx=16, pady=(14, 8))
    tk.Frame(banner, bg=P["accent"], width=4).pack(side="right", fill="y")
    tk.Label(banner, text="סורק את הקובץ…", font=("Segoe UI", 15, "bold"),
             fg=P["accent"], bg=P["neutral_bg"], anchor="e", justify="right",
             padx=14, pady=13).pack(fill="x")

    style = ttk.Style()
    try:                                     # themed bar; falls back silently
        style.theme_use("clam")
        style.configure("Quick.Horizontal.TProgressbar", troughcolor=P["neutral_bg"],
                        background=P["accent"], bordercolor=P["neutral_bg"],
                        lightcolor=P["accent"], darkcolor=P["accent"], thickness=6)
        pb = ttk.Progressbar(root, mode="indeterminate", length=390,
                             style="Quick.Horizontal.TProgressbar")
    except Exception:
        pb = ttk.Progressbar(root, mode="indeterminate", length=390)
    pb.pack(fill="x", padx=16, pady=(2, 8))
    tk.Label(root, text="בדיקת סביבה, חילוץ מאפיינים, סיווג, השוואת חתימות והסבר AI…",
             font=("Segoe UI", 9), fg=P["text_muted"], bg=P["bg"], anchor="e",
             justify="right", wraplength=390).pack(fill="x", padx=18, pady=(0, 16))

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
    root.configure(bg=P["bg"])

    # ── header: file name + app mark ────────────────────────────────────────
    header = tk.Frame(root, bg=P["surface"])
    header.pack(fill="x")
    inner = tk.Frame(header, bg=P["surface"])
    inner.pack(fill="x", padx=18, pady=(13, 12))
    tk.Label(inner, text="AntivirusAI", font=("Segoe UI", 9, "bold"),
             fg=P["accent"], bg=P["surface"]).pack(side="left")
    tk.Label(inner, text=res["name"], font=("Segoe UI", 12, "bold"),
             fg=P["text"], bg=P["surface"], anchor="e",
             justify="right").pack(side="right")
    tk.Frame(root, bg=P["border"], height=1).pack(fill="x")

    # ── verdict banner ──────────────────────────────────────────────────────
    shown = None
    if not res["selfcheck_ok"]:
        accent, bg = P["neutral"], P["neutral_bg"]
        icon, text = "•", "בדיקת סביבה נכשלה — לא ניתן לסרוק בבטחה"
    else:
        shown = signature.display_verdict(
            res["ml_verdict"], res.get("signature_status"), res.get("hash_verdict"))
        accent, bg, icon, text = _verdict_style(shown)
        if shown == signature.SIGNED_SAFE and res.get("signature_signer"):
            text = f"נקי — חתום ע\"י {res['signature_signer']}"

    banner = tk.Frame(root, bg=bg)
    banner.pack(fill="x", padx=16, pady=(14, 4))
    bar = tk.Frame(banner, bg=accent, width=4)
    bar.pack(side="right", fill="y")
    bin_ = tk.Frame(banner, bg=bg)
    bin_.pack(fill="x", padx=14, pady=13)
    tk.Label(bin_, text=f"{icon}  {text}", font=("Segoe UI", 15, "bold"),
             fg=accent, bg=bg, anchor="e", justify="right",
             wraplength=400).pack(fill="x")

    # The model's own verdict is never hidden — a green banner on a file the
    # engine flagged must stay auditable, so say so directly under the banner.
    if res["selfcheck_ok"] and shown == signature.SIGNED_SAFE:
        tk.Label(root,
                 text=f"מנוע ה-ML סימן את הקובץ כ-{res['ml_verdict']}, "
                      "אך החתימה הדיגיטלית התקפה גוברת על כך",
                 font=("Segoe UI", 8), fg=P["text_muted"], bg=P["bg"],
                 anchor="e", justify="right", wraplength=430).pack(fill="x", padx=18)

    # ── details card ────────────────────────────────────────────────────────
    card = tk.Frame(root, bg=P["surface"], highlightbackground=P["border"],
                    highlightthickness=1)
    card.pack(fill="x", padx=16, pady=(10, 6))
    info = tk.Frame(card, bg=P["surface"])
    info.pack(fill="x", padx=14, pady=11)

    if res["lgbm_prob"] is not None:
        _row(info, "הסתברות (LightGBM)", f"{res['lgbm_prob'] * 100:.1f}%",
             accent if res["selfcheck_ok"] else None)
    if res["hash_verdict"]:
        known = res["hash_verdict"] == KNOWN_MALWARE
        _row(info, "התאמת חתימה SHA-256",
             "נמצא במאגר החתימות" if known else "לא נמצא במאגר החתימות",
             P["danger"] if known else None)
    if res.get("signature_status"):
        st = res["signature_status"]
        if st == "TRUSTED":
            _row(info, "חתימה דיגיטלית",
                 f"תקפה — {res.get('signature_signer') or 'יצרן מאומת'}", P["success"])
        elif st == "UNSIGNED":
            _row(info, "חתימה דיגיטלית", "אין חתימה מוטבעת", P["text_muted"])
        elif st == "UNTRUSTED":
            _row(info, "חתימה דיגיטלית",
                 f"לא תקפה ({res.get('signature_detail') or ''})", P["danger"])
    if res["sha256"]:
        _row(info, "SHA-256", res["sha256"][:24] + "…", P["text_muted"])
    if not res["selfcheck_ok"]:
        _row(info, "נכשל", ", ".join(res["selfcheck_failed"]), P["danger"])
    if res["error"] and res["ml_verdict"] in (None, ERROR):
        _row(info, "שגיאה", str(res["error"])[:60], P["danger"])

    # ── AI explanation ──────────────────────────────────────────────────────
    if res["explanation"]:
        head = tk.Frame(root, bg=P["bg"])
        head.pack(fill="x", padx=18, pady=(8, 0))
        # Copy button sits on the left of the RTL header, next to its title.
        copy_btn = tk.Button(head, text="📋  העתק", font=("Segoe UI", 8),
                             bg=P["surface_alt"], fg=P["text"],
                             activebackground=P["border"], activeforeground=P["text"],
                             relief="flat", bd=0, padx=10, pady=3, cursor="hand2")
        copy_btn.configure(command=lambda: _copy_explanation(root, res, copy_btn))
        copy_btn.pack(side="left")
        tk.Label(head, text="למה המערכת חושבת כך", font=("Segoe UI", 9, "bold"),
                 fg=P["text_muted"], bg=P["bg"], anchor="e",
                 justify="right").pack(side="right")
        box = scrolledtext.ScrolledText(
            root, height=8, width=54, wrap="word", font=("Segoe UI", 10),
            bg=P["surface"], fg=P["text"], insertbackground=P["text"],
            relief="flat", bd=0, padx=12, pady=10,
            highlightbackground=P["border"], highlightthickness=1)
        box.pack(fill="both", expand=True, padx=16, pady=(5, 4))
        box.tag_configure("rtl", justify="right")
        box.insert("1.0", res["explanation"], "rtl")
        box.configure(state="disabled")
        if res["explain_status"] and res["explain_status"] != "ok":
            tk.Label(root, text=explain.status_message(res["explain_status"], "he"),
                     font=("Segoe UI", 8), fg=P["text_muted"], bg=P["bg"],
                     anchor="e", justify="right", wraplength=430).pack(fill="x", padx=18)

    btnbar = tk.Frame(root, bg=P["bg"])
    btnbar.pack(pady=(10, 14))
    # No quarantine button when the file is shown green — offering to isolate a
    # file we just declared clean is contradictory. Use the CLI's
    # --no-trust-signed to quarantine a signed file anyway.
    if (res["selfcheck_ok"] and res["ml_verdict"] == MALWARE
            and shown != signature.SIGNED_SAFE
            and res.get("path") and res.get("sha256") and os.path.isfile(res["path"])):
        qbtn = tk.Button(btnbar, text="🛡  העבר להסגר", bg=P["danger"], fg="#ffffff",
                         activebackground=P["danger"], activeforeground="#ffffff",
                         font=("Segoe UI", 10, "bold"), relief="flat", bd=0,
                         padx=18, pady=7, cursor="hand2")
        qbtn.configure(command=lambda: _send_to_quarantine(root, res, qbtn))
        qbtn.pack(side="left", padx=5)
    tk.Button(btnbar, text="סגור", font=("Segoe UI", 10),
              bg=P["surface_alt"], fg=P["text"],
              activebackground=P["border"], activeforeground=P["text"],
              relief="flat", bd=0, padx=24, pady=7, cursor="hand2",
              command=root.destroy).pack(side="left", padx=5)
    _center(root)


def _set_clipboard(text: str) -> bool:
    """Put `text` on the Windows clipboard so it OUTLIVES this popup.

    Tk's own clipboard_append is not usable here: Tk registers itself as the
    clipboard owner using delayed rendering, so the data is only produced when
    another app asks for it *and* Tk is still running. Verified empirically —
    after clipboard_append + update(), an external `Get-Clipboard` returned
    EMPTY, and anything copied would be lost the moment this short-lived popup
    closes (exactly when the user goes to paste it).

    So write CF_UNICODETEXT straight to the Win32 clipboard via ctypes: stdlib
    only (no new pinned dependency), correct for Hebrew, and it persists after
    the process exits. Returns True on success; falls back to Tk elsewhere.
    """
    if not sys.platform.startswith("win"):
        return False
    import ctypes
    from ctypes import wintypes

    CF_UNICODETEXT, GMEM_MOVEABLE = 13, 0x0002
    u32 = ctypes.WinDLL("user32", use_last_error=True)
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    u32.OpenClipboard.argtypes = [wintypes.HWND]
    u32.OpenClipboard.restype = wintypes.BOOL
    u32.EmptyClipboard.restype = wintypes.BOOL
    u32.CloseClipboard.restype = wintypes.BOOL
    u32.SetClipboardData.argtypes = [wintypes.UINT, wintypes.HANDLE]
    u32.SetClipboardData.restype = wintypes.HANDLE
    k32.GlobalAlloc.argtypes = [wintypes.UINT, ctypes.c_size_t]
    k32.GlobalAlloc.restype = wintypes.HGLOBAL
    k32.GlobalLock.argtypes = [wintypes.HGLOBAL]
    k32.GlobalLock.restype = wintypes.LPVOID
    k32.GlobalUnlock.argtypes = [wintypes.HGLOBAL]
    k32.GlobalUnlock.restype = wintypes.BOOL
    k32.GlobalFree.argtypes = [wintypes.HGLOBAL]
    k32.GlobalFree.restype = wintypes.HGLOBAL

    buf = ctypes.create_unicode_buffer(text.replace("\n", "\r\n"))
    size = ctypes.sizeof(buf)
    handle = k32.GlobalAlloc(GMEM_MOVEABLE, size)
    if not handle:
        return False
    try:
        ptr = k32.GlobalLock(handle)
        if not ptr:
            k32.GlobalFree(handle)
            return False
        ctypes.memmove(ptr, buf, size)
        k32.GlobalUnlock(handle)
        if not u32.OpenClipboard(None):
            k32.GlobalFree(handle)
            return False
        try:
            u32.EmptyClipboard()
            if not u32.SetClipboardData(CF_UNICODETEXT, handle):
                k32.GlobalFree(handle)
                return False
            # On success the SYSTEM owns the block — must not free it here.
        finally:
            u32.CloseClipboard()
        return True
    except Exception:
        try:
            k32.GlobalFree(handle)
        except Exception:
            pass
        return False


def _copy_explanation(root, res: dict, btn) -> None:
    """Copy the explanation to the clipboard, with the file's identifying
    details so the copied text is self-contained (useful for pasting into a
    report or a message to someone else). Confirms visually on the button.

    Failure is non-fatal — it only affects the copy, never the scan result.
    """
    parts = [f"AntivirusAI — {res.get('name', '')}"]
    if res.get("ml_verdict"):
        parts.append(f"תוצאה: {res['ml_verdict']}")
    if res.get("lgbm_prob") is not None:
        parts.append(f"הסתברות: {res['lgbm_prob'] * 100:.1f}%")
    if res.get("hash_verdict"):
        parts.append(f"התאמת חתימה: {res['hash_verdict']}")
    if res.get("signature_status"):
        signer = res.get("signature_signer")
        parts.append(f"חתימה דיגיטלית: {res['signature_status']}"
                     + (f" ({signer})" if signer else ""))
    if res.get("sha256"):
        parts.append(f"SHA-256: {res['sha256']}")
    parts.append("")
    parts.append(res.get("explanation") or "")
    text = "\n".join(parts).strip()

    ok = _set_clipboard(text)
    if not ok:                      # non-Windows / Win32 call failed
        try:
            root.clipboard_clear()
            root.clipboard_append(text)
            root.update()
            ok = True
        except Exception:
            ok = False
    btn.configure(text="✓  הועתק" if ok else "ההעתקה נכשלה")
    # Restore the original label so the button stays usable for a second copy.
    root.after(1600, lambda: btn.configure(text="📋  העתק"))


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
        btn.configure(text="✓ בהסגר", state="disabled", bg=P["success"],
                      disabledforeground="#ffffff")
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
    root.configure(bg=P["bg"])
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


def run_popup(path: str, *, do_explain: bool = True) -> int:
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
    root.configure(bg=P["bg"])
    try:
        root.attributes("-topmost", True)
    except Exception:
        pass
    _render_scanning(root, os.path.basename(path))
    _center(root)

    q: "queue.Queue" = queue.Queue()

    def worker():
        try:
            r = quick_scan(path, do_explain=do_explain)
        except Exception as e:  # never let the worker die silently under pythonw
            r = {"path": path, "name": os.path.basename(path), "sha256": None, "size": 0,
                 "ml_verdict": ERROR, "lgbm_prob": None,
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
    return 1 if res.get("ml_verdict") == MALWARE else 0


# ── entry point ───────────────────────────────────────────────────────────────
def main(argv=None) -> int:
    import argparse
    ap = argparse.ArgumentParser(prog="avscan quickscan",
                                 description="Scan one file and show a popup verdict.")
    ap.add_argument("file", help="path to the file to scan")
    ap.add_argument("--text", action="store_true", help="print result instead of a popup")
    ap.add_argument("--no-explain", action="store_true", help="skip the Gemini explanation")
    args = ap.parse_args(argv)

    if args.text:
        res = quick_scan(args.file, do_explain=not args.no_explain)
        _print_text(res)
        return 1 if res["ml_verdict"] == MALWARE else 0

    # GUI: show a "scanning…" window immediately, scan on a worker thread, then
    # render the results in the same window.
    try:
        return run_popup(args.file, do_explain=not args.no_explain)
    except Exception as e:
        # Last-resort fallback if Tk can't start at all.
        res = quick_scan(args.file, do_explain=not args.no_explain)
        try:
            import tkinter.messagebox as mb
            mb.showinfo("AntivirusAI", f"{res['name']}: {res['ml_verdict']}")
        except Exception:
            print(f"{res['name']}: {res['ml_verdict']} ({e})")
        return 1 if res["ml_verdict"] == MALWARE else 0


if __name__ == "__main__":
    sys.exit(main())
