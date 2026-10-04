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

import io
import json
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
from avscan.engine import get_engine, sha256_bytes, MALWARE, SAFE, ERROR  # noqa: E402
from avscan.hashdb import HashDB, KNOWN_MALWARE  # noqa: E402
from avscan.selfcheck import run_selfcheck  # noqa: E402


def _read_file(path: str, chunk: int = 8 * 1024 * 1024) -> bytes:
    """Read a file in chunks rather than one giant request.

    A single .read() of a several-hundred-MB file intermittently fails with
    OSError EINVAL on virtual/network filesystems (reproduced on a 846MB
    installer sitting on a Google Drive letter, which streams the file in on
    demand). Chunked reads ask the driver for a normal-sized block at a time
    and go through unchanged. Same bytes, same order — nothing downstream
    (hash, features, verdict) can tell the difference.
    """
    parts = []
    with open(path, "rb") as f:
        while True:
            block = f.read(chunk)
            if not block:
                break
            parts.append(block)
    return b"".join(parts)


def quick_scan(path: str, *, do_explain: bool = True) -> dict:
    """Scan a single file. Returns a result dict; never raises."""
    res = {
        "path": path, "name": os.path.basename(path), "sha256": None, "size": 0,
        "ml_verdict": None, "lgbm_prob": None,
        "hash_verdict": None, "explanation": None, "explain_status": None,
        "evidence": None, "top_groups": None, "vector": None,
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
        # Read once and extract once: the hash, the verdict and the explanation
        # layer all work off the same bytes and the same feature vector, so a
        # scan costs one read + one extraction no matter how big the file is.
        data = _read_file(path)
        sha = sha256_bytes(data)
        ml, vector = engine.classify_with_vector(data)
        res.update(sha256=sha, size=len(data), ml_verdict=ml.ml_verdict,
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
        # positive, so it is checked for anything flagged (MALWARE, or ERROR
        # under the fail-closed policy — a file that failed feature extraction
        # can still have a perfectly readable Authenticode signature).
        if ml.ml_verdict in (MALWARE, ERROR):
            sig = signature.verify(path)
            res["signature_status"] = sig.status
            res["signature_signer"] = sig.signer
            res["signature_detail"] = sig.detail

        # Local evidence/vector are free to compute for ANY verdict (no
        # network call) and are what powers the "all parameters" / raw-data
        # sections in the popup, so this now always runs. Only the actual
        # Gemini call stays reserved for flagged files: its prompt is worded
        # "why was this blocked" (avscan/explain.py::build_prompt), which
        # would be an actively wrong thing to send for a SAFE file — forcing
        # explain_enabled=False for the request makes explain_bytes() stop
        # right after computing the local summary/evidence/vector, same as
        # if the user had disabled the feature.
        want_ai = do_explain and ml.ml_verdict == MALWARE
        call_settings = dict(config.load_settings())
        if not want_ai:
            call_settings["explain_enabled"] = False
        out = explain.explain_bytes(engine, data, ml, settings=call_settings,
                                    hash_verdict=res.get("hash_verdict"),
                                    signature_status=res.get("signature_status"),
                                    signature_signer=res.get("signature_signer"),
                                    vector=vector)
        res["explanation"] = out.get("summary") or None
        res["explain_status"] = out.get("status")
        res["evidence"] = out.get("evidence")
        res["top_groups"] = out.get("top_groups")
        res["vector"] = out.get("vector")
    except Exception as e:
        res["error"] = f"scan failed: {e}"
    return res


# ── text output (headless / tests) ───────────────────────────────────────────
def _print_text(res: dict) -> None:
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
    # danger, not neutral: a file we couldn't read/parse is treated as flagged
    # (fail-closed), so it must look as urgent as a real MALWARE verdict.
    ERROR:             ("danger",  "⚠",  "לא ניתן היה לנתח — טופל כחשוד"),
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
    tk.Label(line, text=value, font=theme.font("small"),
             fg=accent or P["text"], bg=P["surface"],
             anchor="e", justify="right").pack(side="right")
    tk.Label(line, text=f"{label}:  ", font=theme.font("small"),
             fg=P["text_muted"], bg=P["surface"],
             anchor="e", justify="right").pack(side="right")
    return line


def _clear(widget) -> None:
    for c in widget.winfo_children():
        c.destroy()


def _center(root) -> None:
    """Resize the window to fit its content (so nothing is clipped) and center it.

    The height is CLAMPED to the screen: at a larger type scale — or on a small
    laptop/VM display — the natural height of the results view exceeds the
    screen, and an unclamped window pushes its own button bar (close, send to
    quarantine) off the bottom edge where it cannot be reached. The two
    evidence boxes are packed with expand=True, so the geometry manager absorbs
    the clamp by shrinking them, and they scroll internally; the buttons and
    the verdict banner keep their natural size.
    """
    root.geometry("")               # drop any fixed size -> auto-fit to content
    root.update_idletasks()
    screen_w, screen_h = root.winfo_screenwidth(), root.winfo_screenheight()
    max_w, max_h = int(screen_w * 0.95), int(screen_h * 0.90)
    # maxsize, not just geometry: a geometry set before the window is mapped is
    # overridden when Tk re-requests its natural size on map, which put the
    # button bar off-screen. maxsize is enforced by the window manager and
    # keeps holding later, when "show raw data" adds 2381 numbers to the view.
    root.maxsize(max_w, max_h)
    w = min(max(root.winfo_reqwidth(), 470), max_w)
    h = min(root.winfo_reqheight(), max_h)
    x = max(0, (screen_w - w) // 2)
    y = max(0, (screen_h - h) // 3)
    root.geometry(f"{w}x{h}+{x}+{y}")


def _render_scanning(root, name: str, size: int = 0):
    """The immediate 'scanning…' screen (shown before the slow work).

    The bar is driven by a self-scheduled `after` loop (not Progressbar.start),
    which — together with the low thread-switch interval set in run_popup — keeps
    it moving smoothly even while the worker thread is busy importing/loading.

    Feature extraction is inherently O(file size) — around a minute for a
    several-hundred-MB installer — so the screen also shows the file's size and
    a running elapsed count. Without them a legitimately slow scan is
    indistinguishable from a hung one.
    """
    import time
    import tkinter as tk
    from tkinter import ttk

    _clear(root)
    root.configure(bg=P["bg"])

    header = tk.Frame(root, bg=P["surface"])
    header.pack(fill="x")
    inner = tk.Frame(header, bg=P["surface"])
    inner.pack(fill="x", padx=18, pady=(13, 12))
    tk.Label(inner, text="AntivirusAI", font=theme.font("small", bold=True),
             fg=P["accent"], bg=P["surface"]).pack(side="left")
    tk.Label(inner, text=name, font=theme.font("title", bold=True), fg=P["text"],
             bg=P["surface"], anchor="e", justify="right").pack(side="right")
    tk.Frame(root, bg=P["border"], height=1).pack(fill="x")

    banner = tk.Frame(root, bg=P["neutral_bg"])
    banner.pack(fill="x", padx=16, pady=(14, 8))
    tk.Frame(banner, bg=P["accent"], width=4).pack(side="right", fill="y")
    tk.Label(banner, text="סורק את הקובץ…", font=theme.font("banner", bold=True),
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

    note = "בדיקת סביבה, חילוץ מאפיינים, סיווג, השוואת חתימות והסבר AI…"
    if size:
        mb = size / (1024 * 1024)
        note = f"גודל הקובץ: {mb:,.0f} MB — " + note
        if mb >= 100:
            note += "\nקובץ גדול: חילוץ המאפיינים סורק את כל הקובץ ועשוי לקחת דקה או יותר."
    tk.Label(root, text=note, font=theme.font("small"), fg=P["text_muted"], bg=P["bg"],
             anchor="e", justify="right", wraplength=theme.scaled(390)).pack(fill="x", padx=18)

    elapsed = tk.Label(root, text="", font=theme.font("micro"), fg=P["text_muted"],
                       bg=P["bg"], anchor="e", justify="right")
    elapsed.pack(fill="x", padx=18, pady=(4, 16))

    started = time.monotonic()

    def _tick():
        if not pb.winfo_exists():   # stops itself once the results view replaces it
            return
        pb.step(5)
        secs = int(time.monotonic() - started)
        if secs:
            elapsed.configure(text=f"פועל כבר {secs} שניות…")
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
    tk.Label(inner, text="AntivirusAI", font=theme.font("small", bold=True),
             fg=P["accent"], bg=P["surface"]).pack(side="left")
    tk.Label(inner, text=res["name"], font=theme.font("title", bold=True),
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
    tk.Label(bin_, text=f"{icon}  {text}", font=theme.font("banner", bold=True),
             fg=accent, bg=bg, anchor="e", justify="right",
             wraplength=theme.scaled(400)).pack(fill="x")

    # The model's own verdict is never hidden — a green banner on a file the
    # engine flagged must stay auditable, so say so directly under the banner.
    if res["selfcheck_ok"] and shown == signature.SIGNED_SAFE:
        tk.Label(root,
                 text=f"מנוע ה-ML סימן את הקובץ כ-{res['ml_verdict']}, "
                      "אך החתימה הדיגיטלית התקפה גוברת על כך",
                 font=theme.font("micro"), fg=P["text_muted"], bg=P["bg"],
                 anchor="e", justify="right", wraplength=theme.scaled(430)).pack(fill="x", padx=18)

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
        copy_btn = tk.Button(head, text="📋  העתק", font=theme.font("micro"),
                             bg=P["surface_alt"], fg=P["text"],
                             activebackground=P["border"], activeforeground=P["text"],
                             relief="flat", bd=0, padx=10, pady=3, cursor="hand2")
        copy_btn.configure(command=lambda: _copy_explanation(root, res, copy_btn))
        copy_btn.pack(side="left")
        tk.Label(head, text="למה המערכת חושבת כך", font=theme.font("small", bold=True),
                 fg=P["text_muted"], bg=P["bg"], anchor="e",
                 justify="right").pack(side="right")
        box = scrolledtext.ScrolledText(
            root, height=6, width=50, wrap="word", font=theme.font("body"),
            bg=P["surface"], fg=P["text"], insertbackground=P["text"],
            relief="flat", bd=0, padx=12, pady=10,
            highlightbackground=P["border"], highlightthickness=1)
        box.pack(fill="both", expand=True, padx=16, pady=(5, 4))
        box.tag_configure("rtl", justify="right")
        box.insert("1.0", res["explanation"], "rtl")
        box.configure(state="disabled")
        if res["explain_status"] and res["explain_status"] != "ok":
            tk.Label(root, text=explain.status_message(res["explain_status"], "he"),
                     font=theme.font("micro"), fg=P["text_muted"], bg=P["bg"],
                     anchor="e", justify="right", wraplength=theme.scaled(430)).pack(fill="x", padx=18)

    # ── all measured parameters (not just the summary's headline points) ────
    if res.get("evidence"):
        tk.Label(root, text="כל הפרמטרים שנאספו מהקובץ", font=theme.font("small", bold=True),
                 fg=P["text_muted"], bg=P["bg"], anchor="e",
                 justify="right").pack(fill="x", padx=18, pady=(10, 0))
        ev_box = scrolledtext.ScrolledText(
            root, height=6, width=50, wrap="word", font=theme.font("small"),
            bg=P["surface"], fg=P["text"], insertbackground=P["text"],
            relief="flat", bd=0, padx=12, pady=10,
            highlightbackground=P["border"], highlightthickness=1)
        ev_box.pack(fill="both", expand=True, padx=16, pady=(5, 4))
        ev_box.tag_configure("rtl", justify="right")
        ev_box.insert("1.0", explain.format_all_evidence(
            res["evidence"], res.get("top_groups") or [], "he"), "rtl")
        ev_box.configure(state="disabled")

    # ── raw feature vector (2381 numbers, grouped) — hidden until asked for ──
    raw_state = {"shown": False}
    if res.get("vector"):
        raw_label = tk.Label(root, text="הווקטור הגולמי (2381 המספרים שהמודל ראה)",
                             font=theme.font("small", bold=True), fg=P["text_muted"], bg=P["bg"],
                             anchor="e", justify="right")
        raw_box = scrolledtext.ScrolledText(
            root, height=8, width=50, wrap="none", font=theme.font("micro", mono=True),
            bg=P["surface"], fg=P["text"], insertbackground=P["text"],
            relief="flat", bd=0, padx=12, pady=10,
            highlightbackground=P["border"], highlightthickness=1)
        raw_box.insert("1.0", explain.format_raw_vector(res["vector"], "he"))
        raw_box.configure(state="disabled")
        # not packed yet — toggled into view by the button below

        def _toggle_raw():
            if raw_state["shown"]:
                raw_label.pack_forget()
                raw_box.pack_forget()
                raw_btn.configure(text="הצג נתונים גולמיים")
            else:
                raw_label.pack(fill="x", padx=18, pady=(10, 0), before=btnbar)
                raw_box.pack(fill="both", expand=True, padx=16, pady=(5, 4), before=btnbar)
                raw_btn.configure(text="הסתר נתונים גולמיים")
            raw_state["shown"] = not raw_state["shown"]
            _center(root)

    btnbar = tk.Frame(root, bg=P["bg"])
    btnbar.pack(pady=(10, 14))
    # No quarantine button when the file is shown green — offering to isolate a
    # file we just declared clean is contradictory. Use the CLI's
    # --no-trust-signed to quarantine a signed file anyway.
    if (res["selfcheck_ok"] and res["ml_verdict"] in (MALWARE, ERROR)
            and shown != signature.SIGNED_SAFE
            and res.get("path") and res.get("sha256") and os.path.isfile(res["path"])):
        qbtn = tk.Button(btnbar, text="🛡  העבר להסגר", bg=P["danger"], fg="#ffffff",
                         activebackground=P["danger"], activeforeground="#ffffff",
                         font=theme.font("body", bold=True), relief="flat", bd=0,
                         padx=18, pady=7, cursor="hand2")
        qbtn.configure(command=lambda: _send_to_quarantine(root, res, qbtn))
        qbtn.pack(side="left", padx=5)
    if res.get("vector"):
        raw_btn = tk.Button(btnbar, text="הצג נתונים גולמיים", font=theme.font("body"),
                            bg=P["surface_alt"], fg=P["text"],
                            activebackground=P["border"], activeforeground=P["text"],
                            relief="flat", bd=0, padx=18, pady=7, cursor="hand2")
        raw_btn.configure(command=_toggle_raw)
        raw_btn.pack(side="left", padx=5)
    tk.Button(btnbar, text="סגור", font=theme.font("body"),
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


def _console_python() -> str:
    """python.exe next to the running pythonw.exe (so the child can use a pipe)."""
    exe = sys.executable or ""
    base = os.path.basename(exe).lower()
    if base == "pythonw.exe":
        cand = os.path.join(os.path.dirname(exe), "python.exe")
        if os.path.isfile(cand):
            return cand
    return exe


def _scan_in_subprocess(path: str, *, do_explain: bool = True, timeout: int = 1800):
    """Run the scan in a CHILD PROCESS and return its result dict (None on failure).

    This is not an optimisation — it is what keeps the window alive. EMBER's
    feature extraction runs inside lief, a C++ extension that holds the GIL for
    the whole parse, so a worker *thread* starves Tk's event loop: measured on a
    57MB file, the UI fired 80 of the expected 292 frames and froze for 1.3s in
    one stretch. That scales with file size — a few hundred MB is long enough
    for Windows to grey the window out as "Not Responding", which is exactly
    what a stuck scan looks like. A separate process has its own GIL, and the
    thread waiting on its output is blocked in I/O (GIL released), so the
    animation, the elapsed counter and the window controls all stay live.

    Returns None if the child could not be run at all, so the caller can fall
    back to scanning in-process rather than leaving the user with nothing.
    """
    import subprocess

    exe = _console_python()
    script = os.path.abspath(__file__)
    if not exe or not os.path.isfile(script):
        return None
    cmd = [exe, script, path, "--json"]
    if not do_explain:
        cmd.append("--no-explain")
    # No console window for the child (the parent is a windowed pythonw process).
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    try:
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                              stdin=subprocess.DEVNULL, timeout=timeout,
                              creationflags=flags)
    except Exception:
        return None
    try:
        # The child prints one JSON object; ignore any library chatter before it.
        raw = proc.stdout.decode("utf-8", "replace")
        start = raw.find("{")
        if start < 0:
            return None
        res = json.loads(raw[start:])
    except Exception:
        return None
    # The child ran but produced no verdict (an I/O error on its side, say).
    # Report that as a failure so the caller retries in-process: running the
    # scan out-of-process must never turn a file that would have scanned fine
    # into an error. A self-check refusal is a real answer, so it stands.
    if res.get("ml_verdict") is None and res.get("selfcheck_ok", True):
        return None
    return res


def _yield_gil_to_ui() -> None:
    """Last-resort smoothing for the in-process fallback path.

    Only helps between C calls — it cannot preempt lief mid-parse — which is why
    the subprocess above is the real fix and this is just the fallback.
    """
    try:
        sys.setswitchinterval(0.0005)
    except Exception:
        pass


def run_popup(path: str, *, do_explain: bool = True) -> int:
    """Show a 'scanning…' window IMMEDIATELY, run the scan on a background thread,
    then swap in the results in the same window. Returns the exit code."""
    import queue
    import threading
    import tkinter as tk

    holder: dict = {"res": None}
    root = tk.Tk()
    root.title("AntivirusAI — סריקה מהירה")
    root.configure(bg=P["bg"])
    try:
        root.attributes("-topmost", True)
    except Exception:
        pass
    try:
        size = os.path.getsize(path)
    except OSError:
        size = 0
    _render_scanning(root, os.path.basename(path), size)
    _center(root)

    q: "queue.Queue" = queue.Queue()

    def worker():
        try:
            r = _scan_in_subprocess(path, do_explain=do_explain)
            if r is None:                       # subprocess unavailable — scan here
                _yield_gil_to_ui()
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
        # A raise in here is swallowed by Tk's callback handler (and stderr is
        # /dev/null under pythonw), which would leave the window sitting on the
        # "scanning…" screen forever. Always leave the user with a verdict.
        try:
            _render_results(root, res)
        except Exception as e:
            res["error"] = f"display failed: {type(e).__name__}: {e}"
            res.update(explanation=None, evidence=None, top_groups=None, vector=None)
            _render_results(root, res)

    root.after(150, poll)
    root.mainloop()

    res = holder["res"] or {}
    return 1 if res.get("ml_verdict") in (MALWARE, ERROR) else 0


# ── entry point ───────────────────────────────────────────────────────────────
def main(argv=None) -> int:
    import argparse
    ap = argparse.ArgumentParser(prog="avscan quickscan",
                                 description="Scan one file and show a popup verdict.")
    ap.add_argument("file", help="path to the file to scan")
    ap.add_argument("--text", action="store_true", help="print result instead of a popup")
    ap.add_argument("--json", action="store_true",
                    help="print the result as JSON (used by the popup's scan process)")
    ap.add_argument("--no-explain", action="store_true", help="skip the Gemini explanation")
    args = ap.parse_args(argv)

    if args.json:
        res = quick_scan(args.file, do_explain=not args.no_explain)
        out = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")
        json.dump(res, out, ensure_ascii=False)
        out.flush()
        return 1 if res["ml_verdict"] in (MALWARE, ERROR) else 0

    if args.text:
        res = quick_scan(args.file, do_explain=not args.no_explain)
        _print_text(res)
        return 1 if res["ml_verdict"] in (MALWARE, ERROR) else 0

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
        return 1 if res["ml_verdict"] in (MALWARE, ERROR) else 0


if __name__ == "__main__":
    sys.exit(main())
