"""Tests for the right-click Quick Scan popup (avscan/quickscan.py).

Builds the real Tk widget tree (in a withdrawn window, so nothing appears on
screen) and inspects it. Tk gives us no screenshot, so the assertions read the
widgets' actual configured colours and text instead — which is enough to catch
a banner rendered in the wrong colour, a missing disclosure line, or a
quarantine button offered on a file we just called clean.
"""
import pytest

tk = pytest.importorskip("tkinter", reason="the popup requires tkinter")

from avscan import quickscan as qs  # noqa: E402
from avscan import signature, theme  # noqa: E402

P = theme.palette("dark")


@pytest.fixture(scope="module")
def tk_root():
    """One Tcl interpreter for the whole module.

    Creating and destroying a fresh tk.Tk() per test is flaky — after a few
    teardowns Tcl intermittently loses track of tk.tcl and the next Tk() raises
    "Can't find a usable tk.tcl", which showed up as a different test skipping
    on each run. One interpreter plus a Toplevel per test is stable.
    """
    try:
        r = tk.Tk()
    except tk.TclError as e:                      # no display available
        pytest.skip(f"no Tk display: {e}")
    r.withdraw()
    yield r
    try:
        r.destroy()
    except Exception:
        pass


@pytest.fixture
def root(tk_root):
    """A throwaway window per test, rendered into exactly like the real popup."""
    top = tk.Toplevel(tk_root)
    top.withdraw()
    yield top
    try:
        top.destroy()
    except Exception:
        pass


def make_res(**over):
    res = dict(
        name="sample.exe", path=r"C:\samples\sample.exe", sha256="ab" * 32,
        size=1024, ml_verdict="MALWARE", lgbm_prob=0.9987,
        hash_verdict="NOT_IN_DB", error=None, selfcheck_ok=True,
        selfcheck_failed=[], explanation=None, explain_status=None,
        signature_status=None, signature_signer=None, signature_detail=None)
    res.update(over)
    return res


def walk(w):
    """Every widget in the tree, depth-first."""
    out = []
    for c in w.winfo_children():
        out.append(c)
        out.extend(walk(c))
    return out


def texts(w):
    out = []
    for c in walk(w):
        try:
            t = c.cget("text")
        except Exception:
            continue
        if t:
            out.append(str(t))
    return out


def banner_of(w):
    """The big verdict label: the first label rendered in the theme's banner
    font. Keyed off theme.font() rather than a literal point size, so changing
    the popup's type scale does not silently stop this test from finding the
    banner it is supposed to be checking."""
    banner_size = str(theme.font("banner", bold=True)[1])
    for c in walk(w):
        if c.winfo_class() != "Label":
            continue
        try:
            font = str(c.cget("font"))
        except Exception:
            continue
        parts = font.split()
        if banner_size in parts and "bold" in parts:
            return c.cget("fg"), c.cget("bg"), str(c.cget("text"))
    return None


def has_button(w, needle):
    return any(c.winfo_class() == "Button" and needle in str(c.cget("text"))
               for c in walk(w))


# ── verdict banner ──────────────────────────────────────────────────────────
@pytest.mark.parametrize("verdict,key", [
    ("MALWARE", "danger"),
    ("SAFE", "success"),
])
def test_banner_colour_matches_verdict(root, verdict, key):
    qs._render_results(root, make_res(ml_verdict=verdict))
    fg, bg, _ = banner_of(root)
    assert fg == P[key]
    assert bg == P[f"{key}_bg"]


def test_signed_file_gets_a_green_banner_naming_the_signer(root):
    qs._render_results(root, make_res(
        name="Claude Setup.exe", signature_status="TRUSTED",
        signature_signer="Anthropic, PBC"))
    fg, bg, text = banner_of(root)
    assert fg == P["success"]
    assert bg == P["success_bg"]
    assert "Anthropic, PBC" in text


def test_signed_banner_still_discloses_the_ml_verdict(root):
    """Auditability: a green banner on a file the engine flagged must say so."""
    qs._render_results(root, make_res(
        signature_status="TRUSTED", signature_signer="Anthropic, PBC"))
    joined = " ".join(texts(root))
    assert "MALWARE" in joined


def test_signed_but_known_malware_hash_stays_red(root):
    """UI reflection of the safety carve-out — a stolen certificate must not
    turn a known sample green."""
    qs._render_results(root, make_res(
        hash_verdict="KNOWN_MALWARE", signature_status="TRUSTED",
        signature_signer="Stolen Cert Inc"))
    fg, bg, _ = banner_of(root)
    assert fg == P["danger"]
    assert bg == P["danger_bg"]


def test_failed_selfcheck_shows_a_neutral_banner(root):
    qs._render_results(root, make_res(selfcheck_ok=False,
                                      selfcheck_failed=["numpy version"]))
    fg, bg, _ = banner_of(root)
    assert fg == P["neutral"]
    assert bg == P["neutral_bg"]


# ── quarantine button ───────────────────────────────────────────────────────
def test_quarantine_button_offered_for_unsigned_malware(root, tmp_path):
    f = tmp_path / "bad.exe"
    f.write_bytes(b"MZ" + b"\0" * 100)
    qs._render_results(root, make_res(path=str(f), name="bad.exe",
                                      signature_status="UNSIGNED"))
    assert has_button(root, "הסגר")


def test_quarantine_button_hidden_when_shown_green(root, tmp_path):
    """Offering to isolate a file we just declared clean is contradictory."""
    f = tmp_path / "signed.exe"
    f.write_bytes(b"MZ" + b"\0" * 100)
    qs._render_results(root, make_res(path=str(f), name="signed.exe",
                                      signature_status="TRUSTED",
                                      signature_signer="Anthropic, PBC"))
    assert not has_button(root, "הסגר")
    assert has_button(root, "סגור")          # close button still there


def test_quarantine_button_offered_for_signed_known_malware(root, tmp_path):
    f = tmp_path / "evil.exe"
    f.write_bytes(b"MZ" + b"\0" * 100)
    qs._render_results(root, make_res(path=str(f), name="evil.exe",
                                      hash_verdict="KNOWN_MALWARE",
                                      signature_status="TRUSTED",
                                      signature_signer="Stolen Cert Inc"))
    assert has_button(root, "הסגר")


# ── details + explanation ───────────────────────────────────────────────────
def test_details_card_lists_the_measurements(root):
    qs._render_results(root, make_res(signature_status="UNSIGNED"))
    joined = " ".join(texts(root))
    assert "99.9%" in joined
    assert "SHA-256" in joined
    assert "חתימה דיגיטלית" in joined


def test_explanation_box_and_copy_button_appear(root):
    qs._render_results(root, make_res(explanation="הסבר לדוגמה", explain_status="ok"))
    assert has_button(root, "העתק")
    boxes = [c for c in walk(root) if c.winfo_class() == "Text"]
    assert boxes, "the explanation text box was not created"
    assert boxes[0].cget("bg") == P["surface"]


def test_no_explanation_means_no_copy_button(root):
    qs._render_results(root, make_res(explanation=None))
    assert not has_button(root, "העתק")


def test_all_parameters_section_shows_full_evidence(root):
    evidence = [
        {"key": "entropy", "he": "רמת ערבול גבוהה", "en": "high entropy",
         "suspicious": True, "group": "byte-entropy patterns"},
        {"key": "size", "he": "גודל הקובץ: 10 KB", "en": "file size: 10 KB",
         "suspicious": False, "group": "general file info"},
    ]
    qs._render_results(root, make_res(
        explanation="הסבר לדוגמה", explain_status="ok",
        evidence=evidence, top_groups=[]))
    joined = " ".join(texts(root))
    assert "כל הפרמטרים שנאספו מהקובץ" in joined
    text_widgets = [c for c in walk(root) if c.winfo_class() == "Text"]
    # explanation box + the new all-evidence box
    assert len(text_widgets) >= 2
    bodies = [w.get("1.0", "end") for w in text_widgets]
    assert any("רמת ערבול גבוהה" in b and "גודל הקובץ: 10 KB" in b for b in bodies)


def test_no_evidence_means_no_all_parameters_section(root):
    qs._render_results(root, make_res(
        explanation="הסבר לדוגמה", explain_status="ok", evidence=None))
    joined = " ".join(texts(root))
    assert "כל הפרמטרים שנאספו מהקובץ" not in joined


def test_scanning_screen_builds(root):
    qs._render_scanning(root, "sample.exe")
    joined = " ".join(texts(root))
    assert "סורק" in joined
    assert any(c.winfo_class() == "TProgressbar" for c in walk(root))


def test_scanning_screen_warns_that_a_big_file_takes_a_while(root):
    """Feature extraction is O(file size); a minute of silence reads as a hang."""
    qs._render_scanning(root, "huge.exe", 800 * 1024 * 1024)
    joined = " ".join(texts(root))
    assert "800 MB" in joined
    assert "דקה" in joined


def test_chunked_read_returns_the_whole_file(tmp_path):
    """A single huge .read() fails with EINVAL on some virtual/network drives."""
    f = tmp_path / "blob.bin"
    payload = bytes(range(256)) * 5000          # 1.28 MB, spans many chunks
    f.write_bytes(payload)
    assert qs._read_file(str(f), chunk=1024) == payload


def test_scan_runs_out_of_process_so_the_window_cannot_freeze(benign_exes):
    """EMBER extraction runs inside lief, which holds the GIL for the whole
    parse and starves Tk's event loop; the scan must happen in a child."""
    res = qs._scan_in_subprocess(str(benign_exes[0]))
    assert res is not None, "subprocess scan did not return a result"
    assert res["ml_verdict"] in ("MALWARE", "SAFE", "ERROR")
    assert res["sha256"] and len(res["vector"]) == 2381


def test_subprocess_failure_falls_back_rather_than_reporting_an_error(monkeypatch, tmp_path):
    """A child that ran but produced no verdict must not be shown as the answer
    — the caller re-scans in-process instead."""
    import subprocess as sp
    f = tmp_path / "x.exe"
    f.write_bytes(b"MZ" + b"\0" * 200)

    class Fake:
        returncode = 0
        stdout = b'{"ml_verdict": null, "selfcheck_ok": true, "error": "scan failed"}'
    monkeypatch.setattr(sp, "run", lambda *a, **k: Fake())
    assert qs._scan_in_subprocess(str(f)) is None

    # a self-check refusal IS a real answer and is kept
    class Refused:
        returncode = 0
        stdout = b'{"ml_verdict": null, "selfcheck_ok": false, "selfcheck_failed": ["numpy"]}'
    monkeypatch.setattr(sp, "run", lambda *a, **k: Refused())
    assert qs._scan_in_subprocess(str(f))["selfcheck_ok"] is False


def test_quick_scan_extracts_features_only_once(benign_exes, monkeypatch):
    """Extraction dominates scan time (~2 minutes on an 846MB installer), so
    computing the vector for the verdict and again for the explanation layer
    doubled every scan and made the popup look stuck."""
    engine = qs.get_engine()
    calls = []
    real = engine.extractor.feature_vector
    monkeypatch.setattr(engine.extractor, "feature_vector",
                        lambda data: (calls.append(1), real(data))[1])

    res = qs.quick_scan(str(benign_exes[0]), do_explain=False)

    assert len(calls) == 1, f"file was feature-extracted {len(calls)} times"
    assert res["ml_verdict"] is not None
    assert res["vector"] and len(res["vector"]) == 2381


# ── palette discipline ──────────────────────────────────────────────────────
def test_popup_uses_only_palette_colours(root):
    """Every colour in the popup must come from theme.py, so the popup and the
    Qt window cannot drift apart."""
    qs._render_results(root, make_res(
        explanation="x", signature_status="TRUSTED", signature_signer="A, B"))
    allowed = {v.lower() for v in P.values()} | {"#ffffff", "", "systembuttonface"}
    used = set()
    for c in walk(root):
        for opt in ("bg", "fg", "background", "foreground"):
            try:
                v = str(c.cget(opt)).lower()
            except Exception:
                continue
            if v:
                used.add(v)
    stray = {u for u in used if u.startswith("#")} - allowed
    assert not stray, f"hard-coded colours in the popup: {stray}"


def test_render_is_idempotent(root):
    """Re-rendering must clear the previous tree, not stack a second copy."""
    qs._render_results(root, make_res())
    first = len(walk(root))
    qs._render_results(root, make_res())
    assert len(walk(root)) == first


def test_no_vector_means_no_raw_data_button(root):
    qs._render_results(root, make_res(explanation="הסבר", vector=None))
    assert not has_button(root, "נתונים גולמיים")


def test_raw_data_button_appears_and_toggles(root):
    qs._render_results(root, make_res(
        explanation="הסבר", explain_status="ok",
        evidence=[{"key": "size", "he": "גודל: 1KB", "en": "size: 1KB",
                  "suspicious": False, "group": "general file info"}],
        top_groups=[], vector=[0.25] * 2381))
    assert has_button(root, "הצג נתונים גולמיים")
    # The raw-vector widget is built immediately (so its content never needs
    # recomputing), just not handed to the packer until toggled. `root` is a
    # withdrawn window in this fixture, so winfo_ismapped() is always False
    # regardless of pack state — winfo_manager() ("" vs "pack") is the check
    # that actually reflects pack_forget()/pack() here.
    text_widgets = [c for c in walk(root) if c.winfo_class() == "Text"]
    raw_box = next(w for w in text_widgets if "0.2500" in w.get("1.0", "end"))
    assert raw_box.frame.winfo_manager() == ""

    btn = next(c for c in walk(root)
              if c.winfo_class() == "Button" and "נתונים גולמיים" in c.cget("text"))
    btn.invoke()
    assert btn.cget("text") == "הסתר נתונים גולמיים"
    joined = " ".join(texts(root))
    assert "הווקטור הגולמי" in joined
    assert raw_box.frame.winfo_manager() == "pack"

    btn.invoke()
    assert btn.cget("text") == "הצג נתונים גולמיים"
    assert raw_box.frame.winfo_manager() == ""
