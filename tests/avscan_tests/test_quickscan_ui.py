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
        size=1024, ml_verdict="MALWARE", lgbm_prob=0.9987, if_score=None,
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
    """The big verdict label: the first label whose font is 15pt bold."""
    for c in walk(w):
        if c.winfo_class() != "Label":
            continue
        try:
            font = str(c.cget("font"))
        except Exception:
            continue
        if "15" in font and "bold" in font:
            return c.cget("fg"), c.cget("bg"), str(c.cget("text"))
    return None


def has_button(w, needle):
    return any(c.winfo_class() == "Button" and needle in str(c.cget("text"))
               for c in walk(w))


# ── verdict banner ──────────────────────────────────────────────────────────
@pytest.mark.parametrize("verdict,key", [
    ("MALWARE", "danger"),
    ("POTENTIAL_ZERODAY", "warn"),
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


def test_scanning_screen_builds(root):
    qs._render_scanning(root, "sample.exe")
    joined = " ".join(texts(root))
    assert "סורק" in joined
    assert any(c.winfo_class() == "TProgressbar" for c in walk(root))


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
