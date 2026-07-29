"""Tests for the design system (avscan/theme.py).

These assert the things a screenshot cannot: that both palettes are complete,
that text meets WCAG AA contrast on its own background, that every verdict has
a distinct badge, and that the stylesheet is valid enough to contain no unfilled
placeholders.
"""
import re

import pytest

from avscan import theme

MODES = ["dark", "light"]

# Every key the stylesheet and the widgets look up.
REQUIRED_KEYS = {
    "bg", "surface", "surface_alt", "border", "border_soft", "text",
    "text_muted", "accent", "accent_solid", "accent_solid_hover",
    "accent_text", "danger", "danger_bg", "warn", "warn_bg", "success",
    "success_bg", "neutral", "neutral_bg", "selection",
}

HEX = re.compile(r"^#[0-9a-fA-F]{6}$")


@pytest.mark.parametrize("mode", MODES)
def test_palette_is_complete_and_valid_hex(mode):
    p = theme.palette(mode)
    assert REQUIRED_KEYS <= set(p), f"missing: {REQUIRED_KEYS - set(p)}"
    for key, value in p.items():
        assert HEX.match(value), f"{mode}.{key} is not a 6-digit hex colour: {value}"


def test_palettes_have_identical_keys():
    """A key present in one palette but not the other would KeyError only in the
    theme the developer wasn't looking at."""
    assert set(theme.DARK) == set(theme.LIGHT)


def test_unknown_mode_falls_back_instead_of_raising():
    assert theme.palette("solarized") == theme.palette(theme.DEFAULT_MODE)
    assert theme.palette("") == theme.palette(theme.DEFAULT_MODE)


@pytest.mark.parametrize("mode", MODES)
def test_body_text_meets_wcag_aa(mode):
    """Primary text >= 4.5:1 on every surface it is drawn on."""
    p = theme.palette(mode)
    for surface in ("bg", "surface", "surface_alt"):
        ratio = theme.contrast_ratio(p["text"], p[surface])
        assert ratio >= 4.5, f"{mode}: text on {surface} is only {ratio:.2f}:1"


@pytest.mark.parametrize("mode", MODES)
def test_muted_text_meets_wcag_aa(mode):
    """Muted text is used for captions and the current-file line — it still has
    to be readable, so hold it to AA rather than the large-text exemption."""
    p = theme.palette(mode)
    for surface in ("bg", "surface"):
        ratio = theme.contrast_ratio(p["text_muted"], p[surface])
        assert ratio >= 4.5, f"{mode}: muted text on {surface} is {ratio:.2f}:1"


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("key", ["danger", "warn", "success", "neutral"])
def test_status_colours_readable_on_their_own_tint(mode, key):
    """Badges paint `key` text on `key_bg` fill; that pair must be legible.

    Badge text is small and bold, so AA (4.5:1) is the right bar, not the 3:1
    large-text exemption.
    """
    p = theme.palette(mode)
    bg = p.get(f"{key}_bg", p["surface"])
    ratio = theme.contrast_ratio(p[key], bg)
    assert ratio >= 4.5, f"{mode}: {key} on {key}_bg is only {ratio:.2f}:1"


@pytest.mark.parametrize("mode", MODES)
def test_primary_button_text_readable(mode):
    """White label on the solid accent fill, in both the rest and hover states.

    This is why `accent` and `accent_solid` are separate tokens: the blue that
    reads well as text on a dark background is too light to carry white text.
    """
    p = theme.palette(mode)
    for key in ("accent_solid", "accent_solid_hover"):
        ratio = theme.contrast_ratio(p["accent_text"], p[key])
        assert ratio >= 4.5, f"{mode}: button text on {key} is {ratio:.2f}:1"


@pytest.mark.parametrize("mode", MODES)
def test_accent_readable_as_text(mode):
    """`accent` is drawn as text (the ML-only stat, the popup's app mark)."""
    p = theme.palette(mode)
    for surface in ("bg", "surface"):
        ratio = theme.contrast_ratio(p["accent"], p[surface])
        assert ratio >= 4.5, f"{mode}: accent text on {surface} is {ratio:.2f}:1"


# ── Verdict badges ──────────────────────────────────────────────────────────
@pytest.mark.parametrize("mode", MODES)
def test_every_verdict_has_a_badge(mode):
    from avscan import signature
    for verdict in ("MALWARE", "POTENTIAL_ZERODAY", "SAFE", "ERROR",
                    signature.SIGNED_SAFE):
        b = theme.badge(verdict, mode)
        assert b["label"], f"{verdict} has an empty label"
        assert HEX.match(b["fg"]) and HEX.match(b["bg"])


def test_malware_and_safe_badges_are_visually_distinct():
    """The whole point of the badge is instant discrimination — if MALWARE and
    SAFE ever resolved to the same fill the UI would be actively dangerous."""
    for mode in MODES:
        mal = theme.badge("MALWARE", mode)
        safe = theme.badge("SAFE", mode)
        assert mal["bg"] != safe["bg"]
        assert mal["fg"] != safe["fg"]


def test_signed_safe_badge_reads_as_signed_not_as_malware():
    from avscan import signature
    b = theme.badge(signature.SIGNED_SAFE, "dark")
    assert b["label"] == "SIGNED"
    assert b["fg"] == theme.palette("dark")["success"]


def test_unknown_verdict_degrades_to_neutral_badge():
    """A verdict added later must not render as an invisible or misleading pill."""
    b = theme.badge("SOME_FUTURE_VERDICT", "dark")
    assert b["label"] == "SOME_FUTURE_VERDICT"
    assert b["fg"] == theme.palette("dark")["neutral"]
    b_empty = theme.badge("", "dark")
    assert b_empty["label"] == "-"


# ── Stylesheet ──────────────────────────────────────────────────────────────
@pytest.mark.parametrize("mode", MODES)
def test_stylesheet_has_no_unresolved_placeholders(mode):
    qss = theme.stylesheet(mode)
    assert "{p[" not in qss and "None" not in qss
    # An f-string that lost a brace shows up as a stray single brace pair.
    assert qss.count("{") == qss.count("}")


@pytest.mark.parametrize("mode", MODES)
def test_stylesheet_styles_the_widgets_the_gui_actually_uses(mode):
    qss = theme.stylesheet(mode)
    for selector in ("QPushButton#Primary", "QFrame#Card", "QFrame#HeaderBar",
                     "QLabel#StatValue", "QTableWidget", "QHeaderView::section",
                     "QProgressBar::chunk", "QCheckBox::indicator",
                     "QLineEdit", "QComboBox", "QScrollBar:vertical"):
        assert selector in qss, f"{mode} stylesheet is missing {selector}"


def test_dark_and_light_stylesheets_differ():
    assert theme.stylesheet("dark") != theme.stylesheet("light")


@pytest.mark.parametrize("mode", MODES)
def test_stylesheet_only_references_palette_colours(mode):
    """No colour may be hard-coded in the QSS — otherwise switching theme leaves
    an orphan that never changes."""
    p = theme.palette(mode)
    allowed = {v.lower() for v in p.values()} | {"#ffffff"}
    used = {m.lower() for m in re.findall(r"#[0-9a-fA-F]{6}", theme.stylesheet(mode))}
    assert used <= allowed, f"{mode}: hard-coded colours {used - allowed}"


# ── Contrast helper itself ──────────────────────────────────────────────────
def test_contrast_ratio_known_values():
    assert theme.contrast_ratio("#ffffff", "#000000") == pytest.approx(21.0, abs=0.01)
    assert theme.contrast_ratio("#ffffff", "#ffffff") == pytest.approx(1.0, abs=0.01)
    # Order must not matter.
    assert theme.contrast_ratio("#000000", "#ffffff") == pytest.approx(
        theme.contrast_ratio("#ffffff", "#000000"))
