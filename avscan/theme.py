"""
theme.py — design tokens and the Qt stylesheet for the desktop UI.

Deliberately imports NO Qt. It is a pure data + string module so that the whole
design system (palettes, verdict badges, contrast) can be unit-tested in a
plain interpreter, and so the Tk quick-scan popup can share the exact same
colours as the PySide6 main window without pulling Qt in.

Two palettes are provided. Dark is the default: this is a security console and
it is what the rest of the category looks like. Both are tuned for WCAG AA
contrast on body text — see tests/avscan_tests/test_theme.py, which asserts the
ratios rather than trusting the eye.
"""
from __future__ import annotations

DARK = {
    "bg":           "#0d1117",
    "surface":      "#161b22",
    "surface_alt":  "#1c2128",
    "border":       "#30363d",
    "border_soft":  "#21262d",
    "text":         "#e6edf3",
    "text_muted":   "#9198a1",
    # Two blues, because one cannot do both jobs at AA: `accent` is bright
    # enough to read as TEXT on the dark background, `accent_solid` is dark
    # enough that white BUTTON text passes on top of it. Verified in
    # test_theme.py — a single blue fails one side or the other.
    "accent":              "#58a6ff",
    "accent_solid":        "#1a68e0",
    "accent_solid_hover":  "#175fd0",
    "accent_text":         "#ffffff",
    "danger":       "#ff6b63",
    "danger_bg":    "#3d1d1f",
    "warn":         "#e3b341",
    "warn_bg":      "#3a2d12",
    "success":      "#4ac364",
    "success_bg":   "#12341d",
    "neutral":      "#9198a1",
    "neutral_bg":   "#21262d",
    "selection":    "#1f3a5f",
}

LIGHT = {
    "bg":           "#f6f8fa",
    "surface":      "#ffffff",
    "surface_alt":  "#f6f8fa",
    "border":       "#d0d7de",
    "border_soft":  "#e4e8ed",
    "text":         "#1f2328",
    "text_muted":   "#5a626c",
    # In light mode one blue clears both bars, but the keys stay split so the
    # stylesheet reads identically for both themes.
    "accent":              "#0969da",
    "accent_solid":        "#0969da",
    "accent_solid_hover":  "#0860ca",
    "accent_text":         "#ffffff",
    "danger":       "#cf222e",
    "danger_bg":    "#ffebe9",
    "warn":         "#8a6100",
    "warn_bg":      "#fff8c5",
    "success":      "#1a7f37",
    "success_bg":   "#dafbe1",
    "neutral":      "#5a626c",
    "neutral_bg":   "#eaeef2",
    "selection":    "#ddf4ff",
}

PALETTES = {"dark": DARK, "light": LIGHT}
DEFAULT_MODE = "dark"


def palette(mode: str = DEFAULT_MODE) -> dict:
    """Return a palette by name, falling back to the default rather than raising."""
    return PALETTES.get(mode, PALETTES[DEFAULT_MODE])


# ── Verdict badges ──────────────────────────────────────────────────────────
# One source of truth for how a verdict looks, used by the Qt table delegate,
# the summary cards and the Tk popup. Keyed by the DISPLAY verdict returned by
# signature.display_verdict() — not the raw ML verdict.
_BADGES = {
    "MALWARE":           ("MALWARE",   "danger"),
    "POTENTIAL_ZERODAY": ("ZERO-DAY?", "warn"),
    "SAFE":              ("SAFE",      "success"),
    "ERROR":             ("ERROR",     "neutral"),
    "SIGNED_SAFE":       ("SIGNED",    "success"),
}


def badge(verdict: str, mode: str = DEFAULT_MODE) -> dict:
    """Label + colours for a verdict pill.

    Unknown verdicts degrade to a neutral badge carrying the raw string, so a
    future verdict can never render as an invisible or misleading pill.
    """
    p = palette(mode)
    label, key = _BADGES.get(verdict, (verdict or "-", "neutral"))
    return {"label": label, "fg": p[key], "bg": p[f"{key}_bg"]}


# ── Contrast helpers (used by the design tests) ─────────────────────────────
def _srgb_channel(c: float) -> float:
    return c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4


def relative_luminance(hex_color: str) -> float:
    h = hex_color.lstrip("#")
    r, g, b = (int(h[i:i + 2], 16) / 255 for i in (0, 2, 4))
    return (0.2126 * _srgb_channel(r) + 0.7152 * _srgb_channel(g)
            + 0.0722 * _srgb_channel(b))


def contrast_ratio(fg: str, bg: str) -> float:
    """WCAG 2.1 contrast ratio between two hex colours (1.0 – 21.0)."""
    a, b = relative_luminance(fg), relative_luminance(bg)
    lo, hi = sorted((a, b))
    return (hi + 0.05) / (lo + 0.05)


# ── Qt stylesheet ───────────────────────────────────────────────────────────
def stylesheet(mode: str = DEFAULT_MODE) -> str:
    """Full application QSS for the given palette."""
    p = palette(mode)
    return f"""
QWidget {{
    background: {p['bg']};
    color: {p['text']};
    font-family: "Segoe UI", "Inter", system-ui, sans-serif;
    font-size: 13px;
}}

/* Labels must not paint the page background, or every label sitting on a card
   punches a dark rectangle through it. */
QLabel {{ background: transparent; }}

/* ── Cards ─────────────────────────────────────────────────────────────── */
QFrame#Card {{
    background: {p['surface']};
    border: 1px solid {p['border']};
    border-radius: 10px;
}}
QFrame#HeaderBar {{
    background: {p['surface']};
    border: none;
    border-bottom: 1px solid {p['border']};
    border-radius: 0px;
}}
QLabel#AppTitle {{
    font-size: 17px;
    font-weight: 600;
    color: {p['text']};
}}
QLabel#AppSubtitle  {{ color: {p['text_muted']}; font-size: 11px; }}
QLabel#SectionLabel {{
    color: {p['text_muted']};
    font-size: 11px;
    font-weight: 600;
    letter-spacing: 0.6px;
}}
QLabel#StatValue {{ font-size: 26px; font-weight: 600; }}
QLabel#StatLabel {{
    color: {p['text_muted']};
    font-size: 10px;
    font-weight: 600;
    letter-spacing: 0.5px;
}}
QLabel#CurrentFile {{ color: {p['text_muted']}; font-size: 11px; }}

/* ── Inputs ────────────────────────────────────────────────────────────── */
QLineEdit {{
    background: {p['bg']};
    border: 1px solid {p['border']};
    border-radius: 8px;
    padding: 9px 12px;
    selection-background-color: {p['selection']};
}}
QLineEdit:focus  {{ border: 1px solid {p['accent']}; }}
QComboBox {{
    background: {p['surface_alt']};
    border: 1px solid {p['border']};
    border-radius: 8px;
    padding: 6px 10px;
    min-width: 130px;
}}
QComboBox:hover      {{ border: 1px solid {p['accent']}; }}
QComboBox::drop-down {{ border: none; width: 18px; }}
QComboBox QAbstractItemView {{
    background: {p['surface']};
    border: 1px solid {p['border']};
    selection-background-color: {p['selection']};
    outline: none;
}}

/* ── Buttons ───────────────────────────────────────────────────────────── */
QPushButton {{
    background: {p['surface_alt']};
    border: 1px solid {p['border']};
    border-radius: 8px;
    padding: 8px 14px;
    font-weight: 500;
}}
QPushButton:hover    {{ border: 1px solid {p['accent']}; }}
QPushButton:disabled {{ color: {p['text_muted']}; border: 1px solid {p['border_soft']}; }}
QPushButton#Primary {{
    background: {p['accent_solid']};
    color: {p['accent_text']};
    border: 1px solid {p['accent_solid']};
    font-weight: 600;
    padding: 9px 22px;
}}
QPushButton#Primary:hover {{
    background: {p['accent_solid_hover']};
    border: 1px solid {p['accent_solid_hover']};
}}
QPushButton#Primary:disabled {{
    background: {p['neutral_bg']};
    color: {p['text_muted']};
    border: 1px solid {p['border']};
}}
QPushButton#Danger {{ color: {p['warn']}; border: 1px solid {p['warn']}; }}
QPushButton#Danger:hover {{ background: {p['warn_bg']}; }}
QPushButton#IconButton {{
    padding: 6px 10px;
    border-radius: 8px;
    font-size: 14px;
}}

/* ── Toggles ───────────────────────────────────────────────────────────── */
QCheckBox {{ spacing: 8px; padding: 3px 0px; }}
QCheckBox::indicator {{
    width: 16px; height: 16px;
    border-radius: 5px;
    border: 1px solid {p['border']};
    background: {p['bg']};
}}
QCheckBox::indicator:checked {{
    background: {p['accent']};
    border: 1px solid {p['accent']};
}}
QCheckBox::indicator:hover {{ border: 1px solid {p['accent']}; }}

/* ── Table ─────────────────────────────────────────────────────────────── */
QTableWidget {{
    background: {p['surface']};
    border: 1px solid {p['border']};
    border-radius: 10px;
    gridline-color: transparent;
    outline: none;
}}
QTableWidget::item {{
    padding: 7px 10px;
    border-bottom: 1px solid {p['border_soft']};
}}
QTableWidget::item:selected {{ background: {p['selection']}; color: {p['text']}; }}
QHeaderView::section {{
    background: {p['surface_alt']};
    color: {p['text_muted']};
    border: none;
    border-bottom: 1px solid {p['border']};
    padding: 9px 10px;
    font-size: 11px;
    font-weight: 600;
}}
QTableCornerButton::section {{ background: {p['surface_alt']}; border: none; }}

/* ── Progress ──────────────────────────────────────────────────────────── */
QProgressBar {{
    background: {p['neutral_bg']};
    border: none;
    border-radius: 4px;
    height: 6px;
    text-align: center;
}}
QProgressBar::chunk {{ background: {p['accent']}; border-radius: 4px; }}

/* ── Scrollbars ────────────────────────────────────────────────────────── */
QScrollBar:vertical {{
    background: transparent; width: 10px; margin: 4px 2px 4px 0px;
}}
QScrollBar::handle:vertical {{
    background: {p['border']}; border-radius: 5px; min-height: 30px;
}}
QScrollBar::handle:vertical:hover {{ background: {p['text_muted']}; }}
QScrollBar:horizontal {{
    background: transparent; height: 10px; margin: 0px 4px 2px 4px;
}}
QScrollBar::handle:horizontal {{
    background: {p['border']}; border-radius: 5px; min-width: 30px;
}}
QScrollBar::add-line, QScrollBar::sub-line {{ height: 0px; width: 0px; }}
QScrollBar::add-page, QScrollBar::sub-page {{ background: transparent; }}

/* ── Misc ──────────────────────────────────────────────────────────────── */
QStatusBar {{
    background: {p['surface']};
    border-top: 1px solid {p['border']};
    color: {p['text_muted']};
}}
QStatusBar::item {{ border: none; }}
QToolTip {{
    background: {p['surface_alt']};
    color: {p['text']};
    border: 1px solid {p['border']};
    padding: 5px 8px;
    border-radius: 6px;
}}
QMessageBox {{ background: {p['surface']}; }}
"""
