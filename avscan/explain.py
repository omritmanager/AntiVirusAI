"""
explain.py — OPTIONAL natural-language "why" layer (Gemini API).

This is an ADD-ON, not part of the validated pipeline. After the engine has
already produced a verdict, this module can ask Google's Gemini API to explain,
in plain language, *why* a file with these characteristics looks suspicious.

Design / safety:
  * It runs AFTER the ML verdict and NEVER changes it. The core scan + hash
    lookup stay fully offline (spec §14). This is the only place that touches the
    network, and only when the user has provided a key and enabled the feature.
  * Privacy: only the VERDICT, the PROBABILITY, and ABSTRACT feature-group names
    (e.g. "byte-entropy patterns", "imported functions") are sent to Gemini —
    never the file bytes, the file name, or its path.
  * Attribution is real: it uses LightGBM SHAP contributions (pred_contrib) to
    find which EMBER feature groups pushed the decision toward "malware".
  * Fully graceful: no key / offline / API error → returns a local heuristic
    summary built from the same feature groups, so the UI always shows something.
  * stdlib only (urllib) — no new pinned dependency in the locked environment.
"""
from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request

import numpy as np

from . import config

# EMBER v2 (feature_version=2) layout — index ranges -> (short name, description).
# Offsets verified: the 9 groups sum to EXPECTED_DIM (2381).
FEATURE_GROUPS = [
    (0, 256, "byte-value distribution",
     "how raw byte values are distributed across the file"),
    (256, 512, "byte-entropy patterns",
     "randomness of the bytes — high entropy often means packed or encrypted code"),
    (512, 616, "embedded strings",
     "readable strings such as URLs, file paths and registry keys"),
    (616, 626, "general file info",
     "size and counts of imports/exports, resources, TLS and a digital signature"),
    (626, 688, "PE header fields",
     "PE/COFF header values: timestamp, target machine, characteristics, subsystem"),
    (688, 943, "section layout & entropy",
     "number of sections and their sizes and entropy"),
    (943, 2223, "imported functions / DLLs",
     "which Windows APIs and libraries the file imports"),
    (2223, 2351, "exported functions",
     "functions the file exposes to other programs"),
    (2351, 2381, "PE data directories",
     "the PE data-directory table (imports, relocations, TLS, resources, ...)"),
]

# Plain, everyday meaning of each feature group — no jargon. These are what get
# sent to Gemini (and used in the offline fallback), so the explanation stays
# understandable to a non-technical user.
_GROUP_PLAIN_HE = {
    "byte-value distribution": "הרכב התוכן של הקובץ נראה שונה מתוכנה רגילה",
    "byte-entropy patterns": "הקובץ נראה דחוס או מעורבל — דרך נפוצה שבה נוזקות מסתירות את עצמן",
    "embedded strings": "מוסתרים בקובץ טקסטים כמו כתובות אינטרנט או נתיבים",
    "general file info": "מאפיינים כלליים חשודים, למשל חוסר בחתימה דיגיטלית של יצרן מוכר",
    "PE header fields": "פרטי הזיהוי הפנימיים של הקובץ נראים לא תקינים או מזויפים",
    "section layout & entropy": "המבנה הפנימי של הקובץ בנוי בצורה לא רגילה",
    "imported functions / DLLs": "הפעולות שהקובץ מבקש לבצע במחשב נראות חריגות (כמו גישה למערכת או לרשת)",
    "exported functions": "הקובץ חושף יכולות לתוכנות אחרות בצורה חריגה",
    "PE data directories": "הארגון הפנימי של הקובץ נראה חשוד",
}
_GROUP_PLAIN_EN = {
    "byte-value distribution": "the file's contents look different from normal software",
    "byte-entropy patterns": "the file looks compressed or scrambled — a common way malware hides",
    "embedded strings": "hidden text inside the file, such as web addresses or file paths",
    "general file info": "general warning signs, e.g. it isn't signed by a known publisher",
    "PE header fields": "the file's internal ID details look wrong or faked",
    "section layout & entropy": "the file is put together in an unusual way",
    "imported functions / DLLs": "the actions the file wants to perform on your PC look unusual (e.g. system or network access)",
    "exported functions": "the file exposes capabilities to other programs in an unusual way",
    "PE data directories": "the file's internal organization looks suspicious",
}

_VERDICT_HE = {
    "MALWARE": "זדוני (נוזקה)",
    "POTENTIAL_ZERODAY": "חשוד (זיהוי חריגה — יום-0 אפשרי)",
    "SAFE": "תקין",
}


def top_feature_groups(vector, booster, top_k: int = 4):
    """Return the feature groups that pushed the decision toward malware, most
    first, as a list of (name, description, signed_contribution)."""
    X = np.asarray(vector, dtype=np.float32).reshape(1, -1)
    # pred_contrib -> per-feature SHAP contributions to the raw (log-odds) score;
    # positive contribution pushes toward the positive class (malware).
    contrib = booster.predict(X, pred_contrib=True)[0]
    out = []
    for start, end, name, desc in FEATURE_GROUPS:
        out.append((name, desc, float(contrib[start:end].sum())))
    out.sort(key=lambda r: r[2], reverse=True)
    return out[:top_k]


def local_feature_summary(groups, language: str = "he") -> str:
    """A deterministic, offline explanation in plain language, from the top
    feature groups. Used when Gemini is unavailable, so the UI is never empty."""
    positive = [g for g in groups if g[2] > 0] or groups[:2]
    if language == "he":
        reasons = "; ".join(_GROUP_PLAIN_HE.get(n, n) for n, _d, _s in positive[:3])
        return f"התוכנה סימנה את הקובץ כחשוד מהסיבות הבאות: {reasons}."
    reasons = "; ".join(_GROUP_PLAIN_EN.get(n, n) for n, _d, _s in positive[:3])
    return f"The file was flagged as suspicious because: {reasons}."


def build_prompt(verdict: str, prob: float, groups, language: str = "he") -> str:
    prob_pct = f"{prob * 100:.0f}%"
    if language == "he":
        reasons = "; ".join(_GROUP_PLAIN_HE.get(n, n) for n, _d, _s in groups) or "לא ידוע"
        return (
            "אתה עוזר שמסביר למשתמש רגיל, בלי שום רקע טכני, למה תוכנת אנטי-וירוס "
            f"סימנה קובץ כחשוד. התוכנה נתנה לקובץ ציון חשד של כ-{prob_pct}. "
            f"הסימנים שהיא מצאה, במילים פשוטות: {reasons}. "
            "כתוב תשובה בעברית פשוטה וברורה, ב-2 עד 3 משפטים קצרים, כאילו אתה מסביר "
            "לחבר שלא מבין במחשבים. אסור להשתמש במונחים טכניים (למשל: אנטרופיה, PE, "
            "sections, header, hash, וקטור). אם מזכירים רעיון טכני — יש להסביר אותו "
            "במילים של יום-יום. אל תטען בוודאות שזו נוזקה — זו רק הערכה. אל תמציא פרטים."
        )
    reasons = "; ".join(_GROUP_PLAIN_EN.get(n, n) for n, _d, _s in groups) or "unknown"
    return (
        "You are helping an ordinary, non-technical user understand why an "
        f"antivirus flagged a file as suspicious. It gave the file a suspicion "
        f"score of about {prob_pct}. The warning signs it found, in plain words: "
        f"{reasons}. Answer in 2-3 short, simple sentences, as if explaining to a "
        "friend with no computer background. Do NOT use technical terms (e.g. "
        "entropy, PE, sections, header, hash, vector); if you must mention a "
        "technical idea, explain it in everyday words. Do not claim certainty — "
        "this is only an estimate. Do not invent details."
    )


def call_gemini(prompt: str, api_key: str, model: str, timeout: int = 15) -> str | None:
    """POST the prompt to Gemini via stdlib urllib. Returns the text or None on
    any failure (network, bad key, safety block, parse error)."""
    url = config.GEMINI_ENDPOINT.format(model=model) + "?key=" + urllib.parse.quote(api_key)
    body = json.dumps({
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {"temperature": 0.3, "maxOutputTokens": 2048},
    }).encode("utf-8")
    req = urllib.request.Request(
        url, data=body, headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except Exception:
        return None
    try:
        parts = data["candidates"][0]["content"]["parts"]
        text = "".join(p.get("text", "") for p in parts).strip()
        return text or None
    except Exception:
        return None


def explain_bytes(engine, data: bytes, ml_result, *, settings: dict | None = None,
                  api_key: str | None = None) -> dict:
    """High-level entry point. Returns a dict:
        ai_explanation : str | None   (Gemini text, if it succeeded)
        summary        : str          (always present — AI text or local heuristic)
        top_groups     : list[(name, desc, contribution)]
        status         : "ok" | "disabled" | "no_key" | "no_vector" | "api_error"
    Never raises.
    """
    settings = settings or config.load_settings()
    language = settings.get("gemini_language", "he")

    result = {"ai_explanation": None, "summary": "", "top_groups": [], "status": "ok"}

    vector = engine.processed_vector(data)
    if vector is None:
        result["status"] = "no_vector"
        return result
    try:
        groups = top_feature_groups(vector, engine.lgbm.booster_, top_k=4)
    except Exception:
        groups = []
    result["top_groups"] = groups
    result["summary"] = local_feature_summary(groups, language) if groups else ""

    if not settings.get("explain_enabled", True):
        result["status"] = "disabled"
        return result
    api_key = api_key or config.get_gemini_api_key()
    if not api_key:
        result["status"] = "no_key"
        return result

    prompt = build_prompt(ml_result.ml_verdict, ml_result.lgbm_prob or 0.0, groups, language)
    text = call_gemini(prompt, api_key,
                       settings.get("gemini_model", config.DEFAULT_GEMINI_MODEL),
                       int(settings.get("gemini_timeout", 15)))
    if text:
        result["ai_explanation"] = text
        result["summary"] = text
    else:
        result["status"] = "api_error"
    return result


def status_message(status: str, language: str = "he") -> str:
    """Short human note explaining why an AI explanation is/ isn't shown."""
    if language == "he":
        return {
            "ok": "הסבר נוצר על-ידי Gemini.",
            "disabled": "שכבת ההסבר כבויה (explain_enabled=false).",
            "no_key": "לא הוגדר מפתח API ל-Gemini — מוצג ניתוח מקומי בלבד. "
                      "הגדר GEMINI_API_KEY או config/gemini_key.txt.",
            "api_error": "פנייה ל-Gemini נכשלה (רשת/מפתח) — מוצג ניתוח מקומי בלבד.",
            "no_vector": "לא ניתן היה לחלץ מאפיינים מהקובץ.",
        }.get(status, "")
    return {
        "ok": "Explanation generated by Gemini.",
        "disabled": "Explanation layer is off (explain_enabled=false).",
        "no_key": "No Gemini API key set — showing local analysis only. "
                  "Set GEMINI_API_KEY or config/gemini_key.txt.",
        "api_error": "Gemini request failed (network/key) — showing local analysis only.",
        "no_vector": "Could not extract features from the file.",
    }.get(status, "")
