"""
explain.py — OPTIONAL natural-language "why" layer (Gemini API).

This is an ADD-ON, not part of the validated pipeline. After the engine has
already produced a verdict, this module explains, in plain language, *why* a
file with these characteristics looks suspicious.

Design / safety:
  * It runs AFTER the ML verdict and NEVER changes it. The core scan + hash
    lookup stay fully offline (spec §14). This is the only place that touches the
    network, and only when the user has provided a key and enabled the feature.
  * Privacy: only the VERDICT, the PROBABILITY, AGGREGATE numeric measurements
    (entropy, section count, import count, ...), and a bounded set of generic
    Windows API / PE section names (e.g. "WriteProcessMemory", ".rsrc") are
    sent to Gemini — never the file bytes, the file name, or its path. API/
    section names are standard, publicly-documented Windows terms, not
    user data; only names matching a small curated watchlist are ever sent
    (see _SUSPICIOUS_API_CATEGORIES), not the file's full import table.
  * Attribution is real, in two independent layers:
      1. WEIGHTS  — LightGBM SHAP contributions (pred_contrib) say which EMBER
         feature groups actually pushed *this* decision toward "malware".
      2. EVIDENCE — concrete, human-checkable measurements read straight out of
         the EMBER vector at verified indices (is it signed? how many sections?
         how many imports? how random are the bytes?), PLUS a second pass over
         the raw PE structure via lief (real section names/entropy, and named
         Windows API functions when they match a small suspicious-technique
         watchlist — see extract_pe_detail()). This is what keeps the
         explanation truthful instead of generic: the model is told real facts
         and is forbidden from inventing anything beyond them.
  * Fully graceful: no key / offline / API error → returns a local explanation
    built from the same real measurements, so the UI always shows something.
  * stdlib only (urllib) — no new pinned dependency in the locked environment.

EMBER v2 index map used by extract_evidence() was verified against the installed
`ember/features.py` (feature order: ByteHistogram 256, ByteEntropyHistogram 256,
StringExtractor 104, GeneralFileInfo 10, HeaderFileInfo 62, SectionInfo 255,
ImportsInfo 1280, ExportsInfo 128, DataDirectories 30 = 2381).
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

# ── Verified scalar indices (see module docstring) ───────────────────────────
# StringExtractor block (512..616): numstrings, avlength, printables,
# printabledist[96], entropy, paths, urls, registry, MZ
I_NUMSTRINGS, I_AVLENGTH, I_PRINTABLES = 512, 513, 514
I_STR_ENTROPY, I_PATHS, I_URLS, I_REGISTRY, I_MZ = 611, 612, 613, 614, 615
# GeneralFileInfo block (616..626)
I_SIZE, I_VSIZE, I_HAS_DEBUG, I_EXPORTS, I_IMPORTS = 616, 617, 618, 619, 620
I_HAS_RELOC, I_HAS_RESOURCES, I_HAS_SIGNATURE, I_HAS_TLS, I_SYMBOLS = 621, 622, 623, 624, 625
# SectionInfo block (688..943): first 5 are plain counts
I_NUM_SECTIONS, I_ZERO_SIZE_SECTIONS, I_EMPTY_NAME_SECTIONS = 688, 689, 690
I_RX_SECTIONS, I_W_SECTIONS = 691, 692

# Plain, everyday meaning of each feature group — no jargon. Used to label the
# model's own weighting when no concrete measurement is available for a group.
_GROUP_PLAIN_HE = {
    "byte-value distribution": "הרכב התוכן הגולמי של הקובץ",
    "byte-entropy patterns": "מידת ה'ערבול' של התוכן (סימן לדחיסה/הצפנה)",
    "embedded strings": "הטקסטים המוסתרים בתוך הקובץ",
    "general file info": "מאפייני היסוד של הקובץ (חתימה, ייבוא/ייצוא, משאבים)",
    "PE header fields": "פרטי הכותרת הפנימית של הקובץ",
    "section layout & entropy": "אופן חלוקת הקובץ לאזורים פנימיים",
    "imported functions / DLLs": "הפעולות שהקובץ מבקש לבצע במערכת",
    "exported functions": "היכולות שהקובץ חושף לתוכנות אחרות",
    "PE data directories": "טבלאות הארגון הפנימיות של הקובץ",
}
_GROUP_PLAIN_EN = {
    "byte-value distribution": "the raw make-up of the file's contents",
    "byte-entropy patterns": "how scrambled the contents are (a sign of packing/encryption)",
    "embedded strings": "the text hidden inside the file",
    "general file info": "the file's basic properties (signature, imports/exports, resources)",
    "PE header fields": "the file's internal header details",
    "section layout & entropy": "how the file is split into internal regions",
    "imported functions / DLLs": "the actions the file asks to perform on the system",
    "exported functions": "the capabilities the file exposes to other programs",
    "PE data directories": "the file's internal organisation tables",
}


# ─────────────────────────────────────────────────────────────────────────────
# Layer 1 — model attribution (which groups drove THIS decision)
# ─────────────────────────────────────────────────────────────────────────────
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


def group_weights(groups) -> list[tuple[str, str, float, int]]:
    """Attach a relative share (%) to each group, computed over the POSITIVE
    (toward-malware) contributions only. Returns (name, desc, contrib, pct)."""
    positive = [g for g in groups if g[2] > 0]
    total = sum(g[2] for g in positive)
    out = []
    for name, desc, contrib in groups:
        pct = int(round(100.0 * contrib / total)) if (total > 0 and contrib > 0) else 0
        out.append((name, desc, contrib, pct))
    return out


# ─────────────────────────────────────────────────────────────────────────────
# Layer 2 — concrete evidence (real measurements, human-checkable)
# ─────────────────────────────────────────────────────────────────────────────
def shannon_entropy(data: bytes) -> float:
    """Shannon entropy of the raw bytes, 0..8. ~8.0 = indistinguishable from
    random (packed/encrypted); ordinary compiled code is typically ~5.5-6.8."""
    if not data:
        return 0.0
    counts = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
    probs = counts[counts > 0] / len(data)
    return float(-(probs * np.log2(probs)).sum())


def _he_count(n: int, one: str, many: str) -> str:
    """Hebrew count phrasing: '1 פעולות' is wrong, 'פעולה אחת' is right."""
    return one if n == 1 else f"{n} {many}"


def _fmt_size(num_bytes: float) -> str:
    n = float(num_bytes)
    for unit in ("B", "KB", "MB", "GB"):
        # The loop always returns by its last ("GB") iteration, since that
        # iteration's own condition is unconditionally true.
        if n < 1024 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024


# ─────────────────────────────────────────────────────────────────────────────
# Layer 3 — real PE structure (section names/entropy, named API functions)
# ─────────────────────────────────────────────────────────────────────────────
# A small, deliberately conservative watchlist of Windows API functions whose
# CO-OCCURRENCE is a specific, well-known technique signature — not a single
# import in isolation. Two design rules keep this from reintroducing the exact
# shortcut-learning bias this project has already spent real effort removing
# (see avscan/signature.py's docstring on the Go-binary false-positive class):
#   1. Every category requires >= MIN_MATCH names from the SAME category to
#      actually be present, not just one. A single WriteProcessMemory call is
#      extremely common in ordinary software; the specific combination with
#      VirtualAllocEx and CreateRemoteThread is not.
#   2. Categories describing something nearly every modern toolchain does
#      legitimately are deliberately EXCLUDED: dynamic API resolution
#      (LoadLibrary+GetProcAddress) and plain network access (InternetOpen /
#      HttpSendRequest) are exactly the patterns that caused the Go-binary
#      false positive this project already fixed at the signature-verification
#      layer — flagging them here as "suspicious" would fight that fix.
# Names are real, public Win32 API identifiers (never invented).
_SUSPICIOUS_API_CATEGORIES = {
    "process_injection": {
        "min_match": 2,
        "he": "פעולות הזרקת קוד לתהליך אחר",
        "en": "code-injection into another running process",
        "names": {"CreateRemoteThread", "CreateRemoteThreadEx", "WriteProcessMemory",
                  "VirtualAllocEx", "NtUnmapViewOfSection", "QueueUserAPC",
                  "SetThreadContext", "NtCreateThreadEx", "RtlCreateUserThread"},
    },
    "anti_debug": {
        "min_match": 1,
        "he": "בדיקות אם הקובץ מנותח או מנופה (אנטי-דיבאג)",
        "en": "checks for whether the file is being analysed/debugged (anti-debug)",
        "names": {"IsDebuggerPresent", "CheckRemoteDebuggerPresent",
                  "NtQueryInformationProcess", "OutputDebugStringA",
                  "OutputDebugStringW", "NtSetInformationThread"},
    },
    "input_capture": {
        "min_match": 2,
        "he": "מעקב אחר הקשות מקלדת",
        "en": "keystroke monitoring",
        "names": {"GetAsyncKeyState", "GetKeyState", "GetKeyboardState",
                  "SetWindowsHookExA", "SetWindowsHookExW"},
    },
    "credential_access": {
        "min_match": 1,
        "he": "קריאת סיסמאות/אישורים שמורים של המשתמש",
        "en": "reading the user's saved passwords/credentials",
        "names": {"CryptUnprotectData", "LsaRetrievePrivateData",
                  "CredEnumerateA", "CredEnumerateW", "CredReadA", "CredReadW"},
    },
}

# Section names strongly associated with known packers/protectors. Presence
# alone is a real (if imperfect) structural fact — it does not claim malice.
_PACKER_SECTION_NAMES = {
    "UPX0", "UPX1", "UPX2", ".ASPACK", ".ADATA", ".PACKED", ".NSP0", ".NSP1",
    ".NSP2", ".PERPLEX", ".VMP0", ".VMP1", "KKRUNCHY", ".PETITE",
}


def extract_pe_detail(data: bytes) -> dict:
    """Re-parse the raw PE structure (independent of the EMBER vector) for
    facts too specific to survive EMBER's hashing: real section names and
    per-section entropy, and named API functions when they match
    _SUSPICIOUS_API_CATEGORIES.

    Never raises — returns {} on any failure (corrupt file, non-PE, parse
    error), matching every other function in this module's failure contract.
    """
    try:
        import lief
        binary = lief.PE.parse(data)
        if binary is None:
            return {}

        sections = [{"name": (s.name or "").strip("\x00"), "size": int(s.size),
                    "entropy": float(s.entropy)} for s in binary.sections]

        imported = set()
        for imp in binary.imports:
            for entry in imp.entries:
                if entry.name:
                    imported.add(entry.name)

        matched_categories = {}
        for key, cat in _SUSPICIOUS_API_CATEGORIES.items():
            hit = sorted(imported & cat["names"])
            if len(hit) >= cat["min_match"]:
                matched_categories[key] = hit

        return {"sections": sections, "matched_categories": matched_categories}
    except Exception:
        return {}


def extract_evidence(vector, data: bytes | None = None) -> list[dict]:
    """Read real, interpretable measurements out of the EMBER vector (and the
    raw bytes, for whole-file entropy) and turn each into a checkable fact.

    Each item: {key, he, en, suspicious(bool), group}. `suspicious` marks facts
    that deviate from what ordinary, legitimately-built software looks like —
    it is a plain-language flag for the reader, NOT part of the verdict.
    Never raises; returns [] if the vector is unusable.
    """
    ev: list[dict] = []
    try:
        v = np.asarray(vector, dtype=np.float64).ravel()
        if v.shape[0] != config.EXPECTED_DIM:
            return []
    except Exception:
        return []

    def add(key, he, en, suspicious, group):
        ev.append({"key": key, "he": he, "en": en,
                   "suspicious": bool(suspicious), "group": group})

    # Independent second pass over the raw PE structure (real section names,
    # named API functions) — see extract_pe_detail()'s own docstring for why
    # this exists alongside the EMBER vector rather than replacing it.
    pe_detail = extract_pe_detail(data) if data else {}

    # -- whole-file entropy (computed from the actual bytes: most reliable) ----
    if data:
        h = shannon_entropy(data)
        packed = h >= 7.0
        add("entropy",
            f"רמת ה'ערבול' של התוכן היא {h:.2f} מתוך 8 "
            + ("— גבוה מאוד, אופייני לקובץ דחוס/מוצפן שמסתיר את תוכנו"
               if packed else "— טווח רגיל לתוכנה מהודרת"),
            f"content randomness is {h:.2f} out of 8 "
            + ("— very high, typical of a packed/encrypted file hiding its contents"
               if packed else "— a normal range for compiled software"),
            packed, "byte-entropy patterns")

    # -- digital signature ----------------------------------------------------
    # ACCURACY NOTE: EMBER's has_signature comes from LIEF and detects only an
    # EMBEDDED Authenticode certificate. Windows also signs many legitimate
    # system files through a separate system catalog (verified: notepad.exe has
    # no embedded cert yet is validly catalog-signed). So "no embedded
    # signature" must NEVER be stated as "unsigned" — the caveat travels with
    # the fact so neither the AI nor the local fallback can overstate it.
    has_sig = v[I_HAS_SIGNATURE] > 0
    add("signature",
        "הקובץ נושא חתימה דיגיטלית מוטבעת של יצרן (תקפות החתימה לא נבדקה)" if has_sig
        else "לקובץ אין חתימה דיגיטלית מוטבעת (הערה: חלק מתוכנות Windows הלגיטימיות "
             "חתומות דרך קטלוג מערכת נפרד, ולכן זה כשלעצמו אינו הוכחה לבעיה)",
        "the file carries an embedded publisher signature (validity not verified)" if has_sig
        else "the file has no embedded digital signature (note: some legitimate Windows "
             "programs are signed via a separate system catalog, so this alone is not proof "
             "of a problem)",
        not has_sig, "general file info")

    # -- imports: what the file asks the OS to do ----------------------------
    imports = int(v[I_IMPORTS])
    few_imports = imports < 15
    add("imports",
        "הקובץ מבקש " + _he_count(imports, "פעולת מערכת אחת בלבד", "פעולות מערכת")
        + (" — מעט חריג, סימן אפשרי לכך שרשימת הפעולות האמיתית מוסתרת"
           if few_imports else ""),
        f"the file requests {imports} system operation{'s' if imports != 1 else ''}"
        + (" — unusually few, a possible sign the real list is hidden"
           if few_imports else ""),
        few_imports, "imported functions / DLLs")

    # -- named suspicious API combinations (real functions, from lief) -------
    # Deliberately factual/structural phrasing ("imports these functions,
    # commonly used together for X") rather than a behavioural claim ("this
    # file does X") — build_prompt's rule 3 forbids the latter, and this
    # wording is what keeps the evidence item consistent with that rule.
    for cat_key, matches in pe_detail.get("matched_categories", {}).items():
        cat = _SUSPICIOUS_API_CATEGORIES[cat_key]
        names = ", ".join(matches)
        add(f"api_{cat_key}",
            f"הקובץ מייבא פונקציות Windows שמשמשות יחד בדרך כלל ל{cat['he']}: {names}",
            f"the file imports Windows functions commonly used together for "
            f"{cat['en']}: {names}",
            True, "imported functions / DLLs")

    # -- section layout ------------------------------------------------------
    nsec = int(v[I_NUM_SECTIONS])
    zero_sec = int(v[I_ZERO_SIZE_SECTIONS])
    noname_sec = int(v[I_EMPTY_NAME_SECTIONS])
    real_sections = pe_detail.get("sections") or []
    packer_names = sorted({s["name"] for s in real_sections
                           if s["name"].upper() in _PACKER_SECTION_NAMES})
    odd_sections = (zero_sec > 0 or noname_sec > 0 or nsec == 0 or nsec > 8
                    or bool(packer_names))
    detail_he, detail_en = [], []
    if zero_sec:
        detail_he.append(f"{zero_sec} מהם ריקים לגמרי")
        detail_en.append(f"{zero_sec} of them completely empty")
    if noname_sec:
        detail_he.append(f"{noname_sec} ללא שם")
        detail_en.append(f"{noname_sec} unnamed")
    if packer_names:
        detail_he.append("בשם האופייני לכלי דחיסה/הסתרה (" + ", ".join(packer_names) + ")")
        detail_en.append("named after a known packer/protector tool (" + ", ".join(packer_names) + ")")
    elif real_sections:
        # Real names are far more concrete than a bare count, and cost
        # nothing extra since extract_pe_detail() already parsed them.
        names_str = ", ".join(s["name"] for s in real_sections if s["name"])
        if names_str:
            detail_he.append(f"בשמות: {names_str}")
            detail_en.append(f"named: {names_str}")
    add("sections",
        ("הקובץ מחולק לאזור פנימי אחד" if nsec == 1
         else f"הקובץ מחולק ל-{nsec} אזורים פנימיים")
        + (" (" + ", ".join(detail_he) + ")" if detail_he else "")
        + (" — חלוקה לא שגרתית" if odd_sections else " — מבנה תקני"),
        f"the file is split into {nsec} internal region{'s' if nsec != 1 else ''}"
        + (" (" + ", ".join(detail_en) + ")" if detail_en else "")
        + (" — an unusual layout" if odd_sections else " — a standard structure"),
        odd_sections, "section layout & entropy")

    # -- localized packing: one region far more compressed than the rest ----
    # Whole-file entropy blends everything together and can look "normal" even
    # when a single embedded payload is packed — this catches that case with a
    # real, named section instead of a diluted average.
    if data and real_sections:
        whole_file_h = shannon_entropy(data)
        hottest = max(real_sections, key=lambda s: s["entropy"], default=None)
        if hottest and hottest["entropy"] >= 7.5 and hottest["entropy"] - whole_file_h >= 1.0:
            add("section_entropy",
                f"האזור בשם \"{hottest['name']}\" דחוס/מוצפן במיוחד "
                f"(רמת ערבול {hottest['entropy']:.1f} מתוך 8), יותר מהממוצע בקובץ כולו",
                f"the region named \"{hottest['name']}\" is unusually compressed/encrypted "
                f"(randomness {hottest['entropy']:.1f} out of 8), higher than the file's overall average",
                True, "section layout & entropy")

    # -- embedded strings: URLs / registry keys ------------------------------
    # Reported as CONTEXT, not as an accusation: ordinary software routinely
    # contains URLs and registry keys, so flagging them as suspicious would cry
    # wolf and is precisely what makes an explanation feel fake.
    urls = int(v[I_URLS])
    registry = int(v[I_REGISTRY])
    if urls or registry:
        bits_he, bits_en = [], []
        if urls:
            bits_he.append(_he_count(urls, "כתובת אינטרנט אחת", "כתובות אינטרנט"))
            bits_en.append(f"{urls} web address{'es' if urls != 1 else ''}")
        if registry:
            bits_he.append(_he_count(registry, "מפתח רישום (Registry) אחד של Windows",
                                     "מפתחות רישום (Registry) של Windows"))
            bits_en.append(f"{registry} Windows Registry key{'s' if registry != 1 else ''}")
        add("strings",
            "בתוך הקובץ מוטמעים " + " ו-".join(bits_he),
            "embedded inside the file: " + " and ".join(bits_en),
            False, "embedded strings")

    # -- resources / TLS -----------------------------------------------------
    if v[I_HAS_TLS] > 0:
        add("tls",
            "הקובץ מריץ קוד עוד לפני שהתוכנית מתחילה רשמית (TLS) — "
            "טכניקה לגיטימית שנוזקות גם משתמשות בה כדי להתחמק מבדיקה",
            "the file runs code before the program officially starts (TLS) — "
            "a legitimate technique also used by malware to evade inspection",
            True, "PE data directories")

    # -- size ----------------------------------------------------------------
    size = v[I_SIZE] if v[I_SIZE] > 0 else (len(data) if data else 0)
    if size:
        add("size", f"גודל הקובץ: {_fmt_size(size)}",
            f"file size: {_fmt_size(size)}", False, "general file info")

    return ev


# ─────────────────────────────────────────────────────────────────────────────
# Offline explanation (used whenever Gemini is unavailable)
# ─────────────────────────────────────────────────────────────────────────────
def local_feature_summary(groups, language: str = "he", evidence=None,
                          verdict: str = "", prob: float | None = None,
                          signature_status: str | None = None,
                          signature_signer: str | None = None) -> str:
    """A deterministic, offline explanation built from the SAME real
    measurements the AI layer gets, so the UI is never empty and never vague."""
    evidence = evidence or []
    # Suspicious findings first, then neutral context to fill out the picture —
    # so the user sees what actually stood out AND what the file plainly is.
    suspicious = [e for e in evidence if e["suspicious"]]
    context = [e for e in evidence if not e["suspicious"]]
    shown = (suspicious + context)[:4]
    he = language == "he"

    # A valid signature leads, even offline — it is the strongest counter-signal.
    trusted_he = trusted_en = ""
    if signature_status == "TRUSTED":
        who = signature_signer or "יצרן מאומת"
        trusted_he = (f"⚠ ככל הנראה אזעקת שווא: הקובץ חתום דיגיטלית בתוקף על ידי \"{who}\", "
                      "והחתימה אומתה מול Windows. הקובץ לא הועבר להסגר.\n\n")
        trusted_en = (f'LIKELY FALSE ALARM: the file is validly signed by "{signature_signer or "a verified publisher"}", '
                      "verified against Windows' trust store. It was not quarantined.\n\n")

    if he:
        if prob is not None:
            head = f"המנוע נתן לקובץ ציון חשד של {prob * 100:.0f}% (הסף לחסימה: {config.LGBM_THRESHOLD * 100:.0f}%)."
        else:
            head = "הקובץ סומן כחשוד."
        if shown:
            lines = "\n".join("• " + e["he"] for e in shown)
            return trusted_he + f"{head}\n\nמה נמצא בקובץ עצמו:\n{lines}"
        if groups:
            top = _GROUP_PLAIN_HE.get(groups[0][0], groups[0][0])
            return trusted_he + f"{head}\n\nהגורם המשמעותי ביותר בהחלטה היה {top}."
        return trusted_he + head

    if prob is not None:
        head = f"The engine gave this file a suspicion score of {prob * 100:.0f}% (blocking threshold: {config.LGBM_THRESHOLD * 100:.0f}%)."
    else:
        head = "The file was flagged as suspicious."
    if shown:
        lines = "\n".join("- " + e["en"] for e in shown)
        return trusted_en + f"{head}\n\nWhat was found in the file itself:\n{lines}"
    if groups:
        top = _GROUP_PLAIN_EN.get(groups[0][0], groups[0][0])
        return trusted_en + f"{head}\n\nThe biggest single factor in the decision was {top}."
    return trusted_en + head


# ─────────────────────────────────────────────────────────────────────────────
# Prompt construction
# ─────────────────────────────────────────────────────────────────────────────
def rank_evidence(evidence, groups):
    """Order measurements by how much their feature group actually drove THIS
    decision (SHAP), and split them into standout findings vs. neutral context.

    Ranking by real attribution is what makes the explanation specific to the
    file instead of a checklist. Crucially the caller is given ONLY the ordered
    measurements — never the raw percentages — because a model shown a bare
    group weight will happily reprint it as if it were a measurement (observed
    live: a 75% SHAP share was echoed to the user as "randomness is 75%").
    """
    order = {name: i for i, (name, _d, _c, _p) in enumerate(group_weights(groups))}
    fallback = len(order)
    ranked = sorted(evidence, key=lambda e: order.get(e["group"], fallback))
    return ([e for e in ranked if e["suspicious"]],
            [e for e in ranked if not e["suspicious"]])


def build_prompt(verdict: str, prob: float, groups, language: str = "he",
                 evidence=None, hash_verdict: str | None = None,
                 quarantined: bool = False, signature_status: str | None = None,
                 signature_signer: str | None = None) -> str:
    """Build a STRICTLY GROUNDED prompt.

    Every line the model can see is a real measurement taken from this file,
    ordered by real SHAP attribution. There are deliberately NO abstract
    feature-group labels and NO internal percentages in the prompt: those are
    what a model reaches for when it has nothing concrete to say, and they are
    what made earlier output sound authoritative but invented.
    """
    evidence = evidence or []
    prob_pct = f"{prob * 100:.0f}%"
    thr_pct = f"{config.LGBM_THRESHOLD * 100:.0f}%"
    he = language == "he"
    lang_key = "he" if he else "en"

    standout, context = rank_evidence(evidence, groups)
    if he:
        findings = "\n".join(f"- {e[lang_key]}" for e in standout) or \
            "- (לא נמצא אף מאפיין חריג בודד; ההחלטה נובעת מצירוף המאפיינים בכללותו)"
        background = "\n".join(f"- {e[lang_key]}" for e in context) or "- (אין)"
    else:
        findings = "\n".join(f"- {e[lang_key]}" for e in standout) or \
            "- (no single unusual property stood out; the decision came from the overall combination)"
        background = "\n".join(f"- {e[lang_key]}" for e in context) or "- (none)"

    # Authenticode result. A valid signature is the strongest counter-evidence
    # available offline, so it is stated up front as a fact the answer must
    # weigh — not buried among the structural measurements.
    sig_he = sig_en = ""
    if signature_status == "TRUSTED":
        who_he = signature_signer or "יצרן מאומת"
        sig_he = ("\nעובדה חשובה נגד החשד: הקובץ חתום דיגיטלית בתוקף על ידי "
                  f"\"{who_he}\", והחתימה אומתה מול מאגר האמון של Windows. "
                  "לנוזקות אמיתיות כמעט אף פעם אין חתימה תקפה של יצרן מזוהה, "
                  "ולכן סביר מאוד שזו אזעקת שווא. הקובץ לא הועבר להסגר בגלל זה.")
        sig_en = ("\nIMPORTANT COUNTER-EVIDENCE: the file is validly signed by "
                  f"\"{signature_signer or 'a verified publisher'}\" and the signature was "
                  "verified against Windows' trust store. Real malware almost never carries "
                  "a valid signature from an identifiable publisher, so this is very likely a "
                  "false alarm. The file was not quarantined for this reason.")
    elif signature_status == "UNTRUSTED":
        sig_he = ("\nעובדה: לקובץ יש חתימה דיגיטלית אך היא אינה תקפה "
                  "(פגה, שונתה, או שאינה מגיעה מגורם מהימן) — זהו סימן מדאיג.")
        sig_en = ("\nFACT: the file has a digital signature but it is NOT valid "
                  "(expired, altered, or not from a trusted issuer) — this is a worrying sign.")
    elif signature_status == "UNSIGNED":
        sig_he = ("\nעובדה: לקובץ אין חתימה דיגיטלית מוטבעת. זה נפוץ גם בתוכנות "
                  "לגיטימיות קטנות, ולכן אינו הוכחה לבעיה בפני עצמו.")
        sig_en = ("\nFACT: the file has no embedded digital signature. This is common in "
                  "small legitimate programs too, so on its own it is not proof of a problem.")

    hash_line_he = hash_line_en = ""
    if hash_verdict == "KNOWN_MALWARE":
        hash_line_he = ("\nעובדה ודאית: טביעת האצבע (SHA-256) של הקובץ הזה נמצאת "
                        "במאגר נוזקות מוכרות. זו התאמה מדויקת, לא הערכה סטטיסטית.")
        hash_line_en = ("\nCERTAIN FACT: this file's SHA-256 fingerprint appears in the "
                        "known-malware database. That is an exact match, not a statistical estimate.")
    elif hash_verdict == "NOT_IN_DB":
        hash_line_he = ("\nעובדה: טביעת האצבע של הקובץ אינה מופיעה במאגר הנוזקות המוכרות — "
                        "כלומר הזיהוי מבוסס על התנהגות ומבנה בלבד, לא על נוזקה מוכרת.")
        hash_line_en = ("\nFACT: the file's fingerprint is NOT in the known-malware database — "
                        "so this detection is based on structure/behaviour alone, not on a known sample.")

    if he:
        verdict_he = {
            "MALWARE": f"המנוע סיווג את הקובץ כזדוני. ציון החשד: {prob_pct}, "
                       f"כאשר הסף לחסימה הוא {thr_pct}.",
        }.get(verdict, f"המנוע סימן את הקובץ כחשוד (ציון {prob_pct}).")
        action_he = ("הקובץ כבר הועבר לבידוד (הסגר) ואינו יכול לרוץ."
                     if quarantined else
                     "הקובץ לא הועבר לבידוד — הוא רק סומן לתשומת ליבך ועדיין נמצא במקומו.")
        # A flagged file is not always quarantined (e.g. a trusted signature
        # skips the action): the wording must not claim something was blocked
        # when it wasn't.
        headline_he = "נחסם" if quarantined else "סומן"
        return f"""אתה מסביר למשתמש ביתי, ללא רקע טכני, למה תוכנת אנטי-וירוס {headline_he} לו קובץ. המשתמש מודאג ורוצה תשובה כנה וברורה.

## הנתונים על הקובץ הזה
{verdict_he}{hash_line_he}{sig_he}
{action_he}

מאפיינים חריגים שנמדדו בקובץ (מסודרים לפי מידת ההשפעה שלהם על ההחלטה, החשוב ביותר ראשון):
{findings}

נתוני רקע על הקובץ (עובדות נכונות, אך אינן חשודות כשלעצמן):
{background}

## חוקים מחייבים
1. השתמש אך ורק בנתונים שלמעלה. אל תוסיף שום עובדה שלא מופיעה שם.
2. כל מספר שאתה כותב חייב להופיע ככתבו ברשימות שלמעלה. אסור לחשב, להעריך או להמציא מספרים. אם לא נמדד משהו — אל תזכיר אותו בכלל.
3. אסור בהחלט להמציא: שם של וירוס/משפחת נוזקות, מה הקובץ "עושה" (גונב סיסמאות, מצפין קבצים, מרגל), מאיפה הוא הגיע, או מתי נוצר. אנחנו לא יודעים את זה — המנוע ניתח את מבנה הקובץ, לא את התנהגותו בפועל.
3א. אם מופיעה עובדה על פונקציות מערכת ספציפיות שהקובץ מייבא יחד (למשל "הזרקת קוד") — זו עובדה מבנית בלבד: הקובץ מייבא את הפונקציות האלה, זה הכול. תאר זאת כ"הקובץ מייבא פונקציות שמשמשות בדרך כלל ל..." ולעולם לא כ"הקובץ מבצע..." או "הקובץ הוא...". מותר לצטט את שמות הפונקציות עצמן כפי שהן (הן אינן מונח טכני אסור לפי כלל 7), אך אסור להרחיב מעבר לעובדה שיובאו.
4. בנה את ההסבר מהרשימה "מאפיינים חריגים", לפי הסדר שבה. השתמש ב"נתוני רקע" רק אם צריך להשלים תמונה — ואל תציג נתון רקע כאילו הוא סיבה לחשד.
5. היה כן לגבי אי-ודאות: זהו מודל סטטיסטי. אם אין התאמה במאגר הנוזקות, אמור במפורש שזו הערכה ושייתכן שמדובר בזיהוי שגוי — במיוחד אם המשתמש הוריד את הקובץ מאתר רשמי (מתקינים ותוכנות דחוסות מזוהים לפעמים בטעות).
5א. אם צוינה חתימה דיגיטלית תקפה — זו העובדה החשובה ביותר בתשובה. פתח בה, אמור בבירור שסביר שזו אזעקת שווא, ונקוב בשם היצרן. אל תקבור אותה בסוף ואל תסתור אותה.
6. אם מדידה מגיעה עם הסתייגות (למשל שחתימה חסרה אינה הוכחה לבעיה) — שמור על ההסתייגות, אל תשמיט אותה.
7. בלי מונחים טכניים. אסור: אנטרופיה, PE, section, header, hash, API, TLS, וקטור, SHA-256, כותרת. במקומם — מילים יומיומיות ("מידת הערבול של התוכן", "אזורים פנימיים", "טביעת אצבע דיגיטלית", "פעולות שהקובץ מבקש מהמערכת"). שמות פונקציות/אזורים קונקרטיים שמופיעים ברשימות למעלה (למשל WriteProcessMemory, UPX0) מותר לצטט כלשונם — הם אינם מהמונחים האסורים.
8. אל תיתן הוראות טכניות מסוכנות. אסור להבטיח שהמחשב "מוגן", "נקי" או "נגוע" — בידוד של קובץ אחד לא אומר שהמחשב כולו בטוח. דבר על הקובץ הזה בלבד.

## פורמט התשובה (בעברית, קצר)
שורה ראשונה: משפט אחד שמסביר מה קרה ובאיזו רמת ודאות.
אחריה הכותרת "למה זה {headline_he}:" ומתחתיה 2-4 נקודות תבליט (•), כל אחת משפט אחד המבוסס על מאפיין מהרשימה, כולל המספר שנמדד.
לסיום הכותרת "מה כדאי לעשות:" ומשפט אחד עם המלצה מעשית.
סה"כ עד 90 מילים. בלי מבוא, בלי סיכום, בלי אמוג'י."""

    verdict_en = {
        "MALWARE": f"The engine classified the file as malicious. Suspicion score: {prob_pct}, "
                   f"where the blocking threshold is {thr_pct}.",
    }.get(verdict, f"The engine flagged the file as suspicious (score {prob_pct}).")
    action_en = ("The file has already been moved to quarantine and cannot run."
                 if quarantined else
                 "The file was NOT quarantined — it was only flagged for your attention "
                 "and is still in place.")
    headline_en = "blocked" if quarantined else "flagged"
    return f"""You are explaining to a home user with no technical background why their antivirus {headline_en} a file. They are worried and want an honest, clear answer.

## Data about this file
{verdict_en}{hash_line_en}{sig_en}
{action_en}

Unusual properties measured in the file (ordered by how much they influenced the decision, most important first):
{findings}

Background facts about the file (true, but not suspicious in themselves):
{background}

## Binding rules
1. Use ONLY the data above. Do not add any fact that is not there.
2. Every number you write must appear verbatim in the lists above. Do not compute, estimate or invent numbers. If something was not measured, do not mention it at all.
3. Absolutely do NOT invent: a virus/malware family name, what the file "does" (steals passwords, encrypts files, spies), where it came from, or when it was made. We do not know these — the engine analysed the file's structure, not its actual behaviour.
3a. If a fact lists specific system functions imported together (e.g. for "code injection"), that is a structural fact only: the file imports these functions, nothing more. Phrase it as "the file imports functions commonly used for ..." and NEVER as "the file performs ..." or "the file is a ...". You may quote the function names themselves verbatim (they are not banned jargon under rule 7), but do not extend beyond the fact that they were imported.
4. Build the explanation from the "Unusual properties" list, in that order. Use "Background facts" only to round out the picture — never present a background fact as a reason for suspicion.
5. Be honest about uncertainty: this is a statistical model. If there is no known-malware database match, say plainly that this is an estimate and could be a false alarm — especially if the user downloaded the file from an official site (installers and compressed programs are sometimes misidentified).
5a. If a valid digital signature is stated, that is the single most important fact in your answer. Lead with it, say plainly that this is likely a false alarm, and name the publisher. Do not bury it at the end and do not contradict it.
6. If a measurement comes with a caveat (e.g. that a missing signature is not proof of a problem), keep the caveat — do not drop it.
7. No technical jargon. Banned: entropy, PE, section, header, hash, API, TLS, vector, SHA-256. Use everyday words instead ("how scrambled the contents are", "internal regions", "digital fingerprint", "actions the file asks the system to perform"). Concrete function/region names that appear in the lists above (e.g. WriteProcessMemory, UPX0) may be quoted verbatim — they are not among the banned terms.
8. Do not give dangerous technical instructions. Never promise the computer is "protected", "clean" or "infected" — quarantining one file does not make the whole machine safe. Talk about this file only.

## Response format (short)
First line: one sentence saying what happened and how certain it is.
Then the heading "Why it was {headline_en}:" followed by 2-4 bullet points (-), each one sentence based on a property from the list, including the measured number.
End with the heading "What to do:" and one sentence of practical advice.
Max 90 words total. No preamble, no summary, no emoji."""


# ─────────────────────────────────────────────────────────────────────────────
# Gemini call
# ─────────────────────────────────────────────────────────────────────────────
def _post_gemini(prompt: str, api_key: str, model: str, gen_config: dict,
                 timeout: int) -> tuple[str | None, str | None]:
    """One API round-trip. Returns (text, finish_reason); (None, None) on failure."""
    url = config.GEMINI_ENDPOINT.format(model=model) + "?key=" + urllib.parse.quote(api_key)
    body = json.dumps({
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": gen_config,
    }).encode("utf-8")
    req = urllib.request.Request(
        url, data=body, headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except Exception:
        return None, None
    try:
        cand = data["candidates"][0]
        parts = cand.get("content", {}).get("parts", [])
        text = "".join(p.get("text", "") for p in parts).strip()
        return (text or None), cand.get("finishReason")
    except Exception:
        return None, None


def call_gemini(prompt: str, api_key: str, model: str, timeout: int = 15) -> str | None:
    """POST the prompt to Gemini via stdlib urllib. Returns the text or None on
    any failure (network, bad key, safety block, parse error).

    Thinking is DISABLED on purpose. Measured on gemini-2.5-flash with this
    prompt: with thinking on, internal reasoning consumed 1961 of a 2048-token
    budget, leaving 83 tokens for the answer -> finishReason=MAX_TOKENS and a
    reply cut off mid-sentence. This task is a faithful restatement of facts we
    already computed, so it needs no reasoning budget; disabling it yields a
    complete answer at roughly a third of the tokens.

    Older models reject `thinkingConfig`, so a rejected request is retried once
    without it (with a larger cap, to survive the thinking overhead).
    """
    # Low temperature: faithful restatement of measured facts, not creative writing.
    base = {"temperature": 0.2, "maxOutputTokens": 1024}
    text, finish = _post_gemini(
        prompt, api_key, model, {**base, "thinkingConfig": {"thinkingBudget": 0}}, timeout)
    if text and finish != "MAX_TOKENS":
        return text
    # Retry path: model does not support thinkingConfig (or the reply was cut).
    # Give it enough headroom that thinking cannot starve the answer.
    retry, finish2 = _post_gemini(
        prompt, api_key, model, {**base, "maxOutputTokens": 4096}, timeout)
    return retry or text


# ─────────────────────────────────────────────────────────────────────────────
# High-level entry point
# ─────────────────────────────────────────────────────────────────────────────
def explain_bytes(engine, data: bytes, ml_result, *, settings: dict | None = None,
                  api_key: str | None = None, hash_verdict: str | None = None,
                  quarantined: bool = False, signature_status: str | None = None,
                  signature_signer: str | None = None) -> dict:
    """High-level entry point. Returns a dict:
        ai_explanation : str | None   (Gemini text, if it succeeded)
        summary        : str          (always present — AI text or local analysis)
        top_groups     : list[(name, desc, contribution)]
        evidence       : list[dict]   (the concrete measurements)
        status         : "ok" | "disabled" | "no_key" | "no_vector" | "api_error"
    Never raises.
    """
    settings = settings or config.load_settings()
    language = settings.get("gemini_language", "he")

    result = {"ai_explanation": None, "summary": "", "top_groups": [],
              "evidence": [], "status": "ok"}

    vector = engine.processed_vector(data)
    if vector is None:
        result["status"] = "no_vector"
        return result
    try:
        groups = top_feature_groups(vector, engine.lgbm.booster_, top_k=4)
    except Exception:
        groups = []
    try:
        evidence = extract_evidence(vector, data)
    except Exception:
        evidence = []
    result["top_groups"] = groups
    result["evidence"] = evidence

    verdict = ml_result.ml_verdict
    prob = ml_result.lgbm_prob or 0.0
    result["summary"] = local_feature_summary(groups, language, evidence, verdict, prob,
                                              signature_status, signature_signer)

    if not settings.get("explain_enabled", True):
        result["status"] = "disabled"
        return result
    api_key = api_key or config.get_gemini_api_key()
    if not api_key:
        result["status"] = "no_key"
        return result

    prompt = build_prompt(verdict, prob, groups, language,
                          evidence=evidence, hash_verdict=hash_verdict,
                          quarantined=quarantined,
                          signature_status=signature_status,
                          signature_signer=signature_signer)
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
            "ok": "ההסבר נוסח על-ידי Gemini על סמך המדידות שבוצעו בקובץ.",
            "disabled": "שכבת ההסבר כבויה (explain_enabled=false) — מוצג ניתוח מקומי.",
            "no_key": "לא הוגדר מפתח API ל-Gemini — מוצג ניתוח מקומי מלא. "
                      "ניתן להגדיר משתנה סביבה GEMINI_API_KEY.",
            "api_error": "פנייה ל-Gemini נכשלה (רשת/מפתח) — מוצג ניתוח מקומי מלא.",
            "no_vector": "לא ניתן היה לחלץ מאפיינים מהקובץ.",
        }.get(status, "")
    return {
        "ok": "Explanation written by Gemini from the measurements taken on the file.",
        "disabled": "Explanation layer is off (explain_enabled=false) — showing local analysis.",
        "no_key": "No Gemini API key set — showing full local analysis. "
                  "Set the GEMINI_API_KEY environment variable.",
        "api_error": "Gemini request failed (network/key) — showing full local analysis.",
        "no_vector": "Could not extract features from the file.",
    }.get(status, "")
