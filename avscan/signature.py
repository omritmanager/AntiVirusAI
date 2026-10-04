"""
signature.py — Authenticode (code-signing) verification. INDEPENDENT layer.

Why this exists
---------------
The frozen LightGBM model is an EMBER-v2 structural classifier, and it has a
real, systematic false-positive class: modern installers and binaries built with
non-MSVC toolchains. Measured case — the genuine, DigiCert-signed
`Claude Setup.exe` (a Go 1.24 binary) scores 0.9987 MALWARE because:
  * its compile timestamp is zeroed (Go does this for reproducible builds;
    historically a malware trick)      -> +0.85 toward malware
  * its COFF characteristics are minimal                    -> +1.37
  * it imports only kernel32.dll (Go resolves syscalls dynamically), which
    looks exactly like a packer hiding its import table
EMBER's 2018 training data contains almost no Go binaries, so the model has
never learned that these traits are also normal.

A validly signed binary from a trusted CA chain is the strongest real-world
counter-signal available offline, and the scanner previously ignored it.

Design rules (mirrors the hash layer, spec §3.5 / build rule 3)
--------------------------------------------------------------
  * NEVER changes the ML verdict. Recorded side by side, exactly like the
    SHA-256 lookup. `engine.py` is untouched.
  * It only influences the ACTION: a validly signed file is not auto-quarantined
    (still reported). Toggle with settings["trust_signed"].
  * NO NETWORK (spec §14 / build rule 4). Revocation checking is explicitly
    disabled (WTD_REVOKE_NONE) and URL retrieval is forced cache-only
    (WTD_CACHE_ONLY_URL_RETRIEVAL), so verification cannot reach out to a CRL
    or OCSP responder mid-scan.
  * stdlib only (ctypes) — no new pinned dependency in the locked environment.
  * Never raises. Any failure degrades to UNKNOWN, which trusts nothing.

Scope note: this checks EMBEDDED Authenticode only, not Windows catalog (.cat)
signatures. Many OS files are catalog-signed and will report UNSIGNED here
(verified: notepad.exe). That is deliberately conservative — it can only ever
withhold trust, never grant it wrongly — and those paths are already covered by
the System32/SysWOW64/WinSxS whitelist (spec §5).
"""
from __future__ import annotations

import sys
from dataclasses import dataclass

# ── Verdicts ────────────────────────────────────────────────────────────────
TRUSTED = "TRUSTED"          # valid signature, chain trusted by Windows
UNSIGNED = "UNSIGNED"        # no embedded signature at all
UNTRUSTED = "UNTRUSTED"      # signed, but bad/expired/untrusted-root/tampered
UNKNOWN = "UNKNOWN"          # could not determine (non-Windows, API failure)

# ── Win32 constants ─────────────────────────────────────────────────────────
_WTD_UI_NONE = 2
_WTD_REVOKE_NONE = 0
_WTD_CHOICE_FILE = 1
_WTD_STATEACTION_VERIFY = 1
_WTD_STATEACTION_CLOSE = 2
_WTD_SAFER_FLAG = 0x00000100
_WTD_CACHE_ONLY_URL_RETRIEVAL = 0x00001000   # keeps verification OFFLINE

# HRESULTs returned by WinVerifyTrust (as unsigned 32-bit).
_TRUST_E_NOSIGNATURE = 0x800B0100
_TRUST_E_BAD_DIGEST = 0x80096010
_TRUST_E_EXPLICIT_DISTRUST = 0x800B0111
_TRUST_E_SUBJECT_NOT_TRUSTED = 0x800B0004
_CERT_E_UNTRUSTEDROOT = 0x800B0109
_CERT_E_EXPIRED = 0x800B0101
_CERT_E_CHAINING = 0x800B010A
_CERT_E_REVOKED = 0x800B010C

_STATUS_TEXT = {
    _TRUST_E_NOSIGNATURE: "no embedded signature",
    _TRUST_E_BAD_DIGEST: "signature does not match the file (tampered)",
    _TRUST_E_EXPLICIT_DISTRUST: "signature is explicitly distrusted",
    _TRUST_E_SUBJECT_NOT_TRUSTED: "signer is not trusted",
    _CERT_E_UNTRUSTEDROOT: "certificate chains to an untrusted root",
    _CERT_E_EXPIRED: "certificate has expired",
    _CERT_E_CHAINING: "certificate chain could not be built",
    _CERT_E_REVOKED: "certificate was revoked",
}


@dataclass
class SignatureResult:
    status: str = UNKNOWN
    signer: str | None = None       # e.g. 'Anthropic, PBC'
    detail: str | None = None       # human-readable reason for non-TRUSTED

    @property
    def trusted(self) -> bool:
        return self.status == TRUSTED


def _verify_trust(path: str) -> tuple[str, str | None]:
    """Run WinVerifyTrust. Returns (status, detail). Offline-only."""
    import ctypes
    from ctypes import wintypes

    class GUID(ctypes.Structure):
        _fields_ = [("Data1", ctypes.c_ulong), ("Data2", ctypes.c_ushort),
                    ("Data3", ctypes.c_ushort), ("Data4", ctypes.c_ubyte * 8)]

    class WINTRUST_FILE_INFO(ctypes.Structure):
        _fields_ = [("cbStruct", wintypes.DWORD),
                    ("pcwszFilePath", wintypes.LPCWSTR),
                    ("hFile", wintypes.HANDLE),
                    ("pgKnownSubject", ctypes.c_void_p)]

    class WINTRUST_DATA(ctypes.Structure):
        _fields_ = [("cbStruct", wintypes.DWORD),
                    ("pPolicyCallbackData", ctypes.c_void_p),
                    ("pSIPClientData", ctypes.c_void_p),
                    ("dwUIChoice", wintypes.DWORD),
                    ("fdwRevocationChecks", wintypes.DWORD),
                    ("dwUnionChoice", wintypes.DWORD),
                    ("pFile", ctypes.POINTER(WINTRUST_FILE_INFO)),
                    ("dwStateAction", wintypes.DWORD),
                    ("hWVTStateData", wintypes.HANDLE),
                    ("pwszURLReference", wintypes.LPWSTR),
                    ("dwProvFlags", wintypes.DWORD),
                    ("dwUIContext", wintypes.DWORD),
                    ("pSignatureSettings", ctypes.c_void_p)]

    # WINTRUST_ACTION_GENERIC_VERIFY_V2
    action = GUID(0x00AAC56B, 0xCD44, 0x11D0,
                  (ctypes.c_ubyte * 8)(0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE))

    fi = WINTRUST_FILE_INFO(ctypes.sizeof(WINTRUST_FILE_INFO), path, None, None)
    wd = WINTRUST_DATA()
    wd.cbStruct = ctypes.sizeof(WINTRUST_DATA)
    wd.dwUIChoice = _WTD_UI_NONE
    wd.fdwRevocationChecks = _WTD_REVOKE_NONE           # no CRL/OCSP -> offline
    wd.dwUnionChoice = _WTD_CHOICE_FILE
    wd.pFile = ctypes.pointer(fi)
    wd.dwStateAction = _WTD_STATEACTION_VERIFY
    wd.dwProvFlags = _WTD_SAFER_FLAG | _WTD_CACHE_ONLY_URL_RETRIEVAL

    wintrust = ctypes.WinDLL("wintrust", use_last_error=True)
    wintrust.WinVerifyTrust.argtypes = [wintypes.HWND, ctypes.POINTER(GUID),
                                        ctypes.POINTER(WINTRUST_DATA)]
    wintrust.WinVerifyTrust.restype = ctypes.c_long

    try:
        rc = wintrust.WinVerifyTrust(None, ctypes.byref(action), ctypes.byref(wd))
    finally:
        # Always release the state data, even if verification threw.
        wd.dwStateAction = _WTD_STATEACTION_CLOSE
        try:
            wintrust.WinVerifyTrust(None, ctypes.byref(action), ctypes.byref(wd))
        except Exception:
            pass

    code = rc & 0xFFFFFFFF
    if code == 0:
        return TRUSTED, None
    if code == _TRUST_E_NOSIGNATURE:
        return UNSIGNED, _STATUS_TEXT[_TRUST_E_NOSIGNATURE]
    return UNTRUSTED, _STATUS_TEXT.get(code, f"verification failed (0x{code:08X})")


def _signer_name(path: str) -> str | None:
    """Read the signer's display name from the embedded PKCS#7 blob.

    Purely informational — a failure here never changes the trust verdict.
    """
    import ctypes
    from ctypes import wintypes

    CERT_QUERY_OBJECT_FILE = 1
    CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED = 1 << 10
    CERT_QUERY_FORMAT_FLAG_BINARY = 1 << 1
    CMSG_SIGNER_CERT_INFO_PARAM = 7
    CERT_FIND_SUBJECT_CERT = 11 << 16
    X509_ASN_ENCODING, PKCS_7_ASN_ENCODING = 0x1, 0x10000
    CERT_NAME_SIMPLE_DISPLAY_TYPE = 4

    c32 = ctypes.WinDLL("crypt32", use_last_error=True)
    c32.CryptQueryObject.restype = wintypes.BOOL
    c32.CryptMsgGetParam.restype = wintypes.BOOL
    c32.CertFindCertificateInStore.restype = ctypes.c_void_p
    c32.CertFindCertificateInStore.argtypes = [ctypes.c_void_p, wintypes.DWORD,
                                               wintypes.DWORD, wintypes.DWORD,
                                               ctypes.c_void_p, ctypes.c_void_p]
    c32.CertGetNameStringW.restype = wintypes.DWORD
    c32.CertGetNameStringW.argtypes = [ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD,
                                       ctypes.c_void_p, wintypes.LPWSTR, wintypes.DWORD]
    c32.CertFreeCertificateContext.argtypes = [ctypes.c_void_p]
    c32.CertCloseStore.argtypes = [ctypes.c_void_p, wintypes.DWORD]
    c32.CryptMsgClose.argtypes = [ctypes.c_void_p]

    store = ctypes.c_void_p()
    msg = ctypes.c_void_p()
    ok = c32.CryptQueryObject(
        CERT_QUERY_OBJECT_FILE, ctypes.c_wchar_p(path),
        CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED, CERT_QUERY_FORMAT_FLAG_BINARY,
        0, None, None, None, ctypes.byref(store), ctypes.byref(msg), None)
    if not ok:
        return None
    try:
        size = wintypes.DWORD(0)
        if not c32.CryptMsgGetParam(msg, CMSG_SIGNER_CERT_INFO_PARAM, 0,
                                    None, ctypes.byref(size)):
            return None
        buf = ctypes.create_string_buffer(size.value)
        if not c32.CryptMsgGetParam(msg, CMSG_SIGNER_CERT_INFO_PARAM, 0,
                                    buf, ctypes.byref(size)):
            return None
        cert = c32.CertFindCertificateInStore(
            store, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0,
            CERT_FIND_SUBJECT_CERT, buf, None)
        if not cert:
            return None
        try:
            n = c32.CertGetNameStringW(cert, CERT_NAME_SIMPLE_DISPLAY_TYPE,
                                       0, None, None, 0)
            if n <= 1:
                return None
            out = ctypes.create_unicode_buffer(n)
            c32.CertGetNameStringW(cert, CERT_NAME_SIMPLE_DISPLAY_TYPE,
                                   0, None, out, n)
            return out.value or None
        finally:
            c32.CertFreeCertificateContext(cert)
    finally:
        if msg:
            c32.CryptMsgClose(msg)
        if store:
            c32.CertCloseStore(store, 0)


def verify(path: str) -> SignatureResult:
    """Verify a file's Authenticode signature. Never raises; offline only."""
    if not sys.platform.startswith("win"):
        return SignatureResult(UNKNOWN, None, "signature checking requires Windows")
    try:
        status, detail = _verify_trust(str(path))
    except Exception as e:
        return SignatureResult(UNKNOWN, None, f"verification error: {e}")
    signer = None
    if status in (TRUSTED, UNTRUSTED):
        try:
            signer = _signer_name(str(path))
        except Exception:
            signer = None
    return SignatureResult(status, signer, detail)


# ── Display verdict ─────────────────────────────────────────────────────────
# Shown to the user as GREEN. The stored ml_verdict is NOT touched: the report
# JSON, the summary tallies and the audit trail all still say MALWARE. This is
# purely how the result is presented.
SIGNED_SAFE = "SIGNED_SAFE"


def display_verdict(ml_verdict: str, signature_status: str | None,
                    hash_verdict: str | None = None,
                    trust_signed: bool = True) -> str:
    """Map a raw ML verdict to what the UI should show.

    A file that is validly signed by a publisher Windows trusts is presented as
    safe (green), because the model has a known, systematic false-positive rate
    on signed installers and non-MSVC toolchains (measured: a signed Go binary
    scored 0.9987) and a red banner there is simply wrong more often than right.
    ERROR (couldn't be read/parsed) is treated the same as MALWARE here too —
    it is flagged under the app's fail-closed policy, so a valid signature is
    exactly as strong a counter-signal for it as for a real MALWARE verdict
    (e.g. a file with an unusual-but-legitimate header layout that broke
    feature extraction, yet carries a real publisher's signature).

    SAFETY CARVE-OUT: a SHA-256 match against the known-malware database ALWAYS
    wins and stays red. Signed malware is real — attackers do steal or buy code
    signing certificates — so a valid signature must never be able to mask an
    exact match against a known sample. Only the probabilistic verdict is
    softened by a signature; never a definitive one.
    """
    if not trust_signed:
        return ml_verdict
    if hash_verdict == "KNOWN_MALWARE":
        return ml_verdict
    if signature_status == TRUSTED and ml_verdict in ("MALWARE", "ERROR"):
        return SIGNED_SAFE
    return ml_verdict


def describe(result: SignatureResult, language: str = "he") -> str:
    """One-line human summary, for the report/UI/explanation."""
    he = language == "he"
    if result.status == TRUSTED:
        who = result.signer or ("יצרן מאומת" if he else "a verified publisher")
        return (f"חתום דיגיטלית בתוקף על ידי {who}, והחתימה אומתה מול Windows"
                if he else
                f"validly signed by {who}, verified against Windows' trust store")
    if result.status == UNSIGNED:
        return ("לקובץ אין חתימה דיגיטלית מוטבעת" if he
                else "the file has no embedded digital signature")
    if result.status == UNTRUSTED:
        d = result.detail or ""
        return (f"לקובץ יש חתימה דיגיטלית אך היא אינה תקפה ({d})" if he
                else f"the file is signed but the signature is not valid ({d})")
    return ("לא ניתן היה לבדוק את החתימה הדיגיטלית" if he
            else "the digital signature could not be checked")
