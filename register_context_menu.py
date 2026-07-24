"""
register_context_menu.py — add/remove the Windows right-click "Quick Scan" entry.

Adds an entry to the .exe context menu so you can right-click any executable and
run a single-file AntivirusAI scan that pops up the verdict (and a Gemini "why"
if it looks malicious).

Default scope is PER-USER (HKEY_CURRENT_USER) — no administrator rights needed
and it only affects the current user. Use --system for all users (needs admin).

Usage (run with the project's venv Python so the scan command points at it):
    venv_v7\Scripts\python.exe register_context_menu.py --register
    venv_v7\Scripts\python.exe register_context_menu.py --status
    venv_v7\Scripts\python.exe register_context_menu.py --unregister

This modifies the Windows registry (a shell setting), so YOU run it — the app
does not change it automatically. Everything it writes is reversible with
--unregister.
"""
from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path

try:
    import winreg
except ImportError:  # not Windows
    winreg = None

ROOT = Path(__file__).resolve().parent
QUICKSCAN = ROOT / "avscan" / "quickscan.py"
VENV_PYW = ROOT / "venv_v7" / "Scripts" / "pythonw.exe"
VENV_PY = ROOT / "venv_v7" / "Scripts" / "python.exe"

KEY_NAME = "AntivirusAIQuickScan"
DISPLAY_TEXT = "AntivirusAI: סריקה מהירה"
# .exe files use the "exefile" ProgID. Writing under HKCU\Software\Classes merges
# with the system classes, so a per-user entry needs no admin rights.
BASE_SUBKEY = rf"Software\Classes\exefile\shell\{KEY_NAME}"


def _python_exe() -> Path:
    """Prefer the venv's pythonw.exe (no console window for the popup)."""
    if VENV_PYW.exists():
        return VENV_PYW
    if VENV_PY.exists():
        return VENV_PY
    cur = Path(sys.executable)
    pyw = cur.with_name("pythonw.exe")
    return pyw if pyw.exists() else cur


def _command_string() -> str:
    return f'"{_python_exe()}" "{QUICKSCAN}" "%1"'


def _hive(scope: str):
    return winreg.HKEY_LOCAL_MACHINE if scope == "system" else winreg.HKEY_CURRENT_USER


def register(scope: str = "user") -> tuple[str, str]:
    cmd = _command_string()
    hive = _hive(scope)
    with winreg.CreateKey(hive, BASE_SUBKEY) as k:
        winreg.SetValueEx(k, None, 0, winreg.REG_SZ, DISPLAY_TEXT)     # menu label
        winreg.SetValueEx(k, "Icon", 0, winreg.REG_SZ, str(_python_exe()))
    with winreg.CreateKey(hive, BASE_SUBKEY + r"\command") as k:
        winreg.SetValueEx(k, None, 0, winreg.REG_SZ, cmd)
    return BASE_SUBKEY, cmd


def unregister(scope: str = "user") -> None:
    hive = _hive(scope)
    for sub in (BASE_SUBKEY + r"\command", BASE_SUBKEY):
        try:
            winreg.DeleteKey(hive, sub)
        except FileNotFoundError:
            pass


def status(scope: str = "user") -> str | None:
    hive = _hive(scope)
    try:
        with winreg.OpenKey(hive, BASE_SUBKEY + r"\command") as k:
            val, _ = winreg.QueryValueEx(k, None)
            return val
    except FileNotFoundError:
        return None


# ── "quick access" shortcuts (Send To + Desktop) ─────────────────────────────
# Windows 11's MODERN right-click menu only shows packaged (IExplorerCommand /
# MSIX) shell extensions; a classic registry verb like ours is always relegated
# to "Show more options". No registry script can change that. These two shortcuts
# give menu-free quick access instead: drag a file onto the desktop icon, or use
# right-click ▸ Send to.
SHORTCUT_NAME = "AntivirusAI Quick Scan.lnk"


def _make_shortcut(lnk: str, target: str, arguments: str, icon: str) -> None:
    # Pass values via environment variables so PowerShell never re-interprets
    # backslashes (paths like ...\avscan\quickscan.py would otherwise be mangled
    # by escape-sequence handling).
    env = dict(os.environ, SC_LNK=lnk, SC_TGT=target, SC_ARG=arguments, SC_ICO=icon)
    ps = (
        "$s=(New-Object -ComObject WScript.Shell).CreateShortcut($env:SC_LNK);"
        "$s.TargetPath=$env:SC_TGT;$s.Arguments=$env:SC_ARG;"
        "$s.IconLocation=$env:SC_ICO;$s.WindowStyle=1;$s.Save()"
    )
    subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", ps],
                   env=env, check=True, capture_output=True, text=True)


def _desktop_dir() -> str:
    try:
        r = subprocess.run(
            ["powershell", "-NoProfile", "-Command", "[Environment]::GetFolderPath('Desktop')"],
            capture_output=True, text=True, timeout=15)
        d = r.stdout.strip()
        if d and os.path.isdir(d):
            return d
    except Exception:
        pass
    return os.path.join(os.environ.get("USERPROFILE", ""), "Desktop")


def _sendto_lnk() -> str:
    return os.path.join(os.environ.get("APPDATA", ""), "Microsoft", "Windows",
                        "SendTo", SHORTCUT_NAME)


def _desktop_lnk() -> str:
    return os.path.join(_desktop_dir(), SHORTCUT_NAME)


def register_shortcuts() -> list[str]:
    """Create the Send-To and Desktop shortcuts. Returns the paths created."""
    made = []
    target = str(_python_exe())
    args = f'"{QUICKSCAN}"'   # Windows appends the selected/dropped file path
    for lnk in (_sendto_lnk(), _desktop_lnk()):
        try:
            os.makedirs(os.path.dirname(lnk), exist_ok=True)
            _make_shortcut(lnk, target, args, target)
            made.append(lnk)
        except Exception:
            pass
    return made


def unregister_shortcuts() -> None:
    for lnk in (_sendto_lnk(), _desktop_lnk()):
        try:
            if os.path.exists(lnk):
                os.remove(lnk)
        except Exception:
            pass


def main(argv=None) -> int:
    if winreg is None:
        print("This tool only runs on Windows.")
        return 2
    ap = argparse.ArgumentParser(description="Register the .exe right-click Quick Scan entry.")
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--register", action="store_true", help="add the entry (default)")
    g.add_argument("--unregister", action="store_true", help="remove the entry")
    g.add_argument("--status", action="store_true", help="show whether it is registered")
    ap.add_argument("--system", action="store_true",
                    help="all users via HKLM (needs administrator); default is per-user")
    args = ap.parse_args(argv)
    scope = "system" if args.system else "user"

    if not QUICKSCAN.exists():
        print(f"ERROR: cannot find {QUICKSCAN}")
        return 2

    try:
        if args.unregister:
            unregister(scope)
            unregister_shortcuts()
            print(f"Removed the '{DISPLAY_TEXT}' right-click entry + shortcuts ({scope}).")
        elif args.status:
            cur = status(scope)
            print(f"Right-click entry ({scope}): {cur if cur else 'NO'}")
            print(f"Send-To shortcut : {'YES' if os.path.exists(_sendto_lnk()) else 'NO'}")
            print(f"Desktop shortcut : {'YES' if os.path.exists(_desktop_lnk()) else 'NO'}")
        else:  # default = register
            base, cmd = register(scope)
            made = register_shortcuts()
            print(f"Registered Quick Scan ({scope}):")
            print(f"  • right-click .exe entry  (registry key {base})")
            for lnk in made:
                print(f"  • shortcut: {lnk}")
            print(f"\n  command: {cmd}")
            print("\nHow to use it:")
            print("  1) Right-click a .exe. On Windows 11 the entry is under "
                  "'Show more options'\n     (or press Shift+F10 for the classic menu directly).")
            print("  2) QUICK ACCESS (no menu): DRAG any file onto the "
                  "'AntivirusAI Quick Scan' desktop icon.")
            print("  3) Or: right-click a file ▸ 'Send to' ▸ 'AntivirusAI Quick Scan'.")
            print("\nNote: putting an entry in the Windows 11 TOP-LEVEL modern menu "
                  "requires a\npackaged shell extension (MSIX / IExplorerCommand), which a "
                  "script can't create.")
            print("Remove everything with:  python register_context_menu.py --unregister")
    except PermissionError:
        print("Permission denied. For --system you must run as Administrator "
              "(per-user --register needs no admin).")
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
