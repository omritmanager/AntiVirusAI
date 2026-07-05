"""Shared fixtures for the AntivirusAI V7 test suite (spec §13)."""
import glob
import sqlite3
import sys
from pathlib import Path

import pytest

# Make the project root importable (so `import avscan` works under pytest).
ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from avscan import config  # noqa: E402
from avscan.engine import Engine, sha256_file  # noqa: E402

# A junk PE-extension payload the validated model classifies as MALWARE
# (low-entropy non-PE bytes; >= MIN_FILE_BYTES). Used so tests don't ship real
# malware. Verified during the build to score p>=0.40.
JUNK_MALWARE_BYTES = b"x" * 500


@pytest.fixture(scope="session")
def engine() -> Engine:
    """One loaded Engine shared across the whole suite (model load is slow)."""
    return Engine(load_if=True)


@pytest.fixture(scope="session")
def benign_exes() -> list[Path]:
    exes = [Path(p) for p in glob.glob(str(ROOT / "venv_v7" / "Scripts" / "*.exe"))]
    if len(exes) < 3:
        pytest.skip("need >=3 benign .exe files in venv_v7/Scripts for tests")
    return exes[:6]


@pytest.fixture
def mixed_folder(tmp_path, benign_exes) -> Path:
    """A folder with 2 benign PEs, 1 MALWARE-classified junk, 1 ERROR (too small),
    and 1 ignored non-PE-extension file."""
    folder = tmp_path / "scan_me"
    folder.mkdir()
    for i in range(2):
        (folder / f"clean{i}.exe").write_bytes(benign_exes[i].read_bytes())
    (folder / "junk.exe").write_bytes(JUNK_MALWARE_BYTES)
    (folder / "tiny.exe").write_bytes(b"MZ")          # < MIN_FILE_BYTES -> ERROR
    (folder / "notes.txt").write_text("ignored")       # wrong extension
    return folder


@pytest.fixture
def tiny_db(tmp_path, benign_exes) -> tuple[Path, str]:
    """A minimal baseline DB containing exactly one benign file's SHA-256.
    Returns (db_path, the_known_sha256)."""
    known_sha = sha256_file(benign_exes[0])
    db = tmp_path / "tiny.sqlite"
    conn = sqlite3.connect(str(db))
    conn.executescript(
        "CREATE TABLE known_malware(sha256 TEXT PRIMARY KEY, family TEXT, "
        "first_seen TEXT, added_at TEXT);")
    conn.execute("INSERT INTO known_malware VALUES (?,?,?,?)",
                 (known_sha, "unknown", "2026-05", "now"))
    conn.commit()
    conn.close()
    return db, known_sha
