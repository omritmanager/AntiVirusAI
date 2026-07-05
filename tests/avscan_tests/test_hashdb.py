"""Hash DB tests (spec §13): known vs withheld, normalization, graceful absence."""
import pytest

from avscan import config
from avscan.hashdb import HashDB, KNOWN_MALWARE, NOT_IN_DB


def test_known_hash_in_db(tiny_db):
    db_path, known_sha = tiny_db
    db = HashDB(db_path)
    assert db.available
    assert db.contains(known_sha)
    assert db.verdict(known_sha) == KNOWN_MALWARE
    row = db.lookup(known_sha)
    assert row and row["sha256"] == known_sha
    db.close()


def test_unknown_hash_not_in_db(tiny_db):
    db_path, _ = tiny_db
    db = HashDB(db_path)
    assert db.verdict("0" * 64) == NOT_IN_DB
    assert db.lookup("0" * 64) is None
    db.close()


def test_lookup_normalizes_case(tiny_db):
    db_path, known_sha = tiny_db
    db = HashDB(db_path)
    assert db.verdict(known_sha.upper()) == KNOWN_MALWARE
    db.close()


def test_missing_db_degrades_gracefully(tmp_path):
    db = HashDB(tmp_path / "nope.sqlite")
    assert not db.available
    assert db.contains("a" * 64) is False
    assert db.lookup("a" * 64) is None
    assert db.count() == 0
    assert db.verdict("a" * 64) == NOT_IN_DB


@pytest.mark.skipif(not config.BASELINE_SQLITE.exists(),
                    reason="baseline DB not built (run build_hash_db.py)")
def test_real_baseline_split():
    """Known hashes resolve; withheld simulated-zero-day hashes do not."""
    db = HashDB(config.BASELINE_SQLITE)
    assert db.count() > 0
    known = config.KNOWN_HASHES_TXT.read_text().split()
    zeroday = config.SIMULATED_ZERODAY_TXT.read_text().split()
    assert db.verdict(known[0]) == KNOWN_MALWARE
    assert db.verdict(zeroday[0]) == NOT_IN_DB
    # the two sets must be disjoint (no hash both known and withheld)
    assert not (set(known) & set(zeroday))
    db.close()
