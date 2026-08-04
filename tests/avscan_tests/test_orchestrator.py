"""Orchestrator tests (spec §13): comparison_tag table, whitelist, integration."""
import os

from avscan.engine import MALWARE, SAFE, ERROR
from avscan.hashdb import HashDB, KNOWN_MALWARE, NOT_IN_DB
from avscan import orchestrator as orch
from avscan.orchestrator import (comparison_tag, is_whitelisted,
                                 BOTH_CAUGHT, ML_ONLY_CATCH, HASH_ONLY_CATCH,
                                 BOTH_CLEAR, _normalize_prefixes)


def test_comparison_tag_all_four_combinations():
    assert comparison_tag(MALWARE, KNOWN_MALWARE) == BOTH_CAUGHT
    assert comparison_tag(MALWARE, NOT_IN_DB) == ML_ONLY_CATCH
    assert comparison_tag(SAFE, KNOWN_MALWARE) == HASH_ONLY_CATCH
    assert comparison_tag(SAFE, NOT_IN_DB) == BOTH_CLEAR


def test_comparison_tag_edge_cases():
    # no tag when hash layer didn't run, or the file errored
    assert comparison_tag(SAFE, None) is None
    assert comparison_tag(ERROR, KNOWN_MALWARE) is None


def test_whitelist_skips_system_paths():
    prefixes = _normalize_prefixes([r"C:\Windows\System32", r"C:\Windows\SysWOW64"])
    assert is_whitelisted(r"C:\Windows\System32\cmd.exe", prefixes)
    assert is_whitelisted(r"c:\windows\system32\drivers\x.sys", prefixes)  # case-insensitive
    assert not is_whitelisted(r"C:\Users\me\app.exe", prefixes)
    # boundary: a sibling dir that merely shares the prefix string must NOT match
    assert not is_whitelisted(r"C:\Windows\System32Extra\x.exe", prefixes)


def test_whitelist_toggle_skips_everything(mixed_folder):
    res = orch.scan_folder(mixed_folder, whitelist_enabled=True,
                           whitelist_prefixes=[str(mixed_folder)], hash_compare=False)
    assert res.summary.scanned == 0
    assert res.summary.skipped_system == res.summary.total_files_seen


def test_integration_mixed_folder_counts(mixed_folder, engine):
    res = orch.scan_folder(mixed_folder, engine=engine, whitelist_enabled=True,
                           hash_compare=False)
    s = res.summary
    assert s.total_files_seen == 4          # txt ignored
    assert s.scanned == 4                    # all sent to engine
    assert s.skipped_system == 0
    assert s.malware == 1                    # junk.exe
    assert s.safe == 2                       # clean0/clean1
    assert s.errors == 1                     # tiny.exe
    # self-consistency
    assert s.total_files_seen == s.scanned + s.skipped_system
    assert s.malware + s.safe + s.errors == s.scanned


def test_integration_hash_tags(mixed_folder, engine, tiny_db):
    db_path, known_sha = tiny_db
    res = orch.scan_folder(mixed_folder, engine=engine, hash_db=HashDB(db_path),
                           hash_compare=True)
    # junk.exe is MALWARE and its hash is not in the tiny DB -> ML_ONLY_CATCH
    junk = next(r for r in res.results if r.name == "junk.exe")
    assert junk.ml_verdict == MALWARE
    assert junk.comparison_tag == ML_ONLY_CATCH
    assert res.hash_comparison["files"][ML_ONLY_CATCH] == 1
