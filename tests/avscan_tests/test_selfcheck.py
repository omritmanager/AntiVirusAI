"""Self-check tests (spec §13): fails loudly on version mismatch; passes clean."""
import pytest

from avscan import config, selfcheck


def test_version_mismatch_fails_loudly(monkeypatch):
    """Mock a wrong locked version and confirm the check fails, naming the package."""
    monkeypatch.setattr(config, "LOCKED_VERSIONS", {"numpy": "9.9.9-impossible"})
    checks = selfcheck.check_versions()
    assert len(checks) == 1
    c = checks[0]
    assert c.passed is False
    assert "numpy" in c.name
    assert "9.9.9-impossible" in c.detail


def test_real_versions_pass():
    for c in selfcheck.check_versions():
        assert c.passed, f"{c.name}: {c.detail}"


def test_ember_patch_present():
    c = selfcheck.check_ember_patch()
    assert c.passed, c.detail


def test_assets_load():
    checks = selfcheck.check_assets()
    # the primary model must load (it is the first check)
    primary = next(c for c in checks if "lgbm_v7_correct" in c.name)
    assert primary.passed, primary.detail


@pytest.mark.skipif(not config.X_TEST_BALANCED.exists()
                    and not (config.AVSCAN_DIR / "_assets" / "regression_mini.npz").exists(),
                    reason="no regression data available")
def test_regression_f1_meets_threshold():
    check, f1 = selfcheck.check_regression()
    assert check.passed, check.detail
    assert f1 is not None and f1 >= config.REGRESSION_F1_MIN


def test_full_selfcheck_ok():
    result = selfcheck.run_selfcheck(run_regression=True, verbose=False)
    assert result.ok, result.format()
