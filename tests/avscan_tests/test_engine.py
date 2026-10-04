"""Engine tests (spec §13): known vectors, reference parity, safety."""
import numpy as np
import pytest

from avscan import config
from avscan.engine import (Engine, LeakyModelError, MALWARE, SAFE, ERROR,
                           sha256_bytes)


def _reference_classify(data, engine):
    """Inline replica of scan_folder_v7.py's logic for parity checking."""
    if len(data) < 100:
        return ERROR, None
    vec = np.array(engine.extractor.feature_vector(data), dtype=np.float32)
    if len(vec) != 2381 or np.isnan(vec).any() or np.isinf(vec).any():
        return ERROR, None
    vec[config.TEMPORAL_INDICES] = 0.0
    vec = vec.reshape(1, -1)
    p = float(engine.lgbm.predict_proba(vec)[0, 1])
    return (MALWARE if p >= config.LGBM_THRESHOLD else SAFE), p


@pytest.mark.skipif(not config.X_TEST_BALANCED.exists(), reason="test arrays absent")
def test_known_vectors_classify_correctly(engine):
    X = np.load(config.X_TEST_BALANCED)
    y = np.load(config.Y_TEST_BALANCED)
    mal = np.where(y == 1)[0][:60]
    ben = np.where(y == 0)[0][:60]
    mal_hits = sum(engine.classify_vector(X[i]).ml_verdict == MALWARE for i in mal)
    ben_hits = sum(engine.classify_vector(X[i]).ml_verdict == SAFE for i in ben)
    # validated error rates are <1%; allow a small slack to stay deterministic-safe
    assert mal_hits >= 57          # >=95% of malware -> MALWARE
    assert ben_hits >= 57          # >=95% of benign  -> SAFE


def test_engine_matches_reference(engine, benign_exes):
    for exe in benign_exes[:4]:
        data = exe.read_bytes()
        ref_v, ref_p = _reference_classify(data, engine)
        res = engine.classify_bytes(data)
        assert res.ml_verdict == ref_v
        if ref_p is not None:
            assert abs(res.lgbm_prob - ref_p) < 1e-9


def test_leaky_model_refused():
    with pytest.raises(LeakyModelError):
        Engine._assert_not_leaky(config.LGBM_LEAKY_PATH)


def test_bad_input_never_crashes(engine):
    assert engine.classify_bytes(b"").ml_verdict == ERROR
    assert engine.classify_bytes(b"MZ").ml_verdict == ERROR
    assert engine.classify_bytes(None).ml_verdict == ERROR


def test_classify_vector_does_not_mutate_input(engine):
    vec = np.ones(config.EXPECTED_DIM, dtype=np.float32)
    engine.classify_vector(vec)
    assert np.all(vec[config.TEMPORAL_INDICES] == 1.0)


def test_classify_with_vector_agrees_with_the_separate_calls(engine, benign_exes):
    """One extraction must give exactly what two separate calls used to."""
    for exe in benign_exes[:3]:
        data = exe.read_bytes()
        res, vec = engine.classify_with_vector(data)
        assert res.ml_verdict == engine.classify_bytes(data).ml_verdict
        assert np.array_equal(vec, engine.processed_vector(data))


def test_classify_with_vector_returns_no_vector_on_error(engine):
    for bad in (b"", b"MZ", None):
        res, vec = engine.classify_with_vector(bad)
        assert res.ml_verdict == ERROR
        assert vec is None


def test_sha256_helpers_consistent(benign_exes):
    from avscan.engine import sha256_file
    data = benign_exes[0].read_bytes()
    assert sha256_bytes(data) == sha256_file(benign_exes[0])
