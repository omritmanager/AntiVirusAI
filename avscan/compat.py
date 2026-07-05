"""
compat.py — Compatibility shims that MUST run before importing ember (spec §2).

These reproduce, verbatim, the shims from the validated `scan_folder_v7.py`:
  * LIEF lost several module-level exception attributes across versions; EMBER's
    feature code references them, so we recreate any that are missing.
  * NumPy removed the deprecated aliases np.int/np.bool/np.float/np.object; older
    EMBER code still uses them.

Both `selfcheck.py` and `engine.py` call `apply_compat_shims()` BEFORE the first
`import ember`. The function is idempotent.
"""
from __future__ import annotations

_LIEF_EXC_ATTRS = [
    "bad_format", "bad_file", "pe_error",
    "parser_error", "read_out_of_bound", "not_found",
]
_NUMPY_ALIASES = [("int", int), ("bool", bool), ("float", float), ("object", object)]


def apply_compat_shims() -> None:
    """Recreate the LIEF exception attrs and NumPy aliases EMBER expects."""
    import warnings

    import lief

    for attr in _LIEF_EXC_ATTRS:
        if not hasattr(lief, attr):
            setattr(lief, attr, type(attr, (Exception,), {}))

    import numpy as np

    # NumPy 1.26 emits a FutureWarning merely on `hasattr(np, 'bool')` etc.
    # That probe is exactly the validated reference's approach; suppress only the
    # warning noise here — the aliases set below are identical either way.
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", FutureWarning)
        for name, ty in _NUMPY_ALIASES:
            if not hasattr(np, name):
                setattr(np, name, ty)
