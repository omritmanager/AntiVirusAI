"""Enables `python -m avscan ...` (spec §10)."""
import sys

from .cli import main

if __name__ == "__main__":
    sys.exit(main())
