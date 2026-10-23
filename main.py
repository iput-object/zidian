"""Standalone entry point for PyInstaller / zipapp builds.

Uses an absolute import of the package so it works as a top-level script.
"""

import sys

from zidian.cli import main

if __name__ == "__main__":
    sys.exit(main())
