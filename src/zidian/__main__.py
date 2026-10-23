"""Entry point so ``python -m zidian`` and the zipapp binary both work."""

from .cli import main

if __name__ == "__main__":
    raise SystemExit(main())
