"""Support ``python -m portmux``."""

from __future__ import annotations

import sys

from portmux.app.cli import main

if __name__ == "__main__":
    sys.exit(main())
