#!/usr/bin/env python3
# -*- coding: UTF-8 -*-
# -----------------------------------------------------------------------------
#  _   _      _   _     _            _    _____           _
# | \ | | ___| |_| |__ | | ___   ___| | _|_   _|__   ___ | |
# |  \| |/ _ \ __| '_ \| |/ _ \ / __| |/ / | |/ _ \ / _ \| |
# | |\  |  __/ |_| |_) | | (_) | (__|   <  | | (_) | (_) | |
# |_| \_|\___|\__|_.__/|_|\___/ \___|_|\_\ |_|\___/ \___/|_|
#
# Name:     Netblock Tool (NetblockTool.py)
# Purpose:  Find public netblocks owned by a given company
#
# Author:   Alex Poorman
# Sponsor:  NetSPI (https://netspi.com)
#
# This launcher keeps the historical invocation working:
#
#     python3 NetblockTool.py -v -s Google
#
# The implementation now lives in the ``netblocktool`` package.
# -----------------------------------------------------------------------------

from __future__ import annotations

import sys
from pathlib import Path

# Allow running the script directly from a checkout without installing.
sys.path.insert(0, str(Path(__file__).resolve().parent))

MINIMUM_PYTHON = (3, 10)

if sys.version_info < MINIMUM_PYTHON:  # pragma: no cover
    sys.stderr.write(
        f"[ERROR] NetblockTool requires Python "
        f"{MINIMUM_PYTHON[0]}.{MINIMUM_PYTHON[1]} or newer "
        f"(running {sys.version_info.major}.{sys.version_info.minor}).\n"
    )
    raise SystemExit(1)

from netblocktool.cli import main  # noqa: E402  (must follow the version guard)

if __name__ == "__main__":
    raise SystemExit(main())
