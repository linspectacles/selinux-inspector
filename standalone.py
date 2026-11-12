#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# LinSpectacles - Linux Inspector Suite
# Copyright (C) 2026 brunonlinespace
# GPL-3.0-or-later

import sys
from pathlib import Path

APPLETS_ROOT = Path(__file__).resolve().parent.parent
if str(APPLETS_ROOT) not in sys.path:
    sys.path.insert(0, str(APPLETS_ROOT))

from linspectacles_selinux_inspector.selinux_inspector.applet import run_standalone

if __name__ == "__main__":
    raise SystemExit(run_standalone())
