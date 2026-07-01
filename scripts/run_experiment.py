#!/usr/bin/env python3
"""Run the dependent policy-interaction assurance benchmark."""

import sys
from pathlib import Path

PACKAGE_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PACKAGE_ROOT / "src"))

from dependent_policy_assurance.benchmark import main


if __name__ == "__main__":
    main()
