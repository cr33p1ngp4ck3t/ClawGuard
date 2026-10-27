"""Adversarial text must not monopolize the detector worker."""
import subprocess
import sys
from pathlib import Path

import pytest


@pytest.mark.parametrize("text", ["'-' * 100000", "'call function ' * 20000"])
def test_long_nonmatching_pattern_runs_in_bounded_time(text):
    result = subprocess.run(
        [sys.executable, "-c", "from detection.regex_detector import scan_for_injections_weighted; "
         f"assert scan_for_injections_weighted({text})[1] == 0"],
        cwd=Path(__file__).resolve().parents[1], capture_output=True, text=True, timeout=5,
    )
    assert result.returncode == 0, result.stderr
