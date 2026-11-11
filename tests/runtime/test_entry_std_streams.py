"""
A windowed build has no console, so sys.stdout/sys.stderr are None and any
print() during startup raises. That made logging initialisation depend on how
the app was launched: fine from a shell, skipped entirely when started by the
watchdog, Task Scheduler or the Startup shortcut.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

ENTRY_PATH = Path(__file__).resolve().parents[2] / "scripts" / "setup" / "voiceflow_exe_entry.py"


def _load_entry_module():
    spec = importlib.util.spec_from_file_location("voiceflow_exe_entry_under_test", ENTRY_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def entry_module():
    return _load_entry_module()


def _restore(saved):
    sys.stdout, sys.stderr = saved


def test_none_streams_are_replaced(entry_module):
    saved = (sys.stdout, sys.stderr)
    try:
        sys.stdout = None
        sys.stderr = None
        entry_module._ensure_std_streams()

        assert sys.stdout is not None
        assert sys.stderr is not None
        # The whole point: printing must not raise.
        print("startup diagnostic")
        print("startup diagnostic", file=sys.stderr)
    finally:
        _restore(saved)


def test_usable_streams_are_left_alone(entry_module):
    saved = (sys.stdout, sys.stderr)
    try:
        import io

        mine_out, mine_err = io.StringIO(), io.StringIO()
        sys.stdout, sys.stderr = mine_out, mine_err
        entry_module._ensure_std_streams()

        assert sys.stdout is mine_out, "a working stdout was needlessly replaced"
        assert sys.stderr is mine_err
    finally:
        _restore(saved)


def test_stream_that_raises_on_write_is_replaced(entry_module):
    """A closed or broken handle is as bad as None, and does not announce itself."""
    saved = (sys.stdout, sys.stderr)

    class _Broken:
        def write(self, _data):
            raise OSError("handle is invalid")

        def flush(self):
            raise OSError("handle is invalid")

    try:
        sys.stdout = _Broken()
        sys.stderr = _Broken()
        entry_module._ensure_std_streams()

        assert not isinstance(sys.stdout, _Broken)
        print("startup diagnostic")
    finally:
        _restore(saved)
