"""Interactive scheduling for the dictation process (VF-19).

VoiceFlow is started by a Task Scheduler watchdog. Task Scheduler runs tasks at
priority 7, so the app inherits a BelowNormal CPU priority class (and, on
current Windows builds, a lowered memory priority). Only the watchdog script
put the class back to Normal; any other launcher (a different copy of the
script, a shortcut started from a scheduled task, a dev launcher) left the app
starved. On 2026-11-10 GPU decodes that normally take 0.15-0.5 s took 4-21 s
while other work saturated the CPU: a BelowNormal process only runs when no
Normal-priority thread wants the core, and a CUDA decode still needs the CPU to
launch every kernel.

The app now repairs its own scheduling at startup instead of trusting the
launcher, and logs what it found, so the health run can tell a starved launch
from a slow one:

    process_priority before=below_normal after=normal raised=True
        memory_priority_before=... memory_priority_after=... power_throttling=off

Rules: never lower anything, never go above ``above_normal`` (no HIGH or
REALTIME), and never raise on failure. Everything here is best-effort and a
no-op off Windows.
"""

from __future__ import annotations

import ctypes
import logging
import sys
from typing import Any, Dict, Optional

# Win32 priority classes, lowest to highest.
PRIORITY_CLASSES: Dict[str, int] = {
    "idle": 0x00000040,
    "below_normal": 0x00004000,
    "normal": 0x00000020,
    "above_normal": 0x00008000,
    "high": 0x00000080,
    "realtime": 0x00000100,
}
_RANK = ["idle", "below_normal", "normal", "above_normal", "high", "realtime"]
_MAX_TARGET = "above_normal"

# PROCESS_INFORMATION_CLASS values (processthreadsapi.h)
_PROCESS_MEMORY_PRIORITY = 0
_PROCESS_POWER_THROTTLING = 4
_PROCESS_POWER_THROTTLING_CURRENT_VERSION = 1
_PROCESS_POWER_THROTTLING_EXECUTION_SPEED = 0x1
MEMORY_PRIORITY_NORMAL = 5


def priority_name(value: Optional[int]) -> str:
    """``0x4000`` -> ``below_normal``; unknown or None -> ``unknown``."""
    if value is None:
        return "unknown"
    for name, code in PRIORITY_CLASSES.items():
        if code == int(value):
            return name
    return f"0x{int(value):x}"


def _rank(name: str) -> int:
    try:
        return _RANK.index(name)
    except ValueError:
        return -1


class _MemoryPriorityInformation(ctypes.Structure):
    _fields_ = [("MemoryPriority", ctypes.c_ulong)]


class _PowerThrottlingState(ctypes.Structure):
    _fields_ = [
        ("Version", ctypes.c_ulong),
        ("ControlMask", ctypes.c_ulong),
        ("StateMask", ctypes.c_ulong),
    ]


class WindowsSchedulingApi:
    """Thin ctypes wrapper. Every call returns None/False instead of raising."""

    def __init__(self) -> None:
        self._k32: Any = None
        windll = getattr(ctypes, "windll", None)
        if windll is None or not sys.platform.startswith("win"):
            return
        try:
            k32 = windll.kernel32
            k32.GetCurrentProcess.restype = ctypes.c_void_p
            k32.GetPriorityClass.argtypes = [ctypes.c_void_p]
            k32.GetPriorityClass.restype = ctypes.c_ulong
            k32.SetPriorityClass.argtypes = [ctypes.c_void_p, ctypes.c_ulong]
            k32.SetPriorityClass.restype = ctypes.c_int
            self._k32 = k32
        except Exception:
            self._k32 = None

    @property
    def available(self) -> bool:
        return self._k32 is not None

    def _proc(self) -> Any:
        return self._k32.GetCurrentProcess()

    def get_priority_class(self) -> Optional[int]:
        if not self.available:
            return None
        try:
            value = int(self._k32.GetPriorityClass(self._proc()))
            return value or None
        except Exception:
            return None

    def set_priority_class(self, value: int) -> bool:
        if not self.available:
            return False
        try:
            return bool(self._k32.SetPriorityClass(self._proc(), ctypes.c_ulong(int(value))))
        except Exception:
            return False

    def get_memory_priority(self) -> Optional[int]:
        fn = getattr(self._k32, "GetProcessInformation", None) if self.available else None
        if fn is None:
            return None
        try:
            info = _MemoryPriorityInformation()
            ok = fn(self._proc(), _PROCESS_MEMORY_PRIORITY, ctypes.byref(info), ctypes.sizeof(info))
            return int(info.MemoryPriority) if ok else None
        except Exception:
            return None

    def set_memory_priority(self, value: int) -> bool:
        fn = getattr(self._k32, "SetProcessInformation", None) if self.available else None
        if fn is None:
            return False
        try:
            info = _MemoryPriorityInformation(int(value))
            return bool(fn(self._proc(), _PROCESS_MEMORY_PRIORITY, ctypes.byref(info), ctypes.sizeof(info)))
        except Exception:
            return False

    def disable_execution_speed_throttling(self) -> bool:
        """Opt out of EcoQoS for this process (Windows 10 1709+); False where unsupported."""
        fn = getattr(self._k32, "SetProcessInformation", None) if self.available else None
        if fn is None:
            return False
        try:
            state = _PowerThrottlingState(
                _PROCESS_POWER_THROTTLING_CURRENT_VERSION,
                _PROCESS_POWER_THROTTLING_EXECUTION_SPEED,  # control execution speed...
                0,                                          # ...and turn its throttling off
            )
            return bool(fn(self._proc(), _PROCESS_POWER_THROTTLING, ctypes.byref(state), ctypes.sizeof(state)))
        except Exception:
            return False


def ensure_interactive_scheduling(
    minimum: str = "normal",
    *,
    raise_memory_priority: bool = True,
    disable_power_throttling: bool = True,
    api: Any = None,
    log: Optional[logging.Logger] = None,
) -> Dict[str, Any]:
    """Raise this process to at least ``minimum`` and log one ``process_priority`` line.

    ``minimum`` is clamped to ``above_normal``; an unknown name means ``normal``.
    Returns the facts that were logged (also used by the tests).
    """
    api = api if api is not None else WindowsSchedulingApi()
    target = str(minimum or "normal").strip().lower()
    if _rank(target) < 0:
        target = "normal"
    if _rank(target) > _rank(_MAX_TARGET):
        target = _MAX_TARGET

    result: Dict[str, Any] = {
        "available": bool(getattr(api, "available", False)),
        "before": "unknown",
        "after": "unknown",
        "raised": False,
        "memory_before": None,
        "memory_after": None,
        "power_throttling": "unchanged",
    }
    if not result["available"]:
        if log is not None:
            log.info("process_priority available=False")
        return result

    before = api.get_priority_class()
    result["before"] = priority_name(before)
    after_name = result["before"]
    if before is not None and 0 <= _rank(result["before"]) < _rank(target):
        if api.set_priority_class(PRIORITY_CLASSES[target]):
            result["raised"] = True
        after_name = priority_name(api.get_priority_class())
    result["after"] = after_name

    if raise_memory_priority:
        mem_before = api.get_memory_priority()
        result["memory_before"] = mem_before
        mem_after = mem_before
        if mem_before is not None and mem_before < MEMORY_PRIORITY_NORMAL:
            if api.set_memory_priority(MEMORY_PRIORITY_NORMAL):
                mem_after = api.get_memory_priority()
        result["memory_after"] = mem_after

    if disable_power_throttling:
        result["power_throttling"] = "off" if api.disable_execution_speed_throttling() else "unsupported"

    if log is not None:
        log.info(
            "process_priority before=%s after=%s raised=%s memory_priority_before=%s "
            "memory_priority_after=%s power_throttling=%s",
            result["before"],
            result["after"],
            result["raised"],
            "unknown" if result["memory_before"] is None else result["memory_before"],
            "unknown" if result["memory_after"] is None else result["memory_after"],
            result["power_throttling"],
        )
    return result
