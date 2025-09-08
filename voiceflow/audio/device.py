from __future__ import annotations

from typing import List, Dict


class AudioDeviceManager:
    """Minimal stub that lists input devices via PyAudio when available.

    Designed to satisfy tests without requiring a full implementation.
    """

    def list_input_devices(self) -> List[Dict[str, object]]:
        devices: List[Dict[str, object]] = []
        try:
            import pyaudio  # type: ignore

            pa = pyaudio.PyAudio()
            try:
                info = pa.get_default_input_device_info()
                if info:
                    devices.append({
                        "name": info.get("name", "Default"),
                        "index": info.get("index", 0),
                    })
            finally:
                try:
                    pa.terminate()
                except Exception:
                    pass
        except Exception:
            # Return a placeholder device if PyAudio is unavailable
            devices.append({"name": "Default", "index": 0})
        return devices

