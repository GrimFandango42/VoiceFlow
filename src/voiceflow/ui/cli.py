from __future__ import annotations

import threading
import traceback
import sys
from typing import Optional
import logging

import numpy as np

from voiceflow.core.config import Config
from voiceflow.utils.audio_enhanced import EnhancedAudioRecorder as AudioRecorder
from voiceflow.utils.asr_buffer_safe import BufferSafeWhisperASR as WhisperASR
from voiceflow.utils.inject import ClipboardInjector
from voiceflow.utils.hotkeys import PTTHotkeyListener
from voiceflow.utils.utils import is_admin, nvidia_smi_info
from voiceflow.utils.textproc import apply_code_mode
import keyboard
from voiceflow.utils.tray import TrayController
from voiceflow.utils.logging_setup import AsyncLogger, default_log_dir
from voiceflow.utils.settings import load_config, save_config


class App:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.rec = AudioRecorder(cfg)
        self.asr = WhisperASR(cfg)
        self.injector = ClipboardInjector(cfg)
        self._worker: Optional[threading.Thread] = None
        self._worker_lock = threading.Lock()
        self.code_mode = cfg.code_mode_default
        self._log = logging.getLogger("localflow")

    def start_recording(self):
        try:
            if not self.rec.is_recording():
                print("[MIC] Listening...")
                self._log.info("recording_started")
                self.rec.start()
        except Exception as e:
            print(f"Audio start error: {e}")
            traceback.print_exc()
            self._log.exception("audio_start_error: %s", e)

    def stop_recording(self):
        try:
            audio = self.rec.stop()
            try:
                frames = int(getattr(audio, 'size', 0))
            except Exception:
                frames = 0
            self._log.info("recording_stopped frames=%s", frames)
        except Exception as e:
            print(f"Audio stop error: {e}")
            traceback.print_exc()
            self._log.exception("audio_stop_error: %s", e)
            return

        if audio.size == 0:
            print("(No audio captured)")
            return

        def worker(buf: np.ndarray):
            try:
                print("[PROCESSING] PROCESSING...")
                import time as _t
                t0 = _t.perf_counter()
                text = self.asr.transcribe(buf)
                dt = _t.perf_counter() - t0
                self._log.info("transcribed seconds=%.3f chars=%d", dt, len(text))
                out = text
                if self.code_mode:
                    out = apply_code_mode(out, lowercase=self.cfg.code_mode_lowercase)
                print(f"=> {out}")
                if out:
                    self.injector.inject(out)
            except Exception as e:
                print(f"Transcription error: {e}")
                traceback.print_exc()
                self._log.exception("transcription_error: %s", e)

        # Ensure only one worker runs at a time
        with self._worker_lock:
            t = threading.Thread(target=worker, args=(audio,), daemon=True)
            self._worker = t
            t.start()


def main(argv=None):
    cfg = load_config(Config())

    # Initialize async logging to a rotating file
    _alog = AsyncLogger(default_log_dir())

    if not is_admin():
        print("Warning: Not running as Administrator. Global hotkeys and key injection may be limited in elevated apps.")
    info = nvidia_smi_info()
    if info:
        print(f"GPU: {info}")

    app = App(cfg)

    tray = None
    if cfg.use_tray:
        try:
            tray = TrayController(app)
            tray.start()
            print("Tray started (if dependencies installed).")
        except Exception as e:
            print(f"Tray failed to start: {e}")

    # Hotkey toggles
    def toggle_code_mode():
        app.code_mode = not app.code_mode
        state = "ON" if app.code_mode else "OFF"
        print(f"Code mode: {state}")
        save_config(app.cfg)

    def toggle_injection():
        app.cfg.paste_injection = not app.cfg.paste_injection
        state = "Paste" if app.cfg.paste_injection else "Type"
        print(f"Injection: {state}")
        save_config(app.cfg)

    keyboard.add_hotkey('ctrl+alt+c', toggle_code_mode, suppress=False)
    keyboard.add_hotkey('ctrl+alt+p', toggle_injection, suppress=False)
    def toggle_enter():
        app.cfg.press_enter_after_paste = not app.cfg.press_enter_after_paste
        print(f"After-paste Enter: {'ON' if app.cfg.press_enter_after_paste else 'OFF'}")
        save_config(app.cfg)

    keyboard.add_hotkey('ctrl+alt+enter', toggle_enter, suppress=False)

    listener = PTTHotkeyListener(
        cfg,
        on_start=app.start_recording,
        on_stop=app.stop_recording,
    )
    listener.start()
    listener.run_forever()


if __name__ == "__main__":
    sys.exit(main())
