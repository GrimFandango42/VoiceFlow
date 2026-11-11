"""Live caption: the words you are saying, on screen, while the key is held.

This replaces the sliding-window preview in ``core.streaming`` for the app's
caption. That design re-decoded the last 8 seconds every pass, primed with its
own previous output for the same audio, and showed only what the last pass
returned. Three things followed from it:

* past 8 seconds the caption stopped being a transcript and became a moving
  window whose start cut through a word;
* a pass that was still decoding when the key came up could publish after the
  caption had been cleared, or over the final text;
* every way it could fail (model not ready, VAD dependency missing, decode
  error, text refused by the overlay) was a separate silent path, so "the
  caption doesn't show" could not be answered from the log.

The rules here, each enforced by a test in ``tests/runtime/test_live_caption.py``:

1. **Commit as you go.** Audio is decoded once it is behind a pause and is
   then *committed*: its text is kept and its audio is dropped. Only the audio
   after the last commit is re-decoded, so the caption is the whole dictation
   so far and each pass costs a bounded amount of GPU time.
2. **Nothing is published after stop().** ``stop()`` and publishing share a
   lock, so a late decode is dropped, never shown.
3. **One reason, always.** Every session ends with a ``summary()`` that says
   what happened, and a session that cannot caption says why on screen.

The class takes plain callables and has no dependency on the recorder, the ASR
engine or Tk, so the whole pipeline runs in a test with a fake engine.
"""

from __future__ import annotations

import logging
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

import numpy as np

logger = logging.getLogger(__name__)

#: ``transcribe(audio, prompt) -> text``
TranscribeFn = Callable[[np.ndarray, Optional[str]], str]
#: ``fetch(cursor) -> (new_samples, new_cursor)`` -- same contract as
#: ``BoundedRingBuffer.get_samples_since``.
FetchFn = Callable[[int], Tuple[np.ndarray, int]]

_FRAME_SECONDS = 0.03


def find_pause_cut(
    audio: np.ndarray,
    sample_rate: int,
    earliest_seconds: float,
    latest_seconds: float,
) -> int:
    """Sample index of the quietest moment between ``earliest`` and ``latest``.

    A commit has to cut the audio somewhere, and a cut through a word makes
    both halves decode badly. The quietest 30 ms frame in the allowed range is
    a pause if there is one and the gap between two words if there is not.
    Ties go to the latest frame, so as much audio as possible is committed.
    """
    frame = max(1, int(sample_rate * _FRAME_SECONDS))
    lo = max(0, int(earliest_seconds * sample_rate) // frame)
    hi = min(len(audio) // frame, int(latest_seconds * sample_rate) // frame)
    if hi <= lo:
        return max(0, min(len(audio), int(latest_seconds * sample_rate)))
    usable = audio[lo * frame : hi * frame].astype(np.float32, copy=False)
    energy = np.square(usable).reshape(hi - lo, frame).mean(axis=1)
    quietest = float(energy.min())
    # Latest frame within a hair of the minimum.
    candidates = np.nonzero(energy <= quietest * 1.05 + 1e-12)[0]
    best = int(candidates[-1])
    return (lo + best) * frame + frame // 2


def _join(left: str, right: str) -> str:
    left, right = (left or "").strip(), (right or "").strip()
    if not left:
        return right
    if not right:
        return left
    return f"{left} {right}"


class LiveCaptionSession:
    """One held key's worth of live caption.

    ``step()`` does one unit of work and never sleeps, so tests drive it
    directly. ``start()`` runs the same ``step()`` on a daemon thread.
    """

    def __init__(
        self,
        transcribe: TranscribeFn,
        fetch_audio: FetchFn,
        on_text: Callable[[str], None],
        *,
        on_status: Optional[Callable[[str], None]] = None,
        text_filter: Optional[Callable[[str], bool]] = None,
        sample_rate: int = 16000,
        interval_seconds: float = 0.7,
        start_delay_seconds: float = 0.6,
        min_audio_seconds: float = 0.6,
        window_seconds: float = 8.0,
        commit_tail_seconds: float = 1.0,
        silence_rms: float = 0.001,
        prompt_chars: int = 200,
        max_consecutive_errors: int = 3,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._transcribe = transcribe
        self._fetch = fetch_audio
        self._on_text = on_text
        self._on_status = on_status
        self._text_filter = text_filter
        self.sample_rate = int(sample_rate)
        self.interval_seconds = max(0.05, float(interval_seconds))
        self.start_delay_seconds = max(0.0, float(start_delay_seconds))
        self.min_audio_seconds = max(0.1, float(min_audio_seconds))
        self.window_seconds = max(2.0, float(window_seconds))
        self.commit_tail_seconds = max(0.2, float(commit_tail_seconds))
        self.silence_rms = max(0.0, float(silence_rms))
        self.prompt_chars = max(0, int(prompt_chars))
        self.max_consecutive_errors = max(1, int(max_consecutive_errors))
        self._clock = clock

        self._cursor = 0
        self._pending: List[np.ndarray] = []
        self._pending_samples = 0
        self._seen_samples = 0
        self._decoded_at_samples = -1
        self._committed = ""
        self._tentative = ""
        self._last_published = ""

        # Guards _stopped and every call out to on_text/on_status.
        self._publish_lock = threading.Lock()
        self._stopped = False
        self._gave_up = False
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None

        self._started_at = self._clock()
        self._stats: Dict[str, Any] = {
            "passes": 0,
            "commits": 0,
            "published": 0,
            "skipped_silent": 0,
            "filtered": 0,
            "errors": 0,
            "dropped_after_stop": 0,
            "first_text_ms": None,
            "max_decode_ms": 0.0,
            "last_error": "",
            "outcome": "no_audio",
        }
        self._consecutive_errors = 0

    # ------------------------------------------------------------------ public
    @property
    def text(self) -> str:
        """The caption as last computed: committed text plus the open tail."""
        return _join(self._committed, self._tentative)

    def start(self) -> None:
        if self._thread is not None:
            return
        self._thread = threading.Thread(target=self._run, name="LiveCaption", daemon=True)
        self._thread.start()

    def stop(self, join_timeout: float = 0.0) -> Dict[str, Any]:
        """End the session. After this returns, nothing more is published.

        Does not wait for a decode that is in flight (the key release must not
        queue behind the caption); that decode's result is dropped.
        """
        with self._publish_lock:
            self._stopped = True
        self._stop_event.set()
        thread = self._thread
        if thread is not None and join_timeout > 0 and thread is not threading.current_thread():
            thread.join(timeout=join_timeout)
        return self.summary()

    def summary(self) -> Dict[str, Any]:
        out = dict(self._stats)
        out["audio_seconds"] = round(self._seen_samples / float(self.sample_rate), 2)
        out["chars"] = len(self.text)
        return out

    def step(self) -> bool:
        """Do one unit of work. Returns True if a decode ran."""
        if self._stopped or self._gave_up:
            return False
        self._pull_audio()
        pending_seconds = self._pending_samples / float(self.sample_rate)
        seen_seconds = self._seen_samples / float(self.sample_rate)
        if seen_seconds < self.start_delay_seconds or pending_seconds < self.min_audio_seconds:
            return False
        if self._seen_samples == self._decoded_at_samples:
            return False  # nothing new since the last pass

        audio = np.concatenate(self._pending) if len(self._pending) > 1 else self._pending[0]
        self._pending = [audio]

        if pending_seconds > self.window_seconds:
            if not self._commit(audio, pending_seconds):
                return True
            audio = self._pending[0] if self._pending else np.zeros(0, dtype=np.float32)

        self._decoded_at_samples = self._seen_samples
        if len(audio) < int(self.min_audio_seconds * self.sample_rate):
            self._tentative = ""
            self._publish()
            return True
        text = self._decode(audio)
        if text is None:
            return True
        self._tentative = text
        self._publish()
        return True

    # ------------------------------------------------------------------ internals
    def _run(self) -> None:
        try:
            while not self._stop_event.is_set() and not self._gave_up:
                started = self._clock()
                worked = self.step()
                elapsed = self._clock() - started
                wait = (self.interval_seconds - elapsed) if worked else min(0.1, self.interval_seconds)
                if self._stop_event.wait(max(0.02, wait)):
                    break
        except Exception as exc:  # never let the caption take anything else down
            self._record_error(exc)
            logger.exception("live_caption_loop_crashed")

    def _pull_audio(self) -> None:
        try:
            new, cursor = self._fetch(self._cursor)
        except Exception as exc:
            self._record_error(exc)
            return
        self._cursor = int(cursor)
        if new is None or len(new) == 0:
            return
        chunk = np.asarray(new, dtype=np.float32).reshape(-1)
        self._pending.append(chunk)
        self._pending_samples += len(chunk)
        self._seen_samples += len(chunk)
        if self._stats["outcome"] == "no_audio":
            self._stats["outcome"] = "no_text"

    def _commit(self, audio: np.ndarray, pending_seconds: float) -> bool:
        """Decode everything up to a pause once, keep its text, drop its audio."""
        cut = find_pause_cut(
            audio,
            self.sample_rate,
            earliest_seconds=self.window_seconds * 0.4,
            latest_seconds=pending_seconds - self.commit_tail_seconds,
        )
        cut = max(1, min(len(audio) - 1, cut))
        text = self._decode(audio[:cut])
        if text is None:
            return False
        self._committed = _join(self._committed, text)
        self._tentative = ""
        tail = audio[cut:]
        self._pending = [tail]
        self._pending_samples = len(tail)
        self._stats["commits"] += 1
        return True

    def _decode(self, audio: np.ndarray) -> Optional[str]:
        """Text for ``audio``; "" for silence; None if the decode failed."""
        if self.silence_rms > 0 and len(audio):
            frame = max(1, int(self.sample_rate * _FRAME_SECONDS))
            usable = audio[: (len(audio) // frame) * frame]
            if len(usable):
                loudest = float(np.sqrt(np.square(usable).reshape(-1, frame).mean(axis=1).max()))
                if loudest < self.silence_rms:
                    self._stats["skipped_silent"] += 1
                    return ""
        prompt = self._committed[-self.prompt_chars :].strip() if self.prompt_chars else ""
        started = self._clock()
        try:
            raw = self._transcribe(audio, prompt or None)
        except Exception as exc:
            self._record_error(exc)
            return None
        self._consecutive_errors = 0
        self._stats["passes"] += 1
        self._stats["max_decode_ms"] = max(
            float(self._stats["max_decode_ms"]), round((self._clock() - started) * 1000.0, 1)
        )
        text = str(getattr(raw, "text", raw) or "").strip()
        if text and self._text_filter is not None:
            try:
                if self._text_filter(text):
                    self._stats["filtered"] += 1
                    return ""
            except Exception:
                pass
        return text

    def _record_error(self, exc: BaseException) -> None:
        self._stats["errors"] += 1
        self._stats["last_error"] = f"{type(exc).__name__}: {exc}"[:240]
        self._consecutive_errors += 1
        logger.warning("live_caption_error n=%d error=%s", self._consecutive_errors, self._stats["last_error"])
        if self._consecutive_errors >= self.max_consecutive_errors and not self._gave_up:
            self._gave_up = True
            self._stats["outcome"] = "failed"
            self._say(f"Live caption unavailable: {self._stats['last_error']}")

    def _publish(self) -> None:
        text = self.text
        if not text or text == self._last_published:
            return
        with self._publish_lock:
            if self._stopped:
                self._stats["dropped_after_stop"] += 1
                return
            try:
                self._on_text(text)
            except Exception as exc:
                self._stats["last_error"] = f"sink {type(exc).__name__}: {exc}"[:240]
                self._stats["errors"] += 1
                return
        self._last_published = text
        self._stats["published"] += 1
        self._stats["outcome"] = "ok"
        if self._stats["first_text_ms"] is None:
            self._stats["first_text_ms"] = round((self._clock() - self._started_at) * 1000.0, 1)

    def _say(self, message: str) -> None:
        if self._on_status is None:
            return
        with self._publish_lock:
            if self._stopped:
                return
            try:
                self._on_status(message)
            except Exception:
                pass
