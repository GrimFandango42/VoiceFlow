"""Scheduling for the reconstruction pass (VF-17 item 5): sync-in-budget or async.

Speed is already good and must not regress. A reconstruction on a CPU-only local
model takes seconds (llama3.1:8b measured at ~8 s warm on this machine), so it
cannot sit between "release the key" and "text appears". Two paths:

    sync   the pipeline waits up to ``reconstruction_budget_ms`` (default 800)
           for the result; if it arrives, passes the guards and is accepted,
           the improved text is what gets pasted.
    async  the fast text is pasted immediately. The reconstruction keeps
           running in the background (same hard timeout); if it is accepted a
           *pending improvement* is stored and the user is told (overlay note +
           tray entry + hotkey) so they can swap it in with "replace last paste".

``reconstruction_mode``:  ``auto`` (default) | ``sync`` | ``async`` | ``off``.
``auto`` is async until at least ``AUTO_MIN_SAMPLES`` reconstructions have been
timed and their p95 fits the budget; it goes back to async if that stops being
true. On CPU with an 8B model it therefore stays async, and a paste is never
delayed. The wait itself is measured (``added_latency``) so the claim can be
checked rather than assumed.
"""

from __future__ import annotations

import logging
import threading
import time
from collections import deque
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass
from typing import Any, Callable, Deque, List, Optional, Sequence

from voiceflow.ai.reconstruction import ReconstructionOutcome, Reconstructor, percentile

logger = logging.getLogger(__name__)

AUTO_MIN_SAMPLES = 5


class LatencyTracker:
    """Rolling window of latencies (ms)."""

    def __init__(self, maxlen: int = 50) -> None:
        self._values: Deque[float] = deque(maxlen=maxlen)
        self._lock = threading.Lock()

    def record(self, ms: float) -> None:
        with self._lock:
            self._values.append(float(ms))

    def snapshot(self) -> List[float]:
        with self._lock:
            return list(self._values)

    @property
    def count(self) -> int:
        return len(self.snapshot())

    def p50(self) -> float:
        return percentile(self.snapshot(), 0.5)

    def p95(self) -> float:
        return percentile(self.snapshot(), 0.95)


@dataclass
class PendingImprovement:
    utterance_id: str
    pasted_text: str
    improved_text: str
    created_at: float


class ReconstructionJob:
    def __init__(self, seq: int) -> None:
        self.seq = seq
        self.future: Future = Future()  # replaced by the executor's future right after construction
        self.cancelled = False

    def wait(self, timeout_s: float) -> Optional[ReconstructionOutcome]:
        """Outcome if it is ready within ``timeout_s``, else None (never raises)."""
        if timeout_s <= 0 and not self.future.done():
            return None
        try:
            return self.future.result(timeout=max(0.0, timeout_s))
        except Exception:
            return None

    def done(self) -> bool:
        return self.future.done()


class ReconstructionCoordinator:
    def __init__(
        self,
        cfg: Any,
        reconstructor: Optional[Reconstructor] = None,
        *,
        executor: Optional[ThreadPoolExecutor] = None,
        context_size: int = 2,
    ) -> None:
        self.cfg = cfg
        self.reconstructor = reconstructor or Reconstructor(cfg)
        # One worker: successive dictations queue rather than stacking LLM
        # calls on the same CPU cores.
        self._executor = executor or ThreadPoolExecutor(max_workers=1, thread_name_prefix="vf-reconstruct")
        self.latency = LatencyTracker()          # model time, per attempt
        self.added_latency = LatencyTracker()    # time the PASTE was delayed
        self._seq = 0
        self._jobs: Deque[ReconstructionJob] = deque(maxlen=8)
        self._seq_lock = threading.Lock()
        self._context: Deque[str] = deque(maxlen=max(1, context_size))
        self.pending: Optional[PendingImprovement] = None
        self._pending_lock = threading.Lock()

    # ------------------------------------------------------------- policy
    def _opt(self, name: str, default: Any) -> Any:
        return getattr(self.cfg, name, default)

    @property
    def mode(self) -> str:
        if not bool(self._opt("reconstruction_enabled", True)):
            return "off"
        return str(self._opt("reconstruction_mode", "auto") or "auto").lower()

    @property
    def budget_s(self) -> float:
        return max(0.0, float(self._opt("reconstruction_budget_ms", 800))) / 1000.0

    def sync_wait_s(self) -> float:
        """How long the paste may wait for the reconstruction (0 = do not wait)."""
        mode = self.mode
        if mode in {"off", "async"}:
            return 0.0
        if mode == "sync":
            return self.budget_s
        # auto: only wait once we have evidence the model fits the budget.
        if self.latency.count >= AUTO_MIN_SAMPLES and self.latency.p95() <= self.budget_s * 1000.0:
            return self.budget_s
        return 0.0

    # --------------------------------------------------------------- run
    def begin(
        self,
        pre_text: str,
        raw_text: str = "",
        *,
        code_mode: bool = False,
        destination_profile: str = "",
    ) -> Optional[ReconstructionJob]:
        """Start a reconstruction in the background. None when the policy skips it."""
        run, _reason = self.reconstructor.should_run(
            pre_text, code_mode=code_mode, destination_profile=destination_profile
        )
        if not run:
            return None
        with self._seq_lock:
            self._seq += 1
            seq = self._seq
            for older in self._jobs:  # stale queued work is not worth CPU
                older.cancelled = True
            context = tuple(self._context)
        timeout = float(self._opt("reconstruction_timeout_s", 45.0))
        job = ReconstructionJob(seq)

        def _run() -> ReconstructionOutcome:
            if job.cancelled:
                return ReconstructionOutcome("skipped", reason="superseded")
            outcome = self.reconstructor.reconstruct(pre_text, raw_text, context=context, timeout_s=timeout)
            if outcome.status in {"accepted", "rejected", "unchanged"}:
                self.latency.record(outcome.latency_ms)
            return outcome

        # `job` exists before the worker can run, so the closure never races its own handle.
        with self._seq_lock:
            self._jobs.append(job)
        job.future = self._executor.submit(_run)
        return job

    def remember(self, final_text: str) -> None:
        """Feed the text that was actually pasted back in as context for the next utterance."""
        if final_text and final_text.strip():
            self._context.append(final_text.strip())

    # ---------------------------------------------------------- async path
    def attach_async(
        self,
        job: ReconstructionJob,
        *,
        utterance_id: str,
        pasted_text: str,
        on_done: Optional[Callable[[ReconstructionOutcome, bool], None]] = None,
        replaceable: bool = True,
    ) -> None:
        """When ``job`` finishes, record the outcome and (if allowed) publish a pending improvement.

        ``on_done`` always runs, so a rejection or timeout is logged whether or not the paste landed. ``replaceable=False``
        (the paste fell back to the clipboard: there is nothing in the target window to swap) only withholds the
        "replace last paste" offer.
        """

        def _finish(fut: Future) -> None:
            try:
                outcome = fut.result()
            except Exception as exc:
                outcome = ReconstructionOutcome("failed", reason="exception", detail=str(exc))
            usable = False
            with self._seq_lock:
                latest = job.seq == self._seq
            if replaceable and outcome.accepted and latest and outcome.text.strip() != pasted_text.strip():
                with self._pending_lock:
                    self.pending = PendingImprovement(utterance_id, pasted_text, outcome.text, time.time())
                usable = True
            if on_done is not None:
                try:
                    on_done(outcome, usable)
                except Exception as exc:  # callbacks must not kill the worker
                    logger.debug("reconstruction on_done failed: %s", exc)

        job.future.add_done_callback(_finish)

    def clear_pending(self) -> None:
        with self._pending_lock:
            self.pending = None

    def take_pending(self, max_age_s: float = 120.0) -> Optional[PendingImprovement]:
        with self._pending_lock:
            pending = self.pending
            if pending is None:
                return None
            if time.time() - pending.created_at > max_age_s:
                self.pending = None
                return None
            return pending

    def has_pending(self, max_age_s: float = 120.0) -> bool:
        return self.take_pending(max_age_s) is not None

    def shutdown(self) -> None:
        try:
            self._executor.shutdown(wait=False, cancel_futures=True)
        except Exception:
            pass
