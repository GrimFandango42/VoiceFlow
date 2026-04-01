from __future__ import annotations

import argparse
import hashlib
import json
import logging
import time
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import date, datetime, timedelta
from difflib import SequenceMatcher
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from voiceflow.ai.adaptive_memory import AdaptiveLearningManager
from voiceflow.core.config import Config
from voiceflow.core.textproc import format_transcript_text, normalize_context_terms
from voiceflow.utils.settings import config_dir, load_config

logger = logging.getLogger(__name__)

INTENT_CUES = (
    "please",
    "i want",
    "i would like",
    "let's",
    "lets",
    "make sure",
    "we should",
    "should be",
    "need to",
    "fix",
    "improve",
    "not working",
    "still not",
    "goal",
)

INSTRUCTION_THEME_RULES: Dict[str, Tuple[str, ...]] = {
    "formatting_capitalization": (
        "capitalization",
        "capitalize",
        "capitalized",
        "sentence structure",
    ),
    "formatting_paragraphs": (
        "paragraph",
        "paragraphs",
        "spacing",
        "readable",
        "formatting",
        "split",
        "grouping",
    ),
    "noise_resilience": (
        "cough",
        "sneeze",
        "throat",
        "noise",
        "white noise",
        "cut off",
        "clipped",
        "pause",
    ),
    "ui_recent_history": (
        "recent history",
        "history button",
        "reverse chronological",
        "most recent",
    ),
    "ui_correction_review": (
        "correction review",
        "corrections ui",
        "side-by-side",
        "side by side",
        "left right",
        "inline correction",
    ),
    "release_reliability": (
        "trigger",
        "release",
        "stuck",
        "hotkey",
        "stop transcription",
    ),
    "performance_latency": (
        "latency",
        "speed",
        "responsive",
        "real-time",
        "real time",
        "slow",
    ),
    "memory_efficiency": (
        "memory",
        "buffer",
        "leak",
        "cleanup",
        "over 1gb",
    ),
    "learning_system": (
        "self-learning",
        "self learning",
        "learning system",
        "batch job",
        "daily learning",
        "continual learning",
    ),
}

_PAIR_WEIGHT_BY_CORRECTION_SOURCE: Dict[str, float] = {
    "manual_correction": 1.5,
    "user_correction": 1.0,
}
_AUTO_PAIR_WEIGHT = 0.5


def _pair_weight_for_source(source: str) -> float:
    """Return pair accumulation weight for a correction source string.

    Manual corrections (user actively edited the text) are highest signal.
    Generic user-correction records from the history UI get a standard weight.
    Auto-analysis from the history stream gets a reduced weight.
    """
    return _PAIR_WEIGHT_BY_CORRECTION_SOURCE.get(
        str(source or "").strip().lower(), 1.0
    )


THEME_RECOMMENDATIONS: Dict[str, str] = {
    "formatting_capitalization": "Prioritize sentence-start capitalization and punctuation consistency.",
    "formatting_paragraphs": "Rebalance paragraph splitting for readability without over-fragmenting.",
    "noise_resilience": "Strengthen cough/sneeze filtering while preserving nearby spoken words.",
    "ui_recent_history": "Keep recent history ordering and refresh behavior deterministic and immediate.",
    "ui_correction_review": "Keep correction review pinned/inline across repeated dictation cycles.",
    "release_reliability": "Harden hotkey press/release state transitions and stuck-state recovery.",
    "performance_latency": "Protect release-to-text latency while applying quality improvements.",
    "memory_efficiency": "Bound memory growth and purge stale state for long-running sessions.",
    "learning_system": "Use corrections plus conversational instruction signals for daily learning.",
    "workflow_feedback": "Capture unresolved user intent and convert it into next-iteration tasks.",
}


def _safe_jsonl_lines(path: Path) -> Iterable[Dict[str, Any]]:
    if not path.exists():
        return []
    rows: List[Dict[str, Any]] = []
    try:
        with path.open("r", encoding="utf-8") as handle:
            for raw in handle:
                line = raw.strip()
                if not line:
                    continue
                try:
                    payload = json.loads(line)
                except Exception:
                    continue
                if isinstance(payload, dict):
                    rows.append(payload)
    except Exception as exc:
        logger.warning("Failed reading %s: %s", path, exc)
    return rows


def _parse_local_date_from_epoch(value: Any) -> Optional[date]:
    try:
        if value is None:
            return None
        ts = float(value)
        if ts <= 0:
            return None
        return datetime.fromtimestamp(ts).date()
    except Exception:
        return None


def _parse_local_date_from_iso(value: Any) -> Optional[date]:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        return datetime.fromisoformat(text).date()
    except Exception:
        return None


def _parse_local_date_from_hms(value: Any, file_mtime: datetime) -> Optional[date]:
    text = str(value or "").strip()
    parts = text.split(":")
    if len(parts) != 3 or not all(part.isdigit() for part in parts):
        return None
    try:
        hh, mm, ss = (int(parts[0]), int(parts[1]), int(parts[2]))
        candidate = file_mtime.replace(hour=hh, minute=mm, second=ss, microsecond=0)
        # Handle midnight rollover for files written shortly after midnight.
        if candidate > (file_mtime + timedelta(seconds=60)):
            candidate = candidate - timedelta(days=1)
        return candidate.date()
    except Exception:
        return None


def extract_token_replacements(raw_text: str, final_text: str) -> List[Tuple[str, str]]:
    raw_words = _tokenize_words(raw_text)
    final_words = _tokenize_words(final_text)
    if not raw_words or not final_words:
        return []
    matcher = SequenceMatcher(a=[t.lower() for t in raw_words], b=[t.lower() for t in final_words])
    matches: List[Tuple[str, str]] = []
    for tag, a0, a1, b0, b1 in matcher.get_opcodes():
        if tag != "replace":
            continue
        if (a1 - a0) != 1 or (b1 - b0) != 1:
            continue
        src = raw_words[a0]
        dst = final_words[b0]
        if src.lower() == dst.lower():
            continue
        if len(src) < 2 or len(dst) < 2:
            continue
        matches.append((src, dst))
    return matches


def _tokenize_words(text: str) -> List[str]:
    chars = []
    token = []
    for ch in str(text or ""):
        if ch.isalpha() or ch.isdigit() or ch == "'":
            token.append(ch)
        else:
            if token:
                chars.append("".join(token))
                token = []
    if token:
        chars.append("".join(token))
    return chars


@dataclass
class DailyLearningStats:
    target_date: str
    dry_run: bool
    history_items_total: int
    history_items_used: int
    history_items_skipped_ambiguous_date: int
    correction_items_total: int
    correction_items_used: int
    observed_from_user_corrections: int
    observed_from_manual_corrections: int
    observed_from_auto_analysis: int
    instructional_items_total: int
    instructional_items_used: int
    observed_from_instruction_pass: int
    replacement_pairs_from_user: int
    replacement_pairs_from_auto: int
    report_path: str


class DailyLearningJob:
    def __init__(self, cfg: Optional[Config] = None, base_dir: Optional[Path] = None):
        self.cfg = cfg or load_config(Config())
        self.base_dir = Path(base_dir) if base_dir else config_dir()
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self.corrections_path = self.base_dir / "transcription_corrections.jsonl"
        self.history_path = self.base_dir / "recent_history_events.jsonl"
        self.insights_path = self.base_dir / "self_learning_insights.json"
        self.report_dir = self.base_dir / "daily_learning_reports"
        self.report_dir.mkdir(parents=True, exist_ok=True)
        self.manager = AdaptiveLearningManager(self.cfg)
        if base_dir is not None:
            self.manager.audit_path = self.base_dir / "adaptive_audit.jsonl"
            self.manager.patterns_path = self.base_dir / "adaptive_patterns.json"
            self.manager._patterns = {
                "replacements": {},
                "token_counts": {},
                "updated_at": int(time.time()),
            }
            self.manager._load_patterns()
            self.manager._purge_expired()

    def _correction_date(self, payload: Dict[str, Any]) -> Optional[date]:
        candidate = _parse_local_date_from_iso(payload.get("local_ts"))
        if candidate:
            return candidate
        return _parse_local_date_from_epoch(payload.get("ts"))

    def _history_date(self, payload: Dict[str, Any], file_mtime: datetime) -> Optional[date]:
        candidate = _parse_local_date_from_epoch(payload.get("event_epoch"))
        if candidate:
            return candidate
        candidate = _parse_local_date_from_iso(payload.get("local_ts"))
        if candidate:
            return candidate
        candidate = _parse_local_date_from_iso(payload.get("ts"))
        if candidate:
            return candidate
        return _parse_local_date_from_hms(payload.get("ts"), file_mtime=file_mtime)

    def _load_corrections_for_date(self, target: date, max_items: int) -> List[Dict[str, Any]]:
        rows: List[Dict[str, Any]] = []
        for payload in _safe_jsonl_lines(self.corrections_path):
            event_date = self._correction_date(payload)
            if event_date != target:
                continue
            original = str(payload.get("original_text", "")).strip()
            corrected = str(payload.get("corrected_text", "")).strip()
            if not original or not corrected:
                continue
            rows.append(
                {
                    "event_date": event_date.isoformat(),
                    "original_text": original,
                    "corrected_text": corrected,
                    "item_id": int(payload.get("item_id", 0) or 0),
                    "source": str(payload.get("source", "") or "").strip(),
                    "raw_payload": payload,
                }
            )
        if max_items > 0 and len(rows) > max_items:
            rows = rows[-max_items:]
        return rows

    def _load_history_for_date(
        self,
        target: date,
        max_items: int,
    ) -> Tuple[List[Dict[str, Any]], int, int]:
        rows: List[Dict[str, Any]] = []
        total = 0
        skipped_ambiguous = 0
        file_mtime = datetime.now()
        if self.history_path.exists():
            try:
                file_mtime = datetime.fromtimestamp(self.history_path.stat().st_mtime)
            except Exception:
                file_mtime = datetime.now()

        for payload in _safe_jsonl_lines(self.history_path):
            total += 1
            event_date = self._history_date(payload, file_mtime=file_mtime)
            if event_date is None:
                skipped_ambiguous += 1
                continue
            if event_date != target:
                continue
            full_text = str(payload.get("full_text", "")).strip()
            if not full_text:
                continue
            rows.append(
                {
                    "event_date": event_date.isoformat(),
                    "full_text": full_text,
                    "audio_duration": float(payload.get("audio_duration", 0.0) or 0.0),
                    "raw_payload": payload,
                }
            )

        # De-duplicate contiguous repeats from merged/replayed history loads.
        deduped: List[Dict[str, Any]] = []
        seen = set()
        for row in rows:
            key = (
                row["event_date"],
                row["full_text"].strip().lower(),
                round(float(row.get("audio_duration", 0.0)), 3),
            )
            if key in seen:
                continue
            seen.add(key)
            deduped.append(row)

        if max_items > 0 and len(deduped) > max_items:
            deduped = deduped[-max_items:]
        return deduped, total, skipped_ambiguous

    @staticmethod
    def _auto_analyze_text(raw_text: str) -> str:
        normalized = normalize_context_terms(raw_text)
        return format_transcript_text(normalized)

    @staticmethod
    def _content_hash(text: str) -> str:
        return hashlib.sha256(str(text or "").encode("utf-8", errors="ignore")).hexdigest()[:16]

    @staticmethod
    def _instruction_interpretation(raw_text: str) -> str:
        normalized = normalize_context_terms(raw_text)
        return format_transcript_text(normalized)

    @staticmethod
    def _instruction_themes(text: str) -> List[str]:
        lowered = str(text or "").strip().lower()
        if not lowered:
            return []
        matches: List[str] = []
        for theme, keywords in INSTRUCTION_THEME_RULES.items():
            if any(keyword in lowered for keyword in keywords):
                matches.append(theme)
        if not matches and any(cue in lowered for cue in INTENT_CUES):
            matches.append("workflow_feedback")
        return matches

    def _load_insights_state(self) -> Dict[str, Any]:
        default: Dict[str, Any] = {
            "updated_at_local": "",
            "theme_totals": {},
            "entry_points": {},
        }
        if not self.insights_path.exists():
            return default
        try:
            payload = json.loads(self.insights_path.read_text(encoding="utf-8"))
            if isinstance(payload, dict):
                default.update(payload)
        except Exception as exc:
            logger.warning("Failed to load learning insights: %s", exc)
        if not isinstance(default.get("theme_totals"), dict):
            default["theme_totals"] = {}
        if not isinstance(default.get("entry_points"), dict):
            default["entry_points"] = {}
        return default

    def _save_insights_state(self, state: Dict[str, Any]) -> None:
        try:
            state["updated_at_local"] = datetime.now().isoformat(timespec="seconds")
            self.insights_path.write_text(json.dumps(state, indent=2, ensure_ascii=True), encoding="utf-8")
        except Exception as exc:
            logger.warning("Failed to save learning insights: %s", exc)

    def _apply_instructional_signal(
        self,
        *,
        text: str,
        themes: List[str],
        source: str,
        event_date: str,
        dry_run: bool,
        insights_state: Dict[str, Any],
    ) -> bool:
        source_text = str(text or "").strip()
        if not source_text:
            return False

        interpreted = self._instruction_interpretation(source_text)
        if not interpreted:
            return False

        if not dry_run:
            sample_value = (
                interpreted[:200]
                if bool(self.manager.store_raw_text)
                else self._content_hash(interpreted)
            )
            theme_totals = insights_state.setdefault("theme_totals", {})
            for theme in themes:
                bucket = theme_totals.get(theme, {"count": 0, "last_seen": "", "sample": ""})
                bucket["count"] = int(bucket.get("count", 0)) + 1
                bucket["last_seen"] = event_date
                if sample_value:
                    bucket["sample"] = sample_value
                theme_totals[theme] = bucket

            self.manager.observe(
                raw_text=source_text,
                final_text=interpreted,
                metadata={
                    "source": "daily_instruction_pass",
                    "entry_point": source,
                    "event_date": event_date,
                    "themes": themes,
                },
            )
        return True

    def run(
        self,
        days_back: int = 1,
        dry_run: bool = False,
        max_history_items: int = 400,
        max_correction_items: int = 400,
    ) -> Dict[str, Any]:
        if days_back < 1:
            raise ValueError("days_back must be >= 1")

        target_date = (datetime.now().date() - timedelta(days=days_back))
        corrections = self._load_corrections_for_date(target=target_date, max_items=max_correction_items)
        history_rows, history_total, history_skipped_ambiguous = self._load_history_for_date(
            target=target_date,
            max_items=max_history_items,
        )

        pair_counts: Counter[str] = Counter()
        pair_weights: Dict[str, float] = {}
        pair_sources: Dict[str, Counter[str]] = {}
        observed_user = 0
        observed_manual = 0
        observed_auto = 0
        used_history = 0
        used_corrections = 0
        instructional_total = 0
        instructional_used = 0
        observed_instruction = 0
        instructional_theme_counts: Counter[str] = Counter()
        insights_state = self._load_insights_state()
        entry_point_counts: Counter[str] = Counter(
            {
                "correction_items": int(len(corrections)),
                "history_items": int(len(history_rows)),
            }
        )

        for item in corrections:
            original = item["original_text"]
            corrected = item["corrected_text"]
            if not original or not corrected:
                continue
            used_corrections += 1
            item_source = item.get("source", "") or ""
            # Preserve manual_correction source so adaptive_memory weights it at 1.5.
            # All other correction-file entries use the generic daily batch source.
            obs_source = item_source if item_source == "manual_correction" else "daily_user_correction"
            pair_weight = _pair_weight_for_source(item_source)
            pairs = extract_token_replacements(original, corrected)
            for src, dst in pairs:
                key = f"{src.lower()}->{dst.lower()}"
                pair_counts[key] += 1
                pair_weights[key] = round(pair_weights.get(key, 0.0) + pair_weight, 3)
                pair_sources.setdefault(key, Counter())["user"] += 1
            if not dry_run:
                self.manager.observe(
                    raw_text=original,
                    final_text=corrected,
                    metadata={
                        "source": obs_source,
                        "event_date": item["event_date"],
                        "item_id": item.get("item_id", 0),
                    },
                )
            observed_user += 1
            if item_source == "manual_correction":
                observed_manual += 1

            feedback_text = corrected if len(corrected) >= len(original) else original
            themes = self._instruction_themes(feedback_text)
            if themes:
                instructional_total += 1
                instructional_used += 1
                entry_point_counts["instruction_from_corrections"] += 1
                for theme in themes:
                    instructional_theme_counts[theme] += 1
                if self._apply_instructional_signal(
                    text=feedback_text,
                    themes=themes,
                    source="correction_feedback",
                    event_date=item["event_date"],
                    dry_run=dry_run,
                    insights_state=insights_state,
                ):
                    observed_instruction += 1

        for item in history_rows:
            raw_text = item["full_text"]
            improved = self._auto_analyze_text(raw_text)
            if improved.strip() == raw_text.strip():
                continue
            used_history += 1
            pairs = extract_token_replacements(raw_text, improved)
            for src, dst in pairs:
                key = f"{src.lower()}->{dst.lower()}"
                pair_counts[key] += 1
                pair_weights[key] = round(pair_weights.get(key, 0.0) + _AUTO_PAIR_WEIGHT, 3)
                pair_sources.setdefault(key, Counter())["auto"] += 1
            if not dry_run:
                self.manager.observe(
                    raw_text=raw_text,
                    final_text=improved,
                    metadata={
                        "source": "daily_auto_analysis",
                        "event_date": item["event_date"],
                        "audio_duration": float(item.get("audio_duration", 0.0)),
                    },
                )
            observed_auto += 1

            themes = self._instruction_themes(raw_text)
            if themes:
                instructional_total += 1
                instructional_used += 1
                entry_point_counts["instruction_from_history"] += 1
                for theme in themes:
                    instructional_theme_counts[theme] += 1
                if self._apply_instructional_signal(
                    text=raw_text,
                    themes=themes,
                    source="recent_history",
                    event_date=item["event_date"],
                    dry_run=dry_run,
                    insights_state=insights_state,
                ):
                    observed_instruction += 1

        # Gather candidate pairs, then sort by accumulated weight so user-driven
        # corrections rank above equally-observed auto-analysis pairs.
        candidate_pairs: List[Dict[str, Any]] = []
        for key, count in pair_counts.most_common(48):
            src, dst = key.split("->", 1)
            source_counts = pair_sources.get(key, Counter())
            w = round(pair_weights.get(key, float(count)), 3)
            candidate_pairs.append(
                {
                    "from": src,
                    "to": dst,
                    "count": int(count),
                    "weight": w,
                    "sources": {
                        "user": int(source_counts.get("user", 0)),
                        "auto": int(source_counts.get("auto", 0)),
                    },
                }
            )
        candidate_pairs.sort(key=lambda x: (x["weight"], x["count"]), reverse=True)
        top_pairs = candidate_pairs[:24]

        user_pair_total = int(sum(int(source.get("user", 0)) for source in pair_sources.values()))
        auto_pair_total = int(sum(int(source.get("auto", 0)) for source in pair_sources.values()))
        top_instruction_themes = [
            {
                "theme": theme,
                "count": int(count),
                "recommendation": THEME_RECOMMENDATIONS.get(theme, ""),
            }
            for theme, count in instructional_theme_counts.most_common(10)
        ]

        if not dry_run and instructional_used > 0:
            entry_map = insights_state.setdefault("entry_points", {})
            for key, value in entry_point_counts.items():
                entry_map[key] = int(entry_map.get(key, 0)) + int(value)
            self._save_insights_state(insights_state)

        run_ts = datetime.now().strftime("%Y%m%d-%H%M%S")
        report_path = self.report_dir / f"daily_learning_{target_date.isoformat()}_{run_ts}.json"
        stats = DailyLearningStats(
            target_date=target_date.isoformat(),
            dry_run=bool(dry_run),
            history_items_total=int(history_total),
            history_items_used=int(used_history),
            history_items_skipped_ambiguous_date=int(history_skipped_ambiguous),
            correction_items_total=int(len(corrections)),
            correction_items_used=int(used_corrections),
            observed_from_user_corrections=int(observed_user),
            observed_from_manual_corrections=int(observed_manual),
            observed_from_auto_analysis=int(observed_auto),
            instructional_items_total=int(instructional_total),
            instructional_items_used=int(instructional_used),
            observed_from_instruction_pass=int(observed_instruction),
            replacement_pairs_from_user=user_pair_total,
            replacement_pairs_from_auto=auto_pair_total,
            report_path=str(report_path),
        )

        report = {
            "run_at_local": datetime.now().isoformat(timespec="seconds"),
            "target_date": target_date.isoformat(),
            "days_back": int(days_back),
            "dry_run": bool(dry_run),
            "stats": stats.__dict__,
            "top_replacement_pairs": top_pairs,
            "instructional_insights": {
                "top_themes": top_instruction_themes,
                "entry_point_counts": {k: int(v) for k, v in entry_point_counts.items()},
                "insights_path": str(self.insights_path),
            },
            "adaptive_snapshot": self.manager.snapshot(max_rules=12, max_tokens=20),
            "paths": {
                "base_dir": str(self.base_dir),
                "corrections_path": str(self.corrections_path),
                "history_path": str(self.history_path),
                "adaptive_patterns_path": str(self.manager.patterns_path),
                "adaptive_audit_path": str(self.manager.audit_path),
            },
        }

        report_path.write_text(json.dumps(report, indent=2, ensure_ascii=True), encoding="utf-8")
        return report


def run_daily_learning_job(
    days_back: int = 1,
    dry_run: bool = False,
    max_history_items: int = 400,
    max_correction_items: int = 400,
) -> Dict[str, Any]:
    job = DailyLearningJob()
    return job.run(
        days_back=days_back,
        dry_run=dry_run,
        max_history_items=max_history_items,
        max_correction_items=max_correction_items,
    )


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="VoiceFlow daily adaptive learning batch job",
    )
    parser.add_argument("--days-back", type=int, default=1, help="Process data from N days ago (default: 1)")
    parser.add_argument("--dry-run", action="store_true", help="Analyze and report without mutating adaptive patterns")
    parser.add_argument("--max-history-items", type=int, default=400, help="Cap history items loaded per run")
    parser.add_argument("--max-correction-items", type=int, default=400, help="Cap correction items loaded per run")
    parser.add_argument("--print-json", action="store_true", help="Print full JSON report to stdout")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = _build_arg_parser()
    args = parser.parse_args(argv)

    report = run_daily_learning_job(
        days_back=int(args.days_back),
        dry_run=bool(args.dry_run),
        max_history_items=int(args.max_history_items),
        max_correction_items=int(args.max_correction_items),
    )

    stats = report.get("stats", {})
    print(
        "[DAILY-LEARNING] date={date} dry_run={dry_run} corrections={corr_used}/{corr_total} "
        "history={hist_used}/{hist_total} instr={instr_used}/{instr_total} "
        "user_obs={uobs} auto_obs={aobs} instr_obs={iobs}".format(
            date=report.get("target_date", ""),
            dry_run=report.get("dry_run", False),
            corr_used=stats.get("correction_items_used", 0),
            corr_total=stats.get("correction_items_total", 0),
            hist_used=stats.get("history_items_used", 0),
            hist_total=stats.get("history_items_total", 0),
            instr_used=stats.get("instructional_items_used", 0),
            instr_total=stats.get("instructional_items_total", 0),
            uobs=stats.get("observed_from_user_corrections", 0),
            aobs=stats.get("observed_from_auto_analysis", 0),
            iobs=stats.get("observed_from_instruction_pass", 0),
        )
    )
    print(f"[DAILY-LEARNING] report={stats.get('report_path', '')}")

    top_pairs = report.get("top_replacement_pairs", [])
    if top_pairs:
        head = top_pairs[:5]
        preview = ", ".join(f"{item['from']}->{item['to']}({item['count']})" for item in head)
        print(f"[DAILY-LEARNING] top_pairs={preview}")

    if args.print_json:
        print(json.dumps(report, indent=2, ensure_ascii=True))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
