# VoiceFlow Quality Pass — Design

**Date:** 2026-05-09
**Branch:** `feat/voiceflow-quality-pass`
**Author:** Nithin + Claude Code

## Goal

Land three improvements to VoiceFlow in a single branch, three commits, shipped together:

1. Drag-and-drop dock and history panel with persistent custom positions.
2. Tech vocabulary seed that biases Whisper recognition toward AI/coding terms and corrects the post-processed text. Editable file.
3. Replace the dead Ollama-based "AI learning analysis" with a `claude -p` subprocess that runs daily and proposes vocab additions and phrase corrections. Suggest-only on first version; nothing auto-applies.

## Why

Diagnostic findings from `C:\Users\Nithin\AppData\Local\VoiceFlow\`:

- The `VoiceFlow-DailyLearning` scheduled task runs cleanly every morning at 9 AM.
- The May 8 report processed **0 of 554 history items** — `_auto_analyze_text` produces text identical to the raw input on 100% of the day's transcripts, so the diff loop yields nothing.
- `transcription_corrections.jsonl` does not exist — Nithin has never used the correction-review UI.
- `ai_learning_analysis.error = "ollama_unavailable"` every day — Ollama isn't installed/running, so the LLM pass silently fails.
- The only patterns ever learned are runtime post-processor corrections like `cloud → Claude` (count 3) — the rest of the file is single-count phrasal duplicates that never reach the activation threshold.

The system is technically alive, functionally dead. We replace its brain (Claude via Max), give it a reliable cold-start vocab, and improve the actual user-facing affordance (movable dock).

## Scope

### Section 1 — Drag-and-drop dock + history panel

**Files:**
- `src/voiceflow/ui/visual_indicators.py` — bind mouse events.
- `src/voiceflow/ui/visual_config.py` — add `dock_custom_x/y`, `history_custom_x/y` fields and persistence.

**Mechanics:** bind `<ButtonPress-1>`, `<B1-Motion>`, `<ButtonRelease-1>` to the dock window's background frame and to the history panel's title bar. On press, capture the cursor offset from the window origin. On motion, call `window.geometry(f"+{x}+{y}")` with `cursor_screen - press_offset`. On release, persist to `~/.voiceflow/visual_config.json`.

**Persistence:** add to `VisualConfig`:

- `dock_custom_x: int = -1` (sentinel for "not set")
- `dock_custom_y: int = -1`
- `history_custom_x: int = -1`
- `history_custom_y: int = -1`

When sentinel, fall back to the existing positioning logic. When set, restore on next launch.

**Robustness:** on load, clamp coordinates: if `x > screen_w - 100` or `y > screen_h - 50` or either is negative non-sentinel, reset that pair to the sentinel. Handles monitor disconnects.

**UX:** cursor changes to `fleur` while dragging. No edge snapping in v1 (revisit if requested). `topmost` stays asserted.

**Out of scope:** per-app position memory, drag the live caption strip, snap-to-grid, multi-monitor preference re-discovery.

### Section 2 — Tech vocab seed + Whisper `initial_prompt`

**Files:**
- New: `src/voiceflow/core/vocab.py` — load, save, hot-reload, `initial_prompt` builder.
- New: `src/voiceflow/data/vocab_default.txt` — curated seed terms.
- Edit: `src/voiceflow/core/textproc.py` — pull vocab terms into `_GLOBAL_TECH_TERM_RULES`.
- Edit callsites of `engine.transcribe(...)` to pass `initial_prompt=vocab.initial_prompt()`.

**Vocab file format:** plain text, one term per line, optional `=` for canonical mapping.

```
Claude
Claude Code
Claude Desktop
MCP
subagent
prompt cache
cloud=Claude
OpenEI=OpenAI
OpenClub=OpenClaw
co-worker=Cowork
```

The right-hand side (canonical) is what gets written. Lines without `=` are added to the Whisper prompt and used as protected casing.

**Curation strategy:** seed with ~120 terms derived from Nithin's actual 554-transcript history. Categories:

- **Anthropic** (highest priority): Claude, Claude Code, Claude Desktop, Claude Opus, Claude Sonnet, Claude Haiku, Anthropic, MCP, subagent, sub-agents, slash command, prompt cache, system prompt, tool use, agent SDK, hooks, skills, Cowork, OpenClaw.
- **OpenAI**: ChatGPT, GPT-4, GPT-5, OpenAI, Codex, custom GPT, embeddings.
- **Google**: Gemini, Gemini 2.5 Pro, Gemini Flash, Gemini CLI, Google AI Studio.
- **Daily tools**: GitHub, VS Code, Cursor, PowerShell, Tailscale, Hetzner, Docker, Whisper, faster-whisper, CTranslate2.
- **Confirmed mistranscriptions to fix** (from `recent_history_events.jsonl`): cloud→Claude (in AI context), OpenEiase→OpenAI, OpenEI→OpenAI, OpenClaugh→OpenClaw, OpenClub→OpenClaw, Co-work→Cowork, BirdFi→bird feeder.
- **Personal projects**: VoiceFlow, Atlas, OpenClaw, HomeVision, Local Events Madison.

**Initial prompt construction:** join the first 50 highest-priority terms with commas into a single string. faster-whisper accepts up to ~244 tokens of `initial_prompt`. Cap at 200 chars to leave room for the `condition_on_previous_text` chain if it ever gets enabled.

**Hot reload:** `vocab.py` caches the file by mtime. On every `initial_prompt()` call, re-stat the file; reload if changed. Cheap.

**Out of scope:** per-app vocab, vocab from clipboard / surrounding window content, semantic embedding similarity.

### Section 3 — Claude-via-CLI daily learning replacement

**Files:**
- Edit: `src/voiceflow/ai/daily_learning.py` — replace `_run_ai_learning_analysis` body, simplify `INSTRUCTION_THEME_RULES` (remove themed-instruction pass; was never landing).
- Edit: `src/voiceflow/ai/llm_client.py` — keep the result type, swap implementation for a CLI subprocess client + a Gemini fallback.
- Edit: `src/voiceflow/ai/adaptive_memory.py` — one-line fix: call `_save_patterns()` at the end of `_purge_expired()` so the on-disk file matches in-memory state after expiry.
- New: `src/voiceflow/ai/claude_cli_client.py` — subprocess wrapper.
- New: `src/voiceflow/ai/gemini_client.py` — REST client for Gemini, used only as fallback.
- New: `<config_dir>/pending_review.jsonl` (created at runtime).

**Claude CLI invocation:**

```python
result = subprocess.run(
    [claude_path, "-p", prompt_text, "--output-format", "json", "--max-turns", "1"],
    capture_output=True, text=True, timeout=120, encoding="utf-8",
)
```

Parse the JSON envelope (`{"result": "...", "session_id": "...", ...}`), extract the `result` field, then parse the inner JSON the model produced.

**Prompt template (system):** "You analyze a single day of dictated transcripts to improve a local Whisper-based transcription app's accuracy. Return a single JSON object with: `vocab_additions[]` (each `{term, reason, confidence}`), `phrase_corrections[]` (each `{from, to, reason, confidence}`), `protected_terms[]`, `summary` (one sentence). Be conservative. Confidence ∈ {low, medium, high}. Do not propose blanket rewrites."

**Prompt template (user payload):**

```json
{
  "date": "2026-05-08",
  "transcripts": ["...", "..."],
  "current_vocab": ["...", "..."],
  "known_mistranscriptions": {"cloud": "Claude", "OpenEI": "OpenAI"}
}
```

Cap transcripts at 50 most recent entries to control prompt size. Truncate each at 500 chars.

**Suggest-only mode:** all suggestions write to `<config_dir>/pending_review.jsonl`, one suggestion per line with timestamp, source, and full payload. Nothing auto-applies. New CLI command `python -m voiceflow.ai.review pending` lists them. `python -m voiceflow.ai.review approve <id>` applies a single suggestion. `python -m voiceflow.ai.review approve --all` accepts the full batch. Future iteration may add a UI; not in scope here.

**Fallback chain:** if `shutil.which("claude")` is None or the call returns non-zero / timeouts → try Gemini via REST using `GEMINI_API_KEY`. If Gemini fails or key missing → log + skip; the rest of the daily report (stats, adaptive snapshot) still writes.

**Removed:** Ollama imports, `INSTRUCTION_THEME_RULES`, `_instruction_themes`, `_apply_instructional_signal`, `THEME_RECOMMENDATIONS`. Stats payload simplified accordingly.

### Section 4 — voiceflow-debug skill

**File:** `C:\AI_Projects\.claude\skills\voiceflow-debug\SKILL.md`.

Triggers on: "voiceflow", "transcription quality", "dock", "hotkey not working", "what did learning learn", "where are voiceflow logs", "scheduled task". Operational knowledge:

- Data paths (`AppData/Local/VoiceFlow/...`).
- How to inspect `daily_learning_reports/` (latest first).
- How to query the scheduled task.
- How to inspect / approve `pending_review.jsonl`.
- How to read `~/.voiceflow/vocab.txt` and the visual config.
- How to launch the dev mode vs the packaged build.

Skill is information-only — does not modify code. Future code changes go through normal Claude Code flow.

## Sequencing and commits

Single branch `feat/voiceflow-quality-pass`. Three feature commits in order:

1. `feat(ui): drag-and-drop dock and history panel with persistent positions`
2. `feat(asr): tech vocab seed with Whisper initial_prompt and post-processor rules`
3. `feat(learning): claude-cli daily analysis with suggest-only review queue`

A fourth commit adds the `voiceflow-debug` skill at `C:\AI_Projects\.claude\skills\`. The skill commit is on a different repo (`AI_Projects/.claude` is not in the VoiceFlow repo) — handled separately, not part of the VoiceFlow PR.

Optional fifth commit: `chore: remove dead Ollama analysis paths and instruction-theme rules`.

## Testing

**Unit:**

- `tests/test_vocab.py` — load default file, parse `=` mappings, mtime-based reload, `initial_prompt` truncation.
- `tests/test_daily_learning_claude.py` — mock subprocess returning canned JSON, parse round-trip, fallback to Gemini, fallback to skip.
- `tests/test_visual_drag.py` — synthetic Tk event sequence, verify position persisted.
- `tests/test_adaptive_memory.py` — extend existing tests to cover the `_purge_expired` save fix.

**Manual end-to-end:**

1. Launch `python voiceflow.py`.
2. Drag dock to top-right; restart; verify position restored.
3. Hold Ctrl+Shift, say "I want to use Claude with MCP and subagents". Verify "Claude" not "cloud", "MCP" not "M C P", "subagents" not "sub agents".
4. Run `python -m voiceflow.ai.daily_learning --days-back 1 --dry-run`; inspect the report; confirm `claude -p` was called and JSON parsed.
5. Run `python -m voiceflow.ai.review pending`; confirm suggestions appear; approve one; verify vocab.txt updated.

**Risk and rollback:** all three changes are reversible.

- Drag: delete `dock_custom_x/y` keys from visual_config.json → falls back to BOTTOM_CENTER.
- Vocab: delete `~/.voiceflow/vocab.txt` → vocab module returns empty initial_prompt and adds no rules. Whisper behaves as before.
- Daily Claude pass: rename or remove `claude_cli_client.py` import; daily job logs and returns the existing stats. Runtime ASR untouched.

## Out of scope (deferred)

- Drag-to-edge magnet snapping.
- Per-app dock position memory.
- Vocab UI (add/remove via tray menu).
- Auto-apply mode for suggestions.
- Migrating old `adaptive_patterns.json` rules into the new vocab format.
- Replacing the runtime adaptive_memory engine.
- Removing daily_learning batch entirely (Claude pass replaces only its brain).
