"""VF-12: synthesise the speech clips used by vf12_real_whisper_eval.py.

Uses the built-in Windows SAPI voices through COM (offline, no app launch).
Output: build/vf12-real/clips/<id>.wav (16 kHz mono 16-bit), not committed.
"""
from __future__ import annotations

import sys
from pathlib import Path

import win32com.client  # type: ignore[import-not-found]

HERE = Path(__file__).resolve().parent


def main(out_dir: str = "build/vf12-real/clips", only: str = "") -> None:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    rows = [
        ln.split("|", 1)
        for ln in (HERE / "vf12_eval_sentences.txt").read_text(encoding="utf-8").splitlines()
        if ln.strip() and not ln.startswith("#")
    ]
    wanted = {x for x in only.split(",") if x}
    voice = win32com.client.Dispatch("SAPI.SpVoice")
    voices = voice.GetVoices()
    for i, (clip_id, text) in enumerate(rows):
        if wanted and clip_id not in wanted:
            continue
        stream = win32com.client.Dispatch("SAPI.SpFileStream")
        fmt = win32com.client.Dispatch("SAPI.SpAudioFormat")
        fmt.Type = 22  # SAFT16kHz16BitMono
        stream.Format = fmt
        stream.Open(str((out / f"{clip_id}.wav").resolve()), 3)  # SSFMCreateForWrite
        voice.AudioOutputStream = stream
        voice.Voice = voices.Item(i % voices.Count)
        voice.Speak(text)
        stream.Close()
    print(f"clips: {len(rows)} -> {out}")


if __name__ == "__main__":
    main(*sys.argv[1:])
