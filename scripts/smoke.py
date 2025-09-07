from __future__ import annotations

from localflow.config import Config
from localflow.inject import ClipboardInjector
from localflow.textproc import apply_code_mode


def main():
    cfg = Config(paste_injection=False, type_if_len_le=50)
    inj = ClipboardInjector(cfg)
    text = "open bracket hello close bracket comma new line tab world"
    mapped = apply_code_mode(text)
    ok = inj.inject(mapped)
    print("mapped:", mapped)
    print("inject ok:", ok)


if __name__ == "__main__":
    main()

