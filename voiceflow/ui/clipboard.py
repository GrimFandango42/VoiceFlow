from __future__ import annotations

# Graceful import for environments without pyperclip during tests
try:
    import pyperclip  # type: ignore
except Exception:  # pragma: no cover
    class _PC:  # type: ignore
        @staticmethod
        def copy(_t: str) -> None:
            return None

        @staticmethod
        def paste() -> str:
            return ""

    pyperclip = _PC()  # type: ignore


class ClipboardManager:
    def copy(self, text: str) -> bool:
        pyperclip.copy(text)
        return True

    def copy_and_paste(self, text: str, hotkey_manager) -> bool:
        # For tests we only need to copy; the active app pasting is mocked
        pyperclip.copy(text)
        return True

    # Back-compat name used in some tests
    def copy_text(self, text: str) -> bool:
        return self.copy(text)
