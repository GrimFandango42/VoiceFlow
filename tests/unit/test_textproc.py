from __future__ import annotations

from localflow.textproc import apply_code_mode


def test_basic_symbols():
    assert apply_code_mode("open bracket x close bracket") == "[x]"
    assert apply_code_mode("open paren x close paren") == "(x)"
    assert apply_code_mode("open brace x close brace") == "{x}"


def test_punctuation_and_ops():
    s = apply_code_mode("a equals b double equals c comma d")
    assert s == "a = b == c, d"


def test_controls():
    s = apply_code_mode("new line tab")
    assert s == "\n\t"

