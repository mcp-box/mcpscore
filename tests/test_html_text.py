"""Tests for decoding HTML character references."""

import html

import pytest

from mcpscore.html_text import bound_charrefs, unescape


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("&#65;&#x42;&#0067;&#x0044;", "ABCD"),
        ("&#1114109;", "\U0010fffd"),
        ("&#1114112;", "�"),
        ("&#" + "9" * 5000 + ";x", "�x"),
        ("&#x" + "F" * 5000 + ";", "�"),
        ("&#" + "0" * 5000 + "65;", "A"),
        ("&#" + "9" * 5000 + " tail", "� tail"),
        ("&amp;&#x;&#;", "&&#x;&#;"),
        ("no references", "no references"),
    ],
    ids=["short", "max", "past-max", "long-decimal", "long-hex", "leading-zeros", "no-semicolon", "other", "none"],
)
def test_unescape(text: str, expected: str) -> None:
    assert unescape(text) == expected


@pytest.mark.parametrize("text", ["&#65;", "&#x10FFFF;", "&#00000065;", "&#1114112;", "&#65 x", "&lt;&#x3c;"])
def test_bounded_references_decode_like_the_standard_library(text: str) -> None:
    assert html.unescape(bound_charrefs(text)) == html.unescape(text)
