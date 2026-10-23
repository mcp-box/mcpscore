"""HTML character references, decoded without Python's integer-conversion limit."""

import html
import re

# A numeric character reference, with its leading zeros apart from its digits.
_NUMERIC_CHARREF_RE = re.compile(r"&#(?:([xX])0*([0-9a-fA-F]+)|0*([0-9]+))(;?)")


def _bounded(match: re.Match[str]) -> str:
    hex_marker, hex_digits, decimal_digits, semicolon = match.groups()
    digits = hex_digits or decimal_digits
    # Past U+10FFFF a browser decodes U+FFFD; so does html.unescape, if the number is short enough to convert.
    if len(digits) > (6 if hex_marker else 7):
        return "�"
    return f"&#{hex_marker or ''}{digits}{semicolon}"


def bound_charrefs(text: str) -> str:
    """Shorten numeric character references so decoding them never converts a huge integer."""
    return _NUMERIC_CHARREF_RE.sub(_bounded, text) if "&#" in text else text


def unescape(text: str) -> str:
    """Decode character references as ``html.unescape`` does, for any length of numeric reference."""
    return html.unescape(bound_charrefs(text))
