"""IPv6 text parsing and canonical rendering.

Every public helper works on the 128-bit value that an address text stands
for.  Text is only a spelling of that value, so containment and host identity
are decided on the integer form, while rendering follows RFC 5952.
"""

from __future__ import annotations

import re
from typing import List, Tuple

_HEX_RE = re.compile(r"\A[0-9A-Fa-f]{1,4}\Z")
_V4_RE = re.compile(r"\A(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\Z")
_ZONE_RE = re.compile(r"\A[0-9A-Za-z._~-]+\Z")

_GROUPS = 8


def _split_zone(text: str) -> Tuple[str, str]:
    """Split ``text`` into the address body and the optional scope suffix."""
    raw = text.strip()
    if not raw:
        raise ValueError("empty address")
    if "%" not in raw:
        return raw, ""
    bare, _, zone = raw.partition("%")
    if not bare:
        raise ValueError("empty address")
    if not _ZONE_RE.match(zone):
        raise ValueError("invalid zone identifier")
    return bare, zone


def _v4_tokens(part: str) -> List[str]:
    """Turn a dotted quad into the two hexadecimal groups it stands for."""
    match = _V4_RE.match(part)
    if not match:
        raise ValueError("invalid embedded IPv4 part")
    octets = [int(piece) for piece in match.groups()]
    if any(octet > 255 for octet in octets):
        raise ValueError("IPv4 octet out of range")
    high = (octets[0] << 8) | octets[1]
    low = (octets[2] << 8) | octets[3]
    return ["%x" % high, "%x" % low]


def _segment_tokens(segment: str) -> List[str]:
    """Return the hexadecimal group tokens of a colon separated segment."""
    tokens: List[str] = []
    pieces = segment.split(":")
    for index, piece in enumerate(pieces):
        if "." in piece:
            if index != len(pieces) - 1:
                raise ValueError("embedded IPv4 part must be last")
            tokens.extend(_v4_tokens(piece))
            continue
        if not piece:
            raise ValueError("empty group")
        if not _HEX_RE.match(piece):
            raise ValueError("invalid group")
        tokens.append(piece)
    return tokens


def _group_tokens(text: str) -> List[str]:
    """Return exactly eight hexadecimal group tokens for an address body."""
    if not text:
        raise ValueError("empty address")
    if "::" in text:
        halves = text.split("::")
        head_text, tail_text = halves[0], halves[-1]
        head = _segment_tokens(head_text) if head_text else []
        tail = _segment_tokens(tail_text) if tail_text else []
        if len(head) + len(tail) > _GROUPS - 1:
            raise ValueError("too many groups")
        filler = _GROUPS - len(head) - len(tail)
        return head + ["0"] * filler + tail
    tokens = _segment_tokens(text)
    if len(tokens) != _GROUPS:
        raise ValueError("wrong number of groups")
    return tokens


def _value(tokens: List[str]) -> int:
    value = 0
    for token in tokens:
        value = (value << 16) | int(token, 16)
    return value


def _is_zero(token: str) -> bool:
    return int(token, 16) == 0


def _compressible(length: int) -> bool:
    """Return whether a zero run of the given length is a shortening candidate."""
    return length >= 1


def _label(token: str) -> str:
    """Return the text used for one group."""
    stripped = token
    return stripped or "0"


def _longest_zero_run(tokens: List[str]) -> Tuple[int, int]:
    """Return ``(start, length)`` of the zero run that gets shortened."""
    runs: List[Tuple[int, int]] = []
    start = 0
    while start < _GROUPS:
        if not _is_zero(tokens[start]):
            start += 1
            continue
        end = start
        while end < _GROUPS and _is_zero(tokens[end]):
            end += 1
        runs.append((start, end - start))
        start = end
    best_start, best_len = -1, 0
    for start, length in runs:
        if _compressible(length) and length >= best_len:
            best_start, best_len = start, length
    return best_start, best_len


def parse(text: str) -> int:
    """Return the 128-bit integer value spelled by ``text``."""
    body, _zone = _split_zone(text)
    return _value(_group_tokens(body))


def canonical(text: str) -> str:
    """Return the RFC 5952 text of ``text`` without any scope suffix."""
    body, _zone = _split_zone(text)
    tokens = _group_tokens(body)
    value = _value(tokens)
    if value >> 32 == 0:
        low = value & 0xFFFFFFFF
        octets = (
            (low >> 24) & 0xFF,
            (low >> 16) & 0xFF,
            (low >> 8) & 0xFF,
            low & 0xFF,
        )
        return "::%d.%d.%d.%d" % octets
    labels = [_label(token) for token in tokens]
    start, length = _longest_zero_run(tokens)
    if length == 0:
        return ":".join(labels)
    return ":".join(labels[:start]) + "::" + ":".join(labels[start + length:])


def _check_prefix_length(plen: int) -> None:
    if isinstance(plen, bool) or not isinstance(plen, int):
        raise TypeError("prefix length must be an integer")
    if plen <= 0 or plen > 128:
        raise ValueError("prefix length out of range")


def in_prefix(text: str, prefix_text: str, plen: int) -> bool:
    """Return whether ``text`` is covered by ``prefix_text/plen``."""
    _check_prefix_length(plen)
    if _split_zone(text)[1] != _split_zone(prefix_text)[1]:
        return False
    address = parse(text)
    base = parse(prefix_text)
    if plen == 0:
        return True
    shift = 128 - plen
    return address >> shift == base >> shift


def normalize_zone(text: str) -> str:
    """Return the canonical address together with its scope suffix."""
    body, zone = _split_zone(text)
    base = canonical(body)
    if zone:
        return base + "%" + zone.lower()
    return base


def same_host(a: str, b: str) -> bool:
    """Return whether two texts denote the same host."""
    return parse(a) == parse(b)