"""IPv6 text parsing and canonical rendering.

Every public helper works on the 128-bit value that an address text stands
for.  Text is only a spelling of that value, so containment and host identity
are decided on the integer form, while rendering follows RFC 5952.
"""

from __future__ import annotations

import re
from typing import List, Tuple

_HEX_RE = re.compile(r"\A[0-9A-Fa-f]{1,4}\Z")
_V4_RE = re.compile(r"\A([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\Z")
_ZONE_RE = re.compile(r"\A[0-9A-Za-z._~-]+\Z")

_GROUPS = 8
# The IPv4-mapped block is ::ffff:0:0/96, so an address belongs to it exactly
# when its high 96 bits equal this value.
_MAPPED_HIGH = 0xFFFF
_BITS = 128


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
    octets: List[int] = []
    for piece in match.groups():
        if len(piece) > 1 and piece[0] == "0":
            raise ValueError("leading zero in IPv4 octet")
        octet = int(piece, 10)
        if octet > 255:
            raise ValueError("IPv4 octet out of range")
        octets.append(octet)
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
        if len(halves) != 2:
            raise ValueError("'::' may appear at most once")
        head_text, tail_text = halves
        if "." in head_text:
            # A dotted quad spells the low 32 bits, so it can never sit to the
            # left of the compressed zero groups.
            raise ValueError("embedded IPv4 part must be last")
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
    # A single zero group must be written as "0", never as "::".
    return length >= 2


def _label(token: str) -> str:
    """Return the canonical text used for one group."""
    return "%x" % int(token, 16)


def _longest_zero_run(tokens: List[str]) -> Tuple[int, int]:
    """Return ``(start, length)`` of the zero run that gets shortened.

    The longest eligible run wins; ties are broken toward the leftmost run.
    """
    best_start, best_len = -1, 0
    start = 0
    while start < _GROUPS:
        if not _is_zero(tokens[start]):
            start += 1
            continue
        end = start
        while end < _GROUPS and _is_zero(tokens[end]):
            end += 1
        length = end - start
        if _compressible(length) and length > best_len:
            best_start, best_len = start, length
        start = end
    return best_start, best_len


def parse(text: str) -> int:
    """Return the 128-bit integer value spelled by ``text``."""
    body, _zone = _split_zone(text)
    return _value(_group_tokens(body))


def _dotted(value: int) -> str:
    low = value & 0xFFFFFFFF
    return "%d.%d.%d.%d" % (
        (low >> 24) & 0xFF,
        (low >> 16) & 0xFF,
        (low >> 8) & 0xFF,
        low & 0xFF,
    )


def canonical(text: str) -> str:
    """Return the RFC 5952 text of ``text`` without any scope suffix."""
    body, _zone = _split_zone(text)
    tokens = _group_tokens(body)
    value = _value(tokens)
    if value >> 32 == _MAPPED_HIGH:
        # Only the IPv4-mapped block is written in dotted form.
        return "::ffff:" + _dotted(value)
    labels = [_label(token) for token in tokens]
    start, length = _longest_zero_run(tokens)
    if length == 0:
        return ":".join(labels)
    return ":".join(labels[:start]) + "::" + ":".join(labels[start + length:])


def _check_prefix_length(plen: int) -> None:
    if isinstance(plen, bool) or not isinstance(plen, int):
        raise TypeError("prefix length must be an integer")
    if plen < 0 or plen > _BITS:
        raise ValueError("prefix length out of range")


def in_prefix(text: str, prefix_text: str, plen: int) -> bool:
    """Return whether ``text`` is covered by ``prefix_text/plen``.

    Scope suffixes are not part of the address bits and therefore never affect
    membership.
    """
    _check_prefix_length(plen)
    address = parse(text)
    base = parse(prefix_text)
    if plen == 0:
        return True
    shift = _BITS - plen
    return address >> shift == base >> shift


def normalize_zone(text: str) -> str:
    """Return the canonical address together with its scope suffix."""
    body, zone = _split_zone(text)
    base = canonical(body)
    if zone:
        # The scope suffix is opaque and is reproduced exactly as supplied.
        return base + "%" + zone
    return base


def same_host(a: str, b: str) -> bool:
    """Return whether two texts denote the same host.

    Address bits and the scope suffix both take part in host identity, so a
    missing scope never equals a supplied one.
    """
    body_a, zone_a = _split_zone(a)
    body_b, zone_b = _split_zone(b)
    return zone_a == zone_b and _value(_group_tokens(body_a)) == _value(_group_tokens(body_b))
