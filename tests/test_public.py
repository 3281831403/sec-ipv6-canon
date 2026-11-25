"""Public smoke tests for IPv6 text canonicalization."""

from __future__ import annotations

from ipv6canon import canonical, same_host


def test_leading_zeros_are_removed() -> None:
    assert canonical("2001:0db8:0:0:0:0:0:1") == "2001:db8::1"


def test_group_case_is_folded() -> None:
    assert canonical("2001:DB8:0:0:0:0:0:1") == "2001:db8::1"


def test_a_lone_zero_group_is_not_shortened() -> None:
    assert canonical("2001:db8:1:0:1:1:1:1") == "2001:db8:1:0:1:1:1:1"


def test_ipv4_mapped_addresses_stay_dotted() -> None:
    assert canonical("::ffff:1.2.3.4") == "::ffff:1.2.3.4"


def test_same_host_separates_distinct_scopes() -> None:
    assert same_host("2001:db8::1%eth0", "2001:db8::1%eth1") is False