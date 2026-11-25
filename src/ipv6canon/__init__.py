"""Public interface for the sec-ipv6-canon exercise."""

from .address import canonical, in_prefix, normalize_zone, parse, same_host

__all__ = ["parse", "canonical", "in_prefix", "normalize_zone", "same_host"]