from __future__ import annotations

import ipaddress
from collections.abc import Sequence
from dataclasses import dataclass

type CanonicalIP = ipaddress.IPv4Address | ipaddress.IPv6Address
type CanonicalNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network

_IPV4_MAPPED_PREFIX = ipaddress.IPv6Network("::ffff:0:0/96")


class InvalidTargetIPError(ValueError):
    """Raised when an IP literal is malformed or uses a forbidden IPv4-mapped IPv6 form."""


@dataclass(frozen=True, slots=True)
class SafetyVerdict:
    allowed: bool
    reason: str
    canonical_ip: str | None = None
    matched_cidr: str | None = None


def normalize_canonical_ip(raw_ip: str) -> CanonicalIP:
    """Parse and validate a canonical IPv4 or IPv6 literal.

    Explicitly rejects IPv4-mapped IPv6 addresses (::ffff:0:0/96) per INV-5.
    """
    stripped = raw_ip.strip()
    try:
        parsed = ipaddress.ip_address(stripped)
    except ValueError as exc:
        raise InvalidTargetIPError(f"Malformed IP literal: {raw_ip!r}") from exc

    if isinstance(parsed, ipaddress.IPv6Address) and parsed in _IPV4_MAPPED_PREFIX:
        raise InvalidTargetIPError(
            f"IPv4-mapped IPv6 address is forbidden (::ffff:0:0/96): {raw_ip!r}"
        )

    return parsed


def evaluate_allowlist(
    raw_target_ip: str,
    protected_cidrs: Sequence[str],
    now_utc: int,
) -> SafetyVerdict:
    """Pure allowlist evaluator (INV-5, NG-2: zero DNS resolution)."""
    _ = now_utc  # Explicit deterministic time parameter per §1.3
    try:
        target = normalize_canonical_ip(raw_target_ip)
    except InvalidTargetIPError as exc:
        return SafetyVerdict(allowed=False, reason=str(exc))

    for raw_cidr in protected_cidrs:
        network: CanonicalNetwork = ipaddress.ip_network(raw_cidr, strict=False)
        if target.version == network.version and target in network:
            return SafetyVerdict(
                allowed=False,
                reason="ALLOWLIST_VIOLATION",
                canonical_ip=str(target),
                matched_cidr=str(network),
            )

    return SafetyVerdict(
        allowed=True,
        reason="OK",
        canonical_ip=str(target),
        matched_cidr=None,
    )
