from __future__ import annotations

import hashlib
import math
import re
from collections import defaultdict
from collections.abc import Sequence
from dataclasses import dataclass
from uuid import UUID

_EARTH_RADIUS_KM = 6371.0088

_SUSPICIOUS_SHELL_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"bash\s+-i\s+>&\s*/dev/tcp/", re.IGNORECASE),
    re.compile(r"(curl|wget)\s+[^\n|]+\|\s*(ba)?sh\b", re.IGNORECASE),
    re.compile(r"base64\s+(-d|--decode)\s*\|\s*(ba)?sh\b", re.IGNORECASE),
    re.compile(r"python3?\s+-c\s+['\"].*import\s+socket", re.IGNORECASE),
    re.compile(r"\bnc\s+-e\s+/bin/(ba)?sh\b", re.IGNORECASE),
)


@dataclass(frozen=True, slots=True)
class SecurityEvent:
    event_id: UUID
    tenant_id: UUID
    occurred_at: int
    source_host: str
    source_ip: str
    user_name: str | None = None
    command_line: str | None = None
    geo_lat: float | None = None
    geo_lon: float | None = None
    event_type: str | None = None


@dataclass(frozen=True, slots=True)
class DetectionMatch:
    mitre_technique_id: str
    severity: str
    idempotency_key: str
    summary: str
    target_ip: str
    event_ids: tuple[UUID, ...]


def _sha256_hex(raw: str) -> str:
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Great-circle distance in kilometers between two WGS84 coordinates."""
    phi1 = math.radians(lat1)
    phi2 = math.radians(lat2)
    d_phi = math.radians(lat2 - lat1)
    d_lambda = math.radians(lon2 - lon1)
    a = math.sin(d_phi / 2.0) ** 2 + math.cos(phi1) * math.cos(phi2) * math.sin(d_lambda / 2.0) ** 2
    c = 2.0 * math.atan2(math.sqrt(a), math.sqrt(1.0 - a))
    return _EARTH_RADIUS_KM * c


def detect_ssh_brute_force(
    events: Sequence[SecurityEvent],
    now_utc: int,
    window_seconds: int = 300,
    threshold: int = 5,
) -> tuple[DetectionMatch, ...]:
    """T1110: SSH brute force within window."""
    window_start = now_utc - window_seconds
    by_key: dict[tuple[UUID, str], list[SecurityEvent]] = defaultdict(list)

    for ev in events:
        if ev.event_type == "ssh_auth_failure" and window_start <= ev.occurred_at <= now_utc:
            by_key[(ev.tenant_id, ev.source_ip)].append(ev)

    bucket = now_utc // window_seconds
    matches: list[DetectionMatch] = []
    for (tenant_id, source_ip), group in sorted(
        by_key.items(), key=lambda x: (str(x[0][0]), x[0][1])
    ):
        if len(group) >= threshold:
            idem = _sha256_hex(f"T1110:{tenant_id}:{source_ip}:{bucket}")
            matches.append(
                DetectionMatch(
                    mitre_technique_id="T1110",
                    severity="HIGH",
                    idempotency_key=idem,
                    summary=f"SSH brute force: {len(group)} failures from {source_ip}",
                    target_ip=source_ip,
                    event_ids=tuple(e.event_id for e in group),
                )
            )
    return tuple(matches)


def detect_suspicious_shell(
    events: Sequence[SecurityEvent],
    now_utc: int,
    window_seconds: int = 300,
) -> tuple[DetectionMatch, ...]:
    """T1059.004: High-confidence reverse-shell / obfuscated Unix shell command."""
    window_start = now_utc - window_seconds
    matches: list[DetectionMatch] = []

    for ev in events:
        if not (window_start <= ev.occurred_at <= now_utc):
            continue
        if not ev.command_line:
            continue
        if any(pat.search(ev.command_line) for pat in _SUSPICIOUS_SHELL_PATTERNS):
            idem = _sha256_hex(f"T1059.004:{ev.tenant_id}:{ev.source_host}:{ev.event_id}")
            matches.append(
                DetectionMatch(
                    mitre_technique_id="T1059.004",
                    severity="CRITICAL",
                    idempotency_key=idem,
                    summary=f"Suspicious Unix shell execution on {ev.source_host}",
                    target_ip=ev.source_ip,
                    event_ids=(ev.event_id,),
                )
            )
    return tuple(matches)


def detect_impossible_travel(
    events: Sequence[SecurityEvent],
    now_utc: int,
    window_seconds: int = 3600,
    max_speed_kmh: float = 900.0,
    min_distance_km: float = 100.0,
) -> tuple[DetectionMatch, ...]:
    """T1078: Impossible travel between two geo-tagged auth events (> 900 km/h and >= 100 km)."""
    window_start = now_utc - window_seconds
    by_user: dict[tuple[UUID, str], list[SecurityEvent]] = defaultdict(list)

    for ev in events:
        if (
            window_start <= ev.occurred_at <= now_utc
            and ev.user_name is not None
            and ev.geo_lat is not None
            and ev.geo_lon is not None
            and ev.event_type in (None, "auth_success")
        ):
            by_user[(ev.tenant_id, ev.user_name)].append(ev)

    matches: list[DetectionMatch] = []
    for (tenant_id, user_name), group in sorted(
        by_user.items(), key=lambda x: (str(x[0][0]), x[0][1])
    ):
        ordered = sorted(group, key=lambda e: (e.occurred_at, str(e.event_id)))
        for idx in range(len(ordered) - 1):
            e1 = ordered[idx]
            e2 = ordered[idx + 1]
            dt = abs(e2.occurred_at - e1.occurred_at)
            if dt <= 0:
                continue
            assert e1.geo_lat is not None and e1.geo_lon is not None
            assert e2.geo_lat is not None and e2.geo_lon is not None
            dist_km = haversine_km(e1.geo_lat, e1.geo_lon, e2.geo_lat, e2.geo_lon)
            speed_kmh = dist_km / (dt / 3600.0)
            if dist_km >= min_distance_km and speed_kmh > max_speed_kmh:
                lo_id, hi_id = sorted((str(e1.event_id), str(e2.event_id)))
                idem = _sha256_hex(f"T1078:{tenant_id}:{user_name}:{lo_id}:{hi_id}")
                matches.append(
                    DetectionMatch(
                        mitre_technique_id="T1078",
                        severity="HIGH",
                        idempotency_key=idem,
                        summary=(
                            f"Impossible travel for {user_name}: "
                            f"{dist_km:.1f} km in {dt}s ({speed_kmh:.0f} km/h)"
                        ),
                        target_ip=e2.source_ip,
                        event_ids=(e1.event_id, e2.event_id),
                    )
                )
    return tuple(matches)


def evaluate_all_rules(
    events: Sequence[SecurityEvent],
    now_utc: int,
) -> tuple[DetectionMatch, ...]:
    """Run all deterministic v1 detection rules over an event window."""
    return (
        *detect_ssh_brute_force(events, now_utc=now_utc),
        *detect_suspicious_shell(events, now_utc=now_utc),
        *detect_impossible_travel(events, now_utc=now_utc),
    )
