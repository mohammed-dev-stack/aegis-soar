from __future__ import annotations

import re
from dataclasses import dataclass

_CONTROL_CHARS_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_HTML_TAG_RE = re.compile(r"<[^>]+>")

_INJECTION_RULES: tuple[tuple[str, str, re.Pattern[str]], ...] = (
    (
        "AI_PI_IGNORE_INSTRUCTIONS",
        "HIGH",
        re.compile(r"ignore\s+(all\s+)?(previous|prior)\s+instructions", re.IGNORECASE),
    ),
    (
        "AI_PI_SYSTEM_OVERRIDE",
        "HIGH",
        re.compile(r"\b(system\s+override|developer\s+mode|jailbreak)\b", re.IGNORECASE),
    ),
    (
        "AI_PI_DELIMITER_SMUGGLING",
        "MEDIUM",
        re.compile(r"(<\|im_start\|>|<\|system\|>|###\s*SYSTEM\b|\[INST\])", re.IGNORECASE),
    ),
    (
        "AI_PI_EXECUTION_DIRECTIVE",
        "HIGH",
        re.compile(
            r"\b(auto[- ]?approve|bypass\s+allowlist|isolate\s+\d{1,3}(?:\.\d{1,3}){3})\b",
            re.IGNORECASE,
        ),
    ),
)


@dataclass(frozen=True, slots=True)
class Finding:
    rule_id: str
    severity: str
    matched_span: str
    detected_at_utc: int


@dataclass(frozen=True, slots=True)
class GuardResult:
    sanitized_display_text: str
    findings: tuple[Finding, ...]


def inspect_triage_text(raw_text: str, now_utc: int) -> GuardResult:
    """Pure, I/O-free defense-in-depth sanitizer and telemetry detector (INV-4).

    Never persists to the database; callers persist audit_log rows when findings
    is non-empty. Primary defense remains architectural isolation.
    """
    findings: list[Finding] = []
    for rule_id, severity, pattern in _INJECTION_RULES:
        for match in pattern.finditer(raw_text):
            findings.append(
                Finding(
                    rule_id=rule_id,
                    severity=severity,
                    matched_span=match.group(0)[:128],
                    detected_at_utc=now_utc,
                )
            )

    cleaned = _CONTROL_CHARS_RE.sub("", raw_text)
    cleaned = _HTML_TAG_RE.sub("", cleaned)
    for _, _, pattern in _INJECTION_RULES:
        cleaned = pattern.sub("[REDACTED_UNTRUSTED_DIRECTIVE]", cleaned)

    return GuardResult(
        sanitized_display_text=cleaned.strip(),
        findings=tuple(findings),
    )
