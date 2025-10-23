"""Helpers to convert SIP call models into Mermaid diagrams."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Dict, List


def _participant_label(ip: str, intel: Dict[str, Dict[str, object]]) -> str:
    details = intel.get(ip, {})
    isp = details.get("isp") or "Unknown"
    country = details.get("country") or "--"
    asn = details.get("asn") or "--"
    return f"{ip} ({isp} | {country} | {asn})"


def _alias(ip: str) -> str:
    return f"P{ip.replace('.', '_')}"


def _format_summary(summary: str) -> str:
    summary = summary.strip()
    if not summary:
        return "SIP"
    return summary


def ladder_to_mermaid(call: Dict[str, object], ip_intel: Dict[str, Dict[str, object]]) -> str:
    """Render a Mermaid sequence diagram for a SIP call."""

    participants: List[Dict[str, object]] = call.get("participants", [])  # type: ignore[assignment]
    events: List[Dict[str, object]] = call.get("events", [])  # type: ignore[assignment]

    lines: List[str] = ["sequenceDiagram"]

    for participant in participants:
        ip = participant.get("ip")  # type: ignore[assignment]
        if not ip:
            continue
        alias = _alias(ip)
        label = _participant_label(ip, ip_intel)
        lines.append(f"    participant {alias} as {label}")

    for event in events:
        src = event.get("src")
        dst = event.get("dst")
        if not src or not dst:
            continue
        timestamp = event.get("t")
        try:
            dt = datetime.fromtimestamp(float(timestamp), tz=timezone.utc)
            ts_str = dt.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        except (TypeError, ValueError):
            ts_str = "unknown"
        summary = _format_summary(str(event.get("summary", "SIP")))
        lines.append(f"    {_alias(str(src))}->>{_alias(str(dst))}: {summary} (t={ts_str})")

    return "\n".join(lines) + "\n"


__all__ = ["ladder_to_mermaid"]
