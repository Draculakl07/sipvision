"""SIP ladder parsing utilities."""
from __future__ import annotations

import re
from collections import OrderedDict
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

from ..settings import resolve_tshark_path
from ..utils.exec import run_cmd


_FIELDS = [
    "frame.time_epoch",
    "ip.src",
    "ip.dst",
    "udp.srcport",
    "udp.dstport",
    "sip.Call-ID",
    "sip.Method",
    "sip.Status-Code",
    "sip.Request-Line",
    "sip.Status-Line",
    "sip.CSeq.method",
    "sip.From",
    "sip.To",
]


class SipParseError(RuntimeError):
    """Raised when tshark parsing fails."""


def _discover_pcaps(inputs: Iterable[str]) -> List[Path]:
    """Collect pcap paths from mixed file/directory inputs."""
    files: List[Path] = []
    for item in inputs:
        path = Path(item)
        if path.is_file() and path.suffix.lower() in {".pcap", ".pcapng"}:
            files.append(path.resolve())
        elif path.is_dir():
            for child in path.rglob("*"):
                if child.is_file() and child.suffix.lower() in {".pcap", ".pcapng"}:
                    files.append(child.resolve())
    # Deduplicate while preserving discovery order
    seen = OrderedDict((p, None) for p in files)
    return list(seen.keys())


def _compile_call_filter(callid_filter: Optional[str]) -> Optional[re.Pattern[str]]:
    if not callid_filter:
        return None
    try:
        return re.compile(callid_filter)
    except re.error:
        return None


def _call_matches(call_id: str, callid_filter: Optional[str], pattern: Optional[re.Pattern[str]]) -> bool:
    if not callid_filter:
        return True
    if pattern:
        return bool(pattern.search(call_id))
    return call_id == callid_filter


def parse_sip_to_ladder(
    inputs: List[str],
    ip_filter: Optional[str] = None,
    callid_filter: Optional[str] = None,
    tshark_path: Optional[str] = None,
    timeout_s: int = 45,
) -> Dict[str, Dict[str, object]]:
    """Parse SIP messages and arrange them into ladder-friendly structures."""

    tshark = resolve_tshark_path(tshark_path)
    pcaps = _discover_pcaps(inputs)
    if not pcaps:
        return {}

    calls: Dict[str, Dict[str, object]] = {}
    participants_index: Dict[str, "OrderedDict[Tuple[str, Optional[int]], Dict[str, object]]"] = {}
    files_seen: Dict[str, set[Path]] = {}
    call_filter_pattern = _compile_call_filter(callid_filter)

    for pcap in pcaps:
        cmd = [
            str(tshark),
            "-r",
            str(pcap),
            "-Y",
            "sip",
            "-T",
            "fields",
            "-E",
            "separator=|",
            "-E",
            "quote=d",
            "-E",
            "header=n",
        ] + [item for field in _FIELDS for item in ("-e", field)]

        exit_code, stdout_iter = run_cmd(cmd, timeout_s)
        if exit_code != 0:
            raise SipParseError(f"tshark exited with {exit_code} while parsing {pcap}")

        for line in stdout_iter:
            if not line:
                continue
            parts = line.split("|")
            if len(parts) != len(_FIELDS):
                continue

            (
                ts,
                ip_src,
                ip_dst,
                src_port,
                dst_port,
                call_id,
                method,
                status_code,
                request_line,
                status_line,
                cseq_method,
                from_header,
                to_header,
            ) = parts

            if not call_id:
                continue

            try:
                timestamp = float(ts)
            except (TypeError, ValueError):
                continue

            if ip_filter and ip_filter not in {ip_src, ip_dst}:
                continue
            if not _call_matches(call_id, callid_filter, call_filter_pattern):
                continue

            summary: str
            if status_code:
                summary = status_line or status_code
            elif method:
                summary = method
            elif request_line:
                summary = request_line.split()[0] if request_line.split() else "SIP"
            else:
                summary = cseq_method or "SIP"

            call = calls.setdefault(
                call_id,
                {
                    "call_id": call_id,
                    "participants": [],
                    "events": [],
                    "meta": {"files_scanned": 0},
                },
            )

            participants_map = participants_index.setdefault(call_id, OrderedDict())
            files_for_call = files_seen.setdefault(call_id, set())
            files_for_call.add(pcap)

            def _normalize_port(value: str) -> Optional[int]:
                try:
                    return int(value)
                except (TypeError, ValueError):
                    return None

            src_key = (ip_src, _normalize_port(src_port))
            if src_key not in participants_map:
                participants_map[src_key] = {"ip": ip_src, "port": src_key[1]}

            dst_key = (ip_dst, _normalize_port(dst_port))
            if dst_key not in participants_map:
                participants_map[dst_key] = {"ip": ip_dst, "port": dst_key[1]}

            call["events"].append(
                {
                    "t": timestamp,
                    "src": ip_src,
                    "sport": src_key[1],
                    "dst": ip_dst,
                    "dport": dst_key[1],
                    "summary": summary.strip() or "SIP",
                    "from": from_header,
                    "to": to_header,
                }
            )

    for call_id, call in calls.items():
        events = call["events"]  # type: ignore[assignment]
        events.sort(key=lambda item: item["t"])
        participants_map = participants_index.get(call_id, OrderedDict())
        call["participants"] = list(participants_map.values())  # type: ignore[assignment]
        call["meta"]["files_scanned"] = len(files_seen.get(call_id, set()))  # type: ignore[index]

    return dict(sorted(calls.items(), key=lambda item: item[0]))


__all__ = ["parse_sip_to_ladder", "SipParseError"]
