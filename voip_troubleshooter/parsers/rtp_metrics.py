"""Extract RTP metrics from capture files."""
from __future__ import annotations

import math
from collections import OrderedDict
from dataclasses import dataclass, field
from pathlib import Path
from statistics import mean
from typing import Dict, Iterable, List, Optional, Tuple

from ..settings import resolve_tshark_path
from ..utils.exec import run_cmd


_RTP_FIELDS = [
    "frame.time_epoch",
    "ip.src",
    "ip.dst",
    "udp.srcport",
    "udp.dstport",
    "rtp.ssrc",
    "rtp.seq",
    "rtp.timestamp",
    "frame.len",
    "rtp.p_type",
    "rtp.p_type_name",
]

_CODEC_DEFAULT = {
    "name": "PCMA",
    "rate": 8000,
    "ie": 0.0,
    "bpl": 10.0,
}

_CODEC_MAP = {
    0: {"name": "PCMU", "rate": 8000, "ie": 0.0, "bpl": 10.0},
    8: {"name": "PCMA", "rate": 8000, "ie": 0.0, "bpl": 10.0},
    18: {"name": "G729", "rate": 8000, "ie": 11.0, "bpl": 19.0},
}


@dataclass
class StreamState:
    ssrc: str
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    codec: Dict[str, float]
    last_seq: Optional[int] = None
    last_transit: Optional[float] = None
    jitter: float = 0.0
    max_loss_burst: int = 0
    buckets: Dict[int, Dict[str, object]] = field(default_factory=dict)


def _discover_pcaps(inputs: Iterable[str]) -> List[Path]:
    files: List[Path] = []
    for item in inputs:
        path = Path(item)
        if path.is_file() and path.suffix.lower() in {".pcap", ".pcapng"}:
            files.append(path.resolve())
        elif path.is_dir():
            for child in path.rglob("*"):
                if child.is_file() and child.suffix.lower() in {".pcap", ".pcapng"}:
                    files.append(child.resolve())
    seen = OrderedDict((p, None) for p in files)
    return list(seen.keys())


def _bucket(state: StreamState, epoch: float) -> Dict[str, object]:
    key = int(math.floor(epoch))
    bucket = state.buckets.setdefault(
        key,
        {
            "t": key,
            "packets": 0,
            "bytes": 0,
            "expected": 0,
            "lost": 0,
            "jitter_samples": [],
            "owd_samples": [],
        },
    )
    return bucket


def _update_loss(state: StreamState, seq: int) -> Tuple[int, int]:
    lost = 0
    expected = 1
    if state.last_seq is not None:
        delta = (seq - state.last_seq) & 0xFFFF
        if delta > 1:
            lost = delta - 1
            state.max_loss_burst = max(state.max_loss_burst, lost)
            expected = delta
    state.last_seq = seq
    return lost, expected


def _update_jitter(state: StreamState, arrival: float, timestamp: int) -> float:
    clock = state.codec.get("rate", 8000)
    transit = arrival * clock - timestamp
    if state.last_transit is None:
        state.last_transit = transit
        return 0.0
    delta = transit - state.last_transit
    state.last_transit = transit
    state.jitter += (abs(delta) - state.jitter) / 16.0
    if clock:
        return (state.jitter / clock) * 1000.0
    return 0.0


def _calc_mos(loss_pct: float, delay_ms: float, codec: Dict[str, float]) -> float:
    r0 = 94.2
    ie = codec.get("ie", 0.0)
    bpl = codec.get("bpl", 10.0)
    effective_ie = ie + (95 - ie) * loss_pct / (loss_pct + bpl) if loss_pct > 0 else ie
    delay = max(delay_ms, 0.0)
    id_factor = 0.024 * delay + 0.11 * max(delay - 177.3, 0)
    r_factor = max(0.0, r0 - effective_ie - id_factor)
    mos = 1 + 0.035 * r_factor + r_factor * (r_factor - 60) * (100 - r_factor) * 7e-6
    return round(min(max(mos, 1.0), 4.5), 2)


def extract_rtp_metrics(
    inputs: List[str],
    tshark_path: Optional[str] = None,
    timeout_s: int = 45,
) -> Dict[str, object]:
    """Extract RTP metrics for the provided inputs."""

    tshark = resolve_tshark_path(tshark_path)
    pcaps = _discover_pcaps(inputs)
    if not pcaps:
        return {"call_id": "unknown", "streams": []}

    streams: Dict[str, StreamState] = {}

    for pcap in pcaps:
        cmd = [
            str(tshark),
            "-r",
            str(pcap),
            "-Y",
            "rtp",
            "-T",
            "fields",
            "-E",
            "separator=|",
            "-E",
            "quote=d",
            "-E",
            "header=n",
        ] + [item for field in _RTP_FIELDS for item in ("-e", field)]

        exit_code, stdout_iter = run_cmd(cmd, timeout_s)
        if exit_code != 0:
            continue

        for line in stdout_iter:
            if not line:
                continue
            parts = line.split("|")
            if len(parts) != len(_RTP_FIELDS):
                continue
            (
                ts,
                ip_src,
                ip_dst,
                src_port,
                dst_port,
                ssrc,
                seq,
                rtp_ts,
                frame_len,
                payload_type,
                _payload_name,
            ) = parts
            try:
                timestamp = float(ts)
                seq_num = int(seq)
                frame_length = int(frame_len)
            except (TypeError, ValueError):
                continue

            payload_type_num: Optional[int]
            try:
                payload_type_num = int(payload_type) if payload_type else None
            except (TypeError, ValueError):
                payload_type_num = None

            codec = _CODEC_MAP.get(payload_type_num, _CODEC_DEFAULT)

            def _normalize_port(value: str) -> int:
                try:
                    return int(value)
                except (TypeError, ValueError):
                    return 0

            src_port_int = _normalize_port(src_port)
            dst_port_int = _normalize_port(dst_port)
            key = f"{ssrc}:{ip_src}:{src_port_int}:{ip_dst}:{dst_port_int}"
            if key not in streams:
                streams[key] = StreamState(
                    ssrc=ssrc,
                    src_ip=ip_src,
                    src_port=src_port_int,
                    dst_ip=ip_dst,
                    dst_port=dst_port_int,
                    codec=codec,
                )
            state = streams[key]

            bucket = _bucket(state, timestamp)
            lost, expected = _update_loss(state, seq_num)
            jitter_ms = _update_jitter(state, timestamp, int(rtp_ts or 0))

            bucket["packets"] += 1  # type: ignore[index]
            bucket["bytes"] += frame_length  # type: ignore[index]
            bucket["expected"] += expected  # type: ignore[index]
            bucket["lost"] += lost  # type: ignore[index]
            bucket["jitter_samples"].append(jitter_ms)  # type: ignore[index]

    streams_output: List[Dict[str, object]] = []

    for state in streams.values():
        bucket_list = []
        all_jitters: List[float] = []
        all_delays: List[float] = []
        all_loss_pct: List[float] = []
        all_mos: List[float] = []

        for key in sorted(state.buckets):
            bucket = state.buckets[key]
            packets = bucket["packets"] or 0
            bytes_sent = bucket["bytes"] or 0
            expected = bucket["expected"] or 0
            lost = bucket["lost"] or 0
            jitter_samples = bucket["jitter_samples"] or [0.0]

            pkt_rate = packets
            bitrate_kbps = (bytes_sent * 8) / 1000.0
            loss_pct = (lost / expected * 100.0) if expected else 0.0
            jitter_ms = max(jitter_samples)
            mos = _calc_mos(loss_pct, 0.0, state.codec)

            bucket_entry = {
                "t": bucket["t"],
                "mos": mos,
                "jitter_ms": round(jitter_ms, 2),
                "owd_ms": None,
                "loss_pct": round(loss_pct, 2),
                "bitrate_kbps": round(bitrate_kbps, 2),
                "pkt_rate": pkt_rate,
            }
            bucket_list.append(bucket_entry)

            all_jitters.extend(jitter_samples)
            all_loss_pct.append(loss_pct)
            all_mos.append(mos)

        def _p95(values: List[float]) -> Optional[float]:
            if not values:
                return None
            sorted_vals = sorted(values)
            index = min(len(sorted_vals) - 1, int(math.ceil(0.95 * len(sorted_vals)) - 1))
            return round(sorted_vals[index], 2)

        stats = {
            "avg_mos": round(mean(all_mos), 2) if all_mos else None,
            "avg_loss_pct": round(mean(all_loss_pct), 2) if all_loss_pct else None,
            "p95_jitter_ms": _p95(all_jitters),
            "p95_owd_ms": _p95(all_delays),
            "max_loss_burst": state.max_loss_burst,
        }

        streams_output.append(
            {
                "src_ip": state.src_ip,
                "dst_ip": state.dst_ip,
                "codec": state.codec.get("name", "PCMA"),
                "direction": f"{state.src_ip}_to_{state.dst_ip}",
                "buckets": bucket_list,
                "stats": stats,
            }
        )

    return {
        "call_id": "unknown",
        "streams": streams_output,
    }


__all__ = ["extract_rtp_metrics"]
