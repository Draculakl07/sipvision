"""Command line interface for the VoIP troubleshooter."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Dict, List

from .parsers.rtp_metrics import extract_rtp_metrics
from .parsers.sip_ladder import parse_sip_to_ladder
from .services.ip_lookup import lookup_many
from .settings import AppSettings
from .utils.mermaid import ladder_to_mermaid


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Analyze VoIP captures")
    subparsers = parser.add_subparsers(dest="command", required=True)

    analyze = subparsers.add_parser("analyze", help="Analyze a pcap or directory")
    analyze.add_argument("inputs", nargs="+", help="pcap files or directories")
    analyze.add_argument("--ip", dest="ip_filter", help="Limit to a specific IP")
    analyze.add_argument("--callid", dest="callid_filter", help="Call-ID or regex to filter")
    analyze.add_argument("--out", dest="out_dir", default="./out", help="Output directory")
    analyze.add_argument(
        "--provider",
        dest="provider",
        choices=["stub", "ipapi", "ipinfo", "maxmind"],
        default=None,
        help="IP intelligence provider",
    )
    return parser


def _write_outputs(out_dir: Path, call_id: str, call: Dict[str, object], mermaid_text: str, rtp_data: Dict[str, object]) -> None:
    call_dir = out_dir / call_id
    call_dir.mkdir(parents=True, exist_ok=True)

    (call_dir / "ladder.mmd").write_text(mermaid_text)
    (call_dir / "ladder.json").write_text(json.dumps(call, indent=2))
    (call_dir / "rtp.json").write_text(json.dumps(rtp_data, indent=2))


def _summarize_calls(calls: Dict[str, Dict[str, object]]) -> str:
    if not calls:
        return "Calls discovered: none"

    lines = ["Calls discovered:"]
    for call_id, call in calls.items():
        events = call.get("events", [])  # type: ignore[assignment]
        if events:
            start = events[0]["t"]
            end = events[-1]["t"]
            duration = end - start
        else:
            duration = 0.0
        parties = sorted({e.get("src") for e in events if e.get("src")} | {e.get("dst") for e in events if e.get("dst")})
        party_str = ", ".join(parties)
        lines.append(f"- {call_id}: {len(events)} events, duration ~{duration:.2f}s, parties: {party_str}")
    return "\n".join(lines)


def main(argv: List[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    settings = AppSettings()
    provider = args.provider or settings.IP_LOOKUP_PROVIDER

    if args.command == "analyze":
        try:
            tshark_path = settings.require_tshark()
        except ValueError as exc:
            parser.error(str(exc))

        calls = parse_sip_to_ladder(
            inputs=args.inputs,
            ip_filter=args.ip_filter,
            callid_filter=args.callid_filter,
            tshark_path=str(tshark_path),
            timeout_s=settings.SUBPROC_TIMEOUT_S,
        )

        unique_ips = sorted({participant["ip"] for call in calls.values() for participant in call.get("participants", []) if participant.get("ip")})
        intel = lookup_many(unique_ips, provider=provider, api_key=settings.IP_LOOKUP_API_KEY)

        rtp_all = extract_rtp_metrics(
            inputs=args.inputs,
            tshark_path=str(tshark_path),
            timeout_s=settings.SUBPROC_TIMEOUT_S,
        )

        out_dir = Path(args.out_dir)
        out_dir.mkdir(parents=True, exist_ok=True)

        for call_id, call in calls.items():
            mermaid_text = ladder_to_mermaid(call, intel)
            call_ips = {p["ip"] for p in call.get("participants", []) if p.get("ip")}
            filtered_streams = [
                stream
                for stream in rtp_all.get("streams", [])
                if stream.get("src_ip") in call_ips or stream.get("dst_ip") in call_ips
            ]
            rtp_payload = {"call_id": call_id, "streams": filtered_streams}
            _write_outputs(out_dir, call_id, call, mermaid_text, rtp_payload)

        print(_summarize_calls(calls))
        print(f"Outputs written to {out_dir.resolve()}")

    return 0


if __name__ == "__main__":
    demo_path = "./sample.pcap"
    print("Demo: python -m voip_troubleshooter.cli analyze", demo_path)
    raise SystemExit(main())
