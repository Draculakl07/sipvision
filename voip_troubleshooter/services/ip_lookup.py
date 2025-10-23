"""IP intelligence lookup services."""
from __future__ import annotations

import ipaddress
import json
from functools import lru_cache
from typing import Dict, Iterable, Optional

import requests

from ..settings import AppSettings


_NORMALIZED_KEYS = ("ip", "asn", "isp", "country", "city", "lat", "lon", "source")


def _normalize_record(ip: str, data: Dict[str, object]) -> Dict[str, object]:
    """Ensure all expected fields exist in a result record."""
    record = {key: data.get(key) for key in _NORMALIZED_KEYS}
    record["ip"] = ip
    return record


def _stub_lookup(ip: str) -> Dict[str, object]:
    try:
        ip_obj = ipaddress.ip_address(ip)
        if ip_obj.is_private:
            isp = "Private Network"
            country = ""
        else:
            isp = "Public Network"
            country = ""
    except ValueError:
        isp = "Unknown"
        country = ""
    return {
        "ip": ip,
        "asn": "",
        "isp": isp,
        "country": country,
        "city": "",
        "lat": None,
        "lon": None,
        "source": "stub",
    }


def _ipapi_lookup(ip: str) -> Dict[str, object]:
    response = requests.get(f"http://ip-api.com/json/{ip}", timeout=10)
    payload = response.json()
    if payload.get("status") != "success":
        return {
            "ip": ip,
            "asn": payload.get("as", ""),
            "isp": payload.get("message", ""),
            "country": payload.get("countryCode", ""),
            "city": payload.get("city", ""),
            "lat": payload.get("lat"),
            "lon": payload.get("lon"),
            "source": "ipapi:error",
        }
    return {
        "ip": ip,
        "asn": payload.get("as", ""),
        "isp": payload.get("isp", ""),
        "country": payload.get("countryCode", ""),
        "city": payload.get("city", ""),
        "lat": payload.get("lat"),
        "lon": payload.get("lon"),
        "source": "ipapi",
    }


def _ipinfo_lookup(ip: str, api_key: Optional[str]) -> Dict[str, object]:
    headers = {}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    response = requests.get(f"https://ipinfo.io/{ip}/json", headers=headers, timeout=10)
    payload = response.json()
    loc = payload.get("loc", "")
    lat, lon = (None, None)
    if loc and "," in loc:
        lat_str, lon_str = loc.split(",", 1)
        try:
            lat = float(lat_str)
            lon = float(lon_str)
        except ValueError:
            lat = lon = None
    source = "ipinfo:error" if payload.get("error") else "ipinfo"
    return {
        "ip": ip,
        "asn": payload.get("org", ""),
        "isp": payload.get("org", ""),
        "country": payload.get("country", ""),
        "city": payload.get("city", ""),
        "lat": lat,
        "lon": lon,
        "source": source,
    }


def _maxmind_stub(ip: str) -> Dict[str, object]:
    return {
        "ip": ip,
        "asn": "",
        "isp": "",
        "country": "",
        "city": "",
        "lat": None,
        "lon": None,
        "source": "maxmind_stub",
    }


@lru_cache(maxsize=256)
def _lookup_single(ip: str, provider: str, api_key: Optional[str]) -> Dict[str, object]:
    if provider == "ipapi":
        return _ipapi_lookup(ip)
    if provider == "ipinfo":
        return _ipinfo_lookup(ip, api_key)
    if provider == "maxmind":
        return _maxmind_stub(ip)
    return _stub_lookup(ip)


def lookup_many(ips: Iterable[str], provider: str, api_key: Optional[str]) -> Dict[str, Dict[str, object]]:
    """Lookup IP intelligence for a collection of addresses."""

    settings = AppSettings()
    work_dir = settings.WORK_DIR
    work_dir.mkdir(parents=True, exist_ok=True)
    cache_file = work_dir / "ip_cache.json"

    disk_cache: Dict[str, Dict[str, object]] = {}
    if cache_file.exists():
        try:
            disk_cache = json.loads(cache_file.read_text())
        except json.JSONDecodeError:
            disk_cache = {}

    results: Dict[str, Dict[str, object]] = {}
    changed = False

    for ip in ips:
        if not ip:
            continue
        key = f"{provider}:{ip}"
        if key in disk_cache:
            results[ip] = disk_cache[key]
            continue

        try:
            record = _lookup_single(ip, provider, api_key)
        except requests.RequestException as exc:  # pragma: no cover - network failure defensive
            record = {
                "ip": ip,
                "asn": "",
                "isp": "",
                "country": "",
                "city": "",
                "lat": None,
                "lon": None,
                "source": f"{provider}:error",
                "error": str(exc),
            }
        normalized = _normalize_record(ip, record)
        results[ip] = normalized
        disk_cache[key] = normalized
        changed = True

    if changed:
        cache_file.write_text(json.dumps(disk_cache, indent=2))

    return results


__all__ = ["lookup_many"]
