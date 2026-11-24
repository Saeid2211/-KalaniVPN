#!/usr/bin/env python3
"""Two live GeoIP witnesses plus an IPinfo Lite fallback for the same exit IP."""
from __future__ import annotations

import ipaddress
import json
import os
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Callable

GEO_URLS = (
    "https://www.cloudflare.com/cdn-cgi/trace",
    "https://get.geojs.io/v1/ip/geo.json",
)
IPINFO_URL = "https://api.ipinfo.io/lite/"
USER_AGENT = "KalaniVPN3-GeoIP/1.0"
GEOIP_ATTRIBUTION = "IP geolocation by IPinfo — https://ipinfo.io"

COUNTRY_NAMES = {
    "UNITED STATES": "US",
    "UNITED STATES OF AMERICA": "US",
    "USA": "US",
    "GERMANY": "DE",
    "NETHERLANDS": "NL",
    "THE NETHERLANDS": "NL",
    "UNITED KINGDOM": "GB",
    "GREAT BRITAIN": "GB",
    "UK": "GB",
    "FRANCE": "FR",
}


def normalize_public_ip(value: Any) -> str | None:
    """Return a canonical globally-routable IP address, otherwise None."""
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        address = ipaddress.ip_address(value.strip())
    except ValueError:
        return None
    if not address.is_global:
        return None
    return address.compressed


def parse_country(payload: Any) -> tuple[str | None, str | None]:
    if isinstance(payload, str):
        fields: dict[str, str] = {}
        for line in payload.splitlines():
            if "=" in line:
                key, value = line.split("=", 1)
                fields[key.strip().lower()] = value.strip()
        code = fields.get("loc") or fields.get("country_code") or fields.get("country")
        ip = fields.get("ip")
    elif isinstance(payload, dict):
        code = (
            payload.get("country_code")
            or payload.get("countryCode")
            or payload.get("loc")
            or payload.get("country")
        )
        ip = payload.get("ip") if isinstance(payload.get("ip"), str) else None
    else:
        return None, None

    if isinstance(code, str):
        code = code.strip().upper()
        if len(code) == 2 and code.isalpha():
            return code, ip
        normalized = COUNTRY_NAMES.get(code)
        if normalized:
            return normalized, ip
    return None, ip


def parse_ipinfo_response(payload: Any, expected_ip: str) -> str | None:
    """Accept an IPinfo vote only when it explicitly refers to the same exit IP."""
    if not isinstance(payload, dict):
        return None
    response_ip = normalize_public_ip(payload.get("ip"))
    if response_ip != expected_ip:
        return None
    code = payload.get("country_code")
    if not isinstance(code, str):
        return None
    code = code.strip().upper()
    if len(code) != 2 or not code.isalpha():
        return None
    return code


def _query_live_provider( proxy: str, url: str, destination: Path, curl_to_file: Callable[..., tuple[int, str] | None], ) -> tuple[str, str, str] | None:
    provider = urllib.parse.urlsplit(url).netloc
    result = curl_to_file(proxy, url, destination, timeout=7)
    if not result or result[0] != 200:
        print(f"GEO_PROVIDER_UNAVAILABLE provider={provider}", flush=True)
        return None

    try:
        raw = destination.read_text(encoding="utf-8")
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError:
            # Cloudflare Trace uses key=value plain text.
            payload = raw
    except Exception as exc:
        print(f"GEO_INVALID_RESPONSE provider={provider} type={type(exc).__name__}", flush=True)
        return None

    country, raw_ip = parse_country(payload)
    exit_ip = normalize_public_ip(raw_ip)
    if not country or not exit_ip:
        print(f"GEO_COUNTRY_OR_PUBLIC_IP_MISSING provider={provider}", flush=True)
        return None
    return country, exit_ip, provider


def lookup_ipinfo_country(exit_ip: str) -> str | None:
    """Look up a supplied exit IP directly from the runner, never through the candidate proxy."""
    token = os.environ.get("IPINFO_TOKEN", "").strip()
    if not token:
        print("IPINFO_LOOKUP_UNAVAILABLE reason=missing-actions-secret", flush=True)
        return None

    encoded_ip = urllib.parse.quote(exit_ip, safe=":")
    url = IPINFO_URL + encoded_ip
    request = urllib.request.Request(
        url,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
            "User-Agent": USER_AGENT,
        },
    )
    try:
        # This request uses the GitHub runner's direct HTTPS connection. It does
        # not depend on whether the candidate proxy can reach a GeoIP API.
        with urllib.request.urlopen(request, timeout=10) as response:
            body = response.read(32 * 1024 + 1)
        if len(body) > 32 * 1024:
            print("IPINFO_LOOKUP_FAILED reason=response-too-large", flush=True)
            return None
        payload = json.loads(body.decode("utf-8"))
    except urllib.error.HTTPError as exc:
        print(f"IPINFO_LOOKUP_FAILED status={exc.code}", flush=True)
        return None
    except Exception as exc:
        print(f"IPINFO_LOOKUP_FAILED type={type(exc).__name__}", flush=True)
        return None

    country = parse_ipinfo_response(payload, exit_ip)
    if not country:
        print("IPINFO_LOOKUP_FAILED reason=ip-or-country-mismatch", flush=True)
        return None
    return country


def resolve_geo_quorum( observations: list[tuple[str, str, str]], ipinfo_country: str | None = None, ) -> tuple[str | None, str | None, str | None]:
    """Require two of three country votes for one identical public exit IP."""
    if not observations:
        return None, None, "geolocation-no-provider-observation"

    exit_ips = {item[1] for item in observations if item[1]}
    if len(exit_ips) != 1 or any(not item[1] for item in observations):
        return None, None, "geolocation-exit-ip-disagreement"

    exit_ip = next(iter(exit_ips))
    counts: dict[str, int] = {}
    for country, _ip, _provider in observations:
        counts[country] = counts.get(country, 0) + 1

    if isinstance(ipinfo_country, str):
        ipinfo_country = ipinfo_country.strip().upper()
        if len(ipinfo_country) == 2 and ipinfo_country.isalpha():
            counts[ipinfo_country] = counts.get(ipinfo_country, 0) + 1

    winners = [country for country, count in counts.items() if count >= 2]
    if len(winners) != 1:
        return None, exit_ip, "geolocation-no-quorum"
    return winners[0], exit_ip, None


def verify_exit_country( proxy: str, temp_dir: Path, curl_to_file: Callable[..., tuple[int, str] | None], ) -> tuple[str | None, str | None, str | None]:
    """Two proxy-routed witnesses; IPinfo Lite is the direct third vote if needed."""
    observations: list[tuple[str, str, str]] = []
    for index, url in enumerate(GEO_URLS):
        item = _query_live_provider(proxy, url, temp_dir / f"geo-{index}.json", curl_to_file)
        if item:
            observations.append(item)

    if not observations:
        print("GEO_COUNTRY_NO_QUORUM providers=none", flush=True)
        return None, None, "geolocation-no-provider-observation"

    exit_ips = {item[1] for item in observations}
    if len(exit_ips) != 1:
        providers = ",".join(item[2] for item in observations)
        print(f"GEO_EXIT_IP_DISAGREEMENT providers={providers}", flush=True)
        return None, None, "geolocation-exit-ip-disagreement"

    exit_ip = next(iter(exit_ips))
    live_countries = {item[0] for item in observations}
    live_agreement = len(observations) == 2 and len(live_countries) == 1
    ipinfo_country = None

    # The fallback is called only when a live service failed or the two live
    # services disagree. It looks up the exact observed IP over direct HTTPS.
    if not live_agreement:
        ipinfo_country = lookup_ipinfo_country(exit_ip)
        if ipinfo_country:
            print(f"IPINFO_COUNTRY country={ipinfo_country} source=IPinfo-Lite", flush=True)

    country, resolved_ip, error = resolve_geo_quorum(observations, ipinfo_country)
    if error:
        providers = ",".join(item[2] for item in observations)
        codes = ",".join(item[0] for item in observations)
        print(
            f"GEO_COUNTRY_NO_QUORUM providers={providers or 'none'} "
            f"live_codes={codes or 'none'} ipinfo={ipinfo_country or 'unavailable'}",
            flush=True,
        )
        return None, resolved_ip or exit_ip, error

    votes = [item[0] for item in observations]
    sources = [item[2] for item in observations]
    if ipinfo_country:
        votes.append(ipinfo_country)
        sources.append("IPinfo-Lite")
    print(
        f"GEO_COUNTRY_QUORUM country={country} "
        f"votes={votes.count(country)}/{len(votes)} sources={','.join(sources)}",
        flush=True,
    )
    return country, resolved_ip, None
