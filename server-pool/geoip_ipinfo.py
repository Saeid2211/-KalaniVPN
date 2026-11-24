#!/usr/bin/env python3
"""Fail-closed GeoIP consensus for KalaniVPN3 using Cloudflare, GeoJS and IPinfo Lite."""
from __future__ import annotations

import ipaddress
import json
import os
import re
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
GEOIP_ATTRIBUTION = "IP geolocation by IPinfo — https://ipinfo.io (CC BY-SA 4.0)"

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

# Explicitly disable environment-configured HTTP(S) proxies. The IPinfo fallback
# must be fetched directly from the GitHub runner, not through the candidate node.
_DIRECT_HTTPS_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


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
    """Parse Cloudflare Trace text or a GeoJS-style JSON response."""
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
        if re.fullmatch(r"[A-Z]{2}", code):
            return code, ip
        normalized = COUNTRY_NAMES.get(code)
        if normalized:
            return normalized, ip
    return None, ip


def parse_ipinfo_response(payload: Any, expected_ip: str) -> str | None:
    """Accept an IPinfo vote only when it explicitly identifies the same exit IP."""
    if not isinstance(payload, dict):
        return None
    response_ip = normalize_public_ip(payload.get("ip"))
    if response_ip != expected_ip:
        return None
    code = payload.get("country_code")
    if not isinstance(code, str):
        return None
    code = code.strip().upper()
    if not re.fullmatch(r"[A-Z]{2}", code):
        return None
    return code


def _query_live_provider( proxy: str, url: str, destination: Path, curl_to_file: Callable[..., tuple[int, str] | None], ) -> tuple[str, str, str] | None:
    """Fetch one GeoIP observation through the candidate proxy."""
    provider = urllib.parse.urlsplit(url).netloc
    try:
        result = curl_to_file(proxy, url, destination, timeout=7)
    except Exception as exc:
        print(f"GEO_PROVIDER_EXCEPTION provider={provider} type={type(exc).__name__}", flush=True)
        return None

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
    """Look up an observed exit IP directly from the runner using IPinfo Lite."""
    token = os.environ.get("IPINFO_TOKEN", "").strip()
    if not token:
        print("IPINFO_LOOKUP_UNAVAILABLE reason=missing-actions-secret", flush=True)
        return None

    if normalize_public_ip(exit_ip) != exit_ip:
        print("IPINFO_LOOKUP_UNAVAILABLE reason=invalid-exit-ip", flush=True)
        return None

    encoded_ip = urllib.parse.quote(exit_ip, safe=":")
    request = urllib.request.Request(
        IPINFO_URL + encoded_ip,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
            "User-Agent": USER_AGENT,
        },
    )
    try:
        # The explicitly configured opener has ProxyHandler({}), so environment
        # proxy variables cannot route this request through the candidate proxy.
        with _DIRECT_HTTPS_OPENER.open(request, timeout=10) as response:
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
    """Require two independent country votes for one identical public exit IP."""
    if not observations:
        return None, None, "geolocation-no-provider-observation"

    normalized: list[tuple[str, str, str]] = []
    seen_providers: set[str] = set()
    for item in observations:
        if not isinstance(item, tuple) or len(item) != 3:
            return None, None, "geolocation-invalid-provider-observation"
        country, raw_ip, provider = item
        if not isinstance(country, str) or not re.fullmatch(r"[A-Za-z]{2}", country.strip()):
            return None, None, "geolocation-invalid-provider-observation"
        exit_ip = normalize_public_ip(raw_ip)
        if not exit_ip or not isinstance(provider, str) or not provider.strip():
            return None, None, "geolocation-invalid-provider-observation"
        provider = provider.strip().lower()
        if provider in seen_providers:
            return None, exit_ip, "geolocation-duplicate-provider"
        seen_providers.add(provider)
        normalized.append((country.strip().upper(), exit_ip, provider))

    exit_ips = {item[1] for item in normalized}
    if len(exit_ips) != 1:
        return None, None, "geolocation-exit-ip-disagreement"
    exit_ip = next(iter(exit_ips))

    counts: dict[str, int] = {}
    for country, _ip, _provider in normalized:
        counts[country] = counts.get(country, 0) + 1

    if isinstance(ipinfo_country, str):
        candidate = ipinfo_country.strip().upper()
        if re.fullmatch(r"[A-Z]{2}", candidate):
            counts[candidate] = counts.get(candidate, 0) + 1

    winners = [country for country, count in counts.items() if count >= 2]
    if len(winners) != 1:
        return None, exit_ip, "geolocation-no-quorum"
    return winners[0], exit_ip, None


def verify_exit_country( proxy: str, temp_dir: Path, curl_to_file: Callable[..., tuple[int, str] | None], ) -> tuple[str | None, str | None, str | None]:
    """Use two proxy-routed witnesses and IPinfo Lite as a direct third vote."""
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

    # Ask IPinfo only when a live witness failed or the two live witnesses disagree.
    # It looks up the exact observed IP over a direct HTTPS connection.
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
