#!/usr/bin/env python3
"""Build a small, independently re-tested public server pool for KalaniVPN3.

The candidate feeds are untrusted input. Nothing from a feed is executed.
Each URI is parsed by the pinned unbox converter, validated by the official
sing-box 1.14.4 binary, then tested through a local SOCKS inbound.
"""
from __future__ import annotations

import base64
import concurrent.futures
import hashlib
import json
import os
import random
import re
import shutil
import socket
import statistics
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
SOURCES_FILE = ROOT / "sources.txt"
OUTPUT_FILE = ROOT / "server-pool.json"

SING_BOX = os.environ.get("SING_BOX_BIN", "sing-box")
UNBOX = os.environ.get("UNBOX_BIN", "unbox")
ALLOWED_COUNTRIES = ("US", "DE", "NL", "GB", "FR")
SUPPORTED_SCHEMES = {"vless", "vmess", "trojan", "ss", "hysteria2", "hy2", "tuic", "anytls"}
SUPPORTED_OUTBOUNDS = {"vless", "vmess", "trojan", "shadowsocks", "hysteria2", "tuic", "anytls"}
MAX_CANDIDATES = int(os.environ.get("MAX_CANDIDATES", "120"))
MAX_WORKERS = int(os.environ.get("MAX_WORKERS", "4"))
MAX_PER_COUNTRY = 5
DOWNLOAD_BYTES = 1_048_576
UPLOAD_BYTES = 262_144
MIN_DOWNLOAD_BPS = 65_536       # 512 kbit/s sustained floor
MIN_UPLOAD_BPS = 16_384         # 128 kbit/s sustained floor
DOWNLOAD_URL = "https://speed.cloudflare.com/__down?bytes=1048576"
UPLOAD_URL = "https://speed.cloudflare.com/__up"
GEO_URLS = ("https://ipwho.is/", "https://ipapi.co/json/")
USER_AGENT = "KalaniVPN3-ServerPool/1.0"

COUNTRY_NAMES = {
    "UNITED STATES": "US", "UNITED STATES OF AMERICA": "US", "USA": "US",
    "GERMANY": "DE", "NETHERLANDS": "NL", "THE NETHERLANDS": "NL",
    "UNITED KINGDOM": "GB", "GREAT BRITAIN": "GB", "UK": "GB",
    "FRANCE": "FR",
}


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def require_binaries() -> None:
    missing = [name for name, value in (("sing-box", SING_BOX), ("unbox", UNBOX), ("curl", "curl"))
               if shutil.which(value) is None]
    if missing:
        raise RuntimeError("Missing required executable(s): " + ", ".join(missing))


def load_sources() -> list[tuple[str, str]]:
    if not SOURCES_FILE.is_file():
        raise RuntimeError(f"Missing source list: {SOURCES_FILE}")
    result: list[tuple[str, str]] = []
    for raw in SOURCES_FILE.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "|" in line:
            url, hint = line.rsplit("|", 1)
            hint = hint.strip().upper()
        else:
            url, hint = line, ""
        url = url.strip()
        if not url.startswith("https://"):
            print("Skipping non-HTTPS source entry")
            continue
        if hint and hint not in ALLOWED_COUNTRIES:
            print(f"Skipping invalid country sampling hint: {hint}")
            continue
        result.append((url, hint))
    return result


def fetch_text(url: str) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=25) as response:
        raw = response.read(12 * 1024 * 1024 + 1)
    if len(raw) > 12 * 1024 * 1024:
        raise ValueError("Source exceeded 12 MiB safety limit")
    text = raw.decode("utf-8", errors="replace")
    if re.search(r"(?i)(?:vless|vmess|trojan|ss|hysteria2|hy2|tuic|anytls)://", text):
        return text
    # Some providers publish a single base64-encoded subscription document.
    compact = re.sub(r"\s+", "", text)
    if compact and re.fullmatch(r"[A-Za-z0-9_+/=-]+", compact):
        try:
            decoded = base64.b64decode(compact + "=" * (-len(compact) % 4)).decode("utf-8", "replace")
            if re.search(r"(?i)(?:vless|vmess|trojan|ss|hysteria2|hy2|tuic|anytls)://", decoded):
                return decoded
        except Exception:
            pass
    return text


def normalize_uri(raw: str) -> str | None:
    line = raw.strip().strip("\ufeff")
    if not line or line.startswith("#") or len(line) > 8192:
        return None
    if "://" not in line:
        return None
    scheme = line.split("://", 1)[0].lower()
    if scheme not in SUPPORTED_SCHEMES:
        return None
    try:
        parsed = urllib.parse.urlsplit(line)
        params = urllib.parse.parse_qs(parsed.query)
        transport = params.get("type", [""])[0].lower()
        if transport == "xhttp" or "xhttp" in line.lower():
            return None
    except Exception:
        return None
    return line


def fingerprint_uri(uri: str) -> str:
    return hashlib.sha256(uri.encode("utf-8")).hexdigest()


def read_previous() -> list[dict[str, Any]]:
    try:
        data = json.loads(OUTPUT_FILE.read_text(encoding="utf-8"))
        nodes = data.get("nodes", [])
        if isinstance(nodes, list):
            return [node for node in nodes if isinstance(node, dict) and isinstance(node.get("uri"), str)]
    except Exception:
        pass
    return []


def collect_candidates(sources: list[tuple[str, str]], previous: list[dict[str, Any]]) -> list[dict[str, str]]:
    by_hash: dict[str, dict[str, str]] = {}
    hinted: dict[str, list[dict[str, str]]] = defaultdict(list)
    general: list[dict[str, str]] = []

    # Previously published entries are tested first on every cycle.
    for node in previous:
        uri = normalize_uri(node.get("uri", ""))
        if not uri:
            continue
        key = fingerprint_uri(uri)
        if key not in by_hash:
            item = {"uri": uri, "source": "previous-pool", "hint": str(node.get("country", "")).upper()}
            by_hash[key] = item

    source_ok = 0
    source_errors = 0
    for url, hint in sources:
        try:
            body = fetch_text(url)
            source_ok += 1
        except Exception as exc:
            source_errors += 1
            print(f"Source fetch failed ({urllib.parse.urlsplit(url).netloc}): {type(exc).__name__}")
            continue
        source_name = urllib.parse.urlsplit(url).netloc + urllib.parse.urlsplit(url).path[-48:]
        for raw_line in body.splitlines():
            uri = normalize_uri(raw_line)
            if not uri:
                continue
            key = fingerprint_uri(uri)
            if key in by_hash:
                continue
            item = {"uri": uri, "source": source_name, "hint": hint}
            by_hash[key] = item
            if hint:
                hinted[hint].append(item)
            else:
                general.append(item)

    if source_ok == 0 and not by_hash:
        raise RuntimeError("Every candidate source failed; previous pool is unavailable")

    # A source country label is only a sampling hint; it is never accepted as
    # the node's country. The actual exit country is verified over the proxy.
    selected: list[dict[str, str]] = []
    selected_hashes: set[str] = set()
    for node in previous:
        uri = normalize_uri(node.get("uri", ""))
        if uri:
            key = fingerprint_uri(uri)
            item = by_hash.get(key)
            if item and key not in selected_hashes:
                selected.append(item)
                selected_hashes.add(key)

    for country in ALLOWED_COUNTRIES:
        rows = [item for item in hinted[country] if fingerprint_uri(item["uri"]) not in selected_hashes]
        random.shuffle(rows)
        for item in rows[:10]:
            selected.append(item)
            selected_hashes.add(fingerprint_uri(item["uri"]))

    remaining = [item for item in list(by_hash.values()) if fingerprint_uri(item["uri"]) not in selected_hashes]
    random.shuffle(remaining)
    selected.extend(remaining[:max(0, MAX_CANDIDATES - len(selected))])
    return selected[:MAX_CANDIDATES]


def make_template(path: Path) -> None:
    path.write_text(
        '{\n'
        '  "log": {"level": "error"},\n'
        '  "outbounds": [\n'
        '    {{ .Unbox_outbounds }},\n'
        '    {"type": "direct", "tag": "direct"}\n'
        '  ],\n'
        '  "route": {"final": "direct"}\n'
        '}\n',
        encoding="utf-8",
    )


def convert_one(uri: str, temp_dir: Path) -> dict[str, Any] | None:
    input_path = temp_dir / "one-uri.txt"
    template_path = temp_dir / "template.json"
    output_path = temp_dir / "parsed.json"
    input_path.write_text(uri + "\n", encoding="utf-8")
    make_template(template_path)
    result = subprocess.run(
        [UNBOX, "parse", "-f", str(input_path), "-t", str(template_path), "-o", str(output_path), "-j", "-n"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=10,
        check=False,
    )
    if result.returncode != 0 or not output_path.is_file():
        return None
    try:
        parsed = json.loads(output_path.read_text(encoding="utf-8"))
        outbound_list = parsed.get("outbounds", [])
        candidates = [item for item in outbound_list if isinstance(item, dict) and item.get("type") in SUPPORTED_OUTBOUNDS]
        if len(candidates) != 1:
            return None
        outbound = candidates[0]
        if outbound.get("detour"):
            return None
        if (outbound.get("transport") or {}).get("type", "").lower() == "xhttp":
            return None
        if not isinstance(outbound.get("server"), str) or not outbound.get("server"):
            return None
        port = int(outbound.get("server_port", 0))
        if not 1 <= port <= 65535:
            return None
        outbound["server_port"] = port
        outbound["tag"] = "kalani-candidate"
        return outbound
    except Exception:
        return None


def parse_country(payload: Any) -> tuple[str | None, str | None]:
    if not isinstance(payload, dict):
        return None, None
    code = payload.get("country_code") or payload.get("countryCode") or payload.get("country")
    if isinstance(code, str):
        code = code.strip().upper()
        if len(code) == 2 and code.isalpha():
            return code, payload.get("ip") if isinstance(payload.get("ip"), str) else None
        normalized = COUNTRY_NAMES.get(code.upper())
        if normalized:
            return normalized, payload.get("ip") if isinstance(payload.get("ip"), str) else None
    return None, payload.get("ip") if isinstance(payload.get("ip"), str) else None


def curl_to_file(proxy: str, url: str, destination: Path, timeout: int = 7) -> tuple[int, str] | None:
    provider = urllib.parse.urlsplit(url).netloc
    command = [
        "curl", "--silent", "--show-error", "--location",
        "--noproxy", "", "--proxy", proxy,
        "--connect-timeout", "3", "--max-time", str(timeout),
        "--output", str(destination), "--write-out", "%{http_code}", url,
    ]
    try:
        done = subprocess.run(command, capture_output=True, text=True, timeout=timeout + 3, check=False)
        if done.returncode != 0:
            detail = (done.stderr or "").strip().replace("\\n", " ")[:180]
            print(f"GEO_CURL_FAIL provider={provider} exit={done.returncode} detail={detail}", flush=True)
            return None

        raw_status = done.stdout.strip()
        status = int(raw_status[-3:]) if raw_status else 0

        if status != 200:
            print(f"GEO_HTTP_FAIL provider={provider} status={status}", flush=True)

        return status, done.stdout

    except subprocess.TimeoutExpired:
        print(f"GEO_TIMEOUT provider={provider}", flush=True)
        return None
    except Exception as exc:
        detail = str(exc).replace("\\n", " ")[:160]
        print(f"GEO_EXCEPTION provider={provider} type={type(exc).__name__} detail={detail}", flush=True)
        return None


def verify_exit_country(proxy: str, temp_dir: Path) -> tuple[str | None, str | None, str | None]:
    observations: list[tuple[str, str | None]] = []
    for index, url in enumerate(GEO_URLS):
        output = temp_dir / f"geo-{index}.json"
        result = curl_to_file(proxy, url, output, timeout=7)
        if not result or result[0] != 200:
            return None, None, "geolocation-provider-failed"
        try:
            code, ip = parse_country(json.loads(output.read_text(encoding="utf-8")))
        except Exception:
            return None, None, "geolocation-invalid-response"
        if not code:
            return None, ip, "geolocation-country-missing"
        observations.append((code, ip))
    if observations[0][0] != observations[1][0]:
        return None, observations[0][1], "geolocation-disagreement"
    return observations[0][0], observations[0][1] or observations[1][1], None


def curl_metrics(command: list[str], timeout: int) -> list[float] | None:
    try:
        done = subprocess.run(command, capture_output=True, text=True, timeout=timeout + 3, check=False)
        if done.returncode != 0:
            return None
        values = done.stdout.strip().split("\t")
        if len(values) < 4:
            return None
        return [float(value) for value in values]
    except Exception:
        return None


def test_download(proxy: str) -> dict[str, float] | None:
    format_string = "%{http_code}\t%{time_starttransfer}\t%{time_total}\t%{size_download}\t%{speed_download}"
    url = DOWNLOAD_URL + "&nonce=" + str(time.time_ns())
    command = [
        "curl", "--silent", "--show-error", "--location", "--fail",
        "--noproxy", "", "--proxy", proxy,
        "--connect-timeout", "5", "--max-time", "13",
        "--output", os.devnull, "--write-out", format_string, url,
    ]
    values = curl_metrics(command, 13)
    if not values or len(values) != 5:
        return None
    status, ttfb, total, downloaded, speed = values
    if int(status) not in (200, 206) or downloaded < DOWNLOAD_BYTES * 0.95 or total <= 0:
        return None
    return {"ttfb": ttfb, "total": total, "bytes": downloaded, "bps": speed}


def test_upload(proxy: str, payload: Path) -> dict[str, float] | None:
    format_string = "%{http_code}\t%{time_starttransfer}\t%{time_total}\t%{size_upload}"
    command = [
        "curl", "--silent", "--show-error", "--location", "--fail",
        "--noproxy", "", "--proxy", proxy,
        "--connect-timeout", "5", "--max-time", "13",
        "--data-binary", "@" + str(payload),
        "--output", os.devnull, "--write-out", format_string, UPLOAD_URL,
    ]
    values = curl_metrics(command, 13)
    if not values or len(values) != 4:
        return None
    status, ttfb, total, uploaded = values
    if int(status) not in (200, 201, 204) or uploaded < UPLOAD_BYTES * 0.95 or total <= 0:
        return None
    return {"ttfb": ttfb, "total": total, "bytes": uploaded, "bps": uploaded / total}


def make_test_config(outbound: dict[str, Any], port: int) -> dict[str, Any]:
    return {
        "log": {"level": "error"},
        "inbounds": [{
            "type": "socks",
            "tag": "kalani-test-in",
            "listen": "127.0.0.1",
            "listen_port": port,
        }],
        "outbounds": [outbound, {"type": "direct", "tag": "direct"}],
        "route": {"final": outbound["tag"], "auto_detect_interface": True},
    }


def score_node(download_bps: float, upload_bps: float, ttfb: float) -> float:
    download_component = min(download_bps / 2_000_000.0, 1.0)
    upload_component = min(upload_bps / 1_000_000.0, 1.0)
    latency_component = max(0.0, 1.0 - min(ttfb, 5.0) / 5.0)
    return round(100.0 * (0.55 * download_component + 0.25 * upload_component + 0.20 * latency_component), 2)


def test_candidate(index: int, candidate: dict[str, str], upload_payload: Path) -> dict[str, Any] | None:
    with tempfile.TemporaryDirectory(prefix="kalani-node-") as work:
        temp_dir = Path(work)
        outbound = convert_one(candidate["uri"], temp_dir)
        if not outbound:
            print(f"REJECT candidate={index+1} stage=uri-conversion", flush=True)
            return None
        port = 20000 + index
        config_path = temp_dir / "sing-box-test.json"
        config_path.write_text(json.dumps(make_test_config(outbound, port), ensure_ascii=False), encoding="utf-8")
        checked = subprocess.run(
            [SING_BOX, "check", "-c", str(config_path)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=8,
            check=False,
        )
        if checked.returncode != 0:
            print(f"REJECT candidate={index+1} stage=sing-box-config-check", flush=True)
            return None

        process = subprocess.Popen(
            [SING_BOX, "run", "-c", str(config_path)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        proxy = f"socks5h://127.0.0.1:{port}"
        try:
            ready = False
            for _ in range(30):
                if process.poll() is not None:
                    print(f"REJECT candidate={index+1} stage=sing-box-exited", flush=True)
                    return None
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=0.25):
                        ready = True
                        break
                except OSError:
                    time.sleep(0.2)
            if not ready:
                print(f"REJECT candidate={index+1} stage=socks-not-ready", flush=True)
                return None

            country, exit_ip, geo_error = verify_exit_country(proxy, temp_dir)
            if geo_error or country not in ALLOWED_COUNTRIES:
                reason = geo_error or "country-not-allowed"
                print(f"REJECT candidate={index+1} stage={reason}", flush=True)
                return None

            downloads: list[dict[str, float]] = []
            for round_no in (1, 2):
                sample = test_download(proxy)
                if not sample:
                    print(f"REJECT candidate={index+1} stage=download-round-{round_no}", flush=True)
                    return None
                downloads.append(sample)
                time.sleep(0.5)

            upload = test_upload(proxy, upload_payload)
            if not upload:
                print(f"REJECT candidate={index+1} stage=upload", flush=True)
                return None

            median_download = statistics.median(item["bps"] for item in downloads)
            median_ttfb = statistics.median(item["ttfb"] for item in downloads)
            upload_bps = upload["bps"]
            if median_download < MIN_DOWNLOAD_BPS or upload_bps < MIN_UPLOAD_BPS:
                print(f"REJECT candidate={index+1} stage=throughput-below-threshold", flush=True)
                return None

            server = outbound.get("server", "")
            port_value = int(outbound.get("server_port", 0))
            protocol = outbound.get("type", "unknown")
            fingerprint = hashlib.sha256(
                json.dumps({key: value for key, value in outbound.items() if key != "tag"},
                           sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
            ).hexdigest()[:20]
            outbound["tag"] = "kalani-" + fingerprint[:12]
            return {
                "id": fingerprint,
                "country": country,
                "protocol": protocol,
                "server": server,
                "server_port": port_value,
                "uri": candidate["uri"],
                "outbound": outbound,
                "source": candidate.get("source", "unknown"),
                "exit_ip": exit_ip,
                "status": "verified",
                "tested_at": utc_now(),
                "metrics": {
                    "download_mbps": round(median_download * 8 / 1_000_000, 3),
                    "upload_mbps": round(upload_bps * 8 / 1_000_000, 3),
                    "download_bytes_each_round": int(statistics.median(item["bytes"] for item in downloads)),
                    "upload_bytes": int(upload["bytes"]),
                    "ttfb_ms": round(median_ttfb * 1000, 1),
                    "download_rounds_passed": 2,
                    "score": score_node(median_download, upload_bps, median_ttfb),
                },
            }
        except Exception as exc:
            print(f"REJECT candidate={index+1} stage=exception-{type(exc).__name__}", flush=True)
            return None
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=2)


def select_top(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    selected: list[dict[str, Any]] = []
    seen: set[str] = set()
    for country in ALLOWED_COUNTRIES:
        country_rows = [node for node in results if node["country"] == country]
        country_rows.sort(
            key=lambda node: (
                node["metrics"]["score"],
                node["metrics"]["download_mbps"],
                node["metrics"]["upload_mbps"],
                -node["metrics"]["ttfb_ms"],
            ),
            reverse=True,
        )
        for node in country_rows:
            endpoint = f'{node["server"].lower()}:{node["server_port"]}'
            if endpoint in seen:
                continue
            seen.add(endpoint)
            selected.append(node)
            if sum(1 for item in selected if item["country"] == country) >= MAX_PER_COUNTRY:
                break
    return selected


def main() -> int:
    require_binaries()
    random.seed(int(time.time() // 1800))
    sources = load_sources()
    previous = read_previous()
    candidates = collect_candidates(sources, previous)
    print(f"Sources configured: {len(sources)}; previous pool: {len(previous)}; candidates selected: {len(candidates)}")
    if not candidates:
        print("No candidates available; preserving the existing pool.")
        return 0

    with tempfile.TemporaryDirectory(prefix="kalani-upload-") as upload_dir:
        upload_payload = Path(upload_dir) / "upload.bin"
        upload_payload.write_bytes(os.urandom(UPLOAD_BYTES))
        passed: list[dict[str, Any]] = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures = {
                executor.submit(test_candidate, index, candidate, upload_payload): candidate
                for index, candidate in enumerate(candidates)
            }
            for future in concurrent.futures.as_completed(futures):
                try:
                    result = future.result()
                except Exception as exc:
                    print(f"REJECT worker-exception-{type(exc).__name__}", flush=True)
                    result = None
                if result:
                    passed.append(result)
                    metrics = result["metrics"]
                    print(
                        f'PASS {result["country"]} {result["protocol"]} '
                        f'down={metrics["download_mbps"]}Mbps '
                        f'up={metrics["upload_mbps"]}Mbps '
                        f'ttfb={metrics["ttfb_ms"]}ms score={metrics["score"]}'
                    )

    selected = select_top(passed)
    if not selected:
        print("No candidate passed the complete validation suite; existing pool is left untouched.")
        return 0

    payload = {
        "schema_version": 1,
        "generated_at": utc_now(),
        "engine": {"name": "sing-box", "version": "1.14.4"},
        "validation": {
            "probe_runtime": "GitHub-hosted ubuntu-24.04",
            "country_rule": "Two independent GeoIP providers must agree on the proxy exit country",
            "transfer_test": "2 x 1 MiB HTTPS download and 1 x 256 KiB HTTPS upload through SOCKS5",
            "download_minimum_mbps": round(MIN_DOWNLOAD_BPS * 8 / 1_000_000, 3),
            "upload_minimum_mbps": round(MIN_UPLOAD_BPS * 8 / 1_000_000, 3),
            "target": "speed.cloudflare.com",
        },
        "countries_allowed": list(ALLOWED_COUNTRIES),
        "max_per_country": MAX_PER_COUNTRY,
        "refresh_interval_minutes": 30,
        "max_age_minutes": 90,
        "country_counts": {country: sum(1 for node in selected if node["country"] == country)
                           for country in ALLOWED_COUNTRIES},
        "nodes": selected,
    }

    temporary_output = OUTPUT_FILE.with_suffix(".json.tmp")
    temporary_output.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    temporary_output.replace(OUTPUT_FILE)
    print("Pool published locally:", len(selected), "verified nodes")
    for country in ALLOWED_COUNTRIES:
        print(f"  {country}: {payload['country_counts'][country]}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        # Do not print candidate URIs or outbound JSON: they contain credentials.
        print(f"Collector failed safely: {type(error).__name__}: {error}", file=sys.stderr)
        raise SystemExit(1)
