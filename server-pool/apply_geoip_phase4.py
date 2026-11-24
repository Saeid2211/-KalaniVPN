#!/usr/bin/env python3
"""Safely adapt the known KalaniVPN3 collector to the IPinfo Lite GeoIP module. The patch is intentionally strict and idempotent. It validates every source anchor before making an atomic replacement, and refuses unknown collector layouts rather than guessing. """
from __future__ import annotations

import ast
import os
from pathlib import Path
import tempfile

ROOT = Path(__file__).resolve().parent
COLLECTOR = ROOT / "collect.py"
IMPORT_LINE = "from geoip_ipinfo import verify_exit_country as verify_exit_country_ipinfo"
WRAPPER_MARKER = "return verify_exit_country_ipinfo(proxy, temp_dir, curl_to_file)"

OLD_GEO_URLS = '''# The third independent provider is queried only when the first two fail or disagree. # This preserves the fast path while allowing a 2-of-3 country consensus. GEO_URLS = ( "https://www.cloudflare.com/cdn-cgi/trace", "https://get.geojs.io/v1/ip/geo.json", "https://ipapi.co/json/", )'''
NEW_GEO_URLS = '''# Country verification uses two candidate-routed witnesses. IPinfo Lite is # queried directly from the runner only when one witness fails or they disagree. GEO_URLS = ( "https://www.cloudflare.com/cdn-cgi/trace", "https://get.geojs.io/v1/ip/geo.json", )'''

OLD_COUNTRY_RULE = '"country_rule": "At least two independent GeoIP providers must agree; a third provider is queried only if the first two fail or disagree",'
NEW_COUNTRY_METADATA = '''"country_rule": "Two candidate-routed GeoIP witnesses must agree on the same public exit IP, or one live witness and direct IPinfo Lite lookup for that exact IP must agree; otherwise the candidate is rejected", "geoip_live_providers": ["Cloudflare Trace", "GeoJS"], "geoip_fallback_provider": { "name": "IPinfo Lite", "endpoint": "https://api.ipinfo.io/lite/{ip}", "authentication": "Authorization: Bearer", "token_source": "GitHub Actions secret IPINFO_TOKEN", "connection": "Direct HTTPS from GitHub runner, not through candidate proxy", "attribution": "IP geolocation by IPinfo — https://ipinfo.io (CC BY-SA 4.0)", },'''


def replace_exactly_once(source: str, old: str, new: str, label: str) -> str:
    count = source.count(old)
    if count != 1:
        raise RuntimeError(f"Refusing patch: {label} expected exactly once, found {count}")
    return source.replace(old, new, 1)


def atomic_write(path: Path, content: str) -> None:
    fd, temporary_name = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_name, path)
    except Exception:
        try:
            os.unlink(temporary_name)
        except OSError:
            pass
        raise


def main() -> int:
    if not COLLECTOR.is_file():
        raise FileNotFoundError("server-pool/collect.py not found")

    source = COLLECTOR.read_text(encoding="utf-8")
    already_patched = (
        IMPORT_LINE in source
        and WRAPPER_MARKER in source
        and '"name": "IPinfo Lite"' in source
        and "ipapi.co/json" not in source
    )
    if already_patched:
        ast.parse(source, filename=str(COLLECTOR))
        print("GeoIP Phase 4 patch already applied; no change needed.")
        return 0

    if IMPORT_LINE in source or WRAPPER_MARKER in source:
        raise RuntimeError("Refusing patch: collector appears partially patched; inspect it manually")

    source = replace_exactly_once(
        source,
        "from typing import Any\n",
        "from typing import Any\n" + IMPORT_LINE + "\n",
        "collector import insertion point",
    )
    source = replace_exactly_once(source, OLD_GEO_URLS, NEW_GEO_URLS, "GeoIP provider list")

    function_start = source.find("def _query_geo_provider(")
    if function_start < 0 or source.find("def _query_geo_provider(", function_start + 1) >= 0:
        raise RuntimeError("Refusing patch: expected exactly one old _query_geo_provider function")
    function_end = source.find("\ndef curl_metrics(", function_start)
    if function_end < 0:
        raise RuntimeError("Refusing patch: end of old GeoIP function block was not found")
    old_function_block = source[function_start:function_end]
    if "def verify_exit_country(" not in old_function_block:
        raise RuntimeError("Refusing patch: old verify_exit_country function was not found in expected block")

    replacement_wrapper = '''def verify_exit_country(proxy: str, temp_dir: Path) -> tuple[str | None, str | None, str | None]: return verify_exit_country_ipinfo(proxy, temp_dir, curl_to_file) '''
    source = source[:function_start] + replacement_wrapper + source[function_end:]
    source = replace_exactly_once(source, OLD_COUNTRY_RULE, NEW_COUNTRY_METADATA, "Pool GeoIP validation metadata")

    required_markers = (
        IMPORT_LINE,
        WRAPPER_MARKER,
        '"https://get.geojs.io/v1/ip/geo.json"',
        '"name": "IPinfo Lite"',
        '"token_source":',
    )
    for marker in required_markers:
        if marker not in source:
            raise RuntimeError(f"Refusing patch: post-patch validation failed for {marker!r}")
    if "ipapi.co/json" in source:
        raise RuntimeError("Refusing patch: obsolete ipapi.co endpoint remains")

    # Confirm the patched Python source is syntactically valid before writing.
    ast.parse(source, filename=str(COLLECTOR))
    atomic_write(COLLECTOR, source)
    print("GeoIP Phase 4 patch applied successfully to server-pool/collect.py")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        print(f"GeoIP patch failed safely: {type(error).__name__}: {error}")
        raise SystemExit(1)
