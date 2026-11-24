#!/usr/bin/env python3
"""Unit tests for KalaniVPN3's fail-closed GeoIP quorum logic."""
import unittest

from geoip_ipinfo import (
    normalize_public_ip,
    parse_country,
    parse_ipinfo_response,
    resolve_geo_quorum,
)


class GeoQuorumTests(unittest.TestCase):
    def test_two_live_providers_agree_for_same_ip(self):
        observations = [
            ("US", "8.8.8.8", "cloudflare"),
            ("US", "8.8.8.8", "geojs"),
        ]
        self.assertEqual(resolve_geo_quorum(observations), ("US", "8.8.8.8", None))

    def test_one_live_provider_plus_ipinfo(self):
        observations = [("NL", "1.1.1.1", "cloudflare")]
        self.assertEqual(resolve_geo_quorum(observations, "NL"), ("NL", "1.1.1.1", None))

    def test_ipinfo_breaks_live_provider_disagreement(self):
        observations = [
            ("FI", "8.8.8.8", "cloudflare"),
            ("US", "8.8.8.8", "geojs"),
        ]
        self.assertEqual(resolve_geo_quorum(observations, "US"), ("US", "8.8.8.8", None))

    def test_three_way_disagreement_fails_closed(self):
        observations = [
            ("FI", "8.8.8.8", "cloudflare"),
            ("US", "8.8.8.8", "geojs"),
        ]
        country, ip, error = resolve_geo_quorum(observations, "DE")
        self.assertIsNone(country)
        self.assertEqual(ip, "8.8.8.8")
        self.assertEqual(error, "geolocation-no-quorum")

    def test_same_country_but_different_exit_ips_fails_closed(self):
        observations = [
            ("US", "8.8.8.8", "cloudflare"),
            ("US", "1.1.1.1", "geojs"),
        ]
        country, ip, error = resolve_geo_quorum(observations)
        self.assertIsNone(country)
        self.assertIsNone(ip)
        self.assertEqual(error, "geolocation-exit-ip-disagreement")

    def test_single_live_provider_without_ipinfo_fails_closed(self):
        country, ip, error = resolve_geo_quorum([("US", "8.8.8.8", "cloudflare")])
        self.assertIsNone(country)
        self.assertEqual(ip, "8.8.8.8")
        self.assertEqual(error, "geolocation-no-quorum")

    def test_ipinfo_response_must_match_exact_exit_ip(self):
        self.assertEqual(
            parse_ipinfo_response({"ip": "8.8.8.8", "country_code": "US"}, "8.8.8.8"),
            "US",
        )
        self.assertIsNone(
            parse_ipinfo_response({"ip": "1.1.1.1", "country_code": "US"}, "8.8.8.8")
        )
        self.assertIsNone(
            parse_ipinfo_response({"ip": "8.8.8.8", "country_code": ""}, "8.8.8.8")
        )

    def test_non_global_addresses_are_rejected(self):
        self.assertEqual(normalize_public_ip("8.8.8.8"), "8.8.8.8")
        self.assertIsNone(normalize_public_ip("127.0.0.1"))
        self.assertIsNone(normalize_public_ip("192.0.2.1"))
        self.assertIsNone(normalize_public_ip("not-an-ip"))

    def test_duplicate_live_provider_cannot_supply_two_votes(self):
        observations = [
            ("US", "8.8.8.8", "cloudflare"),
            ("US", "8.8.8.8", "cloudflare"),
        ]
        country, ip, error = resolve_geo_quorum(observations)
        self.assertIsNone(country)
        self.assertEqual(ip, "8.8.8.8")
        self.assertEqual(error, "geolocation-duplicate-provider")

    def test_cloudflare_trace_payload(self):
        payload = "ip=8.8.8.8\nloc=US\n"
        self.assertEqual(parse_country(payload), ("US", "8.8.8.8"))

    def test_geojs_payload(self):
        payload = {"ip": "1.1.1.1", "country_code": "NL"}
        self.assertEqual(parse_country(payload), ("NL", "1.1.1.1"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
