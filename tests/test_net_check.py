"""离线回归：python3 -B -m unittest -v test_net_check.py

地址/国家均为测试夹具，不代表真实归属；所有网络边界被替换。
"""
import argparse
import contextlib
import errno
import io
import json
import socket
import struct
import sys
import unittest
from unittest.mock import Mock, patch
from urllib.parse import parse_qs, unquote, urlsplit

import net_check as net


EXIT = net.ExitInfo(success=True, ip="8.8.8.8", ip_version=4, country="US")
V6_EXIT = net.ExitInfo(success=True, ip="2001:4860:4860::8888", ip_version=6,
                       country="US", via_proxy=True)
TX = b"0123456789ab"


def candidate(address, kind="srflx", source="stun:fixture"):
    category, version = net.classify_address(address)
    return net.CandidateItem(address=address, candidate_type=kind, source=source,
                             category=category, ip_version=version)


def stun_packet(address=EXIT.ip, xor=True, cookie=0x2112A442, transaction=TX):
    addr = net.ipaddress.ip_address(address)
    port, raw = 45678, addr.packed
    if xor:
        port ^= 0x2112A442 >> 16
        raw = bytes(a ^ b for a, b in zip(raw, struct.pack("!I", 0x2112A442) + TX))
    value = struct.pack("!BBH", 0, 1 if addr.version == 4 else 2, port) + raw
    attribute = struct.pack("!HH", 0x0020 if xor else 0x0001, len(value)) + value
    return struct.pack("!HHI", 0x0101, len(attribute), cookie) + transaction + attribute


def run_webrtc(items=(), extra=(), exit_info=EXIT, countries=None):
    def probe(host, port, timeout, label):
        return net.StunProbeResult(label, candidates=list(items),
                                    responses=sum(item.candidate_type == "srflx" for item in items))
    def attribution(ip, timeout):
        value = (countries or {}).get(ip, "US")
        if isinstance(value, Exception):
            return net.IPAttribution(ip=ip, error=str(value))
        return net.IPAttribution(ip=ip, country=value or "", source="geo:fixture")
    with patch.object(net, "query_single_stun", side_effect=probe), \
         patch.object(net, "lookup_ip_attribution", side_effect=attribution):
        return net.check_webrtc_leak(exit_info, list(extra))


def run_ipv6(route, local=None, default=None):
    with patch.object(net, "has_local_ipv6_route", return_value=route), \
         patch.object(net, "detect_exit_ip", return_value=local or net.ExitInfo(error="timeout")), \
         patch.object(net, "probe_tunnel_v6_endpoint", return_value=default or net.ExitInfo(error="HTTP 429")):
        return net.check_ipv6_exposure(EXIT)[1]


def run_dns(cf_ip=EXIT.ip, ecs="8.8.8.0/24", resolver="8.8.4.4",
            unavailable=(), system_error=False, cf_answer="93.184.215.14",
            google_rcode=0, wrong_question=False, truncated=False, detection=None):
    def fetch(url, **kwargs):
        if any(fragment in url for fragment in unavailable):
            raise TimeoutError("simulated timeout")
        if "/cdn-cgi/trace" in url:
            return 200, f"ip={cf_ip}\nloc=US\n", 1.0, False
        query = parse_qs(urlsplit(url).query)
        is_txt = query["type"] == ["TXT"]
        if is_txt:
            answer = [{"type": 16, "data": f'"{resolver}"'}] if resolver else []
            if ecs:
                answer.append({"type": 16, "data": f'"edns0-client-subnet {ecs}"'})
        else:
            answer = [{"type": 1, "data": cf_answer if "dns.google" not in url else "93.184.215.14"}]
        payload = {
            "Status": google_rcode if "dns.google" in url else 0,
            "Question": [{"name": "wrong.test." if wrong_question else query["name"][0] + ".",
                          "type": 16 if is_txt else 1}],
            "Answer": answer, "TC": truncated,
        }
        return 200, json.dumps(payload), 1.0, False

    def resolve(*args, **kwargs):
        if system_error:
            raise socket.gaierror("simulated system resolver failure")
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("198.18.0.2", 443))]

    with patch.object(net, "fetch_url_with_family", side_effect=fetch), \
         patch.object(net.socket, "getaddrinfo", side_effect=resolve), \
         patch.object(net, "probe_dns_resolvers", return_value=detection or net.DNSResolverReport()):
        return net.check_dns_reachability(EXIT)


class OfflineCase(unittest.TestCase):
    def setUp(self):
        # 防止测试遗漏的网络调用真正发包。
        for name in ("fetch_url_with_family",):
            blocker = patch.object(net, name, side_effect=AssertionError("network not mocked"))
            blocker.start()
            self.addCleanup(blocker.stop)
        for name in ("socket", "getaddrinfo"):
            blocker = patch.object(net.socket, name, side_effect=AssertionError("network not mocked"))
            blocker.start()
            self.addCleanup(blocker.stop)


class StunParserTests(OfflineCase):
    def test_valid_ipv4_ipv6_and_legacy_mapped(self):
        for address in (EXIT.ip, V6_EXIT.ip):
            for xor in (True, False):
                with self.subTest(address=address, xor=xor):
                    self.assertEqual(net.parse_stun_binding_response(stun_packet(address, xor), TX),
                                     (address, 45678))

    def test_wrong_cookie_or_transaction_is_rejected(self):
        for packet in (stun_packet(cookie=0), stun_packet(transaction=b"wrong_id_123")):
            self.assertIsNone(net.parse_stun_binding_response(packet, TX))

    def test_bad_message_lengths_are_rejected(self):
        valid = stun_packet()
        for length in (0, 4, 7, 16, 1000):
            with self.subTest(length=length):
                packet = valid[:2] + struct.pack("!H", length) + valid[4:]
                self.assertIsNone(net.parse_stun_binding_response(packet, TX))
        self.assertIsNone(net.parse_stun_binding_response(valid[:-1], TX))

    def test_invalid_attribute_after_valid_one_is_rejected(self):
        valid = stun_packet()
        packet = valid[:2] + struct.pack("!H", 16) + valid[4:] + struct.pack("!HH", 0x0001, 8)
        self.assertIsNone(net.parse_stun_binding_response(packet, TX))

    def test_invalid_address_family_and_length_are_rejected(self):
        packet = bytearray(stun_packet())
        packet[25] = 3
        self.assertIsNone(net.parse_stun_binding_response(bytes(packet), TX))
        packet = bytearray(stun_packet())
        packet[22:24] = struct.pack("!H", 7)
        self.assertIsNone(net.parse_stun_binding_response(bytes(packet), TX))

    def test_query_timeout_keeps_error_and_not_a_response(self):
        sock = Mock()
        sock.getsockname.return_value = ("192.168.1.2", 12345)
        sock.recv.side_effect = TimeoutError("fixture timeout")
        addr = [(socket.AF_INET, socket.SOCK_DGRAM, 17, "", ("198.18.0.2", 3478))]
        with patch.object(net.socket, "getaddrinfo", return_value=addr), \
             patch.object(net.socket, "socket", return_value=sock):
            report = net.query_single_stun("fixture", 3478)
        self.assertEqual(report.responses, 0)
        self.assertTrue(report.errors)
        self.assertTrue(any(item.category == "FAKE-IP" for item in report.candidates))
        sock.close.assert_called_once()

    def test_failed_address_does_not_skip_other_address_in_family(self):
        first, second = Mock(), Mock()
        for sock in (first, second):
            sock.getsockname.return_value = ("192.168.1.2", 12345)
        first.recv.side_effect = TimeoutError("first address down")
        second.recv.return_value = stun_packet()
        addresses = [(socket.AF_INET, socket.SOCK_DGRAM, 17, "", (ip, 3478))
                     for ip in ("8.8.4.4", "9.9.9.9")]
        with patch.object(net.socket, "getaddrinfo", return_value=addresses), \
             patch.object(net.socket, "socket", side_effect=[first, second]), \
             patch.object(net, "build_stun_binding_request", return_value=(b"request", TX)):
            report = net.query_single_stun("fixture", 3478)
        self.assertEqual(report.responses, 1)
        self.assertEqual(len(report.errors), 1)


class WebrtcTests(OfflineCase):
    def test_no_responses_unknown_even_with_fake_ip_and_local_hostname(self):
        report = run_webrtc([
            candidate("198.18.0.2", "dns-resolved", "DNS(fixture)"),
            candidate("audit-mac.local", "host", "verified-mdns-resolver"),
        ])
        self.assertEqual(report.status, net.WARN)
        self.assertFalse(report.has_mdns_obfuscation)
        self.assertFalse(report.stun_srflx_ips)

    def test_matching_exit_passes_without_fake_ip_or_bonjour(self):
        report = run_webrtc([candidate(EXIT.ip)])
        self.assertEqual(report.status, net.PASS)
        self.assertFalse(report.has_fake_ip)
        self.assertFalse(report.has_mdns_obfuscation)
        self.assertEqual(report.browser_status, net.WARN)
        self.assertIn("浏览器未测", report.summary)

    def test_different_us_ip_passes_and_keeps_mismatch_as_diagnostic(self):
        report = run_webrtc([candidate("9.9.9.9")])
        self.assertEqual(report.status, net.PASS)
        self.assertEqual(report.mismatched_ips, ["9.9.9.9"])
        self.assertNotIn("泄漏", report.summary)

    def test_mismatch_preserves_probe_source_for_intermittent_routing(self):
        report = run_webrtc([candidate("9.9.9.9", source="stun:google-direct-ip")],
                            countries={"9.9.9.9": "CN"})
        self.assertEqual(report.status, net.FAIL)
        self.assertIn("stun:google-direct-ip", report.reasons[0])
        self.assertIn("9.9.9.9", report.reasons[0])

    def test_missing_http_baseline_does_not_prevent_independent_geo_check(self):
        self.assertEqual(run_webrtc([candidate(EXIT.ip)], exit_info=net.ExitInfo()).status, net.PASS)

    def test_ipv6_candidate_is_geolocated_without_matching_family_baseline(self):
        report = run_webrtc([candidate(EXIT.ip), candidate(V6_EXIT.ip)])
        self.assertEqual(report.status, net.PASS)
        self.assertEqual(report.mismatched_ips, [])
        self.assertEqual(report.unverified_ips, [])

    def test_socket_source_is_not_browser_exposure(self):
        report = run_webrtc([candidate(EXIT.ip),
                            candidate("9.9.9.9", "host", "udp-route(fixture)")])
        self.assertEqual(report.status, net.PASS)

    def test_only_supplied_ice_mdns_counts_as_observed_mdns(self):
        line = "candidate:1 1 udp 123 12345678-1234-4234-8234-123456789abc.local 5000 typ host"
        report = run_webrtc([candidate(EXIT.ip)], extra=[line])
        self.assertTrue(report.has_mdns_obfuscation)
        self.assertTrue(report.browser_ice_supplied)
        self.assertEqual(report.browser_status, net.WARN)

    def test_malformed_extra_input_is_not_silently_passed(self):
        self.assertEqual(run_webrtc([candidate(EXIT.ip)], extra=["not-an-ip"]).status, net.WARN)

    def test_all_candidate_types_use_geography(self):
        for kind in ("host", "srflx", "prflx", "relay"):
            for country, expected in (("US", net.PASS), ("CN", net.FAIL), ("HK", net.FAIL),
                                       ("SG", net.WARN), ("JP", net.WARN), ("", net.WARN)):
                with self.subTest(kind=kind, country=country):
                    line = f"candidate:1 1 udp 123 9.9.9.9 5000 typ {kind}"
                    report = run_webrtc([candidate(EXIT.ip)], extra=[line], countries={"9.9.9.9": country})
                    self.assertEqual(report.status, expected)

    def test_related_address_is_checked_even_when_main_address_is_us(self):
        for kind in ("srflx", "relay"):
            with self.subTest(kind=kind):
                line = f"candidate:1 1 udp 123 {EXIT.ip} 5000 typ {kind} raddr 9.9.9.9 rport 1234"
                report = run_webrtc([candidate(EXIT.ip)], extra=[line], countries={"9.9.9.9": "HK"})
                self.assertEqual(report.status, net.FAIL)
                self.assertIn("ice-sdp-input:raddr", report.reasons[0])

    def test_private_fake_and_mdns_addresses_are_not_geolocated(self):
        lines = [f"candidate:1 1 udp 123 {ip} 5000 typ host" for ip in (
            "192.168.1.1", "198.18.0.2", "127.0.0.1", "fc00::1", "fd12::1",
            "12345678-1234-4234-8234-123456789abc.local")]
        with patch.object(net, "lookup_ip_attribution") as lookup, \
             patch.object(net, "query_single_stun", return_value=net.StunProbeResult(
                 "fixture", [candidate(EXIT.ip)], 1)):
            report = net.check_webrtc_leak(EXIT, lines)
        self.assertEqual(report.status, net.PASS)
        lookup.assert_not_called()

    def test_geo_failure_warns_and_keeps_evidence(self):
        report = run_webrtc([candidate("9.9.9.9")], countries={"9.9.9.9": TimeoutError("geo timeout")})
        self.assertEqual(report.status, net.WARN)
        self.assertEqual(report.unverified_ips, ["9.9.9.9"])
        self.assertIn("geo timeout", report.reasons[0])

    def test_same_ip_does_not_hide_blocked_country(self):
        for country in ("CN", "HK"):
            with self.subTest(country=country):
                info = net.ExitInfo(success=True, ip=EXIT.ip, country=country)
                self.assertEqual(run_webrtc([candidate(EXIT.ip)], exit_info=info).status, net.FAIL)

    def test_blocked_candidate_wins_over_no_stun_and_unknown_candidate(self):
        report = run_webrtc(extra=["9.9.9.9", "1.1.1.1"],
                            countries={"9.9.9.9": "CN", "1.1.1.1": ""})
        self.assertEqual(report.status, net.FAIL)
        self.assertIn("CN", report.reasons[0])

    def test_partial_stun_failure_is_warning(self):
        def probe(host, port, timeout, label):
            return (net.StunProbeResult(label, [candidate(EXIT.ip)], 1) if host == "stun.cloudflare.com"
                    else net.StunProbeResult(label, errors=["timeout"]))
        with patch.object(net, "query_single_stun", side_effect=probe):
            report = net.check_webrtc_leak(EXIT)
        self.assertEqual(report.status, net.WARN)
        self.assertIn("1/5", report.summary)

    def test_invalid_related_address_or_port_prevents_pass(self):
        for suffix in ("5000 typ relay raddr invalid", "5000 typ relay raddr", "99999 typ host"):
            with self.subTest(suffix=suffix):
                line = f"candidate:1 1 udp 123 {EXIT.ip} {suffix}"
                self.assertEqual(run_webrtc([candidate(EXIT.ip)], extra=[line]).status, net.WARN)

    def test_multiline_ice_argument_does_not_hide_later_blocked_candidate(self):
        lines = (f"candidate:1 1 udp 123 {EXIT.ip} 5000 typ host\n"
                 "a=candidate:2 1 udp 123 9.9.9.9 5001 typ relay")
        report = run_webrtc([candidate(EXIT.ip)], extra=[lines], countries={"9.9.9.9": "HK"})
        self.assertEqual(report.status, net.FAIL)

    def test_malformed_candidate_type_and_multicast_warn(self):
        for line in (f"candidate:1 1 udp 123 {EXIT.ip} 5000 typ hostile", "224.0.0.1", "ff02::1"):
            with self.subTest(line=line):
                self.assertEqual(run_webrtc([candidate(EXIT.ip)], extra=[line]).status, net.WARN)


class IPv6Tests(OfflineCase):
    def test_route_with_probe_failures_is_unknown_not_disabled(self):
        report = run_ipv6(True)
        self.assertEqual(report.status, net.WARN)
        self.assertTrue(report.local_route_available)
        self.assertTrue(report.local_probe_error)

    def test_no_route_and_no_ipv6_exit_pass_under_router_disabled_policy(self):
        for error in ("TLS EOF occurred in violation of protocol", "timeout", "HTTP 429"):
            with self.subTest(error=error):
                report = run_ipv6(False, default=net.ExitInfo(error=error))
                self.assertEqual(report.status, net.PASS)
                self.assertIn("本机无路由", report.summary)
                self.assertIn("未测得 IPv6 出口", report.summary)
                self.assertEqual(report.reasons, [])
                self.assertFalse(report.ipv6_reachable)
                self.assertEqual(report.default_probe_error, error)
                self.assertEqual(report.default_probe.error, error)
                self.assertIn("路由器关闭 IPv6", report.policy)

    def test_proxy_only_v6_is_not_a_native_leak(self):
        report = run_ipv6(False, default=V6_EXIT)
        self.assertEqual(report.status, net.PASS)
        self.assertFalse(report.local_stack_v6_reachable)
        self.assertTrue(report.default_path_v6_reachable)
        self.assertNotIn("直连", report.summary)

    def test_us_local_and_default_ipv6_pass(self):
        report = run_ipv6(True, local=V6_EXIT, default=V6_EXIT)
        self.assertEqual(report.status, net.PASS)
        self.assertTrue(report.local_stack_v6_reachable)
        self.assertNotIn("直连", report.summary)

    def test_both_ipv6_paths_use_geography(self):
        for country, expected in (("US", net.PASS), ("CN", net.FAIL), ("HK", net.FAIL),
                                   ("SG", net.WARN), ("JP", net.WARN), ("", net.WARN), ("ZZ", net.WARN)):
            info = net.ExitInfo(success=True, ip=V6_EXIT.ip, ip_version=6, country=country)
            with self.subTest(country=country, path="default"):
                self.assertEqual(run_ipv6(False, default=info).status, expected)
            with self.subTest(country=country, path="local"):
                self.assertEqual(run_ipv6(True, local=info, default=V6_EXIT).status, expected)

    def test_us_local_does_not_hide_hk_proxy_ipv6(self):
        hk = net.ExitInfo(success=True, ip="2606:4700:4700::1111", ip_version=6, country="HK")
        report = run_ipv6(True, local=V6_EXIT, default=hk)
        self.assertEqual(report.status, net.FAIL)
        self.assertIn("默认/代理", report.reasons[0])
        self.assertIn("HK", report.reasons[0])

    def test_ipv6_error_wins_over_other_path_timeout(self):
        cn = net.ExitInfo(success=True, ip=V6_EXIT.ip, ip_version=6, country="CN")
        self.assertEqual(run_ipv6(True, local=cn).status, net.FAIL)

    def test_wrong_address_family_is_warning(self):
        self.assertEqual(run_ipv6(False, default=EXIT).status, net.WARN)

    def test_us_path_does_not_hide_other_path_failure(self):
        self.assertEqual(run_ipv6(True, local=V6_EXIT).status, net.WARN)
        self.assertEqual(run_ipv6(True, default=V6_EXIT).status, net.WARN)

    def test_route_probe_error_is_unknown(self):
        self.assertEqual(run_ipv6(None).status, net.WARN)

    def test_unknown_route_is_not_treated_as_disabled_even_with_us_proxy(self):
        self.assertEqual(run_ipv6(None, default=V6_EXIT).status, net.WARN)

    def test_route_known_unreachable_is_false(self):
        with patch.object(net.socket, "socket", side_effect=OSError(errno.ENETUNREACH, "no route")):
            self.assertIs(net.has_local_ipv6_route(), False)

    def test_route_permission_or_other_error_is_not_false(self):
        with patch.object(net.socket, "socket", side_effect=OSError(errno.EACCES, "denied")):
            self.assertIsNone(net.has_local_ipv6_route())

    def test_ula_route_must_be_probed(self):
        sock = Mock()
        sock.getsockname.return_value = ("fd12::1", 5000, 0, 0)
        with patch.object(net.socket, "socket", return_value=sock):
            self.assertIs(net.has_local_ipv6_route(), True)


class DNSTests(OfflineCase):
    def test_good_doh_does_not_prove_system_dns_safe(self):
        report = run_dns()
        self.assertEqual(report.doh_status, net.PASS)
        self.assertEqual(report.status, net.WARN)
        self.assertEqual(report.system_dns_status, net.WARN)
        self.assertTrue(report.system_dns_is_fake_ip)

    def test_same_country_different_cf_exit_is_auxiliary_anomaly(self):
        report = run_dns(cf_ip="9.9.9.9")
        self.assertEqual(report.doh_status, net.WARN)
        self.assertEqual(report.status, net.WARN)
        self.assertIs(report.cf_egress_aligned, False)

    def test_same_country_different_ecs_is_auxiliary_anomaly(self):
        report = run_dns(ecs="9.9.9.0/24")
        self.assertEqual(report.doh_status, net.WARN)
        self.assertEqual(report.status, net.WARN)
        self.assertIs(report.google_egress_aligned, False)

    def test_resolver_address_is_not_client_evidence(self):
        report = run_dns(ecs="")
        self.assertEqual(report.status, net.WARN)
        self.assertIsNone(report.google_egress_aligned)
        self.assertTrue(report.google_doh_ok)

    def test_zero_prefix_bad_prefix_and_cross_family_ecs_are_unknown(self):
        for subnet in ("0.0.0.0/0", "invalid", "2001:4860::/32"):
            with self.subTest(subnet=subnet):
                report = run_dns(ecs=subnet)
                self.assertEqual(report.status, net.WARN)
                self.assertIsNone(report.google_egress_aligned)

    def test_doh_timeout_is_unknown_not_leak(self):
        for provider in ("dns.google", "cloudflare-dns.com"):
            unavailable = [provider]
            if provider == "cloudflare-dns.com":
                unavailable.append("1.1.1.1/dns-query")
            with self.subTest(provider=provider):
                report = run_dns(unavailable=unavailable)
                self.assertEqual(report.status, net.WARN)
                self.assertEqual(report.doh_status, net.WARN)

    def test_ecs_failure_is_not_google_doh_unreachability(self):
        report = run_dns(unavailable=["o-o.myaddr"])
        self.assertTrue(report.google_doh_ok)
        self.assertEqual(report.doh_status, net.WARN)

    def test_trace_failure_is_unknown_not_egress_mismatch(self):
        report = run_dns(unavailable=["cdn-cgi/trace"])
        self.assertEqual(report.status, net.WARN)
        self.assertIsNone(report.cf_egress_aligned)
        self.assertTrue(report.cf_trace_error)

    def test_system_resolver_failure_is_recorded_and_not_safe(self):
        report = run_dns(system_error=True)
        self.assertEqual(report.status, net.WARN)
        self.assertEqual(report.system_dns_ips, [])
        self.assertTrue(report.system_dns_error)

    def test_domain_fallback_does_not_claim_ip_doh_success(self):
        report = run_dns(unavailable=["1.1.1.1/dns-query"])
        self.assertTrue(report.cloudflare_doh_ok)
        self.assertFalse(report.endpoints[0].reachable)
        self.assertTrue(report.endpoints[1].reachable)
        self.assertNotIn("1.1.1.1", report.summary)

    def test_nonpublic_doh_answer_is_auxiliary_anomaly(self):
        for address in ("198.18.0.2", "127.0.0.1"):
            with self.subTest(address=address):
                self.assertEqual(run_dns(cf_answer=address).doh_status, net.WARN)

    def test_region_policy_is_independent_of_doh_ip_comparison(self):
        detection = net.DNSResolverReport(status=net.PASS, summary="US")
        report = run_dns(cf_ip="9.9.9.9", detection=detection)
        self.assertEqual(report.status, net.PASS)
        self.assertEqual(report.system_dns_status, net.PASS)
        self.assertEqual(report.doh_status, net.WARN)
        self.assertEqual(report.reasons, [])
        self.assertTrue(report.doh_reasons)

    def test_doh_failure_does_not_override_successful_region_samples(self):
        detection = net.DNSResolverReport(status=net.PASS, summary="US")
        report = run_dns(unavailable=["dns.google"], detection=detection)
        self.assertEqual(report.status, net.PASS)
        self.assertEqual(report.doh_status, net.WARN)

    def test_blocked_region_fails_even_when_doh_is_good(self):
        detection = net.DNSResolverReport(status=net.FAIL, summary="HK", reasons=["8.8.8.8 [HK]"])
        report = run_dns(detection=detection)
        self.assertEqual(report.status, net.FAIL)
        self.assertEqual(report.doh_status, net.PASS)
        self.assertEqual(report.reasons, detection.reasons)

    def test_servfail_is_unknown_not_pollution_or_leak(self):
        report = run_dns(google_rcode=2)
        self.assertEqual(report.status, net.WARN)
        self.assertFalse(report.google_doh_ok)
        self.assertEqual(report.endpoints[2].error, "DNS RCODE=2")

    def test_mismatched_question_is_not_valid_evidence(self):
        report = run_dns(wrong_question=True)
        self.assertEqual(report.status, net.WARN)
        self.assertFalse(report.cloudflare_doh_ok)

    def test_truncated_response_is_not_valid_evidence(self):
        report = run_dns(truncated=True)
        self.assertEqual(report.status, net.WARN)
        self.assertFalse(report.google_doh_ok)

    def test_cross_family_cf_trace_is_unknown(self):
        report = run_dns(cf_ip=V6_EXIT.ip)
        self.assertEqual(report.status, net.WARN)
        self.assertIsNone(report.cf_egress_aligned)


class DNSResolverSamplingTests(OfflineCase):
    def probe(self, snapshots=None, countries=None, mismatched_session=False, used_proxy=False):
        snapshots = snapshots if snapshots is not None else [{EXIT.ip: i + 1} for i in range(5)]
        countries = countries or {}
        calls, metadata_calls = [], []

        def fetch(url, **kwargs):
            parsed = urlsplit(url)
            if parsed.path == "/dnsdetection/":
                index = len(calls)
                calls.append((url, kwargs))
                snapshot = snapshots[index]
                if isinstance(snapshot, Exception):
                    raise snapshot
                session = parsed.hostname.split(".")[0][:40]
                payload = {"session": "wrong" if mismatched_session else session, "ip": snapshot}
                return 200, json.dumps(payload), 1.0, used_proxy
            if parsed.hostname == "ipleak.net" and parsed.path.startswith("/json/"):
                ip = unquote(parsed.path[len("/json/"):])
                metadata_calls.append(ip)
                value = countries.get(ip, "US")
                if isinstance(value, Exception):
                    raise value
                data = value if isinstance(value, dict) else {
                    "ip": ip, "country_code": value, "country_name": "fixture",
                    "isp_name": "fixture resolver", "as_number": 13335,
                }
                return 200, json.dumps(data), 1.0, False
            raise AssertionError(f"unexpected URL: {url}")

        with patch.object(net, "fetch_url_with_family", side_effect=fetch):
            report = net.probe_dns_resolvers(timeout=3.0, sample_count=len(snapshots))
        return report, calls, metadata_calls

    def test_five_unique_labels_share_one_40_character_session(self):
        report, calls, _ = self.probe()
        self.assertEqual(report.status, net.PASS)
        self.assertEqual(report.successful_samples, 5)
        self.assertEqual(len(report.session), 40)
        hosts = [urlsplit(url).hostname.split(".")[0] for url, _ in calls]
        self.assertEqual(len(set(hosts)), 5)
        for host in hosts:
            self.assertTrue(host.startswith(report.session + "-"))
            self.assertLessEqual(len(host), 63)
            self.assertEqual(host.count("-"), 1, "IPLeak rejects extra hyphens inside the label")

    def test_sampling_uses_system_path_and_bypasses_http_proxy(self):
        _, calls, _ = self.probe()
        for _, kwargs in calls:
            self.assertIs(kwargs["bypass_system_proxy"], True)
            self.assertIsNone(kwargs["proxy_url"])
            self.assertEqual(kwargs["family"], socket.AF_UNSPEC)

    def test_cumulative_counts_are_not_summed_and_old_ips_are_retained(self):
        snapshots = [{EXIT.ip: 1}, {EXIT.ip: 3, "9.9.9.9": 2}, {EXIT.ip: 2}]
        report, _, lookups = self.probe(snapshots)
        self.assertEqual(report.status, net.PASS)
        self.assertEqual({r.ip: r.query_count for r in report.resolvers},
                         {EXIT.ip: 3, "9.9.9.9": 2})
        self.assertCountEqual(lookups, [EXIT.ip, "9.9.9.9"])

    def test_china_and_hong_kong_each_fail(self):
        for country in ("CN", "HK", "cn", "hk"):
            with self.subTest(country=country):
                report, _, _ = self.probe(countries={EXIT.ip: country})
                self.assertEqual(report.status, net.FAIL)
                self.assertIn(country.upper(), report.reasons[0])
                self.assertIn(EXIT.ip, report.reasons[0])

    def test_us_passes_and_other_known_regions_warn(self):
        for country in ("US", "DE", "SG", "JP", "MO", "TW"):
            with self.subTest(country=country):
                expected = net.PASS if country == "US" else net.WARN
                self.assertEqual(self.probe(countries={EXIT.ip: country})[0].status, expected)

    def test_us_resolver_does_not_hide_other_country(self):
        report, _, _ = self.probe([{EXIT.ip: 1, "9.9.9.9": 1}], countries={"9.9.9.9": "SG"})
        self.assertEqual(report.status, net.WARN)
        self.assertIn("9.9.9.9 [SG]", report.reasons[0])

    def test_blocked_region_wins_over_other_country_warning(self):
        report, _, _ = self.probe([{EXIT.ip: 1, "9.9.9.9": 1}],
                                  countries={EXIT.ip: "SG", "9.9.9.9": "HK"})
        self.assertEqual(report.status, net.FAIL)
        self.assertIn("HK", report.reasons[0])

    def test_one_blocked_ip_among_allowed_resolvers_fails(self):
        report, _, _ = self.probe([{EXIT.ip: 1, "9.9.9.9": 1}],
                                  countries={EXIT.ip: "US", "9.9.9.9": "HK"})
        self.assertEqual(report.status, net.FAIL)
        self.assertIn("9.9.9.9 [HK]", report.reasons[0])

    def test_early_blocked_ip_is_not_erased_by_later_snapshot(self):
        report, _, _ = self.probe([{"9.9.9.9": 1}, {EXIT.ip: 1}],
                                  countries={"9.9.9.9": "CN"})
        self.assertEqual(report.status, net.FAIL)

    def test_unknown_country_is_not_an_allowed_region(self):
        for country in (None, "", "ZZ", "XX", "QQ", "USA", 1):
            with self.subTest(country=country):
                report, _, _ = self.probe(countries={EXIT.ip: country})
                self.assertEqual(report.status, net.WARN)
                self.assertEqual(report.resolvers[0].country, "")
                self.assertTrue(report.resolvers[0].error)

    def test_one_missing_geolocation_prevents_pass(self):
        report, _, _ = self.probe([{EXIT.ip: 1, "9.9.9.9": 1}],
                                  countries={"9.9.9.9": TimeoutError("geo timeout")})
        self.assertEqual(report.status, net.WARN)

    def test_partial_sample_timeout_prevents_pass(self):
        report, _, _ = self.probe([{EXIT.ip: 1}, TimeoutError("sample timeout")])
        self.assertEqual(report.status, net.WARN)
        self.assertEqual(report.successful_samples, 1)
        self.assertIn("sample timeout", report.reasons[-1])

    def test_blocked_region_takes_precedence_over_missing_evidence(self):
        report, _, _ = self.probe([{EXIT.ip: 1, "9.9.9.9": 1}, TimeoutError("sample timeout")],
                                  countries={EXIT.ip: "CN", "9.9.9.9": None})
        self.assertEqual(report.status, net.FAIL)
        self.assertIn("[CN]", report.reasons[0])
        self.assertTrue(any("归属未确认" in reason for reason in report.reasons))

    def test_empty_response_is_unknown(self):
        report, _, lookups = self.probe([{}, {}])
        self.assertEqual(report.status, net.WARN)
        self.assertEqual(report.successful_samples, 0)
        self.assertEqual(lookups, [])

    def test_all_timeouts_are_unknown(self):
        report, _, _ = self.probe([TimeoutError("one"), TimeoutError("two")])
        self.assertEqual(report.status, net.WARN)
        self.assertEqual(report.resolvers, [])

    def test_cross_session_result_is_not_used(self):
        report, _, lookups = self.probe(countries={EXIT.ip: "CN"}, mismatched_session=True)
        self.assertEqual(report.status, net.WARN)
        self.assertEqual(lookups, [])
        self.assertIn("会话不匹配", report.samples[0].error)

    def test_wrong_ip_in_geolocation_is_not_used(self):
        metadata = {"ip": "9.9.9.9", "country_code": "CN"}
        report, _, _ = self.probe(countries={EXIT.ip: metadata})
        self.assertEqual(report.status, net.WARN)
        self.assertEqual(report.resolvers[0].country, "")

    def test_country_code_not_registered_country_controls_policy(self):
        for actual, registered, expected in (("US", "CN", net.PASS), ("HK", "US", net.FAIL)):
            with self.subTest(actual=actual):
                metadata = {"ip": EXIT.ip, "country_code": actual, "registered_country_code": registered}
                self.assertEqual(self.probe(countries={EXIT.ip: metadata})[0].status, expected)

    def test_ipv6_resolver_is_also_checked(self):
        report, _, lookups = self.probe([{V6_EXIT.ip: 1}], countries={V6_EXIT.ip: "HK"})
        self.assertEqual(report.status, net.FAIL)
        self.assertEqual(lookups, [V6_EXIT.ip])

    def test_invalid_entry_is_not_silently_ignored_for_pass(self):
        for key, count in (("198.18.0.2", 1), ("not-an-ip", 1),
                           ("224.0.0.1", 1), ("ff02::1", 1),
                           ("9.9.9.9", 0), ("9.9.9.9", True), ("9.9.9.9", "1")):
            with self.subTest(key=key, count=count):
                report, _, _ = self.probe([{EXIT.ip: 1, key: count}])
                self.assertEqual(report.status, net.WARN)
                self.assertTrue(report.samples[0].error)

    def test_valid_blocked_entry_survives_other_invalid_entries(self):
        report, _, _ = self.probe([{EXIT.ip: 1, "not-an-ip": 2}], countries={EXIT.ip: "CN"})
        self.assertEqual(report.status, net.FAIL)

    def test_accidental_http_proxy_path_is_unknown(self):
        report, _, lookups = self.probe(used_proxy=True)
        self.assertEqual(report.status, net.WARN)
        self.assertEqual(lookups, [])

    def test_http_geolocation_failure_is_unknown(self):
        with patch.object(net, "fetch_url_with_family", return_value=(429, "{}", 1.0, False)):
            resolver = net.lookup_dns_resolver(EXIT.ip)
        self.assertEqual(resolver.country, "")
        self.assertIn("HTTP 429", resolver.error)

    def test_malformed_dns_response_is_rejected(self):
        for body in ("not-json", "[]", '{"session":"fixture"}', '{"session":"fixture","ip":[]}'):
            with self.subTest(body=body), self.assertRaises(ValueError):
                net.parse_dns_observations(body, "fixture")


class CliTests(OfflineCase):
    def run_cli(self, statuses, json_output):
        output = io.StringIO()
        argv = ["net_check.py"] + (["--json"] if json_output else [])
        with patch.object(sys, "argv", argv), contextlib.redirect_stdout(output), \
             patch.object(net, "detect_exit_ip", return_value=EXIT), \
             patch.object(net, "check_webrtc_leak", return_value=net.WebRTCReport(status=statuses[0])), \
             patch.object(net, "check_ipv6_exposure",
                          return_value=(net.ExitInfo(), net.IPv6Report(status=statuses[1]))), \
             patch.object(net, "check_dns_reachability", return_value=net.DNSReport(status=statuses[2])):
            code = net.main()
        return code, output.getvalue()

    def test_table_and_json_have_identical_three_state_exit_codes(self):
        for statuses, expected, code in (
            ([net.PASS] * 3, net.PASS, 0),
            ([net.PASS, net.PASS, net.WARN], net.WARN, 2),
            ([net.WARN, net.FAIL, net.WARN], net.FAIL, 1),
        ):
            with self.subTest(statuses=statuses):
                table_code, table = self.run_cli(statuses, False)
                json_code, raw = self.run_cli(statuses, True)
                data = json.loads(raw)
                self.assertEqual(table_code, code)
                self.assertEqual(json_code, code)
                self.assertEqual(data["return_code"], code)
                self.assertEqual(data["status"], expected)
                self.assertEqual(data["all_passed"], code == 0)
                self.assertEqual(data["schema_version"], 3)
                self.assertEqual(data["region_policy"], net.REGION_POLICY)
                self.assertIn(net.STATUS_LABELS[expected], table)
                self.assertEqual(sum(line.startswith(("[1]", "[2]", "[3]", "[4]"))
                                     for line in table.splitlines()), 4)

    def test_aggregate_fails_closed_on_unknown_status(self):
        self.assertEqual(net.aggregate_status([net.PASS, "unexpected"]), net.WARN)
        self.assertEqual(net.aggregate_status([]), net.WARN)

    def test_warning_has_its_own_icon_and_label(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            net.print_table_row(2, "STUN", net.WARN, "无回包", "采样", ["无法确认"])
        self.assertIn("⚠", output.getvalue())
        self.assertIn("警告", output.getvalue())
        self.assertNotIn("❌", output.getvalue())

    def test_tty_row_clears_progress_with_real_control_characters(self):
        output = io.StringIO()
        with patch.object(output, "isatty", return_value=True), contextlib.redirect_stdout(output):
            net.print_table_row(1, "出口", net.PASS, EXIT.ip, "目标: US")
        self.assertTrue(output.getvalue().startswith("\r\x1b[K"))
        self.assertNotIn("\\033", output.getvalue())

    def test_null_or_malformed_country_is_unknown_not_wrong_country(self):
        for country in (None, "", 1, "None", "USA", "ZZ", "QQ"):
            with self.subTest(country=country):
                info = net.parse_ipinfo_payload(json.dumps({"ip": EXIT.ip, "country": country}), 0, False)
                self.assertEqual(net.evaluate_exit_country(info).status, net.WARN)

    def test_exit_query_failure_and_missing_country_are_unknown(self):
        self.assertEqual(net.evaluate_exit_country(net.ExitInfo(error="timeout")).status, net.WARN)
        info = net.ExitInfo(success=True, ip=EXIT.ip, country="")
        self.assertEqual(net.evaluate_exit_country(info).status, net.WARN)

    def test_main_exit_uses_fixed_geography_policy(self):
        for country, expected in (("US", net.PASS), ("us", net.PASS), ("CN", net.FAIL),
                                   (" hk ", net.FAIL), ("DE", net.WARN), ("SG", net.WARN),
                                   ("MO", net.WARN), ("TW", net.WARN)):
            with self.subTest(country=country):
                info = net.ExitInfo(success=True, ip=EXIT.ip, country=country)
                self.assertEqual(net.evaluate_exit_country(info).status, expected)

    def test_conflicting_legacy_options_are_rejected_before_network(self):
        for options in (["--expect-country", "SG"], ["--expect-country", "HK"], ["--require-no-ipv6"]):
            with self.subTest(options=options), patch.object(sys, "argv", ["net_check.py"] + options), \
                 contextlib.redirect_stderr(io.StringIO()), patch.object(net, "detect_exit_ip") as detect, \
                 self.assertRaises(SystemExit) as raised:
                net.main()
            self.assertEqual(raised.exception.code, 2)
            detect.assert_not_called()

    def test_fake_exit_is_rejected(self):
        for ip in ("198.18.0.2", "224.0.0.1", "ff02::1"):
            with self.subTest(ip=ip), self.assertRaises(ValueError):
                net.parse_ipinfo_payload(json.dumps({"ip": ip, "country": "US"}), 1.0, False)

    def test_real_ipv6_check_propagates_hk_proxy_to_cli_error(self):
        hk = net.ExitInfo(success=True, ip=V6_EXIT.ip, ip_version=6, country="HK")
        output = io.StringIO()
        with patch.object(sys, "argv", ["net_check.py", "--json"]), contextlib.redirect_stdout(output), \
             patch.object(net, "detect_exit_ip", return_value=EXIT), \
             patch.object(net, "check_webrtc_leak", return_value=net.WebRTCReport(status=net.PASS)), \
             patch.object(net, "has_local_ipv6_route", return_value=False), \
             patch.object(net, "probe_tunnel_v6_endpoint", return_value=hk), \
             patch.object(net, "check_dns_reachability", return_value=net.DNSReport(status=net.PASS)):
            code = net.main()
        payload = json.loads(output.getvalue())
        self.assertEqual(code, 1)
        self.assertEqual(payload["ipv6_exposure"]["status"], net.FAIL)
        self.assertFalse(payload["all_passed"])

    def test_timeout_must_be_finite_and_positive(self):
        for value in ("0", "-1", "nan", "inf"):
            with self.subTest(value=value), self.assertRaises(argparse.ArgumentTypeError):
                net.positive_timeout(value)

    def test_dns_sample_count_is_bounded(self):
        for value in ("0", "-1", "21"):
            with self.subTest(value=value), self.assertRaises(argparse.ArgumentTypeError):
                net.dns_sample_count(value)
        self.assertEqual(net.dns_sample_count("5"), 5)


if __name__ == "__main__":
    unittest.main(verbosity=2)
