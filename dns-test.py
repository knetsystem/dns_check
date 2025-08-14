#!/usr/bin/env python3
# Requires: pip install dnspython
#
# Outputs Prometheus text format to stdout.
# Minimal metrics:
#   - knet_dns_check_result{scope,check,server|host,ns_ip?,ip_family,transport,resolver?,failure_reason} 0/1
#   - knet_dns_script_duration_seconds
#   - knet_dns_last_run_timestamp_seconds
# Optional (VERBOSE=1):
#   - knet_dns_check_duration_seconds{...}
#   - knet_dns_check_rcode{...}
#   - knet_dns_check_answers{...}

import os, time
from typing import List, Tuple
import dns.resolver, dns.reversename, dns.rcode, dns.exception

VERBOSE = os.getenv("VERBOSE", "0") == "1"
TIMEOUT = float(os.getenv("TIMEOUT", "2.0"))
PUBLIC_PTR_MODE = os.getenv("PUBLIC_PTR_MODE", "fcrdns").lower()  # 'fcrdns' (default) or 'exact'

# ---------- Authoritative checks (scope=auth) ----------
AUTH_CHECKS: List[Tuple[str, str, str, str]] = [
    ("ptr_82_211_192_242", "PTR",  "82.211.192.242",                          "arthur.k-net.dk."),
    ("ptr_82_211_192_0",   "PTR",  "82.211.192.0",                            "0052d3c000.dynamic-ip4.rev.k-net.dk."),
    ("a_0052d3c000",       "A",    "0052d3c000.dynamic-ip4.rev.k-net.dk.",    "82.211.192.0"),
    ("ptr_2a03_19c0_2_2",  "PTR",  "2a03:19c0::2:2",                          "arthur.k-net.dk."),
    ("ptr_2a03_19c0_1",    "PTR",  "2a03:19c0::1",                            "2a03-19c0--1.dynamic-ip6.rev.k-net.dk."),
    ("aaaa_2a03_19c0_1",   "AAAA", "2a03-19c0--1.dynamic-ip6.rev.k-net.dk.",  "2a03:19c0::1"),
]

AUTH_SERVERS = [
    {"name": "ns1.k-net.dk", "v4": "94.130.175.44",  "v6": "2a01:4f8:c0c:13d2::1"},
    {"name": "ns2.k-net.dk", "v4": "65.21.158.218",  "v6": "2a01:4f9:c010:882d::1"},
]
AUTH_TRANSPORTS = ["udp", "tcp"]

# ---------- Public recursor checks (scope=public, TCP-only) ----------
HOST_EXPECTATIONS = [
    {"host": "ns1.k-net.dk.", "A": "94.130.175.44", "AAAA": "2a01:4f8:c0c:13d2::1"},
    {"host": "ns2.k-net.dk.", "A": "65.21.158.218", "AAAA": "2a01:4f9:c010:882d::1"},
]
PUBLIC_RECURSORS = [{"resolver": "1.1.1.1"}, {"resolver": "2620:fe::9"}]  # v4 CF, v6 Quad9
PUBLIC_TRANSPORTS = ["tcp"]  # per your request

def make_resolver(ns_ip: str) -> dns.resolver.Resolver:
    r = dns.resolver.Resolver(configure=False)
    r.nameservers = [ns_ip]
    r.timeout = TIMEOUT
    r.lifetime = TIMEOUT
    return r

def run_query(resolver: dns.resolver.Resolver, qname: str, rtype: str, use_tcp: bool):
    t0 = time.time()
    rcode_num = None
    answers_txt: List[str] = []
    ok_proto = False
    reason = "other"
    try:
        ans = resolver.resolve(qname, rtype, tcp=use_tcp)
        answers_txt = [rr.to_text() for rr in ans]
        rcode_num = ans.response.rcode()
        ok_proto = (rcode_num == dns.rcode.NOERROR)
        reason = "ok" if ok_proto else "other"
        if not answers_txt:
            reason = "noanswer"
    except dns.resolver.NXDOMAIN:
        rcode_num = dns.rcode.NXDOMAIN
        reason = "nxdomain"
    except dns.resolver.NoAnswer:
        rcode_num = dns.rcode.NOERROR
        reason = "noanswer"
    except dns.exception.Timeout:
        reason = "timeout"
    except Exception:
        reason = "other"
    dur = time.time() - t0
    return ok_proto, dur, answers_txt, (rcode_num if rcode_num is not None else -1), reason

def print_headers():
    print("# HELP knet_dns_check_result 1 if the check succeeded (query + expected answer matched), else 0")
    print("# TYPE knet_dns_check_result gauge")
    if VERBOSE:
        print("# HELP knet_dns_check_duration_seconds Duration of the DNS query")
        print("# TYPE knet_dns_check_duration_seconds gauge")
        print("# HELP knet_dns_check_rcode DNS RCODE (-1 if unknown)")
        print("# TYPE knet_dns_check_rcode gauge")
        print("# HELP knet_dns_check_answers Number of RRs in the answer section we saw")
        print("# TYPE knet_dns_check_answers gauge")
    print("# HELP knet_dns_script_duration_seconds Total runtime of the script")
    print("# TYPE knet_dns_script_duration_seconds gauge")
    print("# HELP knet_dns_last_run_timestamp_seconds Unix timestamp when script started")
    print("# TYPE knet_dns_last_run_timestamp_seconds gauge")

def main():
    script_start = time.time()
    now_ts = int(script_start)
    print_headers()

    # ------- Loop 1: Authoritative (scope=auth) -------
    for srv in AUTH_SERVERS:
        for fam_label, ns_ip in (("ipv4", srv.get("v4")), ("ipv6", srv.get("v6"))):
            if not ns_ip:
                continue
            for transport in AUTH_TRANSPORTS:
                resolver = make_resolver(ns_ip)
                use_tcp = (transport == "tcp")
                for check_name, rtype, value, expected in AUTH_CHECKS:
                    # PTR needs reverse domain; A/AAAA use hostname directly.
                    qname = dns.reversename.from_address(value).to_text() if rtype == "PTR" else value
                    ok_proto, dur, answers, rcode_num, reason = run_query(resolver, qname, rtype, use_tcp)
                    ok = ok_proto and (expected in answers)
                    failure_reason = "ok" if ok else (reason if reason != "ok" else "mismatch")
                    labels = (
                        f'scope="auth",'
                        f'check="{check_name}",'
                        f'server="{srv["name"]}",'
                        f'ns_ip="{ns_ip}",'
                        f'ip_family="{fam_label}",'
                        f'transport="{transport}",'
                        f'failure_reason="{failure_reason}"'
                    )
                    print(f'knet_dns_check_result{{{labels}}} {1 if ok else 0}')
                    if VERBOSE:
                        print(f'knet_dns_check_duration_seconds{{{labels}}} {dur:.6f}')
                        print(f'knet_dns_check_rcode{{{labels}}} {rcode_num}')
                        print(f'knet_dns_check_answers{{{labels}}} {len(answers)}')

    # ------- Loop 2: Public recursors (scope=public, TCP-only) -------
    for rec in PUBLIC_RECURSORS:
        resolver_ip = rec["resolver"]
        resolver = make_resolver(resolver_ip)
        fam_label = "ipv6" if ":" in resolver_ip else "ipv4"
        transport = "tcp"
        use_tcp = True

        for he in HOST_EXPECTATIONS:
            host = he["host"].rstrip(".")  # for labels
            fqdn = he["host"]              # with trailing dot for queries

            # A/AAAA forward checks (exact IPs)
            for rtype in ("A", "AAAA"):
                expected_ip = he[rtype]
                ok_proto, dur, answers, rcode_num, reason = run_query(resolver, fqdn, rtype, use_tcp)
                ok = ok_proto and (expected_ip in answers)
                failure_reason = "ok" if ok else (reason if reason != "ok" else "mismatch")
                labels = (
                    f'scope="public",'
                    f'check="public_{rtype.lower()}_{host}",'
                    f'host="{host}",'
                    f'resolver="{resolver_ip}",'
                    f'ip_family="{fam_label}",'
                    f'transport="{transport}",'
                    f'failure_reason="{failure_reason}"'
                )
                print(f'knet_dns_check_result{{{labels}}} {1 if ok else 0}')
                if VERBOSE:
                    print(f'knet_dns_check_duration_seconds{{{labels}}} {dur:.6f}')
                    print(f'knet_dns_check_rcode{{{labels}}} {rcode_num}')
                    print(f'knet_dns_check_answers{{{labels}}} {len(answers)}')

            # PTR checks: FCrDNS by default; exact-match if PUBLIC_PTR_MODE=exact
            for ip_val in (he["A"], he["AAAA"]):
                # Reverse query: IP -> PTR names
                rev_qname = dns.reversename.from_address(ip_val).to_text()
                ok_proto, dur, ptr_names, rcode_num, reason = run_query(resolver, rev_qname, "PTR", use_tcp)

                if PUBLIC_PTR_MODE == "exact":
                    expected_ptr = fqdn  # exact hostname with trailing dot
                    ok = ok_proto and (expected_ptr in ptr_names)
                    failure_reason = "ok" if ok else (reason if reason != "ok" else "mismatch")
                else:
                    # FCrDNS: at least one PTR name must resolve back to the same IP.
                    ok = False
                    if ok_proto and ptr_names:
                        for ptr in ptr_names:
                            # Resolve the PTR name to A/AAAA and see if it includes the original IP
                            ok_fwd, _, fwd_ips, _, _ = run_query(resolver, ptr, "A" if "." in ip_val else "AAAA", use_tcp)
                            if ok_fwd and (ip_val in fwd_ips):
                                ok = True
                                break
                    failure_reason = "ok" if ok else (reason if reason != "ok" else "mismatch")

                labels = (
                    f'scope="public",'
                    f'check="public_ptr_{ip_val}",'
                    f'host="{host}",'
                    f'resolver="{resolver_ip}",'
                    f'ip_family="{fam_label}",'
                    f'transport="{transport}",'
                    f'failure_reason="{failure_reason}"'
                )
                print(f'knet_dns_check_result{{{labels}}} {1 if ok else 0}')
                if VERBOSE:
                    print(f'knet_dns_check_duration_seconds{{{labels}}} {dur:.6f}')
                    print(f'knet_dns_check_rcode{{{labels}}} {rcode_num}')
                    print(f'knet_dns_check_answers{{{labels}}} {len(ptr_names)}')

    # Script-level metrics
    script_dur = time.time() - script_start
    print(f'knet_dns_script_duration_seconds {script_dur:.6f}')
    print(f'knet_dns_last_run_timestamp_seconds {int(script_start)}')

if __name__ == "__main__":
    main()

