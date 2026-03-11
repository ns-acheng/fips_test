#!/usr/bin/env python3
"""
check_fips_cipher.py — FIPS 140-3 TLS Cipher Suite PCAP Verification Tool

Parses a pcap file captured by NS Client, extracts every TLS 1.2/1.3
ClientHello and ServerHello, and verifies that only FIPS-approved cipher
suites are offered and selected.

FIPS-approved list is derived from the NS Client FIPS Mode Support design
document (§4.4.3).

Usage:
    python tools/check_fips_cipher.py                           # default pcap
    python tools/check_fips_cipher.py data/other.pcap
    python tools/check_fips_cipher.py data/cap.pcap --strict    # FAIL on non-FIPS offered
"""

import argparse
import json
import os
import struct
import sys
from collections import defaultdict
from pathlib import Path

# ---------------------------------------------------------------------------
# ANSI color helpers
# ---------------------------------------------------------------------------
_USE_COLOR = sys.stdout.isatty() or os.environ.get("FORCE_COLOR", "") == "1"

def _green(s):
    return f"\033[32m{s}\033[0m" if _USE_COLOR else s

def _red(s):
    return f"\033[31m{s}\033[0m" if _USE_COLOR else s

def _yellow(s):
    return f"\033[93m{s}\033[0m" if _USE_COLOR else s

# ---------------------------------------------------------------------------
# FIPS 140-3 approved cipher suites (design doc §4.4.3)
# ---------------------------------------------------------------------------
def _load_ciphers():
    _path = os.path.join(os.path.dirname(__file__), "fips_ciphers.json")
    with open(_path) as _f:
        _data = json.load(_f)
    _fips = {int(k, 16): v for k, v in _data["fips_allows"].items()}
    _denied = {int(k, 16): v for k, v in _data["fips_denied"].items()}
    _signaling = {int(k, 16) for k in _data["signaling_suites"]}
    _grease = {int(k, 16) for k in _data["grease_values"]}
    return _fips, _denied, _signaling, _grease

FIPS_ALLOWED_CIPHERS, FIPS_DENIED_CIPHERS, SIGNALING_SUITES, GREASE_VALUES = (
    _load_ciphers()
)

SIGNALING_SUITE_NAMES = {
    0x00FF: "TLS_EMPTY_RENEGOTIATION_INFO_SCSV",
    0x5600: "TLS_FALLBACK_SCSV",
}

# Signaling cipher suite values (not real ciphers, skip in compliance check)
# GREASE values (RFC 8701) — dummy probes injected by clients, not real ciphers

TLS_VERSION_NAMES = {
    (3, 0): "SSL 3.0",
    (3, 1): "TLS 1.0",
    (3, 2): "TLS 1.1",
    (3, 3): "TLS 1.2",
    (3, 4): "TLS 1.3",
}

# TLS versions that are FIPS-acceptable
FIPS_ALLOWED_VERSIONS = {(3, 3), (3, 4)}  # TLS 1.2, TLS 1.3


def cipher_name(code):
    """Return human-readable name for a cipher suite code."""
    if code in GREASE_VALUES:
        return f"GREASE_0x{code:04X}"
    if code in FIPS_ALLOWED_CIPHERS:
        return FIPS_ALLOWED_CIPHERS[code]
    if code in FIPS_DENIED_CIPHERS:
        return FIPS_DENIED_CIPHERS[code]
    if code in SIGNALING_SUITE_NAMES:
        return SIGNALING_SUITE_NAMES[code]
    return f"UNKNOWN_0x{code:04X}"


def is_fips_ok(code):
    """Check if a cipher suite code is FIPS-approved."""
    return code in FIPS_ALLOWED_CIPHERS


def is_signaling(code):
    """Check if a cipher suite code is a signaling/GREASE value (not a real cipher)."""
    return code in SIGNALING_SUITES or code in GREASE_VALUES


# ---------------------------------------------------------------------------
# ETL PID extraction
# ---------------------------------------------------------------------------

_ETL_PACKET_PROVIDER = '2ed6006e-4729-4609-b423-3ee7bcd678ef'


def extract_pids_from_etl(etl_path):
    """Extract per-packet PID map from an ETL file.

    Uses the etl-parser library to read events natively in Python.
    Returns a dict mapping 1-based packet index to ProcessId.
    """
    from etl.etl import build_from_stream, IEtlFileObserver

    class _PidCollector(IEtlFileObserver):
        def __init__(self):
            self.events = []  # (timestamp, pid)

        def on_event_record(self, event):
            try:
                prov = event.source.event_header.provider_id.inner
                d4 = bytes(prov.data4)
                guid = (f"{prov.data1:08x}-{prov.data2:04x}-{prov.data3:04x}"
                        f"-{d4[:2].hex()}-{d4[2:].hex()}")
            except (AttributeError, KeyError):
                return
            if guid == _ETL_PACKET_PROVIDER:
                self.events.append((event.get_timestamp(),
                                    event.get_process_id()))

        def on_perfinfo_trace(self, e): pass
        def on_system_trace(self, e): pass
        def on_trace_record(self, e): pass
        def on_win_trace(self, e): pass

    try:
        with open(etl_path, "rb") as fh:
            data = fh.read()
        etl_file = build_from_stream(data)
        collector = _PidCollector()
        etl_file.parse(collector)
        # Sort by timestamp to match PCAP packet order (etl2pcapng sorts the same way)
        collector.events.sort(key=lambda x: x[0])
        return {i: pid for i, (_, pid) in enumerate(collector.events, 1)}
    except Exception as exc:
        print(f"WARNING: ETL PID extraction failed: {exc}", file=sys.stderr)
        return {}


# ---------------------------------------------------------------------------
# TLS ClientHello / ServerHello parsing (from raw TLS record payload)
# ---------------------------------------------------------------------------

def parse_client_hello(payload):
    """
    Parse a ClientHello from the TLS handshake payload (after record header).
    Returns dict with 'version', 'cipher_suites' list, or None on failure.
    """
    # payload[0] = handshake type (1 = ClientHello)
    # payload[1:4] = handshake length
    # payload[4:6] = client version
    # payload[6:38] = random (32 bytes)
    # payload[38] = session_id length ...
    if len(payload) < 39:
        return None
    hs_type = payload[0]
    if hs_type != 1:
        return None

    ver = (payload[4], payload[5])
    offset = 6 + 32  # skip version(2) + random(32) = start at session_id

    # session_id
    if offset >= len(payload):
        return None
    sid_len = payload[offset]
    offset += 1 + sid_len

    # cipher_suites
    if offset + 2 > len(payload):
        return None
    cs_len = struct.unpack("!H", payload[offset:offset + 2])[0]
    offset += 2
    if offset + cs_len > len(payload):
        return None

    suites = []
    for i in range(0, cs_len, 2):
        code = struct.unpack("!H", payload[offset + i:offset + i + 2])[0]
        suites.append(code)

    # Parse extensions for supported_versions and SNI
    actual_ver = ver
    sni = None
    ext_offset = offset + cs_len
    # skip compression methods
    if ext_offset < len(payload):
        comp_len = payload[ext_offset]
        ext_offset += 1 + comp_len
    # extensions
    plen = len(payload)
    if ext_offset + 2 <= plen:
        ext_total = struct.unpack("!H", payload[ext_offset:ext_offset + 2])[0]
        ext_offset += 2
        ext_end = min(ext_offset + ext_total, plen)
        while ext_offset + 4 <= ext_end:
            ext_type = struct.unpack("!H", payload[ext_offset:ext_offset + 2])[0]
            ext_len = struct.unpack("!H", payload[ext_offset + 2:ext_offset + 4])[0]
            ext_offset += 4
            if ext_offset + ext_len > ext_end:
                break
            if ext_type == 0 and ext_len >= 5:  # server_name (SNI)
                # SNI list length (2 bytes), then entries
                sni_list_len = struct.unpack("!H", payload[ext_offset:ext_offset + 2])[0]
                sni_off = ext_offset + 2
                sni_end = min(ext_offset + sni_list_len + 2, ext_offset + ext_len)
                while sni_off + 3 <= sni_end:
                    name_type = payload[sni_off]
                    name_len = struct.unpack("!H", payload[sni_off + 1:sni_off + 3])[0]
                    sni_off += 3
                    if name_type == 0 and sni_off + name_len <= sni_end:
                        sni = payload[sni_off:sni_off + name_len].decode("ascii", errors="replace")
                    sni_off += name_len
            if ext_type == 43 and ext_len >= 3:  # supported_versions
                sv_list_len = payload[ext_offset]
                for j in range(0, min(sv_list_len, ext_len - 1), 2):
                    if ext_offset + 2 + j >= plen:
                        break
                    sv = (payload[ext_offset + 1 + j], payload[ext_offset + 2 + j])
                    if sv == (3, 4):
                        actual_ver = (3, 4)
                        break
            ext_offset += ext_len

    return {"version": actual_ver, "cipher_suites": suites, "sni": sni}


def parse_server_hello(payload):
    """
    Parse a ServerHello from the TLS handshake payload (after record header).
    Returns dict with 'version', 'cipher_suite', or None on failure.
    """
    if len(payload) < 39:
        return None
    hs_type = payload[0]
    if hs_type != 2:
        return None

    ver = (payload[4], payload[5])
    offset = 6 + 32  # skip version(2) + random(32)

    # session_id
    if offset >= len(payload):
        return None
    sid_len = payload[offset]
    offset += 1 + sid_len

    # selected cipher suite
    if offset + 2 > len(payload):
        return None
    suite = struct.unpack("!H", payload[offset:offset + 2])[0]
    offset += 2

    # Check supported_versions extension for TLS 1.3
    actual_ver = ver
    # skip compression method (1 byte)
    offset += 1
    # extensions
    plen = len(payload)
    if offset + 2 <= plen:
        ext_total = struct.unpack("!H", payload[offset:offset + 2])[0]
        offset += 2
        ext_end = min(offset + ext_total, plen)
        while offset + 4 <= ext_end:
            ext_type = struct.unpack("!H", payload[offset:offset + 2])[0]
            ext_len = struct.unpack("!H", payload[offset + 2:offset + 4])[0]
            offset += 4
            if offset + ext_len > ext_end:
                break
            if ext_type == 43 and ext_len >= 2:  # supported_versions
                sv = (payload[offset], payload[offset + 1])
                if sv == (3, 4):
                    actual_ver = (3, 4)
            offset += ext_len

    return {"version": actual_ver, "cipher_suite": suite}


# ---------------------------------------------------------------------------
# pcap processing
# ---------------------------------------------------------------------------

def _extract_ip_data(pkt_data, link_type):
    """Extract IP-layer bytes from a raw packet given its link type.
    Returns ip_data bytes or None."""
    if link_type == 1:
        # Ethernet
        if len(pkt_data) < 14:
            return None
        eth_type = struct.unpack("!H", pkt_data[12:14])[0]
        if eth_type == 0x8100:  # VLAN
            if len(pkt_data) < 18:
                return None
            eth_type = struct.unpack("!H", pkt_data[16:18])[0]
            return pkt_data[18:] if eth_type == 0x0800 else None
        elif eth_type == 0x0800:
            return pkt_data[14:]
        elif eth_type == 0x86DD:
            return pkt_data[14:]
        return None
    elif link_type == 101:
        # Raw IP
        return pkt_data
    return None


def _process_packet(pkt_data, link_type, pkt_num, client_hellos, results,
                    pid_map=None):
    """Process one packet: extract TLS ClientHello/ServerHello if present."""
    ip_data = _extract_ip_data(pkt_data, link_type)
    if ip_data is None or len(ip_data) < 20:
        return

    ip_ver = (ip_data[0] >> 4)
    if ip_ver == 4:
        ihl = (ip_data[0] & 0x0F) * 4
        proto = ip_data[9]
        src_ip = ".".join(str(b) for b in ip_data[12:16])
        dst_ip = ".".join(str(b) for b in ip_data[16:20])
        ip_payload = ip_data[ihl:]
    elif ip_ver == 6:
        if len(ip_data) < 40:
            return
        proto = ip_data[6]
        src_ip = ":".join(f"{ip_data[8+i]:02x}{ip_data[9+i]:02x}" for i in range(0, 16, 2))
        dst_ip = ":".join(f"{ip_data[24+i]:02x}{ip_data[25+i]:02x}" for i in range(0, 16, 2))
        ip_payload = ip_data[40:]
    else:
        return

    if proto != 6:  # TCP
        return

    if len(ip_payload) < 20:
        return
    src_port = struct.unpack("!H", ip_payload[0:2])[0]
    dst_port = struct.unpack("!H", ip_payload[2:4])[0]
    tcp_data_off = ((ip_payload[12] >> 4) * 4)
    tcp_payload = ip_payload[tcp_data_off:]

    if len(tcp_payload) < 6:
        return

    # --- TLS record layer ---
    content_type = tcp_payload[0]
    if content_type != 22:  # Handshake
        return
    hs_payload = tcp_payload[5:]
    if len(hs_payload) < 4:
        return

    hs_type = hs_payload[0]
    flow_key = (src_ip, src_port, dst_ip, dst_port)
    rev_key = (dst_ip, dst_port, src_ip, src_port)

    if hs_type == 1:  # ClientHello
        ch = parse_client_hello(hs_payload)
        if ch:
            ch["pkt_num"] = pkt_num
            ch["src_ip"] = src_ip
            ch["src_port"] = src_port
            ch["dst_ip"] = dst_ip
            ch["dst_port"] = dst_port
            if pid_map:
                ch["pid"] = pid_map.get(pkt_num)
            client_hellos[flow_key] = ch

    elif hs_type == 2:  # ServerHello
        sh = parse_server_hello(hs_payload)
        if sh:
            sh["pkt_num"] = pkt_num
            sh["src_ip"] = src_ip
            sh["src_port"] = src_port
            sh["dst_ip"] = dst_ip
            sh["dst_port"] = dst_port
            if pid_map:
                sh["pid"] = pid_map.get(pkt_num)
            ch = client_hellos.get(rev_key)
            results.append({
                "client_hello": ch,
                "server_hello": sh,
            })


# ---------------------------------------------------------------------------
# pcap (classic) reader
# ---------------------------------------------------------------------------

def _read_pcap(filedata):
    """Yield (pkt_num, pkt_bytes, link_type) from classic pcap bytes."""
    magic = struct.unpack("<I", filedata[:4])[0]
    if magic == 0xA1B2C3D4:
        endian = "<"
    elif magic == 0xD4C3B2A1:
        endian = ">"
    else:
        return

    _ver_maj, _ver_min, _tz, _sig, _snaplen, link_type = struct.unpack(
        endian + "HHiIII", filedata[4:24]
    )

    offset = 24
    pkt_num = 0
    while offset + 16 <= len(filedata):
        _ts_sec, _ts_usec, incl_len, _orig_len = struct.unpack(
            endian + "IIII", filedata[offset:offset + 16]
        )
        offset += 16
        if offset + incl_len > len(filedata):
            break
        pkt_num += 1
        yield pkt_num, filedata[offset:offset + incl_len], link_type
        offset += incl_len


# ---------------------------------------------------------------------------
# pcapng reader
# ---------------------------------------------------------------------------

def _read_pcapng(filedata):
    """Yield (pkt_num, pkt_bytes, link_type) from pcapng bytes."""
    # Detect endianness from Section Header Block byte-order magic
    bom = struct.unpack_from("<I", filedata, 8)[0]
    endian = "<" if bom == 0x1A2B3C4D else ">"

    iface_link_types = {}
    iface_idx = 0
    pkt_num = 0
    offset = 0
    sz = len(filedata)

    while offset + 8 <= sz:
        btype = struct.unpack_from(endian + "I", filedata, offset)[0]
        blen = struct.unpack_from(endian + "I", filedata, offset + 4)[0]
        if blen < 12 or offset + blen > sz:
            break

        if btype == 1:  # Interface Description Block
            lt = struct.unpack_from(endian + "H", filedata, offset + 8)[0]
            iface_link_types[iface_idx] = lt
            iface_idx += 1

        elif btype == 6:  # Enhanced Packet Block
            iface_id = struct.unpack_from(endian + "I", filedata, offset + 8)[0]
            cap_len = struct.unpack_from(endian + "I", filedata, offset + 20)[0]
            pkt_data = filedata[offset + 28: offset + 28 + cap_len]
            link_type = iface_link_types.get(iface_id, -1)
            pkt_num += 1
            yield pkt_num, pkt_data, link_type

        elif btype == 3:  # Simple Packet Block (rare)
            orig_len = struct.unpack_from(endian + "I", filedata, offset + 8)[0]
            cap_len = blen - 16  # block overhead
            if cap_len > 0:
                pkt_data = filedata[offset + 12: offset + 12 + cap_len]
                link_type = iface_link_types.get(0, -1)
                pkt_num += 1
                yield pkt_num, pkt_data, link_type

        offset += blen
        # pcapng blocks are padded to 4-byte boundary within block_total_length
        # but block_total_length itself should be a multiple of 4; add safety pad
        pad = blen % 4
        if pad:
            offset += 4 - pad


# ---------------------------------------------------------------------------
# unified entry point
# ---------------------------------------------------------------------------

def process_pcap(filepath, pid_map=None):
    """
    Read a pcap or pcapng file, extract TLS ClientHello/ServerHello from
    each packet, return a list of handshake result dicts.

    If *pid_map* is provided (dict mapping 1-based pkt index to PID),
    each ClientHello / ServerHello dict will include a ``pid`` key.
    """
    with open(filepath, "rb") as f:
        filedata = f.read()

    if len(filedata) < 12:
        print("ERROR: File too small to be a valid capture.", file=sys.stderr)
        sys.exit(1)

    magic = struct.unpack("<I", filedata[:4])[0]
    if magic in (0xA1B2C3D4, 0xD4C3B2A1):
        reader = _read_pcap(filedata)
        fmt = "pcap"
    elif magic == 0x0A0D0D0A:
        reader = _read_pcapng(filedata)
        fmt = "pcapng"
    else:
        print("ERROR: Unrecognized capture format (expected pcap or pcapng).",
              file=sys.stderr)
        sys.exit(1)

    if pid_map:
        print(f"Format: {fmt}  (PID map: {len(pid_map)} packets)")
    else:
        print(f"Format: {fmt}")
    results = []
    client_hellos = {}

    for pkt_num, pkt_bytes, link_type in reader:
        _process_packet(pkt_bytes, link_type, pkt_num, client_hellos, results,
                        pid_map=pid_map)

    return results


# ---------------------------------------------------------------------------
# FIPS compliance check + report
# ---------------------------------------------------------------------------

def check_and_report(results, strict=False, pid_filter=None):
    """
    Analyze each handshake for FIPS compliance and print report.
    Returns 0 if all pass, 1 if any fail.

    If *pid_filter* is given (set of ints), only handshakes whose
    ClientHello **or** ServerHello was sent by one of those PIDs
    are included in the report.
    """
    passed = 0
    failed = 0
    warnings = 0
    non_fips_stats = defaultdict(lambda: {"offered": 0, "selected": 0})
    handshake_details = []

    for idx, hs in enumerate(results, 1):
        ch = hs["client_hello"]
        sh = hs["server_hello"]

        # ---- PID filter ----
        if pid_filter is not None:
            ch_pid = ch.get("pid") if ch else None
            sh_pid = sh.get("pid") if sh else None
            if ch_pid not in pid_filter and sh_pid not in pid_filter:
                continue

        verdict = "PASS"
        issues = []

        # --- Server Hello checks ---
        sh_ver = sh["version"]
        sh_ver_name = TLS_VERSION_NAMES.get(sh_ver, f"Unknown({sh_ver[0]}.{sh_ver[1]})")
        sel_code = sh["cipher_suite"]

        if sh_ver not in FIPS_ALLOWED_VERSIONS:
            verdict = "FAIL"
            issues.append(f"Non-FIPS TLS version: {sh_ver_name}")

        if not is_fips_ok(sel_code) and not is_signaling(sel_code):
            verdict = "FAIL"
            non_fips_stats[sel_code]["selected"] += 1
            issues.append(f"Selected cipher is NOT FIPS-approved: 0x{sel_code:04X} {cipher_name(sel_code)}")

        # --- Client Hello checks ---
        ch_offered = []
        ch_non_fips = []
        if ch:
            ch_ver = ch["version"]
            for code in ch["cipher_suites"]:
                ch_offered.append(code)
                if is_signaling(code):
                    continue
                if not is_fips_ok(code):
                    ch_non_fips.append(code)
                    non_fips_stats[code]["offered"] += 1
            if ch_non_fips:
                if strict:
                    verdict = "FAIL"
                    issues.append(f"ClientHello offers {len(ch_non_fips)} non-FIPS cipher(s)")
                else:
                    warnings += 1
                    issues.append(f"WARN: ClientHello offers {len(ch_non_fips)} non-FIPS cipher(s)")

        if verdict == "PASS":
            passed += 1
        else:
            failed += 1

        handshake_details.append({
            "index": idx,
            "sh": sh,
            "ch": ch,
            "sh_ver_name": sh_ver_name,
            "sel_code": sel_code,
            "ch_offered": ch_offered,
            "ch_non_fips": ch_non_fips,
            "verdict": verdict,
            "issues": issues,
        })

    # --- Print detailed report ---
    for d in handshake_details:
        sh = d["sh"]
        ch = d["ch"]
        sni = ch.get("sni") if ch else None
        sni_str = f"  SNI: {sni}" if sni else ""
        sh_pid = sh.get("pid")
        ch_pid = ch.get("pid") if ch else None
        pid_label = ""
        if sh_pid is not None or ch_pid is not None:
            parts = []
            if ch_pid is not None:
                parts.append(f"CH-PID={ch_pid}")
            if sh_pid is not None:
                parts.append(f"SH-PID={sh_pid}")
            pid_label = f"  [{', '.join(parts)}]"
        print(f"\n=== Handshake #{d['index']}  (pkt {sh['pkt_num']}, "
              f"{sh['src_ip']}:{sh['src_port']} -> {sh['dst_ip']}:{sh['dst_port']})"
              f"{pid_label} ===")
        if sni:
            print(f"  SNI: {_yellow(sni)}")
        print(f"  TLS Version (ServerHello): {d['sh_ver_name']}")

        # ClientHello
        if ch:
            print(f"  ClientHello (pkt {ch['pkt_num']}, "
                  f"{ch['src_ip']}:{ch['src_port']} -> {ch['dst_ip']}:{ch['dst_port']})")
            ch_ver_name = TLS_VERSION_NAMES.get(ch["version"],
                                                 f"Unknown({ch['version'][0]}.{ch['version'][1]})")
            print(f"    Version: {ch_ver_name}")
            print(f"    Offered cipher suites ({len(d['ch_offered'])}):")
            for code in d["ch_offered"]:
                if is_signaling(code):
                    tag = "[SIGNAL]  "
                elif is_fips_ok(code):
                    tag = _green("[FIPS OK] ")
                else:
                    tag = _red("[NON-FIPS]")
                print(f"      {tag}  0x{code:04X}  {cipher_name(code)}")
        else:
            print("  ClientHello: (not captured / not matched)")

        # ServerHello
        sel = d["sel_code"]
        tag = _green("[FIPS OK] ") if is_fips_ok(sel) else _red("[NON-FIPS]")
        print(f"  ServerHello selected suite:")
        print(f"      {tag}  0x{sel:04X}  {cipher_name(sel)}")

        # Verdict
        if d["issues"]:
            for issue in d["issues"]:
                marker = _red("*** FAIL ***") if "FAIL" not in issue and "WARN" not in issue else ""
                print(f"  {issue} {marker}")
        verdict_str = _green(d['verdict']) if d['verdict'] == 'PASS' else _red(d['verdict'])
        print(f"  Result: {verdict_str}")

    # --- Summary ---
    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    print(f"Total handshakes analyzed: {passed + failed}")
    print(f"  {_green('PASS')}: {passed}")
    print(f"  {_red('FAIL')}: {failed}")
    if warnings:
        print(f"  Warnings (non-FIPS offered in ClientHello): {warnings}")

    if non_fips_stats:
        print("\nNon-FIPS cipher suites seen:")
        for code, counts in sorted(non_fips_stats.items()):
            print(f"  0x{code:04X}  {cipher_name(code):50s}  "
                  f"offered={counts['offered']}  selected={counts['selected']}")

    overall = _green("PASS") if failed == 0 else _red("FAIL")
    print(f"\nOverall: {overall}")
    return 0 if failed == 0 else 1


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="FIPS 140-3 TLS Cipher Suite PCAP Verification Tool"
    )
    parser.add_argument(
        "pcap",
        nargs="?",
        default="data/nspktdump.pcap",
        help="Path to pcap file (default: data/nspktdump.pcap)",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="FAIL if ClientHello offers any non-FIPS cipher suite",
    )
    args = parser.parse_args()

    print(f"Parsing: {args.pcap}")
    print(f"Mode: {'STRICT' if args.strict else 'NORMAL'}")
    print(f"FIPS-allowed cipher suites: {len(FIPS_ALLOWED_CIPHERS)}")

    results = process_pcap(args.pcap)
    if not results:
        print("\nNo TLS handshakes (ClientHello/ServerHello pairs) found.")
        sys.exit(0)

    rc = check_and_report(results, strict=args.strict)
    sys.exit(rc)


if __name__ == "__main__":
    main()
