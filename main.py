#!/usr/bin/env python3
"""
Entry point for FIPS TLS cipher suite verification.

Usage:
    python main.py data/nspktdump.pcap --mode=1
    python main.py data/some.pcap --mode=2
    python main.py data/some.etl --mode=1  # auto-convert to data/some.pcap

Modes:
    0 - Non-FIPS: skip cipher check (no verification needed)
    1 - Strict FIPS: FAIL if ClientHello offers ANY non-FIPS cipher
    2 - Permissive FIPS: PASS as long as ServerHello selects a FIPS cipher
"""

import argparse
import json
import subprocess
import sys
from pathlib import Path

from tools.check_fips_cipher import (process_pcap, check_and_report,
                                     FIPS_ALLOWED_CIPHERS, extract_pids_from_etl)

MODE_NAMES = {0: "Non-FIPS", 1: "Strict FIPS", 2: "Permissive FIPS"}


def _resolve_input_capture_path(input_path):
    """
    If input is .etl, convert to .pcap under data/ using etl2pcapng.exe.
    Returns path to the capture file to analyze.
    """
    in_path = Path(input_path)
    if in_path.suffix.lower() != ".etl":
        return str(in_path)

    if not in_path.exists():
        print(f"ERROR: ETL file not found: {in_path}", file=sys.stderr)
        sys.exit(1)

    # Prefer user-requested location first, then repo location.
    converter_candidates = [
        Path("win") / "etl2pcapng.exe",
        Path("tools") / "win" / "etl2pcapng.exe",
    ]
    converter = next((p for p in converter_candidates if p.exists()), None)
    if converter is None:
        print(
            "ERROR: etl2pcapng.exe not found at win/etl2pcapng.exe "
            "or tools/win/etl2pcapng.exe",
            file=sys.stderr,
        )
        sys.exit(1)

    out_dir = Path("data")
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / f"{in_path.stem}.pcap"

    print(f"Converting ETL -> PCAP: {in_path} -> {out_path}")
    cmd = [str(converter), str(in_path), str(out_path)]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        if proc.stdout:
            print(proc.stdout)
        if proc.stderr:
            print(proc.stderr, file=sys.stderr)
        print("ERROR: ETL conversion failed.", file=sys.stderr)
        sys.exit(proc.returncode)

    if not out_path.exists():
        print("ERROR: Converter finished but output pcap was not created.", file=sys.stderr)
        sys.exit(1)

    return str(out_path)


def main():
    parser = argparse.ArgumentParser(
        description="FIPS 140-3 TLS Cipher Suite PCAP Verification Tool"
    )
    parser.add_argument(
        "pcap",
        help="Path to capture file (.pcap/.pcapng/.etl)",
    )
    parser.add_argument(
        "--mode",
        type=int,
        choices=[0, 1, 2],
        default=1,
        help="FipsMode: 0=Non-FIPS (skip), 1=Strict, 2=Permissive (default: 1)",
    )
    parser.add_argument(
        "--pid",
        type=str,
        default=None,
        help=(
            "Comma-separated list of process IDs to filter output. "
            "Only handshakes involving these PIDs are shown. "
            "Requires .etl input (PID info is extracted from the ETL)."
        ),
    )
    parser.add_argument(
        "--failonly",
        type=int,
        choices=[0, 1],
        default=0,
        help="1 = show only FAIL handshakes and skip the summary (default: 0)",
    )
    args = parser.parse_args()

    resolved_capture = _resolve_input_capture_path(args.pcap)

    # --- PID extraction & filter ---
    pid_map = {}
    pid_filter = None
    etl_path = Path(args.pcap)
    resolved_path = Path(resolved_capture)
    pid_json_path = resolved_path.parent / f"{resolved_path.stem}.pid.json"

    if etl_path.suffix.lower() == ".etl" and etl_path.exists():
        print(f"Extracting per-packet PIDs from ETL: {etl_path}")
        pid_map = extract_pids_from_etl(str(etl_path))
        print(f"  PID map: {len(pid_map)} packets mapped")
        # Save PID map so it can be reused with the .pcap later
        if pid_map:
            with open(pid_json_path, "w") as f:
                json.dump({str(k): v for k, v in pid_map.items()}, f)
            print(f"  PID map saved to {pid_json_path}")
    elif args.pid and pid_json_path.exists():
        # Load previously saved PID map for this pcap
        with open(pid_json_path) as f:
            raw = json.load(f)
        pid_map = {int(k): v for k, v in raw.items()}
        print(f"Loaded PID map from {pid_json_path} ({len(pid_map)} packets)")
    elif args.pid:
        print(
            "WARNING: --pid filter requested but no PID data available. "
            f"Run the matching .etl first to generate {pid_json_path}.",
            file=sys.stderr,
        )

    if args.pid:
        try:
            pid_filter = {int(p.strip()) for p in args.pid.split(",")}
        except ValueError:
            print("ERROR: --pid must be a comma-separated list of integers.",
                  file=sys.stderr)
            sys.exit(1)
        print(f"PID filter: {pid_filter}")

    mode_name = MODE_NAMES[args.mode]
    print(f"Pcap:  {resolved_capture}")
    print(f"Mode:  {args.mode} ({mode_name})")
    print(f"FIPS-allowed cipher suites: {len(FIPS_ALLOWED_CIPHERS)}")

    if args.mode == 0:
        print("\nFipsMode 0 — no FIPS verification required. Exiting.")
        sys.exit(0)

    strict = args.mode == 1

    results = process_pcap(resolved_capture, pid_map=pid_map or None)
    if not results:
        print("\nNo TLS handshakes or ClientHello messages found.")
        sys.exit(0)

    rc = check_and_report(results, strict=strict, pid_filter=pid_filter,
                          fail_only=bool(args.failonly))
    sys.exit(rc)


if __name__ == "__main__":
    main()
