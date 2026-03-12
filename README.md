# FIPS TLS Cipher Suite PCAP Verification Tool

Parses a pcap file and verifies that every TLS 1.2/1.3 handshake (ClientHello & ServerHello) uses only FIPS 140-3 approved cipher suites per the NS Client FIPS Mode Support design document.

## Requirements

- Python 3.8+
- Dependencies listed in `requirements.txt` (`dpkt`, `etl-parser`)
- **Windows OS** for `.etl` input conversion (`etl2pcapng.exe` is Windows-only)

Install dependencies:

```
pip install -r requirements.txt
```

## Usage

```
python main.py <pcap_file> --mode=<0|1|2>
```

### Arguments

| Argument | Description |
|----------|-------------|
| `pcap_file` | Path to capture file (`.pcap`, `.pcapng`, or `.etl`) |
| `--mode` | FipsMode (default: `1`) |
| `--pid` | Comma-separated list of PIDs to filter (ETL input only) |
| `--failonly` | `1` = show only FAIL handshakes and skip the summary (default: `0`) |

### ETL Input (Windows only)

If you pass an `.etl` file, `main.py` will auto-convert it to `.pcap`
under `data/` before analysis, using:

`etl2pcapng.exe in.etl out.pcap`

Converter lookup order:
1. `win/etl2pcapng.exe`
2. `tools/win/etl2pcapng.exe`

> Note: ETL conversion is **Windows-only**.

### PID Filtering (ETL input only)

When the input is an `.etl` file, per-packet Process IDs are extracted
using the `etl-parser` library. Each handshake in the output is labeled
with the PID of its ClientHello and ServerHello packets
(e.g. `[CH-PID=13256, SH-PID=0]`).

Use `--pid` to show only handshakes involving specific processes:

```bash
# Show only handshakes where PID 4080 sent the ClientHello or ServerHello
python main.py data/ao.etl --mode=1 --pid=4080

# Multiple PIDs
python main.py data/ao.etl --mode=1 --pid=13256,4080
```

When `--pid` is omitted, all handshakes are shown (with PID labels).

### Modes

| Mode | Name | Behavior |
|------|------|----------|
| `0` | Non-FIPS | Skips verification entirely |
| `1` | Strict FIPS | FAIL if ClientHello offers **any** non-FIPS cipher suite |
| `2` | Permissive FIPS | PASS as long as ServerHello selects a FIPS-approved cipher |

### Examples

```bash
# Strict mode — fail if any non-FIPS cipher is offered
python main.py data/nspktdump.pcap --mode=1

# ETL input (Windows only) — auto-converted to data/session.pcap
python main.py data/session.etl --mode=1

# ETL with PID filter — only show handshakes from PID 4080
python main.py data/session.etl --mode=1 --pid=4080

# Permissive mode — pass if server selects FIPS cipher
python main.py data/nspktdump.pcap --mode=2

# Non-FIPS mode — skip check
python main.py data/nspktdump.pcap --mode=0

# Show only failed handshakes (no summary)
python main.py data/nspktdump.pcap --mode=1 --failonly=1
```

You can also run the checker module directly:

```bash
python tools/check_fips_cipher.py data/nspktdump.pcap
```

## FIPS-Approved Cipher Suites

Cipher suite naming format (TLS 1.2 style):

`TLS_<KEY_EXCHANGE>_WITH_<BULK_CIPHER>_<MAC/HASH>`

Example: `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`


## Output

<img width="1101" height="954" alt="image" src="https://github.com/user-attachments/assets/39b8745c-d9b9-4845-9598-2b432bcc4aeb" />
