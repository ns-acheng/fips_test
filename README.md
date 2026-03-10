# FIPS TLS Cipher Suite PCAP Verification Tool

Parses a pcap file and verifies that every TLS 1.2/1.3 handshake (ClientHello & ServerHello) uses only FIPS 140-3 approved cipher suites per the NS Client FIPS Mode Support design document.

## Requirements

- Python 3.8+
- Dependencies listed in `requirements.txt`
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

### ETL Input (Windows only)

If you pass an `.etl` file, `main.py` will auto-convert it to `.pcap`
under `data/` before analysis, using:

`etl2pcapng.exe in.etl out.pcap`

Converter lookup order:
1. `win/etl2pcapng.exe`
2. `tools/win/etl2pcapng.exe`

> Note: ETL conversion is **Windows-only**.

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

# Permissive mode — pass if server selects FIPS cipher
python main.py data/nspktdump.pcap --mode=2

# Non-FIPS mode — skip check
python main.py data/nspktdump.pcap --mode=0
```

You can also run the checker module directly:

```bash
python tools/check_fips_cipher.py data/nspktdump.pcap
python tools/check_fips_cipher.py data/nspktdump.pcap --strict
```

## FIPS-Approved Cipher Suites

### TLS 1.2

| Code | Name |
|------|------|
| `0xC02F` | TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 |
| `0xC030` | TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 |
| `0xC02B` | TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 |
| `0xC02C` | TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 |
| `0x009E` | TLS_DHE_RSA_WITH_AES_128_GCM_SHA256 |
| `0x009F` | TLS_DHE_RSA_WITH_AES_256_GCM_SHA384 |

### TLS 1.3

| Code | Name |
|------|------|
| `0x1301` | TLS_AES_128_GCM_SHA256 |
| `0x1302` | TLS_AES_256_GCM_SHA384 |

> `TLS_CHACHA20_POLY1305_SHA256` (`0x1303`) is explicitly excluded — the OpenSSL FIPS provider does not include it.

## Output

<img width="1101" height="954" alt="image" src="https://github.com/user-attachments/assets/39b8745c-d9b9-4845-9598-2b432bcc4aeb" />

For each handshake the tool prints:
- ClientHello offered cipher suites tagged `[FIPS OK]` or `[NON-FIPS]`
- ServerHello selected cipher suite with the same tagging
- Per-handshake verdict: `PASS` or `FAIL`

The summary section shows:
- Total / pass / fail counts
- All non-FIPS cipher suites seen with offered/selected counts
- Overall `PASS` or `FAIL`

Exit code is `0` on PASS, `1` on FAIL.

## Project Structure

```
main.py                        # Entry point
tools/
    __init__.py
    check_fips_cipher.py       # Core TLS parsing and FIPS verification
data/
    nspktdump.pcap             # Sample pcap capture
doc/
    design_doc_text.txt        # FIPS design document reference
    test_plan_text.txt         # Test plan
    add_new_value.txt          # Test plan addendum
```
