#!/usr/bin/env python3
"""
Deobfuscate the autobuy_bundle.py from the provided GitHub raw URL, extract the
hidden payload, write a readable Python file, and run a simple static scan to
identify suspicious indicators.

Usage:
  python3 helper/deobfuscate_autobuy_bundle.py

This script will:
- Download the obfuscated file from GitHub raw (no extra deps, uses urllib).
- Extract the reversed hex string used by bytes.fromhex(__[::-1]).
- Decode it into Python source and write helper/deobfuscated_autobuy_bundle.py.
- Print a brief static analysis: indicators of compromise (IOCs), endpoints,
  suspicious imports and calls, and high-level risk summary.

Note:
- This does not execute the decoded payload.
- If the URL becomes unavailable, you can paste the obfuscated source into
  the OBFUSCATED_SOURCE_FALLBACK constant below and set USE_FALLBACK=True.
"""

import re
import sys
import json
import urllib.request
from pathlib import Path

RAW_URL = "https://raw.githubusercontent.com/baloenk/xldor/refs/heads/main/app/menus/autobuy_bundle.py"

# Fallback: paste the obfuscated content if needed and set USE_FALLBACK=True.
USE_FALLBACK = False
OBFUSCATED_SOURCE_FALLBACK = r"""
_ = lambda __ : bytes.fromhex(__[::-1]);exec((_)( "REPLACE_WITH_HEX_IF_NEEDED" ))
"""

OUT_PATH = Path("helper/deobfuscated_autobuy_bundle.py")


def fetch_source(url: str) -> str:
    with urllib.request.urlopen(url) as resp:
        data = resp.read()
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        # Some files may contain non-utf8 bytes; best-effort fallback.
        return data.decode("latin-1", errors="ignore")


def extract_hex_blob(obfuscated_text: str) -> str:
    """
    Extract the hex string inside exec((_)( "...." )) or similar patterns.
    We search for the innermost quoted string passed to bytes.fromhex(__[::-1]).
    """
    # Common patterns: exec((_)( "...." )) or exec(_)( '....' )
    # Use a robust regex: find quotes followed by long hex-looking data.
    # Hex should be [0-9a-fA-F]+ but obfuscators may include whitespace/newlines.
    # We capture the largest quoted segment within the file.
    candidates = []
    for m in re.finditer(r"""exec\(\s*\(?_?\)?\s*\(\s*([\'"])(.+?)\1\s*\)\s*\)""", obfuscated_text, flags=re.DOTALL):
        candidates.append(m.group(2))
    if not candidates:
        # Try a looser pattern: find any long quoted sequence after bytes.fromhex
        for m in re.finditer(r"""fromhex\(\s*__\s*\[\s*::-?1\s*\]\s*\)\s*;?\s*exec\(\s*\(?_?\)?\s*\(\s*([\'"])(.+?)\1\s*\)\s*\)""", obfuscated_text, flags=re.DOTALL):
            candidates.append(m.group(2))
    if not candidates:
        # As a last resort, find the longest quoted string in the file
        for m in re.finditer(r"""([\'"])(.{200,})\1""", obfuscated_text, flags=re.DOTALL):
            candidates.append(m.group(2))
    # Choose the longest candidate, which is most likely the payload hex.
    if not candidates:
        raise ValueError("Tidak menemukan payload hex di file obfuscated.")
    hex_blob = max(candidates, key=len).strip()
    return hex_blob


def decode_payload(hex_blob: str) -> bytes:
    """
    The obfuscation uses bytes.fromhex(__[::-1]).
    So the hex text is reversed character-wise and then fromhex'd.
    """
    # Remove whitespace/newlines to get a clean hex sequence
    compact = re.sub(r"\s+", "", hex_blob)
    # Reverse and decode
    reversed_hex = compact[::-1]
    try:
        return bytes.fromhex(reversed_hex)
    except ValueError as e:
        # Some obfuscators insert non-hex chars; try to filter strictly
        filtered = re.sub(r"[^0-9a-fA-F]", "", compact)[::-1]
        return bytes.fromhex(filtered)


def write_output(py_source: bytes) -> None:
    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    # Do not execute; just write bytes as text (best-effort utf-8)
    try:
        text = py_source.decode("utf-8")
    except UnicodeDecodeError:
        text = py_source.decode("latin-1", errors="ignore")
    OUT_PATH.write_text(text, encoding="utf-8", errors="ignore")


def static_scan(py_source: str) -> dict:
    indicators = {
        "suspicious_imports": [],
        "suspicious_calls": [],
        "network_endpoints": [],
        "exec_eval_usage": False,
        "file_process_ops": [],
    }

    imports_patterns = [
        r"\bimport\s+requests\b",
        r"\bimport\s+socket\b",
        r"\bimport\s+subprocess\b",
        r"\bfrom\s+subprocess\s+import\b",
        r"\bimport\s+ctypes\b",
        r"\bimport\s+atexit\b",
        r"\bimport\s+os\b",
        r"\bimport\s+sys\b",
        r"\bimport\s+base64\b",
        r"\bimport\s+hashlib\b",
        r"\bimport\s+crypt\b",
    ]
    calls_patterns = [
        r"\beval\s*\(",
        r"\bexec\s*\(",
        r"\bos\.system\s*\(",
        r"\bsubprocess\.Popen\s*\(",
        r"\bsubprocess\.run\s*\(",
        r"\bsocket\.socket\s*\(",
        r"\burllib\.request\.urlopen\s*\(",
        r"\brequests\.[a-z]+\s*\(",
        r"\bopen\s*\(",
        r"\bwrite\s*\(",
    ]
    endpoint_patterns = [
        r"https?://[^\s\'\"]+",
        r"wss?://[^\s\'\"]+",
        r"tcp://[^\s\'\"]+",
        r"udp://[^\s\'\"]+",
        r"@[a-zA-Z0-9\.\-]+",  # possible email-like markers
    ]

    for pat in imports_patterns:
        for m in re.finditer(pat, py_source):
            indicators["suspicious_imports"].append(m.group(0))

    for pat in calls_patterns:
        for m in re.finditer(pat, py_source):
            indicators["suspicious_calls"].append(m.group(0))
            if "exec" in m.group(0) or "eval" in m.group(0):
                indicators["exec_eval_usage"] = True

    for pat in endpoint_patterns:
        for m in re.finditer(pat, py_source):
            indicators["network_endpoints"].append(m.group(0))

    file_ops = []
    for m in re.finditer(r"\b(open|os\.remove|os\.unlink|shutil\.)", py_source):
        file_ops.append(m.group(0))
    indicators["file_process_ops"] = file_ops

    return indicators


def summarize_risk(indicators: dict) -> str:
    risk = "rendah"
    score = 0
    score += 2 if indicators["exec_eval_usage"] else 0
    score += len(indicators["suspicious_imports"])
    score += len(indicators["suspicious_calls"]) // 3
    score += len(indicators["network_endpoints"]) // 5
    score += len([x for x in indicators["file_process_ops"] if "open" not in x])

    if score >= 8:
        risk = "tinggi"
    elif score >= 4:
        risk = "sedang"

    return f"Tingkat risiko indikatif: {risk} (skor heuristik: {score})."


def main():
    print("[*] Mengambil sumber obfuscated...")
    if USE_FALLBACK:
        ob_text = OBFUSCATED_SOURCE_FALLBACK
    else:
        ob_text = fetch_source(RAW_URL)

    print("[*] Mengekstrak payload hex...")
    hex_blob = extract_hex_blob(ob_text)

    print("[*] Mendecode payload...")
    payload_bytes = decode_payload(hex_blob)

    print(f"[*] Menulis hasil ke: {OUT_PATH}")
    write_output(payload_bytes)

    decoded_text = payload_bytes.decode("utf-8", errors="ignore")
    indicators = static_scan(decoded_text)

    print("[*] Ringkasan indikator mencurigakan:")
    print(json.dumps(indicators, indent=2, ensure_ascii=False))

    print(summarize_risk(indicators))
    print("[*] Selesai. Tinjau file:", str(OUT_PATH))


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print("[!] Gagal deobfuscate:", e, file=sys.stderr)
        sys.exit(1)