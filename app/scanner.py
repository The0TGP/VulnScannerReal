import asyncio
import httpx
import socket, ssl, json
from datetime import datetime

from .websocket_manager import manager
from .database import SessionLocal
from .models import ScanResult


COMMON_PORTS = [21, 22, 25, 80, 110, 143, 443, 3306, 8080, 8443]


# Send WebSocket progress update
async def update(scan_id: str, message: str):
    try:
        await manager.send(scan_id, message)
    except Exception:
        pass


# -----------------------------
# 1. Port Scanning
# -----------------------------
async def scan_ports(host: str, scan_id: str):
    results = {}

    await update(scan_id, "Scanning ports...")

    async def check_port(port):
        try:
            r, w = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=1)
            w.close()
            return port, True
        except:
            return port, False

    tasks = [check_port(p) for p in COMMON_PORTS]
    completed = await asyncio.gather(*tasks)

    for port, is_open in completed:
        results[port] = "open" if is_open else "closed"

    return results


# -----------------------------
# 2. Security Headers
# -----------------------------
async def check_headers(url: str, scan_id: str):
    await update(scan_id, "Checking security headers...")

    REQUIRED = [
        "Content-Security-Policy",
        "Strict-Transport-Security",
        "X-Frame-Options",
        "X-Content-Type-Options",
        "Referrer-Policy",
        "Permissions-Policy"
    ]

    results = {}

    try:
        async with httpx.AsyncClient(follow_redirects=True, timeout=5) as c:
            r = await c.get(url)

        for h in REQUIRED:
            results[h] = "present" if h in r.headers else "missing"

    except:
        results["error"] = "Could not fetch headers"

    return results


# -----------------------------
# 3. TLS / SSL
# -----------------------------
async def check_tls(host: str, scan_id: str):
    await update(scan_id, "Checking TLS/SSL...")

    result = {}

    try:
        ctx = ssl.create_default_context()
        sock = socket.create_connection((host, 443), timeout=3)
        ssock = ctx.wrap_socket(sock, server_hostname=host)

        cipher = ssock.cipher()
        cert = ssock.getpeercert()

        result["cipher"] = cipher[0]
        result["protocol"] = cipher[1]
        result["certificate_subject"] = cert.get("subject", [])
        result["issuer"] = cert.get("issuer", [])

    except:
        result["error"] = "No TLS support / connection failed"

    return result


# -----------------------------
# 4. XSS & SQL Injection Tests
# -----------------------------
async def test_injection(url: str, scan_id: str):
    await update(scan_id, "Testing XSS & SQL Injection...")

    results = {
        "xss": "not detected",
        "sqli": "not detected"
    }

    try:
        async with httpx.AsyncClient(follow_redirects=True, timeout=5) as c:

            # XSS
            xss = "<testXSS123>"
            r = await c.get(url, params={"q": xss})

            if xss in r.text:
                results["xss"] = "potential"

            # SQLi
            payload = "' OR '1'='1"
            r2 = await c.get(url, params={"id": payload})

            if "error" in r2.text.lower() or "sql" in r2.text.lower():
                results["sqli"] = "potential"

    except:
        results["error"] = "Could not complete tests"

    return results


# -----------------------------
# 5. MASTER SCAN FUNCTION
# -----------------------------
async def run_scan(target: str, scan_id: str):
    # Normalize target
    clean = target.replace("http://", "").replace("https://", "").split("/")[0]
    url = "http://" + clean

    await update(scan_id, f"Target: {clean}")
    await update(scan_id, "Starting scan...")

    # Run scans
    ports = await scan_ports(clean, scan_id)
    headers = await check_headers(url, scan_id)
    tls = await check_tls(clean, scan_id)
    injection = await test_injection(url, scan_id)

    await update(scan_id, "Saving results...")

    # Save results to DB
    db = SessionLocal()
    record = ScanResult(
        target=clean,
        ports=json.dumps(ports),
        headers=json.dumps(headers),
        tls=json.dumps(tls),
        injection=json.dumps(injection),
        timestamp=datetime.utcnow(),
        user="anonymous"
    )
    db.add(record)
    db.commit()

    await update(scan_id, "Scan complete.")

    return {
        "ports": ports,
        "headers": headers,
        "tls": tls,
        "injection": injection
    }


# Start scan in background
def start_scan_background(target: str, scan_id: str):
    asyncio.create_task(run_scan(target, scan_id))
