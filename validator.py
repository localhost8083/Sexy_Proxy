#!/usr/bin/env python3
"""
Sexy_Proxy :: Auto Proxy Validator
==================================

Deep, asynchronous proxy validator.

For every candidate proxy it will:
  1. Detect the working protocol (http / socks4 / socks5).
  2. Verify it actually proxies traffic (real request through it, twice, to
     filter out flaky/honeypot proxies).
  3. Measure latency (ms) and keep the fastest.
  4. Test HTTPS-tunneling capability (TLS through the proxy).
  5. Determine anonymity level (transparent / anonymous / elite) by comparing
     the runner's real public IP and inspecting forwarding headers.
  6. Resolve geo info (country / countryCode) via ip-api.

Results are written to ./results as both .txt (one proxy per line, fastest
first) and .json (full detail), split per protocol plus a combined "best" list.

Usage:
    python validator.py                       # one full pass
    python validator.py --loop 30             # re-validate every 30 seconds
    python validator.py --concurrency 400 --timeout 8

Inputs (auto-discovered, merged + de-duplicated):
    - any *.txt under ./lists/
    - proxies.txt in repo root (optional)
    - every URL listed in sources.txt (remote raw proxy lists)

Lines may be:  ip:port  |  proto://ip:port  |  user:pass@ip:port
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import aiohttp
from aiohttp_socks import ProxyConnector

# --------------------------------------------------------------------------- #
# Config / constants
# --------------------------------------------------------------------------- #

ROOT = Path(__file__).resolve().parent
RESULTS_DIR = ROOT / "results"
LISTS_DIR = ROOT / "lists"
SOURCES_FILE = ROOT / "sources.txt"
LOCAL_PROXIES = ROOT / "proxies.txt"

PROTOCOLS = ("http", "socks4", "socks5")

# Judge endpoints.
#   GEO_JUDGE  -> plaintext/json that echoes our IP + geo  (primary liveness)
#   HDR_JUDGE  -> echoes request headers (anonymity detection)
#   TLS_JUDGE  -> https endpoint (https-tunnel capability)
GEO_JUDGE = "http://ip-api.com/json/?fields=status,country,countryCode,query"
HDR_JUDGE = "http://httpbin.org/get"
TLS_JUDGE = "https://api.ipify.org?format=json"
REAL_IP_URLS = ("https://api.ipify.org?format=json", "https://ifconfig.me/all.json")

PROXY_RE = re.compile(
    r"^(?:(?P<proto>https?|socks4a?|socks5)://)?"
    r"(?:(?P<auth>[^@\s/]+)@)?"
    r"(?P<host>[A-Za-z0-9._-]+):(?P<port>\d{2,5})/?$"
)

UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)


# --------------------------------------------------------------------------- #
# Input loading
# --------------------------------------------------------------------------- #

def normalize_proxy(line: str):
    """Return (proto_or_None, 'host:port', auth_or_None) or None if invalid."""
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    m = PROXY_RE.match(line)
    if not m:
        return None
    proto = m.group("proto")
    if proto == "socks4a":
        proto = "socks4"
    if proto == "https":
        proto = "http"  # https here means "http proxy"; tunneling tested separately
    host = m.group("host")
    port = m.group("port")
    if not (0 < int(port) < 65536):
        return None
    auth = m.group("auth")
    return proto, f"{host}:{port}", auth


def read_lines_from_text(text: str):
    for raw in text.splitlines():
        parsed = normalize_proxy(raw)
        if parsed:
            yield parsed


def load_local_candidates():
    """Collect proxies from lists/*.txt and proxies.txt."""
    candidates = []
    files = []
    if LISTS_DIR.is_dir():
        files.extend(sorted(LISTS_DIR.glob("*.txt")))
    if LOCAL_PROXIES.is_file():
        files.append(LOCAL_PROXIES)
    for fp in files:
        try:
            candidates.extend(read_lines_from_text(fp.read_text(encoding="utf-8", errors="ignore")))
        except OSError as exc:
            print(f"[!] could not read {fp}: {exc}", file=sys.stderr)
    if files:
        print(f"[*] loaded {len(candidates)} entries from {len(files)} local file(s)")
    return candidates


async def fetch_source(session: aiohttp.ClientSession, url: str):
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=30)) as resp:
            if resp.status == 200:
                text = await resp.text()
                got = list(read_lines_from_text(text))
                print(f"[*] source {url} -> {len(got)} proxies")
                return got
            print(f"[!] source {url} -> HTTP {resp.status}", file=sys.stderr)
    except Exception as exc:  # noqa: BLE001 - network sources are best-effort
        print(f"[!] source {url} failed: {exc}", file=sys.stderr)
    return []


async def load_remote_candidates():
    if not SOURCES_FILE.is_file():
        return []
    urls = [
        ln.strip()
        for ln in SOURCES_FILE.read_text(encoding="utf-8", errors="ignore").splitlines()
        if ln.strip() and not ln.strip().startswith("#")
    ]
    if not urls:
        return []
    headers = {"User-Agent": UA}
    async with aiohttp.ClientSession(headers=headers) as session:
        results = await asyncio.gather(*(fetch_source(session, u) for u in urls))
    merged = [p for sub in results for p in sub]
    print(f"[*] loaded {len(merged)} entries from {len(urls)} remote source(s)")
    return merged


def dedupe_candidates(candidates):
    """Merge by host:port. Keep an explicit protocol hint if any line provided one."""
    table = {}
    for proto, addr, auth in candidates:
        cur = table.get(addr)
        if cur is None:
            table[addr] = {"proto": proto, "auth": auth}
        else:
            if cur["proto"] is None and proto is not None:
                cur["proto"] = proto
            if cur["auth"] is None and auth is not None:
                cur["auth"] = auth
    return table


# --------------------------------------------------------------------------- #
# Validation core
# --------------------------------------------------------------------------- #

async def get_real_ip():
    headers = {"User-Agent": UA}
    async with aiohttp.ClientSession(headers=headers) as session:
        for url in REAL_IP_URLS:
            try:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=15)) as r:
                    data = await r.json(content_type=None)
                    ip = data.get("ip_addr") or data.get("ip")
                    if ip:
                        return ip.strip()
            except Exception:  # noqa: BLE001
                continue
    return None


def build_proxy_url(proto: str, addr: str, auth: str | None) -> str:
    if auth:
        return f"{proto}://{auth}@{addr}"
    return f"{proto}://{addr}"


async def _request_through(proto, addr, auth, url, timeout, want_json=True):
    """Single request through the proxy. Returns (latency_ms, payload) or raises."""
    connector = ProxyConnector.from_url(build_proxy_url(proto, addr, auth))
    headers = {"User-Agent": UA, "Accept": "*/*"}
    t0 = time.perf_counter()
    async with aiohttp.ClientSession(connector=connector, headers=headers) as session:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=timeout)) as resp:
            if resp.status != 200:
                raise RuntimeError(f"status {resp.status}")
            payload = await (resp.json(content_type=None) if want_json else resp.text())
    return (time.perf_counter() - t0) * 1000.0, payload


def classify_anonymity(hdr_payload, real_ip):
    """Inspect httpbin /get response: headers + origin -> anonymity level."""
    try:
        headers = {k.lower(): v for k, v in (hdr_payload.get("headers") or {}).items()}
        origin = (hdr_payload.get("origin") or "").lower()
    except AttributeError:
        return "unknown"
    leaks_real_ip = bool(real_ip) and real_ip in origin
    forwarding = any(h in headers for h in ("via", "x-forwarded-for", "forwarded", "proxy-connection"))
    if leaks_real_ip:
        return "transparent"
    if forwarding:
        return "anonymous"
    return "elite"


async def check_proxy(addr, info, timeout, sem, real_ip):
    """Try protocols until one works; return result dict or None."""
    proto_hint = info["proto"]
    auth = info["auth"]
    candidates = [proto_hint] if proto_hint else list(PROTOCOLS)

    async with sem:
        for proto in candidates:
            try:
                # 1) liveness + latency + geo (two hits; require both to pass)
                lat1, geo = await _request_through(proto, addr, auth, GEO_JUDGE, timeout)
                if not isinstance(geo, dict) or geo.get("status") != "success":
                    raise RuntimeError("geo judge rejected")
                lat2, _ = await _request_through(proto, addr, auth, GEO_JUDGE, timeout)
                latency = round(min(lat1, lat2), 1)

                result = {
                    "proxy": addr,
                    "protocol": proto,
                    "latency_ms": latency,
                    "country": geo.get("country"),
                    "country_code": geo.get("countryCode"),
                    "exit_ip": geo.get("query"),
                    "https": False,
                    "anonymity": "unknown",
                    "checked_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                }

                # 2) anonymity (best effort)
                try:
                    _, hdrs = await _request_through(proto, addr, auth, HDR_JUDGE, timeout)
                    result["anonymity"] = classify_anonymity(hdrs, real_ip)
                except Exception:  # noqa: BLE001
                    pass

                # 3) https tunneling capability (best effort)
                try:
                    await _request_through(proto, addr, auth, TLS_JUDGE, timeout)
                    result["https"] = True
                except Exception:  # noqa: BLE001
                    pass

                return result
            except Exception:  # noqa: BLE001 - try next protocol
                continue
    return None


# --------------------------------------------------------------------------- #
# Output
# --------------------------------------------------------------------------- #

def write_outputs(results, started_at, elapsed, total_candidates):
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    results.sort(key=lambda r: r["latency_ms"])  # fastest first

    def proxy_line(r):
        return f"{r['protocol']}://{r['proxy']}"

    # combined working list (fastest first)
    (RESULTS_DIR / "working.txt").write_text(
        "\n".join(proxy_line(r) for r in results) + ("\n" if results else ""),
        encoding="utf-8",
    )
    # top-25 fastest
    (RESULTS_DIR / "best.txt").write_text(
        "\n".join(proxy_line(r) for r in results[:25]) + ("\n" if results else ""),
        encoding="utf-8",
    )
    # per protocol
    for proto in PROTOCOLS:
        subset = [r for r in results if r["protocol"] == proto]
        (RESULTS_DIR / f"{proto}.txt").write_text(
            "\n".join(proxy_line(r) for r in subset) + ("\n" if subset else ""),
            encoding="utf-8",
        )
    # https-capable subset
    https_subset = [r for r in results if r["https"]]
    (RESULTS_DIR / "https_capable.txt").write_text(
        "\n".join(proxy_line(r) for r in https_subset) + ("\n" if https_subset else ""),
        encoding="utf-8",
    )

    # full detail json
    (RESULTS_DIR / "proxies.json").write_text(
        json.dumps(results, indent=2), encoding="utf-8"
    )

    # summary json
    by_proto = {p: sum(1 for r in results if r["protocol"] == p) for p in PROTOCOLS}
    by_anon = {}
    for r in results:
        by_anon[r["anonymity"]] = by_anon.get(r["anonymity"], 0) + 1
    summary = {
        "generated_at": started_at,
        "elapsed_seconds": round(elapsed, 1),
        "candidates_checked": total_candidates,
        "working": len(results),
        "https_capable": len(https_subset),
        "by_protocol": by_proto,
        "by_anonymity": by_anon,
        "fastest_ms": results[0]["latency_ms"] if results else None,
        "slowest_ms": results[-1]["latency_ms"] if results else None,
    }
    (RESULTS_DIR / "summary.json").write_text(
        json.dumps(summary, indent=2), encoding="utf-8"
    )
    return summary


# --------------------------------------------------------------------------- #
# Orchestration
# --------------------------------------------------------------------------- #

async def run_once(concurrency, timeout):
    started_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    t0 = time.perf_counter()

    local, remote = await asyncio.gather(
        asyncio.to_thread(load_local_candidates),
        load_remote_candidates(),
    )
    table = dedupe_candidates(local + remote)
    total = len(table)
    if total == 0:
        print("[!] no candidate proxies found. Add lists/*.txt, proxies.txt, or sources.txt")
        write_outputs([], started_at, time.perf_counter() - t0, 0)
        return

    real_ip = await get_real_ip()
    print(f"[*] runner public IP: {real_ip or 'unknown'}")
    print(f"[*] validating {total} unique proxies (concurrency={concurrency}, timeout={timeout}s)...")

    sem = asyncio.Semaphore(concurrency)
    tasks = [
        asyncio.create_task(check_proxy(addr, info, timeout, sem, real_ip))
        for addr, info in table.items()
    ]

    results = []
    done = 0
    for fut in asyncio.as_completed(tasks):
        res = await fut
        done += 1
        if res:
            results.append(res)
        if done % 200 == 0 or done == total:
            print(f"    progress {done}/{total} | working {len(results)}")

    summary = write_outputs(results, started_at, time.perf_counter() - t0, total)
    print(
        f"[+] done in {summary['elapsed_seconds']}s | "
        f"working {summary['working']}/{total} | "
        f"https {summary['https_capable']} | "
        f"fastest {summary['fastest_ms']} ms"
    )


def parse_args(argv=None):
    p = argparse.ArgumentParser(description="Sexy_Proxy deep async proxy validator")
    p.add_argument("--concurrency", type=int, default=int(os.getenv("CONCURRENCY", "300")),
                   help="max simultaneous proxy checks (default 300)")
    p.add_argument("--timeout", type=float, default=float(os.getenv("TIMEOUT", "8")),
                   help="per-request timeout in seconds (default 8)")
    p.add_argument("--loop", type=int, default=int(os.getenv("LOOP_SECONDS", "0")),
                   help="re-run every N seconds (0 = run once). Use 30 for the 30s goal.")
    return p.parse_args(argv)


async def main_async(args):
    if args.loop > 0:
        print(f"[*] loop mode: every {args.loop}s (Ctrl+C to stop)")
        while True:
            cycle_start = time.perf_counter()
            try:
                await run_once(args.concurrency, args.timeout)
            except Exception as exc:  # noqa: BLE001 - keep the loop alive
                print(f"[!] cycle error: {exc}", file=sys.stderr)
            sleep_for = max(0.0, args.loop - (time.perf_counter() - cycle_start))
            if sleep_for:
                print(f"[*] next cycle in {sleep_for:.0f}s\n")
                await asyncio.sleep(sleep_for)
    else:
        await run_once(args.concurrency, args.timeout)


def main():
    args = parse_args()
    try:
        asyncio.run(main_async(args))
    except KeyboardInterrupt:
        print("\n[*] stopped.")


if __name__ == "__main__":
    main()
