#!/usr/bin/env python3
"""
Sexy_Proxy :: Auto Proxy Validator + Ranking Engine
===================================================

A staged, highly-parallel proxy validator built to chew through very large
aggregated proxy pools (hundreds of thousands of candidates) and emit a
ranked set of real, working, fastest proxies.

PIPELINE (designed for parallel GitHub Actions jobs)
----------------------------------------------------
  1. prepare   -> fetch every source + local lists, de-duplicate, tag each
                  proxy with its source protocol. Writes candidates.jsonl.
  2. validate  -> validate ONE shard of candidates.jsonl in parallel with the
                  other shards. Writes a partial JSON of working proxies.
  3. merge     -> combine all partials, de-duplicate (keep fastest), update the
                  rolling history (uptime / success-rate), RANK everything,
                  and write the final results/ files.

Run a single shard locally / all-in-one:
  python validator.py                         # prepare+validate+merge inline
  python validator.py --loop 600              # repeat every 10 minutes

Staged (what the workflow uses):
  python validator.py prepare  --out candidates.jsonl
  python validator.py validate --candidates candidates.jsonl --shard 0:16 --out partials/0.json
  python validator.py merge    --partials "partials/*.json"

DEEP VALIDATION (per proxy)
---------------------------
  * protocol confirmed (http / socks4 / socks5), tag-driven => 1 attempt
  * real request through it TWICE (filters flaky / honeypot proxies)
  * latency measured (ms)
  * HTTPS-tunnel capability tested
  * anonymity classified (transparent / anonymous / elite)
  * geo resolved (country / country code / exit IP)

RANKING ENGINE
--------------
  score = 45% speed + 40% uptime + 10% https + 5% elite-anonymity
  uptime / success-rate come from results/history.json (rolling, across runs).
"""

from __future__ import annotations

import argparse
import asyncio
import glob as globmod
import json
import os
import re
import sys
import time
import zlib
from datetime import datetime, timezone
from pathlib import Path

import aiohttp
from aiohttp_socks import ProxyConnector

# --------------------------------------------------------------------------- #
# Paths / constants
# --------------------------------------------------------------------------- #

ROOT = Path(__file__).resolve().parent
RESULTS_DIR = ROOT / "results"
LISTS_DIR = ROOT / "lists"
SOURCES_JSON = ROOT / "sources.json"
SOURCES_BULK_JSON = ROOT / "sources_bulk.json"  # opt-in huge scraped lists
SOURCES_TXT = ROOT / "sources.txt"            # optional, untagged extras
LOCAL_PROXIES = ROOT / "proxies.txt"          # optional
HISTORY_FILE = RESULTS_DIR / "history.json"

PROTOCOLS = ("http", "socks4", "socks5")

GEO_JUDGE = "http://ip-api.com/json/?fields=status,country,countryCode,query"
HDR_JUDGE = "http://httpbin.org/get"
TLS_JUDGE = "https://api.ipify.org?format=json"
REAL_IP_URLS = ("https://api.ipify.org?format=json", "https://ifconfig.me/all.json")

# Ranking weights
W_SPEED, W_UPTIME, W_HTTPS, W_ELITE = 0.45, 0.40, 0.10, 0.05
EMA_ALPHA = 0.3
PRUNE_AFTER_RUNS = 50      # drop history entries not seen in this many runs

UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)

BASE_HEADERS = {"User-Agent": UA}


# --------------------------------------------------------------------------- #
# Shared helpers
# --------------------------------------------------------------------------- #

def client_timeout(seconds):
    """aiohttp total-timeout for `seconds` (single source of truth)."""
    return aiohttp.ClientTimeout(total=seconds)


def read_json(path: Path, default=None, *, label=None):
    """Read + parse a JSON file. Return `default` if missing or invalid."""
    if not path.is_file():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        print(f"[!] could not read {label or path}: {exc}", file=sys.stderr)
        return default


def write_json(path: Path, obj):
    """Serialize `obj` as indented JSON, creating parent dirs as needed."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2), encoding="utf-8")


def read_text_lines(path: Path):
    """Read a text file into a list of lines, tolerating bad encodings."""
    return path.read_text(encoding="utf-8", errors="ignore").splitlines()


def _valid_cc(country_code, *, upper):
    """Normalize an ISO-3166 alpha-2 code, or None if it isn't one."""
    cc = (country_code or "").strip()
    cc = cc.upper() if upper else cc.lower()
    return cc if len(cc) == 2 and cc.isalpha() else None


def flag_emoji(country_code):
    """ISO-3166 alpha-2 -> regional-indicator flag emoji ('US' -> '🇺🇸')."""
    cc = _valid_cc(country_code, upper=True)
    if not cc:
        return ""
    return "".join(chr(0x1F1E6 + ord(c) - ord("A")) for c in cc)


def flag_url(country_code):
    """A hosted PNG flag (40px) for the country code, or None."""
    cc = _valid_cc(country_code, upper=False)
    if not cc:
        return None
    return f"https://flagcdn.com/w40/{cc}.png"

PROXY_RE = re.compile(
    r"^(?:(?P<proto>https?|socks4a?|socks5h?)://)?"
    r"(?:(?P<auth>[^@\s/]+)@)?"
    r"(?P<host>\d{1,3}(?:\.\d{1,3}){3}|[A-Za-z0-9._-]+):(?P<port>\d{2,5})"
)


# --------------------------------------------------------------------------- #
# Parsing / loading
# --------------------------------------------------------------------------- #

def normalize_proxy(line: str, default_proto: str | None = None):
    """Parse a proxy line tolerantly. Returns (proto|None, 'host:port', auth|None)."""
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    # Many lists append "  country" or "ip:port:country" -> take the address head.
    token = line.split()[0].split(",")[0]
    m = PROXY_RE.match(token)
    if not m:
        return None
    proto = m.group("proto")
    if proto:
        proto = proto.replace("socks4a", "socks4").replace("socks5h", "socks5")
        if proto == "https":
            proto = "http"
    else:
        proto = default_proto if default_proto not in (None, "mixed") else None
    port = int(m.group("port"))
    if not (0 < port < 65536):
        return None
    return proto, f"{m.group('host')}:{port}", m.group("auth")


def _read_sources_json(path):
    out = []
    for item in read_json(path, default=[], label=path.name):
        if isinstance(item, dict) and item.get("url"):
            out.append({"url": item["url"], "protocol": item.get("protocol")})
    return out


def load_sources_config(include_bulk=False):
    """Return list of {url, protocol}. sources.json (+ optional bulk + txt extras)."""
    sources = _read_sources_json(SOURCES_JSON)
    if include_bulk:
        bulk = _read_sources_json(SOURCES_BULK_JSON)
        print(f"[*] including {len(bulk)} BULK sources (large scraped lists)")
        sources += bulk
    if SOURCES_TXT.is_file():
        for ln in read_text_lines(SOURCES_TXT):
            ln = ln.strip()
            if ln and not ln.startswith("#"):
                sources.append({"url": ln, "protocol": None})
    return sources


def load_local_files():
    """Read lists/*.txt and proxies.txt (untagged -> try all protocols)."""
    out = []
    files = []
    if LISTS_DIR.is_dir():
        files.extend(sorted(LISTS_DIR.glob("*.txt")))
    if LOCAL_PROXIES.is_file():
        files.append(LOCAL_PROXIES)
    for fp in files:
        try:
            for ln in read_text_lines(fp):
                p = normalize_proxy(ln)
                if p:
                    out.append(p)
        except OSError as exc:
            print(f"[!] could not read {fp}: {exc}", file=sys.stderr)
    if out:
        print(f"[*] {len(out)} entries from local files")
    return out


async def fetch_source(session, src, sem):
    url, proto = src["url"], src.get("protocol")
    async with sem:
        try:
            async with session.get(url, timeout=client_timeout(45)) as r:
                if r.status != 200:
                    print(f"[!] {url} -> HTTP {r.status}", file=sys.stderr)
                    return []
                text = await r.text()
        except Exception as exc:  # noqa: BLE001
            print(f"[!] {url} failed: {exc}", file=sys.stderr)
            return []
    got = [p for p in (normalize_proxy(ln, proto) for ln in text.splitlines()) if p]
    print(f"[*] {len(got):>7} from {url}")
    return got


def cap_table(table, max_n, history):
    """Reduce to max_n candidates. Keep proxies already known-good from history
    first, then fill the rest deterministically (stable hash order)."""
    if not max_n or len(table) <= max_n:
        return table
    known_hist = set((history or {}).get("proxies", {}))
    known = [a for a in table if a in known_hist]
    others = sorted((a for a in table if a not in known_hist),
                    key=lambda a: zlib.crc32(a.encode()))
    keep = (known + others)[:max_n]
    print(f"[*] capping {len(table)} -> {len(keep)} "
          f"(kept {min(len(known), len(keep))} known-good from history)")
    return {a: table[a] for a in keep}


async def build_candidate_table(include_bulk=False, max_n=0, history=None):
    """Fetch every source + local lists, de-duplicate by host:port, optional cap."""
    sources = load_sources_config(include_bulk=include_bulk)
    sem = asyncio.Semaphore(16)
    async with aiohttp.ClientSession(headers=BASE_HEADERS) as session:
        batches = await asyncio.gather(*(fetch_source(session, s, sem) for s in sources))
    all_entries = [p for b in batches for p in b] + load_local_files()

    table: dict[str, dict] = {}
    for proto, addr, auth in all_entries:
        cur = table.setdefault(addr, {"protocols": set(), "auth": None})
        if proto:
            cur["protocols"].add(proto)
        if auth and not cur["auth"]:
            cur["auth"] = auth
    print(f"[*] {len(table)} unique candidates after de-duplication")
    return cap_table(table, max_n, history)


def write_candidates(table, path: Path):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        for addr, info in table.items():
            fh.write(json.dumps({
                "addr": addr,
                "protocols": sorted(info["protocols"]),
                "auth": info["auth"],
            }) + "\n")
    print(f"[+] wrote {len(table)} candidates -> {path}")


def read_candidates(path: Path, shard=None):
    """Read candidates.jsonl, optionally keeping only one shard (i, n)."""
    table = {}
    with path.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            rec = json.loads(line)
            addr = rec["addr"]
            if shard is not None:
                i, n = shard
                if zlib.crc32(addr.encode()) % n != i:
                    continue
            table[addr] = {"protocols": set(rec.get("protocols") or []), "auth": rec.get("auth")}
    return table


# --------------------------------------------------------------------------- #
# Validation
# --------------------------------------------------------------------------- #

async def get_real_ip():
    async with aiohttp.ClientSession(headers=BASE_HEADERS) as session:
        for url in REAL_IP_URLS:
            try:
                async with session.get(url, timeout=client_timeout(15)) as r:
                    data = await r.json(content_type=None)
                    ip = data.get("ip_addr") or data.get("ip")
                    if ip:
                        return ip.strip()
            except Exception:  # noqa: BLE001
                continue
    return None


def proxy_url(proto, addr, auth):
    return f"{proto}://{auth}@{addr}" if auth else f"{proto}://{addr}"


async def _request(proto, addr, auth, url, timeout, want_json=True):
    connector = ProxyConnector.from_url(proxy_url(proto, addr, auth))
    headers = {**BASE_HEADERS, "Accept": "*/*"}
    t0 = time.perf_counter()
    async with aiohttp.ClientSession(connector=connector, headers=headers) as session:
        async with session.get(url, timeout=client_timeout(timeout)) as resp:
            if resp.status != 200:
                raise RuntimeError(f"status {resp.status}")
            payload = await (resp.json(content_type=None) if want_json else resp.text())
    return (time.perf_counter() - t0) * 1000.0, payload


def classify_anonymity(hdr_payload, real_ip):
    try:
        headers = {k.lower(): v for k, v in (hdr_payload.get("headers") or {}).items()}
        origin = (hdr_payload.get("origin") or "").lower()
    except AttributeError:
        return "unknown"
    if real_ip and real_ip in origin:
        return "transparent"
    if any(h in headers for h in ("via", "x-forwarded-for", "forwarded", "proxy-connection")):
        return "anonymous"
    return "elite"


async def check_proxy(addr, info, timeout, sem, real_ip):
    candidates = sorted(info["protocols"]) or list(PROTOCOLS)
    auth = info["auth"]
    async with sem:
        for proto in candidates:
            try:
                lat1, geo = await _request(proto, addr, auth, GEO_JUDGE, timeout)
                if not isinstance(geo, dict) or geo.get("status") != "success":
                    raise RuntimeError("geo judge rejected")
                lat2, _ = await _request(proto, addr, auth, GEO_JUDGE, timeout)
                result = {
                    "proxy": addr,
                    "protocol": proto,
                    "latency_ms": round(min(lat1, lat2), 1),
                    "country": geo.get("country"),
                    "country_code": geo.get("countryCode"),
                    "exit_ip": geo.get("query"),
                    "https": False,
                    "anonymity": "unknown",
                    "checked_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                }
                try:
                    _, hdrs = await _request(proto, addr, auth, HDR_JUDGE, timeout)
                    result["anonymity"] = classify_anonymity(hdrs, real_ip)
                except Exception:  # noqa: BLE001
                    pass
                try:
                    await _request(proto, addr, auth, TLS_JUDGE, timeout)
                    result["https"] = True
                except Exception:  # noqa: BLE001
                    pass
                return result
            except Exception:  # noqa: BLE001
                continue
    return None


async def validate_table(table, concurrency, timeout, real_ip):
    sem = asyncio.Semaphore(concurrency)
    tasks = [asyncio.create_task(check_proxy(a, i, timeout, sem, real_ip)) for a, i in table.items()]
    total = len(tasks)
    results, done = [], 0
    for fut in asyncio.as_completed(tasks):
        res = await fut
        done += 1
        if res:
            results.append(res)
        if done % 500 == 0 or done == total:
            print(f"    progress {done}/{total} | working {len(results)}")
    return results


# --------------------------------------------------------------------------- #
# Ranking + outputs
# --------------------------------------------------------------------------- #

def dedupe_working(results):
    """Keep the fastest record per host:port."""
    best = {}
    for r in results:
        cur = best.get(r["proxy"])
        if cur is None or r["latency_ms"] < cur["latency_ms"]:
            best[r["proxy"]] = r
    return list(best.values())


def load_history():
    return read_json(HISTORY_FILE, default={"run_index": 0, "proxies": {}},
                     label="history.json")


def update_history_and_rank(working, history):
    run = history.get("run_index", 0) + 1
    history["run_index"] = run
    hp = history.setdefault("proxies", {})

    for r in working:
        addr = r["proxy"]
        h = hp.get(addr)
        if h is None:
            h = {"first_run": run, "working_count": 0, "ema_latency_ms": r["latency_ms"]}
            hp[addr] = h
        h["last_run"] = run
        h["working_count"] = h.get("working_count", 0) + 1
        h["ema_latency_ms"] = round(
            EMA_ALPHA * r["latency_ms"] + (1 - EMA_ALPHA) * h.get("ema_latency_ms", r["latency_ms"]), 1
        )
        h["protocol"] = r["protocol"]
        h["country"] = r["country"]
        h["country_code"] = r["country_code"]
        h["https"] = r["https"]
        h["anonymity"] = r["anonymity"]

    # prune stale entries
    for addr in [a for a, h in hp.items() if run - h.get("last_run", run) > PRUNE_AFTER_RUNS]:
        del hp[addr]

    # ranking over the currently-working set
    if working:
        lats = [r["latency_ms"] for r in working]
        lo, hi = min(lats), max(lats)
        span = (hi - lo) or 1.0
    else:
        lo, span = 0.0, 1.0

    ranked = []
    for r in working:
        h = hp[r["proxy"]]
        window = run - h["first_run"] + 1
        uptime = h["working_count"] / window if window else 1.0
        norm_lat = (r["latency_ms"] - lo) / span
        score = 100 * (
            W_SPEED * (1 - norm_lat)
            + W_UPTIME * uptime
            + W_HTTPS * (1 if r["https"] else 0)
            + W_ELITE * (1 if r["anonymity"] == "elite" else 0)
        )
        ranked.append({
            **r,
            "ema_latency_ms": h["ema_latency_ms"],
            "uptime": round(uptime, 3),
            "working_count": h["working_count"],
            "runs_observed": window,
            "score": round(score, 2),
        })
    ranked.sort(key=lambda x: (-x["score"], x["latency_ms"]))
    return ranked, run


def write_outputs(ranked, run_index, started_at, elapsed, total_checked):
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    by_speed = sorted(ranked, key=lambda r: r["latency_ms"])

    def line(r):
        return f"{r['protocol']}://{r['proxy']}"

    def dump_txt(name, rows):
        (RESULTS_DIR / name).write_text(
            "\n".join(line(r) for r in rows) + ("\n" if rows else ""), encoding="utf-8"
        )

    dump_txt("working.txt", by_speed)                       # fastest first
    dump_txt("best.txt", by_speed[:25])                     # top 25 fastest
    dump_txt("ranked.txt", ranked)                          # by composite score
    dump_txt("https_capable.txt", [r for r in by_speed if r["https"]])
    for proto in PROTOCOLS:
        dump_txt(f"{proto}.txt", [r for r in by_speed if r["protocol"] == proto])

    write_json(RESULTS_DIR / "ranked.json", ranked)
    write_json(RESULTS_DIR / "proxies.json", by_speed)

    # master.json — the headline list: fastest first, with country + flag
    master = [{
        "rank": i + 1,
        "proxy": r["proxy"],
        "url": line(r),
        "protocol": r["protocol"],
        "latency_ms": r["latency_ms"],
        "country": r["country"],
        "country_code": r["country_code"],
        "flag": flag_emoji(r["country_code"]),
        "flag_url": flag_url(r["country_code"]),
        "https": r["https"],
        "anonymity": r["anonymity"],
        "uptime": r["uptime"],
        "score": r["score"],
    } for i, r in enumerate(by_speed)]
    write_json(RESULTS_DIR / "master.json", master)

    # per-country breakdown
    by_country = {}
    for r in by_speed:
        cc = r["country_code"] or "??"
        c = by_country.setdefault(cc, {"country": r["country"], "count": 0,
                                       "fastest_ms": r["latency_ms"], "top": line(r)})
        c["count"] += 1
        if r["latency_ms"] < c["fastest_ms"]:
            c["fastest_ms"] = r["latency_ms"]
            c["top"] = line(r)
    write_json(RESULTS_DIR / "by_country.json",
               dict(sorted(by_country.items(), key=lambda kv: -kv[1]["count"])))

    summary = {
        "generated_at": started_at,
        "run_index": run_index,
        "elapsed_seconds": round(elapsed, 1),
        "candidates_checked": total_checked,
        "working": len(ranked),
        "https_capable": sum(1 for r in ranked if r["https"]),
        "by_protocol": {p: sum(1 for r in ranked if r["protocol"] == p) for p in PROTOCOLS},
        "by_anonymity": _count(ranked, "anonymity"),
        "countries": len(by_country),
        "fastest_ms": by_speed[0]["latency_ms"] if by_speed else None,
        "top_ranked": ranked[0] if ranked else None,
    }
    write_json(RESULTS_DIR / "summary.json", summary)
    return summary


def _count(rows, key):
    out = {}
    for r in rows:
        out[r[key]] = out.get(r[key], 0) + 1
    return out


def finalize(working, started_at, elapsed, total_checked):
    working = dedupe_working(working)
    history = load_history()
    ranked, run = update_history_and_rank(working, history)
    summary = write_outputs(ranked, run, started_at, elapsed, total_checked)
    write_json(HISTORY_FILE, history)
    print(
        f"[+] run #{run} | checked {total_checked} | working {summary['working']} | "
        f"https {summary['https_capable']} | countries {summary['countries']} | "
        f"fastest {summary['fastest_ms']} ms"
    )
    if summary["top_ranked"]:
        t = summary["top_ranked"]
        print(f"[+] #1 ranked: {t['protocol']}://{t['proxy']} "
              f"score={t['score']} lat={t['latency_ms']}ms uptime={t['uptime']} {t['country']}")
    return summary


# --------------------------------------------------------------------------- #
# Modes
# --------------------------------------------------------------------------- #

async def mode_prepare(args):
    table = await build_candidate_table(
        include_bulk=args.include_bulk, max_n=args.max, history=load_history()
    )
    write_candidates(table, Path(args.out))


async def mode_validate(args):
    shard = None
    if args.shard:
        i, n = (int(x) for x in args.shard.split(":"))
        shard = (i, n)
    table = read_candidates(Path(args.candidates), shard=shard)
    if args.max and len(table) > args.max:
        table = dict(list(table.items())[: args.max])
    real_ip = await get_real_ip()
    label = f"shard {shard[0]+1}/{shard[1]}" if shard else "all"
    print(f"[*] validating {len(table)} candidates ({label}) "
          f"concurrency={args.concurrency} timeout={args.timeout}s real_ip={real_ip}")
    results = await validate_table(table, args.concurrency, args.timeout, real_ip)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({"checked": len(table), "working": results}), encoding="utf-8")
    print(f"[+] {len(results)} working -> {out}")


def mode_merge(args):
    started_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    files = sorted(globmod.glob(args.partials))
    if not files:
        print(f"[!] no partial files matched: {args.partials}", file=sys.stderr)
    working, total = [], 0
    for fp in files:
        data = read_json(Path(fp), default={}, label=f"partial {fp}")
        working.extend(data.get("working", []))
        total += int(data.get("checked", 0))
    print(f"[*] merging {len(files)} partials | raw working {len(working)} | checked {total}")
    finalize(working, started_at, 0.0, total)


async def mode_all_inline(args):
    """prepare + validate + merge in one process (local / --loop)."""
    started_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    t0 = time.perf_counter()
    table = await build_candidate_table(
        include_bulk=args.include_bulk, max_n=args.max, history=load_history()
    )
    if not table:
        print("[!] no candidates. Check sources.json / lists/.")
        finalize([], started_at, time.perf_counter() - t0, 0)
        return
    real_ip = await get_real_ip()
    print(f"[*] validating {len(table)} candidates inline "
          f"(concurrency={args.concurrency}, timeout={args.timeout}s, real_ip={real_ip})")
    results = await validate_table(table, args.concurrency, args.timeout, real_ip)
    finalize(results, started_at, time.perf_counter() - t0, len(table))


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def build_parser():
    p = argparse.ArgumentParser(description="Sexy_Proxy validator + ranking engine")
    p.add_argument("--concurrency", type=int, default=int(os.getenv("CONCURRENCY", "500")))
    p.add_argument("--timeout", type=float, default=float(os.getenv("TIMEOUT", "7")))
    p.add_argument("--loop", type=int, default=int(os.getenv("LOOP_SECONDS", "0")),
                   help="inline mode only: repeat every N seconds")
    p.add_argument("--max", type=int, default=int(os.getenv("MAX_CANDIDATES", "0")),
                   help="cap total candidates (0 = no cap); history-known-good kept first")
    p.add_argument("--include-bulk", action="store_true",
                   default=os.getenv("INCLUDE_BULK", "").lower() in ("1", "true", "yes"),
                   help="also load sources_bulk.json (very large scraped lists)")
    sub = p.add_subparsers(dest="mode")

    sp = sub.add_parser("prepare", help="fetch+dedupe+tag -> candidates.jsonl")
    sp.add_argument("--out", default="candidates.jsonl")

    sv = sub.add_parser("validate", help="validate one shard -> partial json")
    sv.add_argument("--candidates", default="candidates.jsonl")
    sv.add_argument("--shard", help="i:n  e.g. 0:8")
    sv.add_argument("--out", required=True)

    sm = sub.add_parser("merge", help="merge partials -> ranked results/")
    sm.add_argument("--partials", default="partials/*.json")
    return p


async def dispatch(args):
    if args.mode == "prepare":
        await mode_prepare(args)
    elif args.mode == "validate":
        await mode_validate(args)
    elif args.mode == "merge":
        mode_merge(args)            # sync
    else:
        await mode_all_inline(args)


def main():
    args = build_parser().parse_args()
    try:
        if args.loop > 0 and args.mode in (None, "validate"):
            print(f"[*] loop mode: every {args.loop}s (Ctrl+C to stop)")
            while True:
                start = time.perf_counter()
                try:
                    asyncio.run(dispatch(args))
                except Exception as exc:  # noqa: BLE001
                    print(f"[!] cycle error: {exc}", file=sys.stderr)
                sleep_for = max(0.0, args.loop - (time.perf_counter() - start))
                print(f"[*] next cycle in {sleep_for:.0f}s\n")
                time.sleep(sleep_for)
        else:
            asyncio.run(dispatch(args))
    except KeyboardInterrupt:
        print("\n[*] stopped.")


if __name__ == "__main__":
    main()
