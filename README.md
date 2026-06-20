# Sexy_Proxy — Auto Proxy Validator + Ranking Engine

Pulls proxies from many large public sources, **deeply validates** them in
parallel, and publishes a **ranked** set of real, working, fastest proxies as
`.txt` and `.json`.

Built to handle large pools efficiently. The default **curated** source set is
~14k high-quality candidates (fresh/validated lists) so scans finish fast; a
much larger **bulk** tier (~250k+ raw scraped proxies) is available opt-in.

## Pipeline (3 stages, parallelized)

```
prepare  →  validate (8 parallel shards)  →  merge + rank + commit
```

1. **prepare** — fetch every source + local lists, de-duplicate, and tag each
   proxy with its source protocol. Writes `candidates.jsonl`.
2. **validate** — 16 parallel jobs each validate one shard of the candidates,
   so the whole pool is checked at ~16× speed. Each writes a partial result.
3. **merge** — combine all partials, de-duplicate (keep fastest), update the
   rolling history, **rank** everything, and write `results/`.

## Deep validation (per proxy)

- Protocol confirmed — `http` / `socks4` / `socks5` (tag-driven ⇒ 1 attempt).
- Proxies traffic for real — a request is made **through** it **twice**;
  both must succeed (filters flaky / one-shot / honeypot proxies).
- **Latency** measured in ms (fastest of the two hits).
- **HTTPS tunneling** tested (TLS through the proxy).
- **Anonymity** classified: `transparent` / `anonymous` / `elite`.
- **Geo** resolved: country, country code, exit IP.

## Ranking engine

Each working proxy gets a composite **score (0–100)**:

```
score = 45% speed  +  40% uptime  +  10% https  +  5% elite-anonymity
```

`uptime` (a.k.a. success rate) comes from `results/history.json`, a rolling
record kept across runs: how consistently a proxy has been working since it was
first seen, plus an EMA of its latency. Stale proxies (unseen for 50 runs) are
pruned automatically.

## Sources

- **`sources.json`** — the **curated, default** set: smaller, fresher /
  pre-validated lists (~14k candidates). Protocol-tagged so each proxy is tried
  with only one protocol. Each entry is
  `{ "url": ..., "protocol": "http|socks4|socks5|mixed" }`.
- **`sources_bulk.json`** — **opt-in** huge scraped lists (fyvri, MuRongPIG —
  ~250k+ raw, mostly dead). Off by default. Enable with `--include-bulk`
  (or `INCLUDE_BULK=true`).
- **`sources.txt`** — optional untagged extras (tried against all protocols).
- **`lists/*.txt`** and **`proxies.txt`** — your own local lists.

### Keeping the pool reasonable

- Default = curated only (fast).
- Cap the total with `--max N` (env `MAX_CANDIDATES`). When capping, proxies
  already **known-good from `history.json` are kept first**, then the rest fill
  up to N — so you don't lose your proven proxies.

Accepted line formats: `ip:port`, `proto://ip:port`, `user:pass@ip:port`,
and tolerant of `ip:port:country` / trailing columns.

## Outputs (`results/`)

| File | Contents |
|------|----------|
| `ranked.txt` | Working proxies ordered by composite **score** (best first). |
| `ranked.json` | Full ranking detail: score, uptime, latency, ema, country, https, anonymity. |
| `working.txt` | All working proxies, **fastest first**. |
| `best.txt` | Top 25 fastest. |
| `http.txt` / `socks4.txt` / `socks5.txt` | Per-protocol, fastest first. |
| `https_capable.txt` | Subset that tunnels HTTPS. |
| `by_country.json` | Per-country counts + fastest proxy. |
| `proxies.json` | Current working set (full detail). |
| `summary.json` | Run metadata + counts. |
| `history.json` | Rolling per-proxy uptime/latency history (powers ranking). |

## Local usage

```bash
pip install -r requirements.txt

# all-in-one (prepare + validate + merge in one process)
python validator.py                          # curated set (~14k), fast
python validator.py --include-bulk           # add the huge bulk lists
python validator.py --max 8000               # hard-cap the candidate pool
python validator.py --loop 600               # repeat every 10 minutes

# staged (mirrors the workflow)
python validator.py prepare  --out candidates.jsonl
python validator.py --concurrency 500 --timeout 7 \
        validate --candidates candidates.jsonl --shard 0:8 --out partials/0.json
python validator.py merge --partials "partials/*.json"
```

Env vars: `CONCURRENCY`, `TIMEOUT`, `LOOP_SECONDS`, `MAX_CANDIDATES`, `INCLUDE_BULK`.
(Global flags like `--concurrency` go **before** the subcommand.)

## Schedule

`.github/workflows/validate.yml` runs **every 10 minutes**. The `concurrency`
group ensures runs never overlap — the next pipeline waits for the current one
to finish. The merge job commits refreshed `results/` (including `history.json`,
so rankings improve over time).

> GitHub-hosted cron is best-effort — runs can be delayed/skipped under load.
> For a guaranteed faster cadence, run `python validator.py --loop 600` on any
> always-on machine (VPS / self-hosted runner).

> ⚠️ The first scheduled run must be allowed to commit: enable
> **Settings → Actions → General → Workflow permissions → Read and write**.

> Public free proxies are volatile — most candidates fail, and a proxy that
> works now may die in minutes. That's expected; the ranking/history smooths
> this by rewarding proxies with consistent uptime.

