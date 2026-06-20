# Sexy_Proxy — Auto Proxy Validator

Deep, asynchronous proxy validator. It pulls proxies from public sources and/or
your own lists, **really tests each one**, and publishes the working set —
sorted fastest-first — as both `.txt` and `.json`.

## What "deep validation" means here

For every candidate proxy the validator:

1. **Detects the protocol** — tries `http`, `socks4`, `socks5` (or trusts the
   protocol prefix if the line already has one).
2. **Confirms it actually proxies traffic** — makes a real request through it
   to a judge endpoint **twice** and requires both to succeed, filtering out
   flaky / one-shot / honeypot proxies.
3. **Measures latency** in milliseconds (keeps the fastest of the two hits).
4. **Tests HTTPS tunneling** — a TLS request through the proxy to mark it
   `https`-capable.
5. **Classifies anonymity** — `transparent` (leaks your real IP),
   `anonymous` (sends proxy/forwarding headers), or `elite` (clean).
6. **Resolves geo** — country + country code + the proxy's exit IP via ip-api.

## Inputs (auto-discovered, merged, de-duplicated)

| Source | How |
|--------|-----|
| `lists/*.txt` | Drop any number of `.txt` files in `lists/`. |
| `proxies.txt` | Optional single file in repo root. |
| `sources.txt` | Remote raw proxy-list URLs (one per line). |

Accepted line formats: `ip:port`, `proto://ip:port`, `user:pass@ip:port`.

## Outputs (written to `results/`)

| File | Contents |
|------|----------|
| `working.txt` | All working proxies, `proto://ip:port`, **fastest first**. |
| `best.txt` | Top 25 fastest. |
| `http.txt` / `socks4.txt` / `socks5.txt` | Per-protocol, fastest first. |
| `https_capable.txt` | Subset that tunnels HTTPS. |
| `proxies.json` | Full detail per proxy (latency, anonymity, geo, https, timestamp). |
| `summary.json` | Counts, fastest/slowest, run metadata. |

## Local usage

```bash
pip install -r requirements.txt

python validator.py                      # one full pass
python validator.py --loop 30            # re-validate every 30 seconds
python validator.py --concurrency 400 --timeout 8
```

Environment variables also work: `CONCURRENCY`, `TIMEOUT`, `LOOP_SECONDS`.

## Schedule

The included workflow (`.github/workflows/validate.yml`) runs **every 10
minutes**. Runs never overlap: a `concurrency` group makes the next run wait
until the current one finishes before starting. Each run re-validates
everything and commits the refreshed `results/`.

> GitHub-hosted cron is best-effort — a run can occasionally be delayed or
> skipped under load. If you ever need a guaranteed, faster cadence, run the
> validator in loop mode on any always-on machine instead:
>
> ```bash
> python validator.py --loop 600     # re-validate every 10 minutes locally
> ```

## How it works (under the hood)

- `asyncio` + `aiohttp` + `aiohttp_socks` for high concurrency (hundreds of
  simultaneous checks).
- A semaphore caps concurrency so the runner/box isn't overwhelmed.
- Judges: `ip-api.com` (liveness + geo), `httpbin.org/get` (anonymity headers),
  `api.ipify.org` over HTTPS (TLS tunnel test).
- Results are always sorted by latency before writing, so consumers can just
  take the top N for the fastest proxies.

> Public free proxies are volatile — most candidates will fail, and a proxy that
> works now may die in minutes. That's expected; re-run often.
