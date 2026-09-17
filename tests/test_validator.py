"""Unit tests for validator.py.

The repository shipped with zero automated tests; ``validator.py`` was the
single (and therefore least-covered) module. These tests exercise the parsing,
loading, capping, candidate I/O, anonymity classification, ranking, history and
output-writing logic, plus the CLI parser and the async request/validation
layer (with the network fully stubbed out).
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

import pytest

import validator


# --------------------------------------------------------------------------- #
# flag_emoji / flag_url
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize(
    "cc, expected",
    [
        ("US", "\U0001F1FA\U0001F1F8"),
        ("us", "\U0001F1FA\U0001F1F8"),   # lower-cased input still works
        (" gb ", "\U0001F1EC\U0001F1E7"),  # surrounding whitespace stripped
    ],
)
def test_flag_emoji_valid(cc, expected):
    assert validator.flag_emoji(cc) == expected


@pytest.mark.parametrize("cc", [None, "", "U", "USA", "1A", "!!"])
def test_flag_emoji_invalid_returns_empty(cc):
    assert validator.flag_emoji(cc) == ""


def test_flag_url_valid():
    assert validator.flag_url("US") == "https://flagcdn.com/w40/us.png"
    assert validator.flag_url(" Gb ") == "https://flagcdn.com/w40/gb.png"


@pytest.mark.parametrize("cc", [None, "", "U", "USA", "12"])
def test_flag_url_invalid_returns_none(cc):
    assert validator.flag_url(cc) is None


# --------------------------------------------------------------------------- #
# normalize_proxy
# --------------------------------------------------------------------------- #

def test_normalize_proxy_plain_host_port_uses_default_proto():
    assert validator.normalize_proxy("1.2.3.4:8080", "http") == ("http", "1.2.3.4:8080", None)


def test_normalize_proxy_no_default_proto_is_none():
    assert validator.normalize_proxy("1.2.3.4:8080") == (None, "1.2.3.4:8080", None)


def test_normalize_proxy_scheme_overrides_default():
    assert validator.normalize_proxy("socks5://1.2.3.4:1080", "http") == (
        "socks5",
        "1.2.3.4:1080",
        None,
    )


def test_normalize_proxy_https_scheme_maps_to_http():
    assert validator.normalize_proxy("https://1.2.3.4:443") == ("http", "1.2.3.4:443", None)


def test_normalize_proxy_socks_aliases_normalized():
    assert validator.normalize_proxy("socks4a://1.2.3.4:1080")[0] == "socks4"
    assert validator.normalize_proxy("socks5h://1.2.3.4:1080")[0] == "socks5"


def test_normalize_proxy_with_auth():
    assert validator.normalize_proxy("http://user:pass@1.2.3.4:8080") == (
        "http",
        "1.2.3.4:8080",
        "user:pass",
    )


def test_normalize_proxy_mixed_default_treated_as_none():
    assert validator.normalize_proxy("1.2.3.4:8080", "mixed") == (None, "1.2.3.4:8080", None)


def test_normalize_proxy_trailing_country_token_stripped():
    # Lists often append "  Country" or "ip:port,country".
    assert validator.normalize_proxy("1.2.3.4:8080  United States", "http") == (
        "http",
        "1.2.3.4:8080",
        None,
    )
    assert validator.normalize_proxy("1.2.3.4:8080,US", "http") == (
        "http",
        "1.2.3.4:8080",
        None,
    )


def test_normalize_proxy_hostname_allowed():
    assert validator.normalize_proxy("proxy.example.com:3128", "http") == (
        "http",
        "proxy.example.com:3128",
        None,
    )


@pytest.mark.parametrize("line", ["", "   ", "# a comment", "not a proxy", "1.2.3.4"])
def test_normalize_proxy_rejects_garbage(line):
    assert validator.normalize_proxy(line) is None


def test_normalize_proxy_rejects_out_of_range_port():
    # 5-digit port that exceeds 65535 is rejected by the range check.
    assert validator.normalize_proxy("1.2.3.4:70000") is None


# --------------------------------------------------------------------------- #
# _read_sources_json / load_sources_config
# --------------------------------------------------------------------------- #

def test_read_sources_json_parses_entries(tmp_path):
    p = tmp_path / "s.json"
    p.write_text(
        json.dumps(
            [
                {"url": "http://a", "protocol": "http"},
                {"url": "http://b"},           # protocol defaults to None
                {"protocol": "http"},          # no url -> skipped
                "not-a-dict",                  # skipped
            ]
        ),
        encoding="utf-8",
    )
    out = validator._read_sources_json(p)
    assert out == [
        {"url": "http://a", "protocol": "http"},
        {"url": "http://b", "protocol": None},
    ]


def test_read_sources_json_missing_file_returns_empty(tmp_path):
    assert validator._read_sources_json(tmp_path / "nope.json") == []


def test_read_sources_json_bad_json_returns_empty(tmp_path, capsys):
    p = tmp_path / "bad.json"
    p.write_text("{not json", encoding="utf-8")
    assert validator._read_sources_json(p) == []
    assert "could not parse" in capsys.readouterr().err


def test_load_sources_config_combines_json_bulk_and_txt(tmp_path, monkeypatch):
    sj = tmp_path / "sources.json"
    sj.write_text(json.dumps([{"url": "http://main", "protocol": "http"}]), encoding="utf-8")
    sb = tmp_path / "bulk.json"
    sb.write_text(json.dumps([{"url": "http://bulk", "protocol": "socks5"}]), encoding="utf-8")
    st = tmp_path / "sources.txt"
    st.write_text("# comment\nhttp://extra\n\n", encoding="utf-8")

    monkeypatch.setattr(validator, "SOURCES_JSON", sj)
    monkeypatch.setattr(validator, "SOURCES_BULK_JSON", sb)
    monkeypatch.setattr(validator, "SOURCES_TXT", st)

    without_bulk = validator.load_sources_config(include_bulk=False)
    assert {"url": "http://main", "protocol": "http"} in without_bulk
    assert {"url": "http://extra", "protocol": None} in without_bulk
    assert all(s["url"] != "http://bulk" for s in without_bulk)

    with_bulk = validator.load_sources_config(include_bulk=True)
    assert {"url": "http://bulk", "protocol": "socks5"} in with_bulk


# --------------------------------------------------------------------------- #
# load_local_files
# --------------------------------------------------------------------------- #

def test_load_local_files_reads_lists_and_local(tmp_path, monkeypatch):
    lists = tmp_path / "lists"
    lists.mkdir()
    (lists / "a.txt").write_text("1.1.1.1:80\n# skip\ngarbage\n", encoding="utf-8")
    local = tmp_path / "proxies.txt"
    local.write_text("2.2.2.2:8080\n", encoding="utf-8")

    monkeypatch.setattr(validator, "LISTS_DIR", lists)
    monkeypatch.setattr(validator, "LOCAL_PROXIES", local)

    out = validator.load_local_files()
    addrs = {addr for _, addr, _ in out}
    assert addrs == {"1.1.1.1:80", "2.2.2.2:8080"}


def test_load_local_files_none_present(tmp_path, monkeypatch):
    monkeypatch.setattr(validator, "LISTS_DIR", tmp_path / "no-lists")
    monkeypatch.setattr(validator, "LOCAL_PROXIES", tmp_path / "no-proxies.txt")
    assert validator.load_local_files() == []


# --------------------------------------------------------------------------- #
# cap_table
# --------------------------------------------------------------------------- #

def test_cap_table_no_cap_when_zero_or_within_limit():
    table = {"a:1": {}, "b:2": {}}
    assert validator.cap_table(table, 0, None) is table
    assert validator.cap_table(table, 5, None) is table


def test_cap_table_prefers_history_known_good():
    table = {f"{i}.0.0.0:80": {"x": i} for i in range(10)}
    history = {"proxies": {"3.0.0.0:80": {}, "7.0.0.0:80": {}}}
    capped = validator.cap_table(table, 3, history)
    assert len(capped) == 3
    # both known-good survive because they are kept first
    assert "3.0.0.0:80" in capped
    assert "7.0.0.0:80" in capped


def test_cap_table_deterministic_without_history():
    table = {f"{i}.0.0.0:80": {} for i in range(20)}
    first = validator.cap_table(dict(table), 5, None)
    second = validator.cap_table(dict(table), 5, None)
    assert list(first) == list(second)


# --------------------------------------------------------------------------- #
# write_candidates / read_candidates
# --------------------------------------------------------------------------- #

def test_write_then_read_candidates_roundtrip(tmp_path):
    table = {
        "1.1.1.1:80": {"protocols": {"http", "socks5"}, "auth": "u:p"},
        "2.2.2.2:81": {"protocols": set(), "auth": None},
    }
    path = tmp_path / "candidates.jsonl"
    validator.write_candidates(table, path)

    # one JSON object per line, protocols sorted
    lines = path.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 2
    assert json.loads(lines[0])["protocols"] == ["http", "socks5"]

    back = validator.read_candidates(path)
    assert back["1.1.1.1:80"]["protocols"] == {"http", "socks5"}
    assert back["1.1.1.1:80"]["auth"] == "u:p"
    assert back["2.2.2.2:81"]["protocols"] == set()
    assert back["2.2.2.2:81"]["auth"] is None


def test_read_candidates_sharding_partitions_all_addrs(tmp_path):
    table = {f"10.0.0.{i}:80": {"protocols": set(), "auth": None} for i in range(50)}
    path = tmp_path / "c.jsonl"
    validator.write_candidates(table, path)

    n = 4
    seen: set[str] = set()
    for i in range(n):
        shard = validator.read_candidates(path, shard=(i, n))
        # shards are disjoint
        assert seen.isdisjoint(shard)
        seen.update(shard)
    # every address ends up in exactly one shard
    assert seen == set(table)


# --------------------------------------------------------------------------- #
# proxy_url
# --------------------------------------------------------------------------- #

def test_proxy_url_with_and_without_auth():
    assert validator.proxy_url("http", "1.2.3.4:80", None) == "http://1.2.3.4:80"
    assert validator.proxy_url("socks5", "1.2.3.4:80", "u:p") == "socks5://u:p@1.2.3.4:80"


# --------------------------------------------------------------------------- #
# classify_anonymity
# --------------------------------------------------------------------------- #

def test_classify_anonymity_transparent_when_real_ip_leaks():
    payload = {"headers": {}, "origin": "9.9.9.9"}
    assert validator.classify_anonymity(payload, "9.9.9.9") == "transparent"


def test_classify_anonymity_anonymous_when_proxy_header_present():
    payload = {"headers": {"Via": "1.1 proxy"}, "origin": "5.5.5.5"}
    assert validator.classify_anonymity(payload, "9.9.9.9") == "anonymous"


def test_classify_anonymity_elite_when_clean():
    payload = {"headers": {"Accept": "*/*"}, "origin": "5.5.5.5"}
    assert validator.classify_anonymity(payload, "9.9.9.9") == "elite"


def test_classify_anonymity_bad_payload_returns_unknown():
    assert validator.classify_anonymity("not-a-dict", "9.9.9.9") == "unknown"


def test_classify_anonymity_no_real_ip_not_transparent():
    payload = {"headers": {}, "origin": "5.5.5.5"}
    assert validator.classify_anonymity(payload, None) == "elite"


# --------------------------------------------------------------------------- #
# dedupe_working
# --------------------------------------------------------------------------- #

def test_dedupe_working_keeps_fastest():
    results = [
        {"proxy": "1.1.1.1:80", "latency_ms": 300.0},
        {"proxy": "1.1.1.1:80", "latency_ms": 120.0},
        {"proxy": "2.2.2.2:80", "latency_ms": 50.0},
    ]
    out = {r["proxy"]: r["latency_ms"] for r in validator.dedupe_working(results)}
    assert out == {"1.1.1.1:80": 120.0, "2.2.2.2:80": 50.0}


# --------------------------------------------------------------------------- #
# load_history
# --------------------------------------------------------------------------- #

def test_load_history_missing_returns_default(tmp_path, monkeypatch):
    monkeypatch.setattr(validator, "HISTORY_FILE", tmp_path / "history.json")
    assert validator.load_history() == {"run_index": 0, "proxies": {}}


def test_load_history_reads_existing(tmp_path, monkeypatch):
    hf = tmp_path / "history.json"
    hf.write_text(json.dumps({"run_index": 7, "proxies": {"x": {}}}), encoding="utf-8")
    monkeypatch.setattr(validator, "HISTORY_FILE", hf)
    assert validator.load_history()["run_index"] == 7


def test_load_history_corrupt_returns_default(tmp_path, monkeypatch):
    hf = tmp_path / "history.json"
    hf.write_text("{broken", encoding="utf-8")
    monkeypatch.setattr(validator, "HISTORY_FILE", hf)
    assert validator.load_history() == {"run_index": 0, "proxies": {}}


# --------------------------------------------------------------------------- #
# update_history_and_rank
# --------------------------------------------------------------------------- #

def _mk_result(proxy, latency, https=False, anonymity="elite", proto="http"):
    return {
        "proxy": proxy,
        "protocol": proto,
        "latency_ms": latency,
        "country": "United States",
        "country_code": "US",
        "exit_ip": proxy.split(":")[0],
        "https": https,
        "anonymity": anonymity,
    }


def test_update_history_and_rank_new_entries_and_order():
    working = [
        _mk_result("1.1.1.1:80", 300.0, https=False, anonymity="anonymous"),
        _mk_result("2.2.2.2:80", 50.0, https=True, anonymity="elite"),
    ]
    history = {"run_index": 0, "proxies": {}}
    ranked, run = validator.update_history_and_rank(working, history)

    assert run == 1
    # fastest + https + elite proxy should outrank the slow anonymous one
    assert ranked[0]["proxy"] == "2.2.2.2:80"
    assert ranked[0]["score"] >= ranked[1]["score"]
    # derived fields present
    for r in ranked:
        assert "uptime" in r and "score" in r and "ema_latency_ms" in r
    assert history["proxies"]["2.2.2.2:80"]["working_count"] == 1


def test_update_history_and_rank_accumulates_uptime():
    history = {"run_index": 0, "proxies": {}}
    validator.update_history_and_rank([_mk_result("1.1.1.1:80", 100.0)], history)
    ranked, run = validator.update_history_and_rank([_mk_result("1.1.1.1:80", 100.0)], history)
    assert run == 2
    assert history["proxies"]["1.1.1.1:80"]["working_count"] == 2
    assert ranked[0]["uptime"] == 1.0


def test_update_history_and_rank_prunes_stale():
    history = {
        "run_index": 100,
        "proxies": {"old:1": {"first_run": 1, "last_run": 1, "working_count": 1,
                              "ema_latency_ms": 10.0}},
    }
    validator.update_history_and_rank([], history)
    # old:1 was last seen way more than PRUNE_AFTER_RUNS runs ago
    assert "old:1" not in history["proxies"]


# --------------------------------------------------------------------------- #
# write_outputs / _count / finalize
# --------------------------------------------------------------------------- #

def _ranked_row(proxy, latency, https, proto, cc, anonymity, score):
    return {
        "proxy": proxy,
        "protocol": proto,
        "latency_ms": latency,
        "country": "Country " + cc,
        "country_code": cc,
        "https": https,
        "anonymity": anonymity,
        "uptime": 1.0,
        "score": score,
    }


def test_write_outputs_produces_all_files(tmp_path, monkeypatch):
    monkeypatch.setattr(validator, "RESULTS_DIR", tmp_path / "results")
    ranked = [
        _ranked_row("1.1.1.1:80", 50.0, True, "http", "US", "elite", 90.0),
        _ranked_row("2.2.2.2:1080", 120.0, False, "socks5", "DE", "anonymous", 70.0),
    ]
    summary = validator.write_outputs(ranked, 3, "2020-01-01T00:00:00+00:00", 1.5, 100)

    rd = tmp_path / "results"
    for name in ["working.txt", "best.txt", "ranked.txt", "https_capable.txt",
                 "http.txt", "socks4.txt", "socks5.txt", "ranked.json",
                 "proxies.json", "master.json", "by_country.json", "summary.json"]:
        assert (rd / name).is_file(), name

    # working.txt is fastest-first
    assert (rd / "working.txt").read_text().splitlines()[0] == "http://1.1.1.1:80"
    # only the https proxy in https_capable.txt
    assert (rd / "https_capable.txt").read_text().strip() == "http://1.1.1.1:80"
    # per-protocol splits
    assert (rd / "socks5.txt").read_text().strip() == "socks5://2.2.2.2:1080"

    master = json.loads((rd / "master.json").read_text())
    assert master[0]["rank"] == 1
    assert master[0]["flag"] == validator.flag_emoji("US")

    assert summary["working"] == 2
    assert summary["https_capable"] == 1
    assert summary["by_protocol"]["http"] == 1
    assert summary["countries"] == 2
    assert summary["fastest_ms"] == 50.0


def test_write_outputs_empty(tmp_path, monkeypatch):
    monkeypatch.setattr(validator, "RESULTS_DIR", tmp_path / "results")
    summary = validator.write_outputs([], 1, "2020-01-01T00:00:00+00:00", 0.0, 0)
    assert summary["working"] == 0
    assert summary["fastest_ms"] is None
    assert summary["top_ranked"] is None
    assert (tmp_path / "results" / "working.txt").read_text() == ""


def test_count_helper():
    rows = [{"k": "a"}, {"k": "a"}, {"k": "b"}]
    assert validator._count(rows, "k") == {"a": 2, "b": 1}


def test_finalize_writes_history_and_summary(tmp_path, monkeypatch):
    monkeypatch.setattr(validator, "RESULTS_DIR", tmp_path / "results")
    monkeypatch.setattr(validator, "HISTORY_FILE", tmp_path / "results" / "history.json")
    working = [_mk_result("1.1.1.1:80", 50.0, https=True)]
    summary = validator.finalize(working, "2020-01-01T00:00:00+00:00", 2.0, 1)
    assert summary["working"] == 1
    history = json.loads((tmp_path / "results" / "history.json").read_text())
    assert history["run_index"] == 1
    assert "1.1.1.1:80" in history["proxies"]


# --------------------------------------------------------------------------- #
# CLI parser
# --------------------------------------------------------------------------- #

def test_build_parser_defaults(monkeypatch):
    # ensure env doesn't leak into the defaults under test
    for var in ["CONCURRENCY", "TIMEOUT", "LOOP_SECONDS", "MAX_CANDIDATES", "INCLUDE_BULK"]:
        monkeypatch.delenv(var, raising=False)
    parser = validator.build_parser()
    args = parser.parse_args([])
    assert args.mode is None
    assert args.concurrency == 500
    assert args.timeout == 7
    assert args.include_bulk is False


def test_build_parser_prepare_subcommand():
    args = validator.build_parser().parse_args(["prepare", "--out", "cand.jsonl"])
    assert args.mode == "prepare"
    assert args.out == "cand.jsonl"


def test_build_parser_validate_subcommand():
    args = validator.build_parser().parse_args(
        ["validate", "--candidates", "c.jsonl", "--shard", "0:8", "--out", "p.json"]
    )
    assert args.mode == "validate"
    assert args.shard == "0:8"
    assert args.out == "p.json"


def test_build_parser_merge_subcommand():
    args = validator.build_parser().parse_args(["merge", "--partials", "partials/*.json"])
    assert args.mode == "merge"
    assert args.partials == "partials/*.json"


def test_build_parser_include_bulk_flag():
    args = validator.build_parser().parse_args(["--include-bulk"])
    assert args.include_bulk is True


# --------------------------------------------------------------------------- #
# Async layer (network stubbed)
# --------------------------------------------------------------------------- #

class _FakeResp:
    def __init__(self, status=200, json_data=None, text_data=""):
        self.status = status
        self._json = json_data
        self._text = text_data

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def json(self, content_type=None):
        return self._json

    async def text(self):
        return self._text


class _FakeSession:
    def __init__(self, responses):
        # responses: dict url -> _FakeResp (or callable)
        self._responses = responses

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    def get(self, url, timeout=None):
        r = self._responses.get(url)
        if r is None:
            raise AssertionError(f"unexpected url {url}")
        return r() if callable(r) else r


def test_get_real_ip_success(monkeypatch):
    resp = _FakeResp(json_data={"ip": " 8.8.8.8 "})
    monkeypatch.setattr(
        validator.aiohttp,
        "ClientSession",
        lambda *a, **k: _FakeSession({validator.REAL_IP_URLS[0]: resp}),
    )
    assert asyncio.run(validator.get_real_ip()) == "8.8.8.8"


def test_get_real_ip_all_fail_returns_none(monkeypatch):
    def boom():
        raise RuntimeError("network down")

    monkeypatch.setattr(
        validator.aiohttp,
        "ClientSession",
        lambda *a, **k: _FakeSession({u: boom for u in validator.REAL_IP_URLS}),
    )
    assert asyncio.run(validator.get_real_ip()) is None


def test_fetch_source_success(monkeypatch):
    body = "1.1.1.1:80\n2.2.2.2:81\n# comment\n"
    session = _FakeSession({"http://src": _FakeResp(text_data=body)})
    sem = asyncio.Semaphore(1)
    got = asyncio.run(
        validator.fetch_source(session, {"url": "http://src", "protocol": "http"}, sem)
    )
    assert {addr for _, addr, _ in got} == {"1.1.1.1:80", "2.2.2.2:81"}


def test_fetch_source_non_200_returns_empty(monkeypatch):
    session = _FakeSession({"http://src": _FakeResp(status=503)})
    sem = asyncio.Semaphore(1)
    got = asyncio.run(
        validator.fetch_source(session, {"url": "http://src", "protocol": "http"}, sem)
    )
    assert got == []


def test_fetch_source_exception_returns_empty():
    def boom():
        raise RuntimeError("connection refused")

    session = _FakeSession({"http://src": boom})
    sem = asyncio.Semaphore(1)
    got = asyncio.run(
        validator.fetch_source(session, {"url": "http://src", "protocol": "http"}, sem)
    )
    assert got == []


def test_mode_all_inline_full_path(monkeypatch):
    async def fake_build(**kwargs):
        return {"1.1.1.1:80": {"protocols": {"http"}, "auth": None}}

    async def fake_get_real_ip():
        return "9.9.9.9"

    async def fake_validate(table, concurrency, timeout, real_ip):
        return [{"proxy": "1.1.1.1:80", "latency_ms": 1.0}]

    captured = {}

    def fake_finalize(working, started_at, elapsed, total):
        captured["n"] = len(working)
        captured["total"] = total
        return {"working": len(working)}

    monkeypatch.setattr(validator, "build_candidate_table", fake_build)
    monkeypatch.setattr(validator, "get_real_ip", fake_get_real_ip)
    monkeypatch.setattr(validator, "validate_table", fake_validate)
    monkeypatch.setattr(validator, "load_history", lambda: {"run_index": 0, "proxies": {}})
    monkeypatch.setattr(validator, "finalize", fake_finalize)

    class Args:
        include_bulk = False
        max = 0
        concurrency = 10
        timeout = 7

    asyncio.run(validator.mode_all_inline(Args()))
    assert captured == {"n": 1, "total": 1}


def test_mode_validate_respects_max(tmp_path, monkeypatch):
    cand = tmp_path / "cand.jsonl"
    validator.write_candidates(
        {f"1.1.1.{i}:80": {"protocols": {"http"}, "auth": None} for i in range(10)}, cand
    )

    async def fake_get_real_ip():
        return None

    async def fake_validate(table, concurrency, timeout, real_ip):
        return [{"proxy": a, "latency_ms": 1.0} for a in table]

    monkeypatch.setattr(validator, "get_real_ip", fake_get_real_ip)
    monkeypatch.setattr(validator, "validate_table", fake_validate)

    class Args:
        shard = None
        candidates = str(cand)
        max = 3
        concurrency = 10
        timeout = 7
        out = str(tmp_path / "p.json")

    asyncio.run(validator.mode_validate(Args()))
    data = json.loads(Path(Args.out).read_text())
    assert data["checked"] == 3


def test_check_proxy_success(monkeypatch):
    async def fake_request(proto, addr, auth, url, timeout, want_json=True):
        if url == validator.GEO_JUDGE:
            return 42.0, {"status": "success", "country": "United States",
                          "countryCode": "US", "query": "1.1.1.1"}
        if url == validator.HDR_JUDGE:
            return 10.0, {"headers": {}, "origin": "1.1.1.1"}
        return 10.0, {}

    monkeypatch.setattr(validator, "_request", fake_request)
    info = {"protocols": {"http"}, "auth": None}
    sem = asyncio.Semaphore(1)
    result = asyncio.run(validator.check_proxy("1.1.1.1:80", info, 7, sem, "9.9.9.9"))
    assert result["proxy"] == "1.1.1.1:80"
    assert result["protocol"] == "http"
    assert result["latency_ms"] == 42.0
    assert result["country_code"] == "US"
    assert result["https"] is True
    assert result["anonymity"] == "elite"


def test_check_proxy_geo_rejected_returns_none(monkeypatch):
    async def fake_request(proto, addr, auth, url, timeout, want_json=True):
        return 42.0, {"status": "fail"}

    monkeypatch.setattr(validator, "_request", fake_request)
    info = {"protocols": {"http"}, "auth": None}
    sem = asyncio.Semaphore(1)
    assert asyncio.run(validator.check_proxy("1.1.1.1:80", info, 7, sem, None)) is None


def test_validate_table_collects_working(monkeypatch):
    async def fake_check(addr, info, timeout, sem, real_ip):
        # only the .1 proxy "works"
        if addr.endswith(".1:80"):
            return {"proxy": addr, "latency_ms": 10.0}
        return None

    monkeypatch.setattr(validator, "check_proxy", fake_check)
    table = {f"1.1.1.{i}:80": {"protocols": set(), "auth": None} for i in (1, 2, 3)}
    results = asyncio.run(validator.validate_table(table, 5, 7, None))
    assert [r["proxy"] for r in results] == ["1.1.1.1:80"]


# --------------------------------------------------------------------------- #
# mode_merge (integration of read + finalize)
# --------------------------------------------------------------------------- #

def test_mode_merge_reads_partials_and_writes_results(tmp_path, monkeypatch):
    monkeypatch.setattr(validator, "RESULTS_DIR", tmp_path / "results")
    monkeypatch.setattr(validator, "HISTORY_FILE", tmp_path / "results" / "history.json")

    partials = tmp_path / "partials"
    partials.mkdir()
    (partials / "0.json").write_text(
        json.dumps({"checked": 2, "working": [_mk_result("1.1.1.1:80", 50.0, https=True)]}),
        encoding="utf-8",
    )
    (partials / "1.json").write_text(
        json.dumps({"checked": 3, "working": [_mk_result("2.2.2.2:80", 90.0)]}),
        encoding="utf-8",
    )

    class Args:
        partials = str(tmp_path / "partials" / "*.json")

    validator.mode_merge(Args())

    summary = json.loads((tmp_path / "results" / "summary.json").read_text())
    assert summary["working"] == 2
    assert summary["candidates_checked"] == 5


def test_mode_merge_no_partials_warns(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(validator, "RESULTS_DIR", tmp_path / "results")
    monkeypatch.setattr(validator, "HISTORY_FILE", tmp_path / "results" / "history.json")

    class Args:
        partials = str(tmp_path / "nowhere" / "*.json")

    validator.mode_merge(Args())
    assert "no partial files matched" in capsys.readouterr().err
    assert (tmp_path / "results" / "summary.json").is_file()


def test_read_candidates_skips_blank_lines(tmp_path):
    path = tmp_path / "c.jsonl"
    path.write_text(
        json.dumps({"addr": "1.1.1.1:80", "protocols": ["http"], "auth": None}) + "\n\n\n",
        encoding="utf-8",
    )
    assert set(validator.read_candidates(path)) == {"1.1.1.1:80"}


def test_check_proxy_hdr_and_tls_failures_are_tolerated(monkeypatch):
    async def fake_request(proto, addr, auth, url, timeout, want_json=True):
        if url == validator.GEO_JUDGE:
            return 42.0, {"status": "success", "country": "US", "countryCode": "US",
                          "query": "1.1.1.1"}
        raise RuntimeError("hdr/tls judge unreachable")

    monkeypatch.setattr(validator, "_request", fake_request)
    info = {"protocols": {"http"}, "auth": None}
    sem = asyncio.Semaphore(1)
    result = asyncio.run(validator.check_proxy("1.1.1.1:80", info, 7, sem, None))
    # geo succeeded, but hdr/tls judges failed -> defaults preserved
    assert result is not None
    assert result["https"] is False
    assert result["anonymity"] == "unknown"


def test_check_proxy_falls_back_to_all_protocols(monkeypatch):
    tried = []

    async def fake_request(proto, addr, auth, url, timeout, want_json=True):
        tried.append(proto)
        if proto != "socks5":
            raise RuntimeError("proto not supported")
        if url == validator.GEO_JUDGE:
            return 5.0, {"status": "success", "country": "US", "countryCode": "US",
                         "query": "1.1.1.1"}
        return 5.0, {"headers": {}, "origin": "1.1.1.1"}

    monkeypatch.setattr(validator, "_request", fake_request)
    # empty protocols -> tries all of PROTOCOLS in order
    info = {"protocols": set(), "auth": None}
    sem = asyncio.Semaphore(1)
    result = asyncio.run(validator.check_proxy("1.1.1.1:80", info, 7, sem, None))
    assert result["protocol"] == "socks5"
    assert tried[0] == "http"  # http attempted first and failed


def test_write_outputs_by_country_tracks_fastest(tmp_path, monkeypatch):
    monkeypatch.setattr(validator, "RESULTS_DIR", tmp_path / "results")
    ranked = [
        _ranked_row("1.1.1.1:80", 200.0, False, "http", "US", "elite", 60.0),
        _ranked_row("3.3.3.3:80", 40.0, False, "http", "US", "elite", 80.0),
    ]
    validator.write_outputs(ranked, 1, "2020-01-01T00:00:00+00:00", 1.0, 2)
    by_country = json.loads((tmp_path / "results" / "by_country.json").read_text())
    assert by_country["US"]["count"] == 2
    assert by_country["US"]["fastest_ms"] == 40.0
    assert by_country["US"]["top"] == "http://3.3.3.3:80"


def test_build_candidate_table_dedupes_and_merges(monkeypatch):
    async def fake_fetch(session, src, sem):
        return [("http", "1.1.1.1:80", None), ("socks5", "1.1.1.1:80", "u:p")]

    monkeypatch.setattr(validator, "load_sources_config", lambda include_bulk=False: [{"url": "x"}])
    monkeypatch.setattr(validator, "fetch_source", fake_fetch)
    monkeypatch.setattr(validator, "load_local_files", lambda: [("http", "2.2.2.2:81", None)])

    class _S:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return False

    monkeypatch.setattr(validator.aiohttp, "ClientSession", lambda *a, **k: _S())
    table = asyncio.run(validator.build_candidate_table())
    assert set(table) == {"1.1.1.1:80", "2.2.2.2:81"}
    # protocols merged across duplicate entries; auth captured
    assert table["1.1.1.1:80"]["protocols"] == {"http", "socks5"}
    assert table["1.1.1.1:80"]["auth"] == "u:p"


def test_mode_prepare_writes_candidates(tmp_path, monkeypatch):
    async def fake_build(include_bulk=False, max_n=0, history=None):
        return {"1.1.1.1:80": {"protocols": {"http"}, "auth": None}}

    monkeypatch.setattr(validator, "build_candidate_table", fake_build)
    monkeypatch.setattr(validator, "load_history", lambda: {"run_index": 0, "proxies": {}})

    class Args:
        include_bulk = False
        max = 0
        out = str(tmp_path / "cand.jsonl")

    asyncio.run(validator.mode_prepare(Args()))
    assert set(validator.read_candidates(Path(Args.out))) == {"1.1.1.1:80"}


def test_mode_validate_writes_partial(tmp_path, monkeypatch):
    cand = tmp_path / "cand.jsonl"
    validator.write_candidates(
        {f"1.1.1.{i}:80": {"protocols": {"http"}, "auth": None} for i in range(4)}, cand
    )

    async def fake_get_real_ip():
        return "9.9.9.9"

    async def fake_validate(table, concurrency, timeout, real_ip):
        return [{"proxy": a, "latency_ms": 1.0} for a in table]

    monkeypatch.setattr(validator, "get_real_ip", fake_get_real_ip)
    monkeypatch.setattr(validator, "validate_table", fake_validate)

    class Args:
        shard = "0:2"
        candidates = str(cand)
        max = 0
        concurrency = 10
        timeout = 7
        out = str(tmp_path / "partials" / "0.json")

    asyncio.run(validator.mode_validate(Args()))
    data = json.loads(Path(Args.out).read_text())
    # only one shard's worth of candidates were validated
    assert 0 < data["checked"] < 4
    assert len(data["working"]) == data["checked"]


def test_dispatch_routes_modes(monkeypatch):
    calls = []

    async def fake_prepare(args):
        calls.append("prepare")

    async def fake_validate(args):
        calls.append("validate")

    async def fake_all(args):
        calls.append("all")

    monkeypatch.setattr(validator, "mode_prepare", fake_prepare)
    monkeypatch.setattr(validator, "mode_validate", fake_validate)
    monkeypatch.setattr(validator, "mode_merge", lambda args: calls.append("merge"))
    monkeypatch.setattr(validator, "mode_all_inline", fake_all)

    class Args:
        mode = None

    for mode in ["prepare", "validate", "merge", None]:
        Args.mode = mode
        asyncio.run(validator.dispatch(Args()))
    assert calls == ["prepare", "validate", "merge", "all"]


def test_mode_all_inline_no_candidates_finalizes_empty(tmp_path, monkeypatch):
    async def fake_build(**kwargs):
        return {}

    captured = {}

    def fake_finalize(working, started_at, elapsed, total):
        captured["working"] = working
        captured["total"] = total
        return {"working": 0}

    monkeypatch.setattr(validator, "build_candidate_table", fake_build)
    monkeypatch.setattr(validator, "load_history", lambda: {"run_index": 0, "proxies": {}})
    monkeypatch.setattr(validator, "finalize", fake_finalize)

    class Args:
        include_bulk = False
        max = 0
        concurrency = 10
        timeout = 7

    asyncio.run(validator.mode_all_inline(Args()))
    assert captured["working"] == []
    assert captured["total"] == 0


def test_main_invokes_dispatch(monkeypatch):
    ran = []
    monkeypatch.setattr(sys, "argv", ["validator.py", "merge"])
    monkeypatch.setattr(validator.asyncio, "run", lambda coro: ran.append(coro) or coro.close())
    validator.main()
    assert ran, "asyncio.run should have been called"


def test_main_keyboard_interrupt_is_swallowed(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["validator.py", "merge"])

    def raise_ki(coro):
        coro.close()
        raise KeyboardInterrupt

    monkeypatch.setattr(validator.asyncio, "run", raise_ki)
    validator.main()  # should not propagate
    assert "stopped" in capsys.readouterr().out


def test_main_loop_mode_runs_then_stops(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["validator.py", "--loop", "5", "validate", "--out", "x"])
    calls = {"run": 0}

    def fake_run(coro):
        coro.close()
        calls["run"] += 1

    def fake_sleep(_seconds):
        raise KeyboardInterrupt  # break out of the infinite loop after one cycle

    monkeypatch.setattr(validator.asyncio, "run", fake_run)
    monkeypatch.setattr(validator.time, "sleep", fake_sleep)
    validator.main()
    assert calls["run"] == 1


def test_mode_merge_bad_partial_is_skipped(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(validator, "RESULTS_DIR", tmp_path / "results")
    monkeypatch.setattr(validator, "HISTORY_FILE", tmp_path / "results" / "history.json")
    partials = tmp_path / "partials"
    partials.mkdir()
    (partials / "0.json").write_text("{broken", encoding="utf-8")

    class Args:
        partials = str(tmp_path / "partials" / "*.json")

    validator.mode_merge(Args())
    assert "bad partial" in capsys.readouterr().err
    # still produced a (empty) summary
    assert (tmp_path / "results" / "summary.json").is_file()
