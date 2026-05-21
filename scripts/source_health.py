#!/usr/bin/env python3
"""Health-check aggregator sources and optionally disable repeatedly failing ones.

This script intentionally does not discover/merge new public sources. It only
scores known sources, persists consecutive failure counters, and disables a
source after it fails repeatedly.
"""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import json
import os
import re
import ssl
import sys
import traceback
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any

CTX = ssl._create_unverified_context()
USER_AGENT = "AggregatorHealth/1.0 (+https://github.com/Bei0jnthmmq2yh4Quinn/aggregator)"
PROTOCOL_RE = re.compile(r"(?i)(?:^|[^a-z0-9])((?:vmess|vless|trojan|ssr|ss|hysteria2?|tuic)://[^\s<>'\"`]+)")
BASE64_RE = re.compile(r"^[A-Za-z0-9+/=_-]+$")
NOW = dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


@dataclass
class Source:
    sid: str
    kind: str
    name: str
    url: str
    enabled: bool
    item: dict[str, Any]


@dataclass
class CheckResult:
    source: Source
    ok: bool
    status: str
    count: int = 0
    bytes_read: int = 0
    error: str = ""


def trim(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


def read_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def write_json(path: Path, data: Any, *, sort_keys: bool = True) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2, sort_keys=sort_keys)
        f.write("\n")


def stable_id(kind: str, name: str, url: str) -> str:
    return f"{kind}:{name or url}"


def discover_sources(config: dict[str, Any]) -> list[Source]:
    sources: list[Source] = []

    for item in config.get("domains", []) or []:
        if not isinstance(item, dict):
            continue
        url = trim(item.get("sub"))
        if not url.startswith(("http://", "https://")):
            continue
        name = trim(item.get("name")) or url
        enabled = bool(item.get("enable", True))
        sources.append(Source(stable_id("domain", name, url), "domain", name, url, enabled, item))

    crawl = config.get("crawl", {}) if isinstance(config.get("crawl", {}), dict) else {}
    for item in crawl.get("pages", []) or []:
        if not isinstance(item, dict):
            continue
        raw_url = item.get("url")
        urls = raw_url if isinstance(raw_url, list) else [raw_url]
        enabled = bool(item.get("enable", True))
        for idx, url in enumerate(urls):
            url = trim(url)
            if not url.startswith(("http://", "https://")):
                continue
            name = trim(item.get("name")) or url
            # If a single config item contains multiple URLs, disabling the item
            # disables all of them. Current config uses one URL per item.
            sid_name = name if len(urls) == 1 else f"{name}#{idx + 1}"
            sources.append(Source(stable_id("page", sid_name, url), "page", sid_name, url, enabled, item))

    return sources


def fetch(url: str, timeout: int, max_bytes: int) -> tuple[int, bytes]:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=timeout, context=CTX) as resp:
        return resp.getcode(), resp.read(max_bytes)


def maybe_decode_base64(text: str) -> str:
    compact = "".join(text.strip().split())
    if len(compact) < 64 or not BASE64_RE.match(compact):
        return ""

    try:
        padded = compact + "=" * ((4 - len(compact) % 4) % 4)
        decoded = base64.b64decode(padded, validate=False).decode("utf-8", errors="ignore")
    except Exception:
        return ""

    if len(decoded) < 20:
        return ""
    return decoded


def count_protocol_links(text: str) -> int:
    seen: set[str] = set()
    for match in PROTOCOL_RE.finditer(text):
        seen.add(match.group(1).strip())

    # Clash YAML sources may not contain raw protocol URLs. Count proxy entries
    # as a fallback so direct Clash feeds are not marked unhealthy.
    clash_count = 0
    if "proxies:" in text and ("name:" in text or "server:" in text):
        clash_count = len(re.findall(r"(?m)^\s*-\s*(?:name\s*:|\{[^}\n]*\bname\s*:)", text))

    return max(len(seen), clash_count)


def evaluate(source: Source, timeout: int, max_bytes: int, min_links: int) -> CheckResult:
    if not source.enabled:
        return CheckResult(source=source, ok=True, status="skipped", error="disabled")

    try:
        status_code, data = fetch(source.url, timeout=timeout, max_bytes=max_bytes)
        text = data.decode("utf-8", errors="ignore")
        decoded = maybe_decode_base64(text)
        count = count_protocol_links(text)
        if decoded:
            count = max(count, count_protocol_links(decoded))

        if status_code != 200:
            return CheckResult(source, False, "fail", count, len(data), f"http_{status_code}")
        if count < min_links:
            return CheckResult(source, False, "fail", count, len(data), f"links_below_min:{count}<{min_links}")
        return CheckResult(source, True, "ok", count, len(data), "")
    except urllib.error.HTTPError as e:
        return CheckResult(source, False, "fail", 0, 0, f"http_{e.code}")
    except Exception as e:
        return CheckResult(source, False, "fail", 0, 0, f"{type(e).__name__}:{str(e)[:120]}")


def update_state_and_config(
    *,
    config: dict[str, Any],
    state: dict[str, Any],
    results: list[CheckResult],
    disable_threshold: int,
    write_changes: bool,
) -> tuple[int, list[str]]:
    state.setdefault("version", 1)
    sources_state = state.setdefault("sources", {})
    disabled_now = 0
    disabled_names: list[str] = []

    for result in results:
        source = result.source
        entry = sources_state.setdefault(source.sid, {})

        if result.status == "skipped":
            entry.setdefault("consecutive_failures", 0)
            continue

        if result.ok:
            if entry.get("consecutive_failures", 0) != 0 or entry.get("last_error"):
                entry["consecutive_failures"] = 0
                entry.pop("last_error", None)
            entry["disabled"] = False
            continue

        failures = int(entry.get("consecutive_failures", 0)) + 1
        entry["consecutive_failures"] = failures
        entry["last_error"] = result.error
        entry["last_failed_at"] = NOW

        if failures >= disable_threshold and source.enabled:
            disabled_now += 1
            disabled_names.append(source.name)
            entry["disabled"] = True
            entry["disabled_at"] = NOW
            entry["disabled_reason"] = result.error
            if write_changes:
                source.item["enable"] = False
                source.item["disabled_at"] = NOW
                source.item["disabled_reason"] = f"source_health: {result.error}"
                source.item["health_failures"] = failures

    return disabled_now, disabled_names


def render_summary(
    *,
    results: list[CheckResult],
    disabled_now: int,
    disabled_names: list[str],
    total_links: int,
    min_total_links: int,
    min_enabled_sources: int,
    unhealthy: bool,
) -> str:
    ok = [r for r in results if r.status == "ok"]
    failed = [r for r in results if r.status == "fail"]
    skipped = [r for r in results if r.status == "skipped"]

    lines = [
        "# Aggregator Source Health",
        "",
        f"- checked_at: `{NOW}`",
        f"- status: `{'unhealthy' if unhealthy else 'healthy'}`",
        f"- enabled_ok_sources: `{len(ok)}`",
        f"- failed_sources: `{len(failed)}`",
        f"- skipped_disabled_sources: `{len(skipped)}`",
        f"- total_detected_links: `{total_links}`",
        f"- min_total_links: `{min_total_links}`",
        f"- min_enabled_sources: `{min_enabled_sources}`",
        f"- disabled_this_run: `{disabled_now}`",
        "",
    ]

    if disabled_names:
        lines.append("## Disabled this run")
        for name in disabled_names:
            lines.append(f"- `{name}`")
        lines.append("")

    lines.append("## Source results")
    lines.append("")
    lines.append("| status | kind | name | links | bytes | error |")
    lines.append("| --- | --- | --- | ---: | ---: | --- |")
    for result in sorted(results, key=lambda r: (r.status != "fail", r.source.kind, r.source.name)):
        error = result.error.replace("|", "/") if result.error else ""
        name = result.source.name.replace("|", "/")[:120]
        lines.append(
            f"| {result.status} | {result.source.kind} | `{name}` | {result.count} | {result.bytes_read} | {error} |"
        )

    return "\n".join(lines) + "\n"


def write_github_output(path: str, values: dict[str, Any]) -> None:
    if not path:
        return
    with open(path, "a", encoding="utf-8") as f:
        for key, value in values.items():
            text = str(value).replace("\n", " ")
            f.write(f"{key}={text}\n")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Check aggregator source health")
    parser.add_argument("--config", default="subscribe/config/config.json")
    parser.add_argument("--state", default="source_health.json")
    parser.add_argument("--summary", default="source_health_report.md")
    parser.add_argument("--github-output", default=os.environ.get("GITHUB_OUTPUT", ""))
    parser.add_argument("--timeout", type=int, default=20)
    parser.add_argument("--max-bytes", type=int, default=4 * 1024 * 1024)
    parser.add_argument("--min-links", type=int, default=1)
    parser.add_argument("--min-total-links", type=int, default=50)
    parser.add_argument("--min-enabled-sources", type=int, default=3)
    parser.add_argument("--disable-threshold", type=int, default=3)
    parser.add_argument("--write", action="store_true", help="persist state and disable failing sources in config")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    config_path = Path(args.config)
    state_path = Path(args.state)
    summary_path = Path(args.summary)

    try:
        config = read_json(config_path, {})
        state = read_json(state_path, {"version": 1, "sources": {}})
        sources = discover_sources(config)
        results = [evaluate(s, args.timeout, args.max_bytes, args.min_links) for s in sources]
        disabled_now, disabled_names = update_state_and_config(
            config=config,
            state=state,
            results=results,
            disable_threshold=max(1, args.disable_threshold),
            write_changes=args.write,
        )

        ok_enabled = [r for r in results if r.status == "ok"]
        total_links = sum(r.count for r in ok_enabled)
        unhealthy = (
            total_links < args.min_total_links
            or len(ok_enabled) < args.min_enabled_sources
            or disabled_now > 0
        )

        summary = render_summary(
            results=results,
            disabled_now=disabled_now,
            disabled_names=disabled_names,
            total_links=total_links,
            min_total_links=args.min_total_links,
            min_enabled_sources=args.min_enabled_sources,
            unhealthy=unhealthy,
        )
        summary_path.write_text(summary, encoding="utf-8")

        if args.write:
            write_json(state_path, state, sort_keys=True)
            # Only touch the main config when a source is actually disabled.
            # This avoids noisy config rewrites on every scheduled health run.
            if disabled_now > 0:
                write_json(config_path, config, sort_keys=False)

        write_github_output(
            args.github_output,
            {
                "unhealthy": str(unhealthy).lower(),
                "total_links": total_links,
                "ok_sources": len(ok_enabled),
                "failed_sources": len([r for r in results if r.status == "fail"]),
                "disabled_count": disabled_now,
            },
        )

        print(summary)
        return 0
    except Exception as e:
        error = f"source_health fatal: {type(e).__name__}: {e}"
        traceback.print_exc()
        write_github_output(args.github_output, {"unhealthy": "true", "fatal": error})
        summary_path.write_text(f"# Aggregator Source Health\n\n`{error}`\n", encoding="utf-8")
        return 2


if __name__ == "__main__":
    sys.exit(main())
