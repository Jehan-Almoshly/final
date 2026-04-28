#!/usr/bin/env python3
"""
sync_nvd_to_supabase.py
=======================
Pulls CVEs from the NVD JSON 2.0 API and upserts them into the
Supabase `cve_catalog` table so the dashboard has real CVE data
without having to run on Kali.

By default it pulls CVEs modified in the last 30 days (small,
~a few thousand rows). For a fuller backfill use --days or
--year.

Usage
-----
    # last 30 days (default)
    python3 scripts/sync_nvd_to_supabase.py

    # last 120 days
    python3 scripts/sync_nvd_to_supabase.py --days 120

    # full year (heavier — ~25-30k CVEs)
    python3 scripts/sync_nvd_to_supabase.py --year 2024

Reads SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY from .env
(repo root) or the environment.

Stdlib only (no pip required).
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.request
import urllib.parse
import urllib.error
from datetime import datetime, timedelta, timezone
from pathlib import Path

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
PAGE_SIZE = 2000  # NVD allows up to 2000 per page
USER_AGENT = "vuln-manager-replit-sync/1.0"
HTTP_TIMEOUT = 60


def load_env() -> None:
    """Load .env from repo root if SUPABASE_* vars are missing."""
    if os.environ.get("SUPABASE_URL") and os.environ.get("SUPABASE_SERVICE_ROLE_KEY"):
        return
    env_path = Path(__file__).resolve().parent.parent / ".env"
    if not env_path.exists():
        return
    for raw in env_path.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        value = value.strip().strip('"').strip("'")
        os.environ.setdefault(key.strip(), value)


def http_get_json(url: str, retries: int = 4) -> dict:
    delay = 2.0
    last_err: Exception | None = None
    for attempt in range(retries):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
            with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:
                return json.loads(resp.read().decode("utf-8", errors="replace"))
        except (urllib.error.URLError, json.JSONDecodeError, TimeoutError) as exc:
            last_err = exc
            print(f"  retry {attempt + 1}/{retries} after error: {exc}", file=sys.stderr)
            time.sleep(delay)
            delay *= 2
    raise RuntimeError(f"NVD request failed: {last_err}")


def fetch_window(params: dict[str, str]) -> list[dict]:
    """Fetch all CVEs that match the given query params, paging through."""
    out: list[dict] = []
    start_index = 0
    while True:
        page = dict(params)
        page["startIndex"] = str(start_index)
        page["resultsPerPage"] = str(PAGE_SIZE)
        url = f"{NVD_API}?{urllib.parse.urlencode(page)}"
        print(f"  GET {url}")
        data = http_get_json(url)
        items = data.get("vulnerabilities", []) or []
        out.extend(items)
        total = int(data.get("totalResults", 0))
        start_index += len(items)
        print(f"  fetched {start_index}/{total}")
        if start_index >= total or not items:
            break
        time.sleep(6)  # NVD asks for ≤5 req/30s
    return out


def parse_cve(item: dict) -> dict | None:
    cve = item.get("cve", {})
    cve_id = cve.get("id")
    if not cve_id:
        return None
    description = ""
    for d in cve.get("descriptions", []):
        if d.get("lang") == "en":
            description = d.get("value", "")
            break
    metrics = cve.get("metrics", {}) or {}
    score: float | None = None
    severity: str | None = None
    vector: str | None = None
    for key in ("cvssMetricV31", "cvssMetricV30"):
        arr = metrics.get(key) or []
        if arr:
            cvss = arr[0].get("cvssData", {}) or {}
            score = cvss.get("baseScore")
            severity = cvss.get("baseSeverity")
            vector = cvss.get("vectorString")
            break
    if score is None:
        arr = metrics.get("cvssMetricV2") or []
        if arr:
            cvss = arr[0].get("cvssData", {}) or {}
            score = cvss.get("baseScore")
            severity = arr[0].get("baseSeverity")
            vector = cvss.get("vectorString")
    published = cve.get("published")
    if isinstance(published, str) and len(published) >= 10:
        published = published[:10]
    return {
        "cve_id": cve_id,
        "description": description[:6000] if description else None,
        "cvss_v3_severity": severity,
        "cvss_v3_score": float(score) if score is not None else None,
        "cvss_v3_vector": vector,
        "published_date": published,
    }


def upsert_batch(supa_url: str, service_key: str, rows: list[dict]) -> int:
    if not rows:
        return 0
    endpoint = f"{supa_url}/rest/v1/cve_catalog?on_conflict=cve_id"
    payload = json.dumps(rows).encode("utf-8")
    req = urllib.request.Request(
        endpoint,
        data=payload,
        method="POST",
        headers={
            "apikey": service_key,
            "Authorization": f"Bearer {service_key}",
            "Content-Type": "application/json",
            "Prefer": "resolution=merge-duplicates,return=minimal",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:
            resp.read()
            return len(rows)
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"Supabase upsert failed [{exc.code}]: {body}") from exc


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--days", type=int, default=30,
                        help="Pull CVEs modified in the last N days (default 30)")
    parser.add_argument("--year", type=int,
                        help="Pull CVEs published in this year (overrides --days)")
    parser.add_argument("--limit", type=int,
                        help="Stop after processing this many CVEs (debug)")
    args = parser.parse_args()

    load_env()
    supa_url = os.environ.get("SUPABASE_URL", "").rstrip("/")
    service_key = os.environ.get("SUPABASE_SERVICE_ROLE_KEY", "")
    if not supa_url or not service_key:
        print("ERROR: SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY must be set", file=sys.stderr)
        return 2

    if args.year:
        # Pull whole year via published date window — chunk by 120 days because NVD limits range to 120
        start = datetime(args.year, 1, 1, tzinfo=timezone.utc)
        end = datetime(args.year, 12, 31, 23, 59, 59, tzinfo=timezone.utc)
        windows = []
        cur = start
        while cur < end:
            nxt = min(cur + timedelta(days=119), end)
            windows.append((cur, nxt))
            cur = nxt + timedelta(seconds=1)
        params_template = "pubStartDate"
        params_template_end = "pubEndDate"
    else:
        end = datetime.now(timezone.utc)
        start = end - timedelta(days=args.days)
        # NVD limits date range to 120 days per request
        windows = []
        cur = start
        while cur < end:
            nxt = min(cur + timedelta(days=119), end)
            windows.append((cur, nxt))
            cur = nxt + timedelta(seconds=1)
        params_template = "lastModStartDate"
        params_template_end = "lastModEndDate"

    total_inserted = 0
    seen = 0
    for w_start, w_end in windows:
        print(f"Window: {w_start.isoformat()} → {w_end.isoformat()}")
        params = {
            params_template:     w_start.strftime("%Y-%m-%dT%H:%M:%S.000"),
            params_template_end: w_end.strftime("%Y-%m-%dT%H:%M:%S.000"),
        }
        items = fetch_window(params)
        rows: list[dict] = []
        for it in items:
            parsed = parse_cve(it)
            if parsed:
                rows.append(parsed)
                seen += 1
                if args.limit and seen >= args.limit:
                    break
        # Upsert in chunks
        for i in range(0, len(rows), 500):
            chunk = rows[i:i + 500]
            n = upsert_batch(supa_url, service_key, chunk)
            total_inserted += n
            print(f"  upserted {total_inserted} so far")
        if args.limit and seen >= args.limit:
            break
        time.sleep(2)

    print(f"DONE: {total_inserted} CVEs upserted into cve_catalog.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
