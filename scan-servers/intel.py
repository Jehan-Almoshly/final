"""
intel.py
========

End-to-end "scan intelligence" pipeline:

    raw scan output  --extract-->  fingerprints
                     --match-----> CVEs + exploits (local NVD + Exploit-DB)
                     --push------> Supabase (4 real tables)

This module is the only thing gateway.py needs to import to enable
import-on-demand. It hides the matcher/pusher details behind a single
async function: `process_scan_intelligence(...)`.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import fingerprints
from matcher import Matcher, MatchResult
from supabase_push import SupabasePusher, build_payload, severity_counts

# Locations of the local SQLite indexes (built on Kali).
NVD_DB = Path(os.getenv(
    "NVD_DB_PATH",
    str(Path.home() / "vuln-data" / "nvd" / "nvd_index.sqlite"),
))
EXPLOITDB_DB = Path(os.getenv(
    "EXPLOITDB_DB_PATH",
    str(Path.home() / "vuln-data" / "exploitdb" / "exploitdb_index.sqlite"),
))


def indexes_available() -> tuple[bool, str]:
    """Quick sanity check used by gateway /health and intel endpoints."""
    if not NVD_DB.exists():
        return False, f"NVD index missing at {NVD_DB}"
    if not EXPLOITDB_DB.exists():
        return False, f"Exploit-DB index missing at {EXPLOITDB_DB}"
    return True, "ok"


async def process_scan_intelligence(
    *,
    scan_id: str,
    tool: str,
    target: str,
    raw_output: str,
    supabase_url: str,
    supabase_service_key: str,
) -> dict[str, Any]:
    """Run the full extract -> match -> push pipeline for one finished scan.

    Returns a summary dict suitable for logging or returning from an
    HTTP handler. The summary always includes severity counts so the
    caller can update scan_results.{critical,high,medium,low}_count
    in a single follow-up PATCH.
    """
    summary: dict[str, Any] = {
        "scan_id": scan_id,
        "tool": tool,
        "fingerprints": 0,
        "matched_fingerprints": 0,
        "cves": 0,
        "exploits": 0,
        "pushed": None,
        "severity_counts": {
            "critical_count": 0, "high_count": 0,
            "medium_count": 0, "low_count": 0,
            "total_findings": 0,
        },
        "skipped": None,
        "errors": [],
    }

    ok, why = indexes_available()
    if not ok:
        summary["skipped"] = why
        return summary

    # 1. Extract fingerprints
    fps = fingerprints.extract(tool, raw_output)
    summary["fingerprints"] = len(fps)
    if not fps:
        summary["skipped"] = "no fingerprints extracted from scan output"
        return summary

    # 2. Match against local NVD + Exploit-DB
    try:
        with Matcher(NVD_DB, EXPLOITDB_DB) as m:
            results: list[MatchResult] = m.match(fps)
    except Exception as e:
        summary["errors"].append(f"matcher: {type(e).__name__}: {e}")
        return summary

    matched = [r for r in results if r.cves]
    summary["matched_fingerprints"] = len(matched)
    summary["cves"]     = sum(r.total_cves     for r in matched)
    summary["exploits"] = sum(r.total_exploits for r in matched)
    if not matched:
        summary["skipped"] = "fingerprints matched no CVEs"
        return summary

    # 3. Build & push payload
    payload = build_payload(scan_id, tool, target, results)
    summary["severity_counts"] = severity_counts(payload)

    pusher = SupabasePusher(supabase_url, supabase_service_key)
    try:
        push_summary = await pusher.push(payload)
        summary["pushed"] = push_summary
        if push_summary.get("errors"):
            summary["errors"].extend(push_summary["errors"])
    except Exception as e:
        summary["errors"].append(f"push: {type(e).__name__}: {e}")

    return summary
