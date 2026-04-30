"""
supabase_push.py
================

Push the matcher payload into Supabase across the four real tables
created by `supabase/migrations/20260424000000_real_vuln_schema.sql`:

    scan_findings   (one row per matched fingerprint)
    cve_catalog     (deduped CVE rows, upserted on cve_id)
    exploits        (deduped exploit rows, upserted on exploit_db_id)
    finding_cves    (link rows, deduped on (finding_id, cve_id))

The matcher emits its own field names; this module is responsible for
mapping them to the actual Supabase column names.
"""

from __future__ import annotations

import httpx
from typing import Any

from matcher import MatchResult


SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW")


# ---------------------------------------------------------------
# Payload builder (Supabase column names)
# ---------------------------------------------------------------

def build_payload(
    scan_id: str,
    tool: str,
    target: str,
    results: list[MatchResult],
) -> dict[str, list[dict[str, Any]]]:
    """Convert MatchResult list into the row arrays for the 4 tables.

    A "client_id" string is attached to each finding so the pusher can
    match the inserted row's UUID back to the correct CVE links.
    """
    findings: list[dict] = []
    cve_map: dict[str, dict] = {}
    exploit_map: dict[int, dict] = {}
    links: list[dict] = []

    for r in results:
        if not r.cves:
            continue
        fp = r.fingerprint
        client_id = f"{fp.vendor}:{fp.product}:{fp.version or '*'}"
        title = f"{fp.product} {fp.version or '*'} ({fp.vendor})"
        service = f"{fp.vendor}/{fp.product}@{fp.version or '*'}"

        findings.append({
            "client_id": client_id,            # internal — stripped before insert
            "scan_id": scan_id,
            "tool": (tool or "OTHER").upper(),
            "target": target,
            "title": title[:200],
            "service": service[:200],
            "evidence": (fp.evidence or "")[:1000] or None,
            "metadata": {
                "vendor": fp.vendor,
                "product": fp.product,
                "version": fp.version,
                "source": fp.source,
                "cve_count": r.total_cves,
                "exploit_count": r.total_exploits,
            },
        })

        for c in r.cves:
            if c.cve_id not in cve_map:
                cve_map[c.cve_id] = {
                    "cve_id": c.cve_id,
                    "description": (c.description or "")[:500] or None,
                    "cvss_v3_score": c.cvss_score,
                    "cvss_v3_severity": (c.cvss_severity or "").upper() or None,
                    "cvss_v3_vector": c.cvss_vector,
                    "published_date": (c.published_date or "")[:10] or None,
                    "references_urls": c.references[:5],
                    "affected_products": [],
                }
            links.append({
                "client_id": client_id,        # internal — translated to UUID later
                "cve_id": c.cve_id,
                "match_confidence": "version" if fp.version else "fingerprint",
                "match_evidence": (fp.evidence or "")[:300] or None,
            })
            for ex in c.exploits:
                if ex.edb_id in exploit_map:
                    continue
                exploit_map[ex.edb_id] = {
                    "exploit_db_id": ex.edb_id,
                    "cve_id": c.cve_id,
                    "title": (ex.description or f"EDB-{ex.edb_id}")[:200],
                    "type": ex.type,
                    "platform": ex.platform,
                    "date_published": (ex.date_published or "")[:10] or None,
                    "verified": bool(ex.verified) if ex.verified is not None else False,
                    "exploit_url": ex.source_url
                                   or f"https://www.exploit-db.com/exploits/{ex.edb_id}",
                    "raw_path": None,
                }

    # Cap CVSS severity to allowed values
    for c in cve_map.values():
        if c["cvss_v3_severity"] not in (*SEVERITIES, "NONE"):
            c["cvss_v3_severity"] = None

    return {
        "scan_findings": findings,
        "cve_catalog":   list(cve_map.values()),
        "exploits":      list(exploit_map.values()),
        "finding_cves":  links,
    }


# ---------------------------------------------------------------
# Severity rollup for scan_results.{critical,high,medium,low}_count
# ---------------------------------------------------------------

def severity_counts(payload: dict) -> dict[str, int]:
    counts = {f"{s.lower()}_count": 0 for s in SEVERITIES}
    counts["total_findings"] = len(payload.get("scan_findings", []))

    # Per-finding severity = max severity across its linked CVEs
    cve_sev = {c["cve_id"]: (c.get("cvss_v3_severity") or "").upper()
               for c in payload.get("cve_catalog", [])}
    sev_order = {s: i for i, s in enumerate(SEVERITIES)}  # 0 = highest

    by_finding: dict[str, str] = {}
    for link in payload.get("finding_cves", []):
        sev = cve_sev.get(link["cve_id"], "")
        if sev not in sev_order:
            continue
        cur = by_finding.get(link["client_id"])
        if cur is None or sev_order[sev] < sev_order[cur]:
            by_finding[link["client_id"]] = sev

    for sev in by_finding.values():
        key = f"{sev.lower()}_count"
        if key in counts:
            counts[key] += 1
    return counts


# ---------------------------------------------------------------
# Pusher
# ---------------------------------------------------------------

class SupabasePusher:
    """Async HTTP client wrapper for the 4 vulnerability tables."""

    def __init__(self, supabase_url: str, service_key: str) -> None:
        self.url = supabase_url.rstrip("/")
        self.headers = {
            "apikey": service_key,
            "Authorization": f"Bearer {service_key}",
            "Content-Type": "application/json",
        }

    async def push(self, payload: dict) -> dict:
        """Insert/upsert the entire payload. Order matters because of FKs:
        cve_catalog -> exploits -> scan_findings -> finding_cves.
        Returns a summary dict with row counts.
        """
        result = {
            "cve_catalog_upserted": 0,
            "exploits_upserted": 0,
            "scan_findings_inserted": 0,
            "finding_cves_inserted": 0,
            "errors": [],
        }

        async with httpx.AsyncClient(timeout=60) as client:
            # 1) cve_catalog (upsert by cve_id)
            ok, n, err = await self._upsert(
                client, "cve_catalog", payload["cve_catalog"], "cve_id",
            )
            result["cve_catalog_upserted"] = n
            if err:
                result["errors"].append(err)

            # 2) exploits (upsert by exploit_db_id; needs cve_id FK to exist)
            ok, n, err = await self._upsert(
                client, "exploits", payload["exploits"], "exploit_db_id",
            )
            result["exploits_upserted"] = n
            if err:
                result["errors"].append(err)

            # 3) scan_findings (insert; we need server-generated UUIDs back)
            findings_to_insert = [
                {k: v for k, v in row.items() if k != "client_id"}
                for row in payload["scan_findings"]
            ]
            inserted = await self._insert_returning(
                client, "scan_findings", findings_to_insert,
            )
            result["scan_findings_inserted"] = len(inserted)

            # Build client_id -> UUID map by zipping insert order
            client_ids = [r["client_id"] for r in payload["scan_findings"]]
            id_map = {cid: row["id"] for cid, row in zip(client_ids, inserted)
                      if "id" in row}

            # 4) finding_cves (insert links with the new UUIDs)
            link_rows = []
            for link in payload["finding_cves"]:
                fid = id_map.get(link["client_id"])
                if not fid:
                    continue
                link_rows.append({
                    "finding_id": fid,
                    "cve_id": link["cve_id"],
                    "match_confidence": link["match_confidence"],
                    "match_evidence": link["match_evidence"],
                })

            ok, n, err = await self._upsert(
                client, "finding_cves", link_rows, "finding_id,cve_id",
            )
            result["finding_cves_inserted"] = n
            if err:
                result["errors"].append(err)

        return result

    # ---- internals -------------------------------------------------

    async def _upsert(
        self, client: httpx.AsyncClient, table: str,
        rows: list[dict], on_conflict: str,
    ) -> tuple[bool, int, str | None]:
        if not rows:
            return True, 0, None
        try:
            r = await client.post(
                f"{self.url}/rest/v1/{table}",
                params={"on_conflict": on_conflict},
                headers={**self.headers,
                         "Prefer": "resolution=merge-duplicates,return=minimal"},
                json=rows,
            )
            if r.status_code in (200, 201, 204):
                return True, len(rows), None
            return False, 0, f"{table} upsert {r.status_code}: {r.text[:300]}"
        except Exception as e:
            return False, 0, f"{table} upsert exception: {type(e).__name__}: {e}"

    async def _insert_returning(
        self, client: httpx.AsyncClient, table: str, rows: list[dict],
    ) -> list[dict]:
        if not rows:
            return []
        try:
            r = await client.post(
                f"{self.url}/rest/v1/{table}",
                headers={**self.headers, "Prefer": "return=representation"},
                json=rows,
            )
            if r.status_code in (200, 201):
                return r.json()
            print(f"[push] {table} insert {r.status_code}: {r.text[:300]}",
                  flush=True)
            return []
        except Exception as e:
            print(f"[push] {table} insert exception: {type(e).__name__}: {e}",
                  flush=True)
            return []
