"""
matcher.py
==========

Local intelligence matching engine.

Given fingerprints (vendor:product:version) extracted from web scans
(nikto, sqlmap, nmap, ffuf), this engine queries the local SQLite
indexes built by:

    scripts/download_nvd.py          -> ~/vuln-data/nvd/nvd_index.sqlite
    scripts/index_exploitdb.py       -> ~/vuln-data/exploitdb/exploitdb_index.sqlite

and produces a structured MatchResult ready to be pushed to Supabase
(scan_findings + cve_catalog + exploits + finding_cves tables).

The module is *purely offline* — no network calls. Stdlib + sqlite3 only.

Quick CLI demo (run on Kali after both indexes exist):

    python3 scan-servers/matcher.py --demo
    python3 scan-servers/matcher.py --vendor apache --product http_server --version 2.4.49
    python3 scan-servers/matcher.py --json '[{"vendor":"openssl","product":"openssl","version":"1.0.1f"}]'
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sqlite3
import sys
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Iterable, Sequence

DEFAULT_NVD_DB = Path.home() / "vuln-data" / "nvd" / "nvd_index.sqlite"
DEFAULT_EXPLOITDB_DB = Path.home() / "vuln-data" / "exploitdb" / "exploitdb_index.sqlite"


# -------------------------------------------------------------------
# Data classes
# -------------------------------------------------------------------

@dataclass
class Fingerprint:
    """A single product:version observation from a scan tool."""
    vendor: str
    product: str
    version: str | None = None
    source: str | None = None      # e.g. "nmap", "nikto", "sqlmap"
    evidence: str | None = None    # raw text the fingerprint was derived from

    def normalised(self) -> "Fingerprint":
        return Fingerprint(
            vendor=(self.vendor or "").strip().lower(),
            product=(self.product or "").strip().lower(),
            version=(self.version or "").strip() or None,
            source=self.source,
            evidence=self.evidence,
        )


@dataclass
class ExploitHit:
    edb_id: int
    description: str | None
    type: str | None
    platform: str | None
    date_published: str | None
    source_url: str | None
    verified: int | None


@dataclass
class CVEHit:
    cve_id: str
    description: str | None
    cvss_score: float | None
    cvss_severity: str | None
    cvss_vector: str | None
    cvss_version: str | None
    published_date: str | None
    last_modified: str | None
    references: list[str] = field(default_factory=list)
    exploits: list[ExploitHit] = field(default_factory=list)


@dataclass
class MatchResult:
    fingerprint: Fingerprint
    cves: list[CVEHit] = field(default_factory=list)

    @property
    def total_cves(self) -> int:
        return len(self.cves)

    @property
    def total_exploits(self) -> int:
        return sum(len(c.exploits) for c in self.cves)


# -------------------------------------------------------------------
# Loose version comparison
# -------------------------------------------------------------------
# CPE versions ("2.4.49", "1.1.1g", "5.7.1-rc1") are not strict semver,
# so we use a loose tuple parser that compares numeric segments
# numerically and string segments lexicographically.

_VSEP = re.compile(r"[._\-+~]")
_NUM_PREFIX = re.compile(r"^(\d+)(.*)$")


def _vparse(v: str | None) -> tuple:
    if not v:
        return ()
    out: list[tuple] = []
    for part in _VSEP.split(v.strip()):
        m = _NUM_PREFIX.match(part)
        if m:
            out.append((0, int(m.group(1)), m.group(2) or ""))
        else:
            out.append((1, 0, part))
    return tuple(out)


def _vle(a: str, b: str) -> bool: return _vparse(a) <= _vparse(b)
def _vlt(a: str, b: str) -> bool: return _vparse(a) <  _vparse(b)
def _vge(a: str, b: str) -> bool: return _vparse(a) >= _vparse(b)
def _vgt(a: str, b: str) -> bool: return _vparse(a) >  _vparse(b)


def _version_matches(scan_version: str | None, cpe_row: sqlite3.Row) -> bool:
    """Return True if scan_version satisfies the CPE row's version constraint."""
    exact = cpe_row["version"]
    si    = cpe_row["version_start_inc"]
    se    = cpe_row["version_start_exc"]
    ei    = cpe_row["version_end_inc"]
    ee    = cpe_row["version_end_exc"]

    has_range = bool(si or se or ei or ee)

    # CPE row has no version info at all -> applies to every version
    if not exact and not has_range:
        return True

    # No scan version reported but CPE is version-specific -> conservative match
    if not scan_version:
        return True

    # Exact pinned version
    if exact and not has_range:
        return _vparse(scan_version) == _vparse(exact)

    # Range constraint (the common case for "all versions before X")
    if si and _vlt(scan_version, si): return False
    if se and not _vgt(scan_version, se): return False
    if ei and _vgt(scan_version, ei): return False
    if ee and not _vlt(scan_version, ee): return False
    return True


# -------------------------------------------------------------------
# Matcher
# -------------------------------------------------------------------

class Matcher:
    """Offline lookup engine over local NVD + Exploit-DB SQLite indexes."""

    def __init__(
        self,
        nvd_db: Path | str = DEFAULT_NVD_DB,
        exploitdb_db: Path | str = DEFAULT_EXPLOITDB_DB,
    ) -> None:
        nvd_db = Path(nvd_db)
        exploitdb_db = Path(exploitdb_db)
        if not nvd_db.exists():
            raise FileNotFoundError(
                f"NVD index not found at {nvd_db}\n"
                f"hint: run `python3 scripts/download_nvd.py` first"
            )
        if not exploitdb_db.exists():
            raise FileNotFoundError(
                f"Exploit-DB index not found at {exploitdb_db}\n"
                f"hint: run `python3 scripts/index_exploitdb.py` first"
            )

        # Open read-only so the matcher can run alongside future updates.
        self._nvd = sqlite3.connect(f"file:{nvd_db}?mode=ro", uri=True)
        self._nvd.row_factory = sqlite3.Row
        self._exp = sqlite3.connect(f"file:{exploitdb_db}?mode=ro", uri=True)
        self._exp.row_factory = sqlite3.Row

    def close(self) -> None:
        self._nvd.close()
        self._exp.close()

    def __enter__(self) -> "Matcher":
        return self

    def __exit__(self, *_exc) -> None:
        self.close()

    # ---- public API --------------------------------------------------

    def match(self, fingerprints: Sequence[Fingerprint]) -> list[MatchResult]:
        return [self.match_one(fp) for fp in fingerprints]

    def match_one(self, fp: Fingerprint) -> MatchResult:
        fp = fp.normalised()
        result = MatchResult(fingerprint=fp)
        if not fp.vendor or not fp.product:
            return result

        cve_ids = self._candidate_cve_ids(fp)
        if not cve_ids:
            return result

        result.cves = self._load_cves(cve_ids)
        if result.cves:
            self._attach_exploits(result.cves)
        # Sort: critical/high first, then by score desc
        result.cves.sort(
            key=lambda c: (-(c.cvss_score or 0.0), c.cve_id),
        )
        return result

    # ---- internal ---------------------------------------------------

    def _candidate_cve_ids(self, fp: Fingerprint) -> list[str]:
        """Find CVEs whose CPE rows match (vendor, product) AND version range."""
        cur = self._nvd.execute(
            "SELECT cve_id, version, version_start_inc, version_start_exc, "
            "       version_end_inc, version_end_exc "
            "FROM cve_cpes WHERE vendor=? AND product=?",
            (fp.vendor, fp.product),
        )
        matching: set[str] = set()
        for row in cur:
            if _version_matches(fp.version, row):
                matching.add(row["cve_id"])
        return sorted(matching)

    def _load_cves(self, cve_ids: list[str]) -> list[CVEHit]:
        if not cve_ids:
            return []
        # SQLite has a 999-parameter default cap; chunk to be safe.
        out: list[CVEHit] = []
        CHUNK = 500
        for i in range(0, len(cve_ids), CHUNK):
            batch = cve_ids[i : i + CHUNK]
            placeholders = ",".join("?" * len(batch))
            rows = self._nvd.execute(
                f"SELECT cve_id, description, cvss_score, cvss_severity, "
                f"       cvss_vector, cvss_version, published_date, "
                f"       last_modified, references_json "
                f"FROM cves WHERE cve_id IN ({placeholders})",
                batch,
            ).fetchall()
            for r in rows:
                try:
                    refs = json.loads(r["references_json"] or "[]")
                except (json.JSONDecodeError, TypeError):
                    refs = []
                out.append(CVEHit(
                    cve_id=r["cve_id"],
                    description=r["description"],
                    cvss_score=r["cvss_score"],
                    cvss_severity=r["cvss_severity"],
                    cvss_vector=r["cvss_vector"],
                    cvss_version=r["cvss_version"],
                    published_date=r["published_date"],
                    last_modified=r["last_modified"],
                    references=refs,
                ))
        return out

    def _attach_exploits(self, cves: list[CVEHit]) -> None:
        cve_ids = [c.cve_id for c in cves]
        if not cve_ids:
            return
        by_cve: dict[str, list[ExploitHit]] = {cid: [] for cid in cve_ids}
        CHUNK = 500
        for i in range(0, len(cve_ids), CHUNK):
            batch = cve_ids[i : i + CHUNK]
            placeholders = ",".join("?" * len(batch))
            rows = self._exp.execute(
                f"SELECT x.cve_id, e.edb_id, e.description, e.type, "
                f"       e.platform, e.date_published, e.source_url, e.verified "
                f"FROM exploit_cves x "
                f"JOIN exploits e ON e.edb_id = x.edb_id "
                f"WHERE x.cve_id IN ({placeholders}) "
                f"ORDER BY e.date_published DESC",
                batch,
            ).fetchall()
            for r in rows:
                by_cve.setdefault(r["cve_id"], []).append(ExploitHit(
                    edb_id=r["edb_id"],
                    description=r["description"],
                    type=r["type"],
                    platform=r["platform"],
                    date_published=r["date_published"],
                    source_url=r["source_url"],
                    verified=r["verified"],
                ))
        for c in cves:
            c.exploits = by_cve.get(c.cve_id, [])


# -------------------------------------------------------------------
# Supabase payload helper
# -------------------------------------------------------------------

def to_supabase_payload(results: list[MatchResult], scan_id: str) -> dict:
    """Flatten matcher output into rows ready for the 4 Supabase tables.

    Returned shape:
        {
          "scan_findings": [...],   # one per fingerprint that yielded >=1 CVE
          "cve_catalog":   [...],   # deduped CVE rows
          "exploits":      [...],   # deduped exploit rows
          "finding_cves":  [...],   # (finding_id, cve_id) link rows
        }

    finding_id is generated client-side as "scan_id::vendor:product:version"
    so the same finding within one scan is stable across reruns.
    """
    findings, cve_map, exploit_map, links = [], {}, {}, []

    for r in results:
        if not r.cves:
            continue
        fp = r.fingerprint
        finding_id = f"{scan_id}::{fp.vendor}:{fp.product}:{fp.version or '*'}"
        findings.append({
            "finding_id": finding_id,
            "scan_id": scan_id,
            "vendor": fp.vendor,
            "product": fp.product,
            "version": fp.version,
            "source": fp.source,
            "evidence": fp.evidence,
        })
        for c in r.cves:
            if c.cve_id not in cve_map:
                cve_map[c.cve_id] = {
                    "cve_id": c.cve_id,
                    "description": c.description,
                    "cvss_score": c.cvss_score,
                    "cvss_severity": c.cvss_severity,
                    "cvss_vector": c.cvss_vector,
                    "cvss_version": c.cvss_version,
                    "published_date": c.published_date,
                    "last_modified": c.last_modified,
                    "references": c.references,
                }
            links.append({"finding_id": finding_id, "cve_id": c.cve_id})
            for ex in c.exploits:
                if ex.edb_id not in exploit_map:
                    exploit_map[ex.edb_id] = {
                        "edb_id": ex.edb_id,
                        "cve_id": c.cve_id,
                        "description": ex.description,
                        "type": ex.type,
                        "platform": ex.platform,
                        "date_published": ex.date_published,
                        "source_url": ex.source_url,
                        "verified": bool(ex.verified) if ex.verified is not None else None,
                    }

    return {
        "scan_findings": findings,
        "cve_catalog":   list(cve_map.values()),
        "exploits":      list(exploit_map.values()),
        "finding_cves":  links,
    }


# -------------------------------------------------------------------
# CLI
# -------------------------------------------------------------------

DEMO_FINGERPRINTS = [
    Fingerprint("apache", "http_server", "2.4.49", source="nmap",
                evidence="Server: Apache/2.4.49 (Unix)"),
    Fingerprint("openssl", "openssl", "1.0.1f", source="nikto",
                evidence="OpenSSL/1.0.1f reported in TLS handshake"),
    Fingerprint("wordpress", "wordpress", "5.7.1", source="nikto",
                evidence="WordPress 5.7.1 detected via /wp-includes/"),
    Fingerprint("php", "php", "7.4.3", source="nikto",
                evidence="X-Powered-By: PHP/7.4.3"),
    Fingerprint("jquery", "jquery", "1.6.0", source="nikto",
                evidence="jquery-1.6.0.min.js in HTML"),
    Fingerprint("mysql", "mysql", "5.7.32", source="sqlmap",
                evidence="back-end DBMS: MySQL 5.7.32"),
]


def _print_result(r: MatchResult, top: int = 5) -> None:
    fp = r.fingerprint
    title = f"{fp.vendor}:{fp.product}:{fp.version or '*'}"
    print(f"\n=== {title} ({fp.source or '?'}) ===")
    print(f"    matched CVEs: {r.total_cves}   exploits: {r.total_exploits}")
    if not r.cves:
        print("    (no CVEs matched)")
        return
    for c in r.cves[:top]:
        sev = (c.cvss_severity or "?").ljust(8)
        score = f"{c.cvss_score:>4.1f}" if c.cvss_score is not None else "  - "
        desc = (c.description or "")[:80]
        print(f"    [{sev}{score}]  {c.cve_id}  {desc}")
        for ex in c.exploits[:3]:
            print(f"          ↳ EDB-{ex.edb_id} [{ex.type or '?'}] "
                  f"{(ex.description or '')[:60]}")
    if r.total_cves > top:
        print(f"    ... and {r.total_cves - top} more CVEs")


def main(argv: Iterable[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Local NVD + Exploit-DB matching engine.")
    p.add_argument("--nvd-db", type=Path, default=DEFAULT_NVD_DB)
    p.add_argument("--exploitdb-db", type=Path, default=DEFAULT_EXPLOITDB_DB)
    p.add_argument("--demo", action="store_true",
                   help="run a built-in demo against common web fingerprints")
    p.add_argument("--vendor")
    p.add_argument("--product")
    p.add_argument("--version", dest="version_str")
    p.add_argument("--json", dest="json_input",
                   help='JSON list of fingerprints, e.g. \'[{"vendor":"apache",'
                        '"product":"http_server","version":"2.4.49"}]\'')
    p.add_argument("--out", type=Path,
                   help="write the full Supabase payload as JSON to this file")
    p.add_argument("--scan-id", default="demo-scan",
                   help="scan id used when emitting --out payload")
    args = p.parse_args(list(argv) if argv is not None else None)

    # Build fingerprint list
    fps: list[Fingerprint] = []
    if args.demo:
        fps = list(DEMO_FINGERPRINTS)
    if args.json_input:
        for item in json.loads(args.json_input):
            fps.append(Fingerprint(
                vendor=item.get("vendor", ""),
                product=item.get("product", ""),
                version=item.get("version"),
                source=item.get("source"),
                evidence=item.get("evidence"),
            ))
    if args.vendor and args.product:
        fps.append(Fingerprint(args.vendor, args.product, args.version_str,
                               source="cli"))
    if not fps:
        p.error("provide --demo, --json, or --vendor/--product[/--version]")

    try:
        with Matcher(args.nvd_db, args.exploitdb_db) as m:
            results = m.match(fps)
    except FileNotFoundError as e:
        print(f"[!] {e}", file=sys.stderr)
        return 2

    for r in results:
        _print_result(r)

    total_cves = sum(r.total_cves for r in results)
    total_exp = sum(r.total_exploits for r in results)
    print(f"\nSUMMARY: {len(fps)} fingerprints  ->  "
          f"{total_cves} CVEs  ->  {total_exp} exploits")

    if args.out:
        payload = to_supabase_payload(results, args.scan_id)
        args.out.write_text(json.dumps(payload, indent=2, default=str))
        print(f"\n[done] Supabase payload written to {args.out}")
        print(f"       scan_findings={len(payload['scan_findings'])}  "
              f"cve_catalog={len(payload['cve_catalog'])}  "
              f"exploits={len(payload['exploits'])}  "
              f"finding_cves={len(payload['finding_cves'])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
