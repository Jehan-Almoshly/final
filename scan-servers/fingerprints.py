"""
fingerprints.py
===============

Extract software fingerprints (vendor:product:version) from the raw output
produced by NMAP, NIKTO, SQLMAP and FFUF. Output is a list of
matcher.Fingerprint objects ready to be fed to the matching engine.

The extractor is intentionally conservative: it only returns fingerprints
where it is confident about both the product *and* the version. Empty or
ambiguous mentions are skipped to avoid false-positive CVE matches.
"""

from __future__ import annotations

import re
from typing import Iterable

from matcher import Fingerprint


# ---------------------------------------------------------------
# Product name -> (CPE vendor, CPE product) mapping
# Keys are lowercased substrings we look for in tool output.
# ---------------------------------------------------------------
PRODUCT_MAP: dict[str, tuple[str, str]] = {
    # Web servers
    "apache":          ("apache",    "http_server"),
    "apache httpd":    ("apache",    "http_server"),
    "httpd":           ("apache",    "http_server"),
    "nginx":           ("nginx",     "nginx"),
    "iis":             ("microsoft", "iis"),
    "lighttpd":        ("lighttpd",  "lighttpd"),
    "tomcat":          ("apache",    "tomcat"),
    # CMSs
    "wordpress":       ("wordpress", "wordpress"),
    "drupal":          ("drupal",    "drupal"),
    "joomla":          ("joomla",    "joomla!"),
    "magento":         ("magento",   "magento"),
    # Languages / runtimes
    "php":             ("php",       "php"),
    "python":          ("python",    "python"),
    "node.js":         ("nodejs",    "node.js"),
    "nodejs":          ("nodejs",    "node.js"),
    # Crypto
    "openssl":         ("openssl",   "openssl"),
    # JS libraries
    "jquery":          ("jquery",    "jquery"),
    "bootstrap":       ("getbootstrap", "bootstrap"),
    "angularjs":       ("angularjs", "angular.js"),
    # Databases
    "mysql":           ("mysql",     "mysql"),
    "mariadb":         ("mariadb",   "mariadb"),
    "postgresql":      ("postgresql","postgresql"),
    "postgres":        ("postgresql","postgresql"),
    "mssql":           ("microsoft", "sql_server"),
    "microsoft sql server": ("microsoft", "sql_server"),
    "oracle":          ("oracle",    "database"),
}

# Sorted longest-first so "apache httpd" matches before "apache" etc.
_PRODUCT_KEYS_LONGEST_FIRST = sorted(PRODUCT_MAP.keys(), key=len, reverse=True)

# Reasonable version pattern: 1, 1.2, 1.2.3, 1.2.3a, 1.2.3-rc1, 1.0.1f
_VERSION_RE = re.compile(r"\b(\d+(?:\.\d+){0,4}[A-Za-z]?(?:[-_.][A-Za-z0-9]+)?)\b")


def _lookup_product(text: str) -> tuple[str, str] | None:
    t = text.lower()
    for key in _PRODUCT_KEYS_LONGEST_FIRST:
        if key in t:
            return PRODUCT_MAP[key]
    return None


def _pairs_from_line(line: str, source: str) -> list[Fingerprint]:
    """Find every '<Product>/<Version>' or '<Product> <Version>' in one line."""
    out: list[Fingerprint] = []
    seen: set[tuple[str, str, str]] = set()

    # 1) "Product/Version" form (most common in HTTP Server header)
    for m in re.finditer(r"([A-Za-z][\w.+ ]{1,30}?)/(\d[\w.\-]*)", line):
        prod_text, version = m.group(1).strip(), m.group(2).strip()
        cpe = _lookup_product(prod_text)
        if not cpe:
            continue
        key = (cpe[0], cpe[1], version)
        if key in seen:
            continue
        seen.add(key)
        out.append(Fingerprint(
            vendor=cpe[0], product=cpe[1], version=version,
            source=source, evidence=line.strip()[:300],
        ))

    # 2) "Product Version" form (e.g. "nginx 1.18.0", "Apache httpd 2.4.49",
    #    "back-end DBMS: MySQL 5.7.32")
    for prod_key in _PRODUCT_KEYS_LONGEST_FIRST:
        idx = line.lower().find(prod_key)
        if idx < 0:
            continue
        tail = line[idx + len(prod_key) : idx + len(prod_key) + 40]
        m = _VERSION_RE.search(tail)
        if not m:
            continue
        version = m.group(1)
        # Skip obvious non-versions like "200" status codes
        if version.isdigit() and len(version) <= 3:
            continue
        cpe = PRODUCT_MAP[prod_key]
        key = (cpe[0], cpe[1], version)
        if key in seen:
            continue
        seen.add(key)
        out.append(Fingerprint(
            vendor=cpe[0], product=cpe[1], version=version,
            source=source, evidence=line.strip()[:300],
        ))

    return out


# ---------------------------------------------------------------
# Per-tool extractors
# ---------------------------------------------------------------

def from_nmap(output: str) -> list[Fingerprint]:
    """Parse nmap -sV style output. Lines like:
       80/tcp   open  http     Apache httpd 2.4.49 ((Unix) OpenSSL/1.1.1k PHP/7.4.3)
    """
    fps: list[Fingerprint] = []
    for line in output.splitlines():
        if "/tcp" in line and "open" in line:
            fps.extend(_pairs_from_line(line, source="nmap"))
        elif "http-server-header" in line.lower():
            fps.extend(_pairs_from_line(line, source="nmap"))
    return _dedup(fps)


def from_nikto(output: str) -> list[Fingerprint]:
    """Parse nikto output. Header lines and finding lines.
       + Server: Apache/2.4.49 (Unix) OpenSSL/1.1.1k PHP/7.4.3
       + X-Powered-By: PHP/7.4.3
       + Apache/2.4.49 appears to be outdated...
    """
    fps: list[Fingerprint] = []
    for line in output.splitlines():
        if not line.strip():
            continue
        # Skip lines that are pure metadata (start time, scan terminated, etc.)
        low = line.lower()
        if any(s in low for s in (
            "+ start time", "+ end time", "+ scan terminated",
            "+ host:", "+ root page", "+ no cgi",
        )):
            continue
        fps.extend(_pairs_from_line(line, source="nikto"))
    return _dedup(fps)


def from_sqlmap(output: str) -> list[Fingerprint]:
    """Parse sqlmap text output. Useful lines:
       back-end DBMS: MySQL 5.7.32
       web application technology: Apache 2.4.49, PHP 7.4.3
    """
    fps: list[Fingerprint] = []
    for line in output.splitlines():
        low = line.lower()
        if "back-end dbms" in low or "web application technology" in low:
            fps.extend(_pairs_from_line(line, source="sqlmap"))
    return _dedup(fps)


def from_ffuf(output: str) -> list[Fingerprint]:
    """ffuf is mostly path discovery; it rarely yields version fingerprints.
    We scan response banners only when a Server: line is logged.
    """
    fps: list[Fingerprint] = []
    for line in output.splitlines():
        if "server:" in line.lower():
            fps.extend(_pairs_from_line(line, source="ffuf"))
    return _dedup(fps)


# ---------------------------------------------------------------
# Dispatcher
# ---------------------------------------------------------------

_DISPATCH = {
    "NMAP":   from_nmap,
    "NIKTO":  from_nikto,
    "SQLMAP": from_sqlmap,
    "FFUF":   from_ffuf,
}


def extract(tool: str, raw_output: str) -> list[Fingerprint]:
    fn = _DISPATCH.get((tool or "").upper())
    if not fn:
        return []
    return fn(raw_output or "")


def _dedup(fps: Iterable[Fingerprint]) -> list[Fingerprint]:
    seen: set[tuple[str, str, str | None]] = set()
    out: list[Fingerprint] = []
    for fp in fps:
        key = (fp.vendor.lower(), fp.product.lower(), (fp.version or "").lower())
        if key in seen:
            continue
        seen.add(key)
        out.append(fp)
    return out


# ---------------------------------------------------------------
# CLI for quick sanity checks
# ---------------------------------------------------------------

if __name__ == "__main__":
    import argparse
    import json
    import sys

    p = argparse.ArgumentParser(description="Extract fingerprints from scan output.")
    p.add_argument("--tool", required=True, choices=list(_DISPATCH))
    p.add_argument("--file", help="path to raw scan output (default: stdin)")
    args = p.parse_args()

    raw = open(args.file).read() if args.file else sys.stdin.read()
    fps = extract(args.tool, raw)
    print(json.dumps([fp.__dict__ for fp in fps], indent=2))
    print(f"\n[{args.tool}] extracted {len(fps)} fingerprints", file=sys.stderr)
