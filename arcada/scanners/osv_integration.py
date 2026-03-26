"""
OSV.dev vulnerability lookup integration.
Replaces the fragile pip-audit subprocess call with a universal vulnerability database
that supports Python, npm, Go, Rust, Maven, RubyGems, and more.
"""

from __future__ import annotations
import asyncio
import json
import logging
from typing import Any

import httpx

logger = logging.getLogger(__name__)

OSV_API = "https://api.osv.dev/v1/query"
OSV_BATCH_API = "https://api.osv.dev/v1/querybatch"
OSV_SEMAPHORE = asyncio.Semaphore(5)

ECOSYSTEM_MAP = {
    "python": "PyPI",
    "npm": "npm",
    "go": "Go",
    "rust": "crates.io",
    "java": "Maven",
    "ruby": "RubyGems",
    "php": "Packagist",
}


async def query_osv_single(
    package_name: str,
    version: str,
    ecosystem: str,
) -> list[dict[str, Any]]:
    """Query OSV.dev for a single package@version. Returns list of vuln dicts."""
    osv_ecosystem = ECOSYSTEM_MAP.get(ecosystem)
    if not osv_ecosystem:
        return []

    payload = {
        "package": {
            "name": package_name,
            "ecosystem": osv_ecosystem,
        },
    }
    if version:
        payload["version"] = version

    try:
        async with OSV_SEMAPHORE:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.post(OSV_API, json=payload)
        if resp.status_code != 200:
            return []
        data = resp.json()
        return data.get("vulns", [])
    except Exception:
        return []


async def query_osv_batch(
    packages: list[tuple[str, str, str]],
) -> dict[tuple[str, str], list[dict[str, Any]]]:
    """Batch query OSV.dev. Returns {(name, version): [vuln_dicts]}.
    Input: [(name, version, ecosystem), ...]"""
    # Group by ecosystem for batch queries
    by_eco: dict[str, list[tuple[str, str, str]]] = {}
    for name, ver, eco in packages:
        osv_eco = ECOSYSTEM_MAP.get(eco)
        if not osv_eco:
            continue
        by_eco.setdefault(osv_eco, []).append((name, ver, eco))

    results: dict[tuple[str, str], list[dict[str, Any]]] = {}

    tasks = []
    for osv_eco, pkgs in by_eco.items():
        queries = []
        for name, ver, _eco in pkgs:
            q: dict[str, Any] = {"package": {"name": name, "ecosystem": osv_eco}}
            if ver:
                q["version"] = ver
            queries.append(q)

        # OSV batch endpoint allows up to 1000 queries
        for chunk_start in range(0, len(queries), 1000):
            chunk = queries[chunk_start : chunk_start + 1000]
            chunk_pkgs = pkgs[chunk_start : chunk_start + 1000]
            tasks.append(_batch_query(osv_eco, chunk, chunk_pkgs, results))

    await asyncio.gather(*tasks, return_exceptions=True)
    return results


async def _batch_query(
    osv_ecosystem: str,
    queries: list[dict],
    pkgs: list[tuple[str, str, str]],
    results: dict[tuple[str, str], list[dict[str, Any]]],
):
    """Execute a batch query against OSV."""
    try:
        async with OSV_SEMAPHORE:
            async with httpx.AsyncClient(timeout=30.0) as client:
                resp = await client.post(OSV_BATCH_API, json={"queries": queries})
        if resp.status_code != 200:
            return
        data = resp.json()
        for i, result_list in enumerate(data.get("results", [])):
            if i < len(pkgs):
                name, ver, _eco = pkgs[i]
                vulns = result_list.get("vulns", [])
                if vulns:
                    results[(name, ver)] = vulns
    except Exception:
        pass


def format_osv_finding(vuln: dict) -> dict[str, str]:
    """Convert an OSV vuln dict to ARCADA finding fields."""
    vuln_id = vuln.get("id", "UNKNOWN")
    summary = vuln.get("summary", vuln.get("details", "No description available."))
    severity_str = "CRITICAL"

    # Try to extract severity from OSV severity field
    osv_severity = vuln.get("severity", [])
    if osv_severity:
        for s in osv_severity:
            score = s.get("score", "")
            if "CVSS" in s.get("type", ""):
                try:
                    cvss_score = (
                        float(score.split("/")[0].split(":")[-1])
                        if ":" in score
                        else float(score)
                    )
                    if cvss_score >= 9.0:
                        severity_str = "CRITICAL"
                    elif cvss_score >= 7.0:
                        severity_str = "HIGH"
                    elif cvss_score >= 4.0:
                        severity_str = "MEDIUM"
                    else:
                        severity_str = "LOW"
                except (ValueError, IndexError):
                    pass

    # Extract fixed versions
    fix_versions = []
    for affected in vuln.get("affected", []):
        for range_item in affected.get("ranges", []):
            for evt in range_item.get("events", []):
                if "fixed" in evt:
                    fix_versions.append(evt["fixed"])

    # Extract references
    refs = vuln.get("references", [])
    ref_urls = [
        r.get("url", "") for r in refs if r.get("type") in ("ADVISORY", "WEB", "FIX")
    ]
    ref_str = " | ".join(ref_urls[:3]) if ref_urls else ""

    return {
        "id": vuln_id,
        "title": f"Known vulnerability: {vuln_id}",
        "description": summary,
        "severity": severity_str,
        "fix_versions": fix_versions,
        "references": ref_str,
    }
