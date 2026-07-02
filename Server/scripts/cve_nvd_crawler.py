"""
HexaGuard CVE NVD Crawler
─────────────────────────
Queries the NIST NVD REST API v2 for recently published CVEs and
POSTs each new record to the HexaGuard backend API.

Usage:
    python cve_nvd_crawler.py               # one-shot run
    python cve_nvd_crawler.py --watch       # runs every 3600 seconds (1 hour)

Environment variables (or set in a .env file):
    HEXAGUARD_API_URL       Base URL of the HexaGuard backend  (default: http://localhost:5000)
    SCRAPER_API_TOKEN       Bearer token for POST /api/cves
    NVD_API_KEY             Optional NVD API key (higher rate limit)
    CRAWL_INTERVAL_SECONDS  Seconds between runs in --watch mode  (default: 3600)
"""

import argparse
import logging
import os
import time
from datetime import datetime, timedelta, timezone

import requests
from dotenv import load_dotenv

load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), "..", ".env"))

# ── Configuration ──────────────────────────────────────────────────────────────

HEXAGUARD_API_URL = os.getenv("HEXAGUARD_API_URL", "http://localhost:5000")
SCRAPER_API_TOKEN = os.getenv("SCRAPER_API_TOKEN", "scraper-dev-token")
NVD_API_KEY = os.getenv("NVD_API_KEY", "")
CRAWL_INTERVAL = int(os.getenv("CRAWL_INTERVAL_SECONDS", 3600))

NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Mapping from NVD CVSS severity strings to HexaGuard severity labels
SEVERITY_MAP = {
    "CRITICAL": "CRITICAL",
    "HIGH": "HIGH",
    "MEDIUM": "MEDIUM",
    "LOW": "LOW",
    "NONE": "LOW",
}

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger("cve_nvd_crawler")


# ── NVD Fetcher ────────────────────────────────────────────────────────────────

def fetch_recent_cves(hours_back: int = 24) -> list[dict]:
    """
    Fetch CVEs published within the last `hours_back` hours from the NVD API.
    Returns a list of raw NVD CVE item dicts.
    """
    now = datetime.now(timezone.utc)
    pub_start = (now - timedelta(hours=hours_back)).strftime("%Y-%m-%dT%H:%M:%S.000")
    pub_end = now.strftime("%Y-%m-%dT%H:%M:%S.000")

    params = {
        "pubStartDate": pub_start,
        "pubEndDate": pub_end,
        "resultsPerPage": 100,
        "startIndex": 0,
    }

    headers = {}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY

    all_items = []
    while True:
        try:
            resp = requests.get(NVD_API_BASE, params=params, headers=headers, timeout=30)
            resp.raise_for_status()
            data = resp.json()
        except requests.RequestException as exc:
            logger.error("NVD API request failed: %s", exc)
            break

        items = data.get("vulnerabilities", [])
        all_items.extend(items)

        total = data.get("totalResults", 0)
        fetched_so_far = params["startIndex"] + len(items)
        logger.info("Fetched %d / %d CVEs from NVD.", fetched_so_far, total)

        if fetched_so_far >= total or not items:
            break

        params["startIndex"] = fetched_so_far
        time.sleep(1)  # NVD rate-limit courtesy pause

    return all_items


# ── Parser ─────────────────────────────────────────────────────────────────────

def parse_nvd_item(item: dict) -> dict | None:
    """
    Transform a raw NVD vulnerability item into the HexaGuard CVE schema.
    Returns None if the item is missing critical fields.
    """
    cve_data = item.get("cve", {})
    cve_id = cve_data.get("id", "")
    if not cve_id:
        return None

    # Description (prefer English)
    descriptions = cve_data.get("descriptions", [])
    description = next(
        (d["value"] for d in descriptions if d.get("lang") == "en"),
        "No description available.",
    )

    # CVSS score + severity (prefer v3.1, fall back to v3.0, then v2)
    metrics = cve_data.get("metrics", {})
    cvss_score = 0.0
    severity = "LOW"

    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key, [])
        if entries:
            cvss_data = entries[0].get("cvssData", {})
            cvss_score = cvss_data.get("baseScore", 0.0)
            raw_severity = cvss_data.get("baseSeverity", "LOW").upper()
            severity = SEVERITY_MAP.get(raw_severity, "LOW")
            break

    if cvss_score == 0.0:
        logger.debug("Skipping %s — no CVSS score available.", cve_id)
        return None

    # Affected technologies from CPE configurations
    affected_technologies = _extract_technologies(cve_data)
    if not affected_technologies:
        # Still ingest — use a generic placeholder so the record is not lost
        affected_technologies = ["unknown"]

    # Published date
    published_at = cve_data.get("published", datetime.now(timezone.utc).isoformat())

    # Remediation note (NVD doesn't supply structured remediation, so we synthesise one)
    remediation = (
        f"Review the official vendor advisory for {cve_id} and apply available patches. "
        "Monitor NVD and vendor security bulletins for updated remediation guidance."
    )

    return {
        "cve_id": cve_id,
        "severity": severity,
        "cvss_score": cvss_score,
        "affected_technologies": affected_technologies,
        "description": description,
        "remediation": remediation,
        "published_at": published_at,
    }


def _extract_technologies(cve_data: dict) -> list[str]:
    """Extract product names from CPE match strings in NVD configurations."""
    techs = set()
    for config in cve_data.get("configurations", []):
        for node in config.get("nodes", []):
            for cpe_match in node.get("cpeMatch", []):
                # CPE format: cpe:2.3:a:vendor:product:version:...
                cpe = cpe_match.get("criteria", "")
                parts = cpe.split(":")
                if len(parts) >= 5:
                    product = parts[4].replace("_", "-").lower()
                    if product and product != "*":
                        techs.add(product)
    return list(techs)[:10]  # cap at 10 technologies per CVE


# ── Ingestor ───────────────────────────────────────────────────────────────────

def post_cve_to_api(cve_payload: dict) -> bool:
    """
    POST a single CVE payload to POST /api/cves.
    Returns True on success (201), False otherwise.
    409 (duplicate) is silently skipped.
    """
    url = f"{HEXAGUARD_API_URL}/api/cves/"
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {SCRAPER_API_TOKEN}",
    }

    try:
        resp = requests.post(url, json=cve_payload, headers=headers, timeout=15)
        if resp.status_code == 201:
            logger.info("✓ Ingested %s", cve_payload["cve_id"])
            return True
        elif resp.status_code == 409:
            logger.debug("↷ Duplicate — skipped %s", cve_payload["cve_id"])
            return False
        else:
            logger.warning(
                "✗ Failed to ingest %s — HTTP %d: %s",
                cve_payload["cve_id"],
                resp.status_code,
                resp.text[:200],
            )
            return False
    except requests.RequestException as exc:
        logger.error("✗ Request error for %s: %s", cve_payload["cve_id"], exc)
        return False


# ── Main Runner ────────────────────────────────────────────────────────────────

def run_crawl():
    """Fetch → Parse → Ingest one full crawl cycle."""
    logger.info("═══ Starting CVE crawl cycle ═══")
    raw_items = fetch_recent_cves(hours_back=24)
    logger.info("NVD returned %d raw items.", len(raw_items))

    ingested = 0
    skipped = 0

    for item in raw_items:
        payload = parse_nvd_item(item)
        if payload is None:
            skipped += 1
            continue

        success = post_cve_to_api(payload)
        if success:
            ingested += 1

        time.sleep(0.1)  # small delay to avoid hammering the backend

    logger.info(
        "═══ Crawl complete — %d ingested, %d skipped/duplicate ═══",
        ingested,
        skipped,
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="HexaGuard NVD CVE Crawler")
    parser.add_argument(
        "--watch",
        action="store_true",
        help=f"Run continuously every {CRAWL_INTERVAL}s instead of a one-shot run.",
    )
    args = parser.parse_args()

    if args.watch:
        logger.info("Watch mode enabled — crawling every %ds.", CRAWL_INTERVAL)
        while True:
            run_crawl()
            logger.info("Sleeping %ds until next crawl...", CRAWL_INTERVAL)
            time.sleep(CRAWL_INTERVAL)
    else:
        run_crawl()
