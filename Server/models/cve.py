"""
CVE model helpers — schema validation and serialization for the `cves` collection.
"""
from datetime import datetime, timezone

VALID_SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW")


def build_cve(
    cve_id: str,
    severity: str,
    cvss_score: float,
    affected_technologies: list,
    description: str,
    remediation: str,
    published_at: str | None = None,
) -> dict:
    """Return a CVE document ready for MongoDB insertion."""
    severity = severity.upper()
    if severity not in VALID_SEVERITIES:
        raise ValueError(f"Invalid severity '{severity}'.")

    # Parse published_at or default to now
    try:
        pub_dt = datetime.fromisoformat(published_at.replace("Z", "+00:00")) if published_at else datetime.now(timezone.utc)
    except (ValueError, AttributeError):
        pub_dt = datetime.now(timezone.utc)

    return {
        "cve_id": cve_id.strip().upper(),
        "severity": severity,
        "cvss_score": float(cvss_score),
        "affected_technologies": [t.strip().lower() for t in affected_technologies],
        "description": description.strip(),
        "remediation": remediation.strip(),
        "published_at": pub_dt,
        "ingested_at": datetime.now(timezone.utc),
    }


def serialize_cve(doc: dict) -> dict:
    """Convert a MongoDB CVE document to a JSON-safe dict."""
    return {
        "id": str(doc["_id"]),
        "cve_id": doc.get("cve_id", ""),
        "severity": doc.get("severity", "LOW"),
        "cvss_score": float(doc.get("cvss_score", 0)),
        "affected_technologies": doc.get("affected_technologies", []),
        "description": doc.get("description", ""),
        "remediation": doc.get("remediation", ""),
        "published_at": doc["published_at"].isoformat()
        if hasattr(doc.get("published_at"), "isoformat")
        else str(doc.get("published_at", "")),
        "ingested_at": doc["ingested_at"].isoformat()
        if hasattr(doc.get("ingested_at"), "isoformat")
        else str(doc.get("ingested_at", "")),
    }
