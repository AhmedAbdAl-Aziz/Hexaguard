"""
Alert model helpers — schema and serialization for the `alerts` collection.
"""
from datetime import datetime, timezone
from bson import ObjectId

VALID_STATUSES = ("Dispatched", "Read", "Failed")


def build_alert(
    customer_id: ObjectId | str,
    customer_name: str,
    cve_id: str,
    severity: str,
    technology: str,
    status: str = "Dispatched",
) -> dict:
    """Return an alert document ready for MongoDB insertion."""
    return {
        "customer_id": ObjectId(str(customer_id)),
        "customer_name": customer_name,
        "cve_id": cve_id.upper(),
        "severity": severity.upper(),
        "technology": technology.lower(),
        "status": status,
        "notifications_sent": {
            "dashboard": False,
            "email": False,
            "slack": False,
            "webhook": False,
        },
        "timestamp": datetime.now(timezone.utc),
    }


def serialize_alert(doc: dict) -> dict:
    """Convert a MongoDB alert document to a JSON-safe dict."""
    return {
        "id": str(doc["_id"]),
        "customer_id": str(doc["customer_id"]),
        "customer_name": doc["customer_name"],
        "cve_id": doc["cve_id"],
        "severity": doc["severity"],
        "technology": doc["technology"],
        "status": doc["status"],
        "notifications_sent": doc.get("notifications_sent", {}),
        "timestamp": doc["timestamp"].isoformat()
        if hasattr(doc.get("timestamp"), "isoformat")
        else str(doc.get("timestamp", "")),
    }
