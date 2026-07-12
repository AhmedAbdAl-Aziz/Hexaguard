"""
Alert Dispatcher — the core rules engine.

After a new CVE is saved to MongoDB, this module:
  1. Fetches all customer profiles from the `users` collection.
  2. Checks if each customer's tech_stack overlaps with the CVE's affected_technologies.
  3. Creates alert records (with deduplication) for every matched technology.
  4. Emits `ALERT_DISPATCHED` WebSocket events to targeted rooms.
  5. Sends external notifications (email / Slack / webhook) per customer preferences.
"""
import logging

from bson import ObjectId

from extensions import socketio
from fallback_store import get_db
from models.alert import build_alert, serialize_alert
from services.notifications import send_email_alert, send_slack_alert, send_webhook_alert

logger = logging.getLogger(__name__)


def _find_matched_technologies(affected: list[str], stack: list[str]) -> list[str]:
    """Fuzzy case-insensitive matching between CVE technologies and customer stack."""
    affected_norm = [t.lower().strip() for t in affected]
    stack_norm = [t.lower().strip() for t in stack]
    matched = []

    for tech in stack_norm:
        if any(
            aff == tech or aff in tech or tech in aff
            for aff in affected_norm
        ):
            matched.append(tech)

    return matched


def _send_external_notifications(
    customer: dict, cve: dict, matched_techs: list[str]
) -> dict:
    """Send email/Slack/webhook alerts and return delivery status flags."""
    settings = customer.get("notification_settings", {})
    results = {
        "dashboard": settings.get("dashboard", True),
        "email": False,
        "slack": False,
        "webhook": False,
    }

    primary_tech = matched_techs[0] if matched_techs else ""

    if settings.get("email") and customer.get("email"):
        results["email"] = send_email_alert(customer, cve, primary_tech)

    if settings.get("slack") and customer.get("slack_webhook_url"):
        results["slack"] = send_slack_alert(
            customer["slack_webhook_url"], customer, cve, primary_tech
        )

    if settings.get("webhook") and customer.get("custom_webhook_url"):
        results["webhook"] = send_webhook_alert(
            customer["custom_webhook_url"],
            {
                "event": "HEXAGUARD_ALERT",
                "customer_id": str(customer["_id"]),
                "customer_name": customer.get("company_name"),
                "cve_id": cve["cve_id"],
                "severity": cve["severity"],
                "technologies": matched_techs,
            },
        )

    return results


def dispatch_alerts_for_cve(cve: dict) -> list[dict]:
    """
    Main dispatcher entry point.
    Receives a serialized CVE dict (from MongoDB, _id already as string).
    Returns the list of alert dicts that were created.
    """
    db = get_db()
    dispatched = []
    customers = list(
        db.users.find({
            "role": "customer",
            "tech_stack": {"$exists": True, "$not": {"$size": 0}},
        })
    )

    if not customers:
        logger.info("No customers found — nothing to dispatch.")
        return dispatched

    for customer in customers:
        matched_techs = _find_matched_technologies(
            cve.get("affected_technologies", []),
            customer.get("tech_stack", []),
        )

        if not matched_techs:
            continue

        customer_id = str(customer["_id"])
        created_alerts = []

        for tech in matched_techs:
            existing = db.alerts.find_one({
                "customer_id": ObjectId(customer_id),
                "cve_id": cve["cve_id"],
                "technology": tech,
            })
            if existing:
                logger.info(
                    "Skipped duplicate alert: %s / %s / %s",
                    customer["company_name"],
                    cve["cve_id"],
                    tech,
                )
                continue

            alert_doc = build_alert(
                customer_id=customer["_id"],
                customer_name=customer["company_name"],
                cve_id=cve["cve_id"],
                severity=cve["severity"],
                technology=tech,
            )

            result = db.alerts.insert_one(alert_doc)
            alert_doc["_id"] = result.inserted_id
            serialized = serialize_alert(alert_doc)
            created_alerts.append((alert_doc, serialized))
            dispatched.append(serialized)

            logger.info(
                "Alert created: %s → %s (%s)",
                cve["cve_id"],
                customer["company_name"],
                tech,
            )

        if not created_alerts:
            continue

        notif_settings = customer.get("notification_settings", {})
        first_serialized = created_alerts[0][1]

        if notif_settings.get("dashboard", True):
            payload = {
                "alert": first_serialized,
                "cve_id": cve["cve_id"],
                "severity": cve["severity"],
                "customer_id": customer_id,
                "customer_name": customer["company_name"],
                "technologies": matched_techs,
            }
            socketio.emit(
                "ALERT_DISPATCHED",
                payload,
                room=f"customer:{customer_id}",
            )
            socketio.emit("ALERT_DISPATCHED", payload, room="admin")

        notif_results = _send_external_notifications(customer, cve, matched_techs)

        for alert_doc, _ in created_alerts:
            db.alerts.update_one(
                {"_id": alert_doc["_id"]},
                {"$set": {"notifications_sent": notif_results}},
            )

    logger.info(
        "Dispatch complete for %s — %d alert(s) created.",
        cve["cve_id"],
        len(dispatched),
    )
    return dispatched
