"""
GET  /api/alerts           — Return alert history.
PUT  /api/alerts/<id>/read — Mark alert as read.
GET  /api/alerts/stats     — Admin alert statistics.
"""
from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt, get_jwt_identity
from bson import ObjectId

from fallback_store import get_db
from models.alert import serialize_alert

alerts_bp = Blueprint("alerts", __name__, url_prefix="/api/alerts")


@alerts_bp.get("/")
@jwt_required()
def list_alerts():
    claims = get_jwt()
    caller_id = get_jwt_identity()
    is_admin = claims.get("role") == "admin"

    query = {}

    if not is_admin:
        try:
            query["customer_id"] = ObjectId(caller_id)
        except Exception:
            return jsonify({"error": "Invalid identity token."}), 400

    severity = request.args.get("severity", "").upper()
    if severity and severity != "ALL":
        query["severity"] = severity

    status = request.args.get("status", "")
    if status:
        query["status"] = status

    cve_id = request.args.get("cve_id", "").upper()
    if cve_id:
        query["cve_id"] = cve_id

    db = get_db()
    docs = list(db.alerts.find(query).sort("timestamp", -1).limit(500))
    return jsonify([serialize_alert(d) for d in docs]), 200


@alerts_bp.put("/<alert_id>/read")
@jwt_required()
def mark_read(alert_id: str):
    claims = get_jwt()
    caller_id = get_jwt_identity()
    is_admin = claims.get("role") == "admin"

    try:
        oid = ObjectId(alert_id)
    except Exception:
        return jsonify({"error": "Invalid alert ID."}), 400

    db = get_db()
    alert = db.alerts.find_one({"_id": oid})
    if not alert:
        return jsonify({"error": "Alert not found."}), 404

    if not is_admin and str(alert["customer_id"]) != caller_id:
        return jsonify({"error": "Unauthorized."}), 403

    db.alerts.update_one({"_id": oid}, {"$set": {"status": "Read"}})
    return jsonify({"message": "Alert marked as read."}), 200


@alerts_bp.get("/stats")
@jwt_required()
def alert_stats():
    claims = get_jwt()
    if claims.get("role") != "admin":
        return jsonify({"error": "Admin access required."}), 403

    db = get_db()
    return jsonify({
        "total_alerts": db.alerts.count_documents({}),
        "critical_alerts": db.alerts.count_documents({"severity": "CRITICAL"}),
        "dispatched": db.alerts.count_documents({"status": "Dispatched"}),
        "customers_affected": len(db.alerts.distinct("customer_id")),
    }), 200
