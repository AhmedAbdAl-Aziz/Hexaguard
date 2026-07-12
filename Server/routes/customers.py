"""
GET  /api/customers               — List all customers (admin only).
POST /api/customers               — Provision a new customer (admin only).
PUT  /api/customers/<id>/stack    — Update a customer's tech stack (admin or the customer themselves).
"""
from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt, get_jwt_identity
from bson import ObjectId

from fallback_store import get_db
from models.user import build_user, serialize_user

customers_bp = Blueprint("customers", __name__, url_prefix="/api/customers")


def _require_admin():
    """Returns (claims, error_response). error_response is None if caller is admin."""
    claims = get_jwt()
    if claims.get("role") != "admin":
        return claims, (jsonify({"error": "Admin access required."}), 403)
    return claims, None


# ─────────────────────────────────────────────
#  GET /api/customers
# ─────────────────────────────────────────────
@customers_bp.get("/")
@jwt_required()
def list_customers():
    _, err = _require_admin()
    if err:
        return err

    db = get_db()
    docs = list(db.users.find({"role": "customer"}).sort("created_at", -1))
    return jsonify([serialize_user(d) for d in docs]), 200


# ─────────────────────────────────────────────
#  POST /api/customers
# ─────────────────────────────────────────────
@customers_bp.post("/")
@jwt_required()
def provision_customer():
    _, err = _require_admin()
    if err:
        return err

    data = request.get_json(silent=True) or {}
    required = ["username", "company_name", "email"]
    missing = [f for f in required if not data.get(f)]
    if missing:
        return jsonify({"error": f"Missing required fields: {', '.join(missing)}"}), 400

    username = data["username"].strip().lower()

    # Reject duplicate usernames
    db = get_db()
    if db.users.find_one({"username": username}):
        return jsonify({"error": "Username is already registered. Please choose a unique login identifier."}), 409

    try:
        user_doc = build_user(
            username=username,
            password_plain=data.get("password", "customer123"),  # default passkey
            role="customer",
            company_name=data["company_name"],
            email=data["email"],
            security_tier=data.get("security_tier", "Standard Guard"),
            tech_stack=data.get("tech_stack", []),
            notification_settings=data.get("notification_settings"),
        )
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

    result = db.users.insert_one(user_doc)
    user_doc["_id"] = result.inserted_id

    return jsonify({
        "message": "Customer provisioned successfully.",
        "customer": serialize_user(user_doc),
    }), 201


# ─────────────────────────────────────────────
#  PUT /api/customers/<id>/stack
# ─────────────────────────────────────────────
@customers_bp.put("/<customer_id>/stack")
@jwt_required()
def update_stack(customer_id: str):
    claims = get_jwt()
    caller_id = get_jwt_identity()
    is_admin = claims.get("role") == "admin"

    # Customers can only update their own stack
    if not is_admin and caller_id != customer_id:
        return jsonify({"error": "You can only update your own technology stack."}), 403

    try:
        oid = ObjectId(customer_id)
    except Exception:
        return jsonify({"error": "Invalid customer ID format."}), 400

    data = request.get_json(silent=True) or {}
    new_stack = data.get("tech_stack")

    if not isinstance(new_stack, list):
        return jsonify({"error": "'tech_stack' must be a JSON array of strings."}), 400

    cleaned = [t.strip().lower() for t in new_stack if isinstance(t, str) and t.strip()]

    db = get_db()
    db.users.update_one(
        {"_id": oid},
        {"$set": {"tech_stack": cleaned}},
    )

    updated = db.users.find_one({"_id": oid})
    if not updated:
        return jsonify({"error": "Customer not found."}), 404

    return jsonify({
        "message": "Tech stack updated successfully.",
        "customer": serialize_user(updated),
    }), 200


# ─────────────────────────────────────────────
#  PUT /api/customers/<id>/notifications
# ─────────────────────────────────────────────
@customers_bp.put("/<customer_id>/notifications")
@jwt_required()
def update_notifications(customer_id: str):
    claims = get_jwt()
    caller_id = get_jwt_identity()
    is_admin = claims.get("role") == "admin"

    if not is_admin and caller_id != customer_id:
        return jsonify({"error": "You can only update your own notification settings."}), 403

    try:
        oid = ObjectId(customer_id)
    except Exception:
        return jsonify({"error": "Invalid customer ID format."}), 400

    data = request.get_json(silent=True) or {}
    update_fields = {}

    if "notification_settings" in data:
        if not isinstance(data["notification_settings"], dict):
            return jsonify({"error": "'notification_settings' must be a JSON object."}), 400
        update_fields["notification_settings"] = data["notification_settings"]

    if "slack_webhook_url" in data:
        update_fields["slack_webhook_url"] = data["slack_webhook_url"]

    if "custom_webhook_url" in data:
        update_fields["custom_webhook_url"] = data["custom_webhook_url"]

    if not update_fields:
        return jsonify({"error": "No valid fields to update."}), 400

    db = get_db()
    db.users.update_one({"_id": oid}, {"$set": update_fields})

    updated = db.users.find_one({"_id": oid})
    if not updated:
        return jsonify({"error": "Customer not found."}), 404

    return jsonify({
        "message": "Notification settings updated.",
        "customer": serialize_user(updated),
    }), 200
