"""
POST /api/auth/login  — Validate credentials and return JWT.
GET  /api/auth/me     — Return current user from JWT.
"""
from flask import Blueprint, request, jsonify
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
from bson import ObjectId

from fallback_store import get_db
from models.user import check_password, serialize_user

auth_bp = Blueprint("auth", __name__, url_prefix="/api/auth")


@auth_bp.post("/login")
def login():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip().lower()
    password = data.get("password") or ""

    if not username or not password:
        return jsonify({"error": "Username and password are required."}), 400

    db = get_db()
    user = db.users.find_one({"username": username})

    if not user:
        return jsonify({"error": "Invalid username or password."}), 401

    if not check_password(password, user["password_hash"]):
        return jsonify({"error": "Invalid username or password."}), 401

    # JWT identity = user id string; additional_claims carry role for auth guards
    access_token = create_access_token(
        identity=str(user["_id"]),
        additional_claims={"role": user["role"]},
    )

    return jsonify({
        "access_token": access_token,
        "user": serialize_user(user),
    }), 200


@auth_bp.get("/me")
@jwt_required()
def me():
    user_id = get_jwt_identity()

    try:
        oid = ObjectId(user_id)
    except Exception:
        return jsonify({"error": "Invalid identity token."}), 400

    db = get_db()
    user = db.users.find_one({"_id": oid})
    if not user:
        return jsonify({"error": "User not found."}), 404

    return jsonify({"user": serialize_user(user)}), 200
