"""
HexaGuard Flask Backend — Application Factory
Run with:  python app.py
"""
import eventlet
eventlet.monkey_patch()
import logging
from datetime import datetime, timezone
from pathlib import Path

import yaml
from flask import Flask, jsonify
from flask_cors import CORS
from flask_socketio import join_room
from flasgger import Swagger

from config import Config
from extensions import mongo, jwt, socketio
from fallback_store import bootstrap_demo_data, get_db, set_mongo_available, _real_mongo_is_available

SWAGGER_FILE = Path(__file__).parent / "swagger.yml"


def create_app() -> Flask:
    app = Flask(__name__)
    app.config.from_object(Config)
    app.config["MONGO_URI"] = app.config["MONGO_URI"]


    with open(SWAGGER_FILE, encoding="utf-8") as f:
        swagger_template = yaml.safe_load(f)

    Swagger(app, template=swagger_template)

    CORS(
        app,
        origins=app.config["FRONTEND_ORIGIN"],
        supports_credentials=True,
    )

    mongo.init_app(app)
    jwt.init_app(app)
    socketio.init_app(app)

    from routes.auth import auth_bp
    from routes.cves import cves_bp
    from routes.customers import customers_bp
    from routes.alerts import alerts_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(cves_bp)
    app.register_blueprint(customers_bp)
    app.register_blueprint(alerts_bp)

    @app.get("/api/health")
    def health():
        return jsonify({
            "status": "ok",
            "time": datetime.now(timezone.utc).isoformat(),
        }), 200

    @socketio.on("connect")
    def on_connect():
        logging.getLogger(__name__).info("WebSocket client connected.")

    @socketio.on("disconnect")
    def on_disconnect():
        logging.getLogger(__name__).info("WebSocket client disconnected.")

    @socketio.on("JOIN")
    def on_join(data):
        """Client joins role-specific rooms after login."""
        role = data.get("role")
        user_id = data.get("userId")

        if role == "admin":
            join_room("admin")
            logging.getLogger(__name__).info("Admin joined room: admin")
        elif user_id:
            join_room(f"customer:{user_id}")
            logging.getLogger(__name__).info(
                "Customer joined room: customer:%s", user_id
            )

    with app.app_context():
        _ensure_indexes()
        _seed_admin_if_needed()

    return app


def _ensure_indexes():
    """Create MongoDB indexes for query performance."""
    if not _real_mongo_is_available():
        set_mongo_available(False)
        logging.getLogger(__name__).warning("MongoDB unavailable, using fallback in-memory store.")
        return

    try:
        db = mongo.db
        db.users.create_index("username", unique=True)
        db.cves_db.create_index("cve_id", unique=True)
        db.cves_db.create_index("severity")
        db.cves_db.create_index("affected_technologies")
        db.alerts.create_index("customer_id")
        db.alerts.create_index("timestamp")
        db.alerts.create_index([
            ("customer_id", 1),
            ("cve_id", 1),
            ("technology", 1),
        ])
        set_mongo_available(True)
        logging.getLogger(__name__).info("MongoDB indexes ensured.")
    except Exception as exc:
        set_mongo_available(False)
        logging.getLogger(__name__).warning("MongoDB unavailable, using fallback in-memory store: %s", exc)


def _seed_admin_if_needed():
    """Create default admin account if missing."""
    from models.user import build_user

    bootstrap_demo_data()
    db = get_db()

    if not db.users.find_one({"username": "admin"}):
        admin_doc = build_user(
            username="admin",
            password_plain="admin123",
            role="admin",
            company_name="HexaGuard HQ",
            email="admin@hexaguard.local",
        )
        db.users.insert_one(admin_doc)
        logging.getLogger(__name__).warning("Default admin account created.")


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)

app = create_app()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001, debug=True, use_reloader=False)
