"""
HexaGuard Flask Backend — Application Factory
Run with:  python app.py
"""

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

SWAGGER_FILE = Path(__file__).parent / "swagger.yml"


def create_app() -> Flask:
    app = Flask(__name__)
    app.config.from_object(Config)

    with open(SWAGGER_FILE, encoding="utf-8") as f:
        swagger_template = yaml.safe_load(f)

    Swagger(app, template=swagger_template)

    CORS(
        app,
        origins=[app.config["FRONTEND_ORIGIN"]],
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
    mongo.db.users.create_index("username", unique=True)

    mongo.db.cves_db.create_index("cve_id", unique=True)
    mongo.db.cves_db.create_index("severity")
    mongo.db.cves_db.create_index("affected_technologies")

    mongo.db.alerts.create_index("customer_id")
    mongo.db.alerts.create_index("timestamp")
    mongo.db.alerts.create_index([
        ("customer_id", 1),
        ("cve_id", 1),
        ("technology", 1),
    ])

    logging.getLogger(__name__).info("MongoDB indexes ensured.")


def _seed_admin_if_needed():
    """Create default admin account if missing."""
    from models.user import build_user

    if not mongo.db.users.find_one({"username": "admin"}):
        admin_doc = build_user(
            username="admin",
            password_plain="admin123",
            role="admin",
            company_name="HexaGuard HQ",
            email="admin@hexaguard.local",
        )
        mongo.db.users.insert_one(admin_doc)
        logging.getLogger(__name__).warning("Default admin account created.")


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)

app = create_app()


if __name__ == "__main__":
    socketio.run(app, host="0.0.0.0", port=5000, debug=True)
