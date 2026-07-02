"""
User model helpers — schema validation and serialization for the `users` collection.
"""
from datetime import datetime, timezone
import bcrypt


VALID_ROLES = ("admin", "customer")
VALID_TIERS = ("Standard Guard", "Enhanced Guard", "Critical Defense Plus")


def hash_password(plain: str) -> str:
    """Return a bcrypt hash for the given plaintext password."""
    return bcrypt.hashpw(plain.encode(), bcrypt.gensalt()).decode()


def check_password(plain: str, hashed: str) -> bool:
    """Verify a plaintext password against its bcrypt hash."""
    return bcrypt.checkpw(plain.encode(), hashed.encode())


def build_user(
    username: str,
    password_plain: str,
    role: str,
    company_name: str,
    email: str,
    security_tier: str = "Standard Guard",
    tech_stack: list | None = None,
    notification_settings: dict | None = None,
    slack_webhook_url: str | None = None,
    custom_webhook_url: str | None = None,
) -> dict:
    """Return a new user document ready to be inserted into MongoDB."""
    if role not in VALID_ROLES:
        raise ValueError(f"Invalid role '{role}'. Must be one of {VALID_ROLES}.")
    if security_tier not in VALID_TIERS:
        raise ValueError(f"Invalid tier '{security_tier}'.")

    # Derive logo initials from company name
    parts = [p for p in company_name.split() if p]
    if len(parts) >= 2:
        initials = (parts[0][0] + parts[1][0]).upper()
    else:
        initials = company_name[:2].upper()

    return {
        "username": username.strip().lower(),
        "password_hash": hash_password(password_plain),
        "role": role,
        "company_name": company_name.strip(),
        "email": email.strip().lower(),
        "logo_initials": initials,
        "security_tier": security_tier,
        "tech_stack": [t.strip().lower() for t in (tech_stack or [])],
        "notification_settings": notification_settings or {
            "dashboard": True,
            "email": True,
            "slack": False,
            "webhook": False,
        },
        "slack_webhook_url": slack_webhook_url,
        "custom_webhook_url": custom_webhook_url,
        "created_at": datetime.now(timezone.utc),
    }


def serialize_user(doc: dict) -> dict:
    """Convert a MongoDB user document to a JSON-safe dict (strips password hash)."""
    return {
        "id": str(doc["_id"]),
        "username": doc["username"],
        "role": doc["role"],
        "company_name": doc["company_name"],
        "email": doc["email"],
        "logo_initials": doc.get("logo_initials", "??"),
        "security_tier": doc.get("security_tier", "Standard Guard"),
        "tech_stack": doc.get("tech_stack", []),
        "notification_settings": doc.get("notification_settings", {}),
        "slack_webhook_url": doc.get("slack_webhook_url"),
        "custom_webhook_url": doc.get("custom_webhook_url"),
        "created_at": doc.get("created_at", "").isoformat()
        if hasattr(doc.get("created_at", ""), "isoformat")
        else str(doc.get("created_at", "")),
    }
