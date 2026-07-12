from __future__ import annotations

import logging
import re
from copy import deepcopy
from datetime import datetime, timezone
from typing import Any

from bson import ObjectId

from extensions import mongo
from models.alert import build_alert
from models.cve import build_cve
from models.user import build_user

logger = logging.getLogger(__name__)


class FallbackCursor:
    def __init__(self, docs: list[dict], sort_field: str | None = None, sort_direction: int = -1):
        self._docs = docs
        self._sort_field = sort_field
        self._sort_direction = sort_direction
        self._skip = 0
        self._limit = None

    def sort(self, field: str | list[str], direction: int = -1):
        self._sort_field = field
        self._sort_direction = direction
        return self

    def skip(self, n: int):
        self._skip = n
        return self

    def limit(self, n: int):
        self._limit = n
        return self

    def __iter__(self):
        docs = list(self._docs)
        if self._sort_field:
            docs.sort(key=lambda d: d.get(self._sort_field, "") or "", reverse=self._sort_direction < 0)
        if self._skip:
            docs = docs[self._skip:]
        if self._limit is not None:
            docs = docs[:self._limit]
        return iter(deepcopy(d) for d in docs)

    def list(self) -> list[dict]:
        return list(self)


class FallbackCollection:
    def __init__(self, name: str):
        self.name = name
        self._docs: list[dict] = []

    def _match(self, doc: dict, query: Any) -> bool:
        if query is None:
            return True
        if not isinstance(query, dict):
            return doc == query

        if "$or" in query:
            return any(self._match(doc, clause) for clause in query["$or"])

        for key, expected in query.items():
            if key == "$or":
                continue
            if isinstance(expected, dict):
                if "$regex" in expected:
                    actual = str(doc.get(key, ""))
                    pattern = expected["$regex"]
                    flags = expected.get("$options", "")
                    if "i" in flags:
                        actual = actual.lower()
                        pattern = pattern.lower()
                    if re.search(pattern, actual) is None:
                        return False
                elif "$exists" in expected:
                    has_value = key in doc
                    if expected["$exists"] != has_value:
                        return False
                elif "$not" in expected:
                    if "$size" in expected["$not"]:
                        actual = doc.get(key, [])
                        if not isinstance(actual, list):
                            return False
                        if len(actual) == expected["$not"]["$size"]:
                            return False
                    else:
                        return False
                elif "$size" in expected:
                    actual = doc.get(key, [])
                    if not isinstance(actual, list) or len(actual) != expected["$size"]:
                        return False
                else:
                    return False
            else:
                if doc.get(key) != expected:
                    return False
        return True

    def find_one(self, query: dict | None = None) -> dict | None:
        for doc in self._docs:
            if self._match(doc, query):
                return deepcopy(doc)
        return None

    def find(self, query: dict | None = None):
        docs = [deepcopy(doc) for doc in self._docs if self._match(doc, query)]
        return FallbackCursor(docs)

    def insert_one(self, doc: dict):
        stored = deepcopy(doc)
        if "_id" not in stored:
            stored["_id"] = ObjectId()
        self._docs.append(stored)
        return type("InsertResult", (), {"inserted_id": stored["_id"]})()

    def update_one(self, query: dict, update: dict):
        for doc in self._docs:
            if self._match(doc, query):
                changes = update.get("$set", {})
                for key, value in changes.items():
                    doc[key] = deepcopy(value)
                return type("UpdateResult", (), {"matched_count": 1, "modified_count": 1})()
        return type("UpdateResult", (), {"matched_count": 0, "modified_count": 0})()

    def count_documents(self, query: dict | None = None) -> int:
        return sum(1 for doc in self._docs if self._match(doc, query))

    def distinct(self, field: str) -> list[Any]:
        return list({doc.get(field) for doc in self._docs if field in doc})

    def create_index(self, *args, **kwargs):
        return None


class FallbackDatabase:
    def __init__(self):
        self.users = FallbackCollection("users")
        self.cves_db = FallbackCollection("cves_db")
        self.alerts = FallbackCollection("alerts")


fallback_db = FallbackDatabase()
mongo_available = False


def _real_mongo_is_available() -> bool:
    try:
        if not hasattr(mongo, "cx") or mongo.cx is None:
            return False
        mongo.cx.admin.command("ping")
        return True
    except Exception:
        return False


def set_mongo_available(available: bool) -> None:
    global mongo_available
    mongo_available = available


def get_db():
    if mongo_available and _real_mongo_is_available():
        return mongo.db
    return fallback_db


def bootstrap_demo_data() -> None:
    if fallback_db.users.count_documents({}) > 0:
        return

    admin_doc = build_user(
        username="admin",
        password_plain="admin123",
        role="admin",
        company_name="HexaGuard HQ",
        email="admin@hexaguard.local",
        security_tier="Critical Defense Plus",
    )
    admin_result = fallback_db.users.insert_one(admin_doc)
    admin_doc["_id"] = admin_result.inserted_id

    customer_doc = build_user(
        username="acme_security",
        password_plain="customer123",
        role="customer",
        company_name="Acme Corporation",
        email="security-team@acme.com",
        security_tier="Standard Guard",
        tech_stack=["nginx", "postgresql", "docker", "runc", "openssh"],
        notification_settings={"dashboard": True, "email": True, "slack": False, "webhook": False},
    )
    customer_result = fallback_db.users.insert_one(customer_doc)
    customer_doc["_id"] = customer_result.inserted_id

    cve_doc = build_cve(
        cve_id="CVE-2024-3094",
        severity="CRITICAL",
        cvss_score=10.0,
        affected_technologies=["xz-utils", "openssh"],
        description="Malicious code was discovered in xz-utils versions 5.6.0 and 5.6.1.",
        remediation="Upgrade xz-utils immediately and restrict SSH access.",
        published_at="2024-03-29T18:00:00Z",
    )
    cve_result = fallback_db.cves_db.insert_one(cve_doc)
    cve_doc["_id"] = cve_result.inserted_id

    alert_doc = build_alert(
        customer_id=customer_doc["_id"],
        customer_name=customer_doc["company_name"],
        cve_id=cve_doc["cve_id"],
        severity=cve_doc["severity"],
        technology="openssh",
    )
    fallback_db.alerts.insert_one(alert_doc)

    logger.info("Fallback demo data initialized.")
