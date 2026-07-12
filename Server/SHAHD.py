"""
HexaGuard — Database Verification Script
شغّله عشان تتأكد إن كل الداتا موجودة في MongoDB
"""

from pymongo import MongoClient
from pymongo.errors import ConnectionFailure
import sys

# ── حط الـ MONGO_URI هنا ─────────────────────────────────────────────────────
MONGO_URI = "mongodb+srv://admin:Mohamed@cluster0.ggkj0hf.mongodb.net/?appName=Cluster0/CVE_DB"
# ─────────────────────────────────────────────────────────────────────────────

def main():
    print("\n╔══════════════════════════════════════════════╗")
    print("║     HexaGuard — Database Verification       ║")
    print("╚══════════════════════════════════════════════╝\n")

    # ── Step 1: الاتصال ───────────────────────────────────────────────────────
    print("► Connecting to MongoDB...")
    try:
        client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
        client.admin.command("ping")
        print("  ✅ Connection successful\n")
    except ConnectionFailure as e:
        print(f"  ❌ Connection failed: {e}")
        sys.exit(1)

    db = client["CVE_DB"]

    # ── Step 2: تحقق من الـ Collections ──────────────────────────────────────
    print("► Checking collections...")
    existing = db.list_collection_names()
    required = ["users", "cves", "alerts"]

    for col in required:
        if col in existing:
            print(f"  ✅ Collection '{col}' موجودة")
        else:
            print(f"  ❌ Collection '{col}' مش موجودة!")

    print()

    # ── Step 3: عدد الـ Documents ─────────────────────────────────────────────
    print("► Checking document counts...")
    print(f"  ✅ Users:   {db.users.count_documents({})} documents")
    print(f"  ✅ CVEs:    {db.cves.count_documents({})} documents")
    print(f"  ✅ Alerts:  {db.alerts.count_documents({})} documents")
    print()

    # ── Step 4: تفاصيل الـ Users ──────────────────────────────────────────────
    print("► Users breakdown...")
    print(f"  ✅ Admins:    {db.users.count_documents({'role': 'admin'})}")
    print(f"  ✅ Customers: {db.users.count_documents({'role': 'customer'})}")
    print(f"  ✅ Customers with tech stack: {db.users.count_documents({'role': 'customer', 'tech_stack': {'$not': {'$size': 0}}})}")
    print()

    # ── Step 5: تفاصيل الـ CVEs ───────────────────────────────────────────────
    print("► CVEs breakdown by severity...")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        print(f"  ✅ {sev}: {db.cves.count_documents({'severity': sev})}")
    print()

    # ── Step 6: عيّنة من الداتا ───────────────────────────────────────────────
    print("► Sample data preview...")
    last_cve = db.cves.find_one({}, sort=[("ingested_at", -1)])
    if last_cve:
        print(f"  Last CVE:  {last_cve.get('cve_id')} [{last_cve.get('severity')}]")

    last_user = db.users.find_one({"role": "customer"})
    if last_user:
        print(f"  Sample Customer: {last_user.get('company_name')} — stack: {last_user.get('tech_stack', [])}")

    print()

    # ── Summary ───────────────────────────────────────────────────────────────
    if db.users.count_documents({}) > 0 and db.cves.count_documents({}) > 0:
        print("╔══════════════════════════════════════════════╗")
        print("║           ✅ Database looks good!           ║")
        print("╚══════════════════════════════════════════════╝")
    else:
        print("╔══════════════════════════════════════════════╗")
        print("║      ⚠️  Some collections are empty!        ║")
        print("╚══════════════════════════════════════════════╝")
    print()

if __name__ == "__main__":
    main()
