"""
HexaGuard Database Seeder
─────────────────────────
Populates MongoDB with initial CVE records and customer profiles.

Run:
    python scripts/seed_db.py
"""

import sys
import os

sys.path.insert(
    0,
    os.path.join(os.path.dirname(__file__), "..")
)


from dotenv import load_dotenv

load_dotenv(
    dotenv_path=os.path.join(
        os.path.dirname(__file__),
        "..",
        ".env"
    )
)


from pymongo import MongoClient
from pymongo.errors import DuplicateKeyError

from config import Config

from models.user import build_user
from models.cve import build_cve
from models.alert import build_alert



# ==========================
# Mongo Connection
# ==========================

client = MongoClient(
    Config.MONGO_URI
)


db = client.get_default_database()


# ==========================
# Indexes
# ==========================

db.users.create_index(
    "username",
    unique=True
)


db.cves_db.create_index(
    "cve_id",
    unique=True
)


db.alerts.create_index(
    "customer_id"
)



# ==========================
# Users
# ==========================


USERS = [

{
"username":"admin",
"password":"admin123",
"role":"admin",
"company_name":"HexaGuard HQ",
"email":"admin@hexaguard.local",
"security_tier":"Critical Defense Plus"
},


{
"username":"acme_security",
"password":"customer123",
"role":"customer",
"company_name":"Acme Corporation",
"email":"security-team@acme.com",
"security_tier":"Standard Guard",

"tech_stack":[
"nginx",
"postgresql",
"docker",
"runc",
"openssh"
],

"notification_settings":
{
"dashboard":True,
"email":True,
"slack":False,
"webhook":False
}

}

]



print("\n--- Seeding Users ---")


for user in USERS:

    try:

        if db.users.find_one(
            {
            "username":
            user["username"]
            }
        ):

            print(
            f"↷ Already exists: {user['username']}"
            )

            continue



        doc = build_user(

            username=user["username"],

            password_plain=user["password"],

            role=user["role"],

            company_name=user["company_name"],

            email=user["email"],

            security_tier=user.get(
                "security_tier"
            ),

            tech_stack=user.get(
                "tech_stack",
                []
            ),

            notification_settings=user.get(
                "notification_settings"
            )
        )


        db.users.insert_one(doc)


        print(
        f"✓ Created user: {user['username']}"
        )


    except DuplicateKeyError:

        print(
        f"↷ Already exists: {user['username']}"
        )
# ==========================
# CVEs
# ==========================


CVES = [

{
"cve_id":"CVE-2024-3094",
"severity":"CRITICAL",
"cvss_score":10.0,
"affected_technologies":[
    "xz-utils",
    "openssh"
],
"description":
"Malicious code was discovered in xz-utils versions 5.6.0 and 5.6.1. This backdoor allows unauthorized SSH access.",
"remediation":
"Upgrade xz-utils immediately and restrict SSH access.",
"published_at":
"2024-03-29T18:00:00Z"
},


{
"cve_id":"CVE-2021-44228",
"severity":"CRITICAL",
"cvss_score":10.0,
"affected_technologies":[
    "log4j"
],
"description":
"Apache Log4j2 vulnerability allows remote code execution.",
"remediation":
"Upgrade Apache Log4j to patched versions.",
"published_at":
"2021-12-10T08:00:00Z"
},


{
"cve_id":"CVE-2024-21626",
"severity":"HIGH",
"cvss_score":8.6,
"affected_technologies":[
    "docker",
    "runc",
    "kubernetes"
],
"description":
"runc vulnerability allows container escape and root access.",
"remediation":
"Upgrade runc and restrict container privileges.",
"published_at":
"2024-01-31T22:15:00Z"
},


{
"cve_id":"CVE-2022-22965",
"severity":"CRITICAL",
"cvss_score":9.8,
"affected_technologies":[
    "spring-boot"
],
"description":
"Spring4Shell vulnerability allows remote code execution.",
"remediation":
"Upgrade Spring Framework and Spring Boot.",
"published_at":
"2022-04-01T06:15:00Z"
},


{
"cve_id":"CVE-2023-38408",
"severity":"HIGH",
"cvss_score":8.1,
"affected_technologies":[
    "openssh"
],
"description":
"OpenSSH vulnerability allows remote code execution.",
"remediation":
"Upgrade OpenSSH to latest version.",
"published_at":
"2023-07-19T14:00:00Z"
},


{
"cve_id":"CVE-2023-4863",
"severity":"HIGH",
"cvss_score":8.8,
"affected_technologies":[
    "nginx",
    "apache"
],
"description":
"libwebp heap overflow vulnerability.",
"remediation":
"Update libwebp packages.",
"published_at":
"2023-09-12T15:00:00Z"
},


{
"cve_id":"CVE-2023-34048",
"severity":"CRITICAL",
"cvss_score":9.8,
"affected_technologies":[
    "vcenter"
],
"description":
"VMware vCenter remote code execution vulnerability.",
"remediation":
"Apply VMware security patches.",
"published_at":
"2023-10-24T17:30:00Z"
}

]



print("\n--- Seeding CVEs ---")


for cve in CVES:

    existing = db.cves_db.find_one(
        {
        "cve_id":
        cve["cve_id"]
        }
    )


    if existing:

        print(
        f"↷ Already exists: {cve['cve_id']}"
        )

        continue



    doc = build_cve(
        **cve
    )


    db.cves_db.insert_one(
        doc
    )


    print(
    f"✓ Inserted: {cve['cve_id']}"
    )





# ==========================
# Alerts
# ==========================


print("\n--- Seeding Alerts ---")


acme = db.users.find_one(
    {
    "username":
    "acme_security"
    }
)


cve_3094 = db.cves_db.find_one(
    {
    "cve_id":
    "CVE-2024-3094"
    }
)


cve_21626 = db.cves_db.find_one(
    {
    "cve_id":
    "CVE-2024-21626"
    }
)



alerts = []


if acme and cve_3094:

    alerts.append(

        build_alert(

            acme["_id"],

            "Acme Corporation",

            "CVE-2024-3094",

            "CRITICAL",

            "openssh"

        )

    )



if acme and cve_21626:

    alerts.append(

        build_alert(

            acme["_id"],

            "Acme Corporation",

            "CVE-2024-21626",

            "HIGH",

            "runc"

        )

    )





if alerts:


    db.alerts.insert_many(
        alerts
    )


    print(
    f"✓ Inserted {len(alerts)} alerts"
    )


else:

    print(
    "↷ No alerts inserted"
    )



print(
"\n✅ Seed completed successfully\n"
)


client.close()