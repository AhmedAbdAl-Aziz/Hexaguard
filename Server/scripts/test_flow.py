"""Quick end-to-end test: add tech to stack -> ingest CVE -> verify alert."""
import json
import time
import urllib.error
import urllib.request

BASE = "http://localhost:5000"


def req(path, method="GET", data=None, token=None):
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    body = json.dumps(data).encode() if data else None
    request = urllib.request.Request(BASE + path, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=15) as resp:
            return resp.status, json.loads(resp.read().decode())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read().decode())


def main():
    print("=== 1. Login as customer acme_security ===")
    code, data = req("/api/auth/login", "POST", {
        "username": "acme_security",
        "password": "customer123",
    })
    print("Status:", code)
    customer = data["user"]
    token_c = data["access_token"]
    print("Customer:", customer["company_name"], "| stack:", customer.get("tech_stack", []))

    print("\n=== 2. Add technology: elasticsearch ===")
    new_stack = list(dict.fromkeys([*(customer.get("tech_stack") or []), "elasticsearch"]))
    code, data = req(
        f"/api/customers/{customer['id']}/stack",
        "PUT",
        {"tech_stack": new_stack},
        token_c,
    )
    print("Status:", code, "| stack:", data.get("customer", {}).get("tech_stack", data))

    print("\n=== 3. Login as admin ===")
    code, data = req("/api/auth/login", "POST", {"username": "admin", "password": "admin123"})
    token_a = data["access_token"]
    print("Status:", code)

    print("\n=== 4. Ingest CVE affecting elasticsearch ===")
    cve_payload = {
        "cve_id": "CVE-2026-TEST-001",
        "severity": "HIGH",
        "cvss_score": 8.5,
        "affected_technologies": ["elasticsearch", "java"],
        "description": "Test CVE for elasticsearch stack matching validation.",
        "remediation": "Upgrade elasticsearch to latest patched version.",
        "published_at": "2026-07-02T00:00:00Z",
    }
    code, data = req("/api/cves/", "POST", cve_payload, token_a)
    print("Status:", code)
    print("CVE:", data.get("cve", {}).get("cve_id"))
    print("Message:", data.get("message"))

    time.sleep(2)

    print("\n=== 5. Check alerts for acme_security ===")
    code, alerts = req("/api/alerts/", token=token_c)
    print("Status:", code, "| total alerts:", len(alerts))
    matched = [
        a for a in alerts
        if a.get("technology") == "elasticsearch" and a.get("cve_id") == "CVE-2026-TEST-001"
    ]
    print("Matching alerts:", len(matched))
    for alert in matched[:3]:
        print(
            " -",
            alert["cve_id"],
            "|",
            alert["severity"],
            "| tech:",
            alert["technology"],
            "| status:",
            alert["status"],
        )

    print("\n=== 6. CVE visible in database ===")
    code, cves = req("/api/cves/", token=token_c)
    test_cves = [c for c in cves if c.get("cve_id") == "CVE-2026-TEST-001"]
    print("Test CVE in DB:", "YES" if test_cves else "NO")

    print("\n=== RESULT ===")
    if matched:
        print("PASS: Alert dispatched for elasticsearch on acme_security stack")
    else:
        print("FAIL: No matching alert found")
        for alert in alerts[:5]:
            print(" ", alert.get("customer_name"), alert.get("cve_id"), alert.get("technology"))


if __name__ == "__main__":
    main()
