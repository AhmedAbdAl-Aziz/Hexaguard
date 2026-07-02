"""Print sample API responses for documentation/demo."""
import json
import urllib.error
import urllib.request

BASE = "http://localhost:5000"


def call(label, path, method="GET", body=None, token=None, preview=1200):
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    data = json.dumps(body).encode() if body else None
    req = urllib.request.Request(BASE + path, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            out = json.loads(resp.read().decode())
            print(f"\n[{label}] {method} {path} -> {resp.status}")
            print(json.dumps(out, indent=2)[:preview])
            return resp.status, out
    except urllib.error.HTTPError as exc:
        err = exc.read().decode()
        print(f"\n[{label}] {method} {path} -> {exc.code}")
        print(err[:preview])
        return exc.code, err


def main():
    call("Health", "/api/health")

    _, login = call(
        "Login (admin)",
        "/api/auth/login",
        "POST",
        {"username": "admin", "password": "admin123"},
    )
    token = login["access_token"]

    call("Current user", "/api/auth/me", token=token)
    call("CVEs (CRITICAL)", "/api/cves/?severity=CRITICAL", token=token)
    call("Customers", "/api/customers/", token=token)
    call("Alert stats", "/api/alerts/stats", token=token)
    call("Alerts", "/api/alerts/", token=token, preview=800)


if __name__ == "__main__":
    main()
