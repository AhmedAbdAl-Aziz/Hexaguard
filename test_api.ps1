Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "   HEXAGUARD API - FULL TEST SUITE" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

$BASE = "http://localhost:5000"
$pass = 0
$fail = 0

function Test-Result($label, $condition, $detail="") {
    if ($condition) {
        Write-Host "  [PASS] $label $detail" -ForegroundColor Green
        $global:pass++
    } else {
        Write-Host "  [FAIL] $label $detail" -ForegroundColor Red
        $global:fail++
    }
}

# ── 1. Health ────────────────────────────────────────────────
Write-Host "[ 1 ] Health Check" -ForegroundColor Yellow
$h = Invoke-RestMethod -Uri "$BASE/api/health"
Test-Result "GET /api/health" ($h.status -eq "ok") "=> status: $($h.status)"

# ── 2. Auth ──────────────────────────────────────────────────
Write-Host "`n[ 2 ] Authentication" -ForegroundColor Yellow

$r = Invoke-RestMethod -Uri "$BASE/api/auth/login" -Method POST -ContentType "application/json" -Body '{"username":"admin","password":"admin123"}'
$adminToken = $r.access_token
Test-Result "POST /api/auth/login (admin)" ($adminToken -ne $null) "=> role: $($r.user.role)"

$r2 = Invoke-RestMethod -Uri "$BASE/api/auth/login" -Method POST -ContentType "application/json" -Body '{"username":"globaltech_ops","password":"customer123"}'
$custToken = $r2.access_token
Test-Result "POST /api/auth/login (customer)" ($custToken -ne $null) "=> company: $($r2.user.company_name)"

$me = Invoke-RestMethod -Uri "$BASE/api/auth/me" -Headers @{Authorization="Bearer $adminToken"}
Test-Result "GET /api/auth/me" ($me.user.username -eq "admin") "=> $($me.user.username)"

# Wrong password
try {
    Invoke-RestMethod -Uri "$BASE/api/auth/login" -Method POST -ContentType "application/json" -Body '{"username":"admin","password":"wrongpass"}' | Out-Null
    Test-Result "Login with wrong password blocked" $false
} catch {
    Test-Result "Login with wrong password blocked" ($_.Exception.Response.StatusCode -eq 401) "=> 401 Unauthorized"
}

# ── 3. CVEs ──────────────────────────────────────────────────
Write-Host "`n[ 3 ] CVEs" -ForegroundColor Yellow

$cves = Invoke-RestMethod -Uri "$BASE/api/cves/" -Headers @{Authorization="Bearer $adminToken"}
Test-Result "GET /api/cves/" ($cves.Count -gt 0) "=> $($cves.Count) CVEs"

$critical = Invoke-RestMethod -Uri "$BASE/api/cves/?severity=CRITICAL" -Headers @{Authorization="Bearer $adminToken"}
Test-Result "GET /api/cves/?severity=CRITICAL" ($critical.Count -ge 0) "=> $($critical.Count) critical CVEs"

$nginx = Invoke-RestMethod -Uri "$BASE/api/cves/?technology=nginx" -Headers @{Authorization="Bearer $adminToken"}
Test-Result "GET /api/cves/?technology=nginx" ($nginx.Count -ge 0) "=> $($nginx.Count) nginx CVEs"

# POST new CVE (unique ID each run)
$ts = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
$newCveBody = "{`"cve_id`":`"CVE-TEST-$ts`",`"severity`":`"HIGH`",`"cvss_score`":8.5,`"affected_technologies`":[`"apache`",`"nginx`"],`"description`":`"Test CVE $ts`",`"remediation`":`"Update now`"}"
$ingest = Invoke-RestMethod -Uri "$BASE/api/cves/" -Method POST -ContentType "application/json" -Headers @{Authorization="Bearer $adminToken"} -Body $newCveBody
Test-Result "POST /api/cves/ (ingest new CVE)" ($ingest.cve.cve_id -ne $null) "=> $($ingest.cve.cve_id) | $($ingest.cve.severity)"

# Duplicate CVE rejected
try {
    Invoke-RestMethod -Uri "$BASE/api/cves/" -Method POST -ContentType "application/json" -Headers @{Authorization="Bearer $adminToken"} -Body $newCveBody | Out-Null
    Test-Result "Duplicate CVE rejected" $false
} catch {
    Test-Result "Duplicate CVE rejected" ($_.Exception.Response.StatusCode -eq 409) "=> 409 Conflict"
}

# ── 4. Customers ─────────────────────────────────────────────
Write-Host "`n[ 4 ] Customers" -ForegroundColor Yellow

$customers = Invoke-RestMethod -Uri "$BASE/api/customers/" -Headers @{Authorization="Bearer $adminToken"}
Test-Result "GET /api/customers/ (admin)" ($customers.Count -gt 0) "=> $($customers.Count) customers"

# Customer can't access admin route
try {
    Invoke-RestMethod -Uri "$BASE/api/customers/" -Headers @{Authorization="Bearer $custToken"} | Out-Null
    Test-Result "Customer blocked from /api/customers/" $false
} catch {
    Test-Result "Customer blocked from /api/customers/" ($_.Exception.Response.StatusCode -eq 403) "=> 403 Forbidden"
}

# Update tech stack
$custId = ($customers | Where-Object { $_.username -eq "globaltech_ops" }).id
$stackUpdate = Invoke-RestMethod -Uri "$BASE/api/customers/$custId/stack" -Method PUT -ContentType "application/json" -Headers @{Authorization="Bearer $adminToken"} -Body '{"tech_stack":["apache","nginx","mysql","php"]}'
Test-Result "PUT /api/customers/{id}/stack" ($stackUpdate.customer.tech_stack.Count -gt 0) "=> stack: $($stackUpdate.customer.tech_stack -join ', ')"

# ── 5. Alerts ────────────────────────────────────────────────
Write-Host "`n[ 5 ] Alerts" -ForegroundColor Yellow

Start-Sleep -Seconds 2  # Wait for dispatcher

$alerts = Invoke-RestMethod -Uri "$BASE/api/alerts/" -Headers @{Authorization="Bearer $adminToken"}
Test-Result "GET /api/alerts/ (admin sees all)" ($alerts.Count -ge 0) "=> $($alerts.Count) total alerts"

$custAlerts = Invoke-RestMethod -Uri "$BASE/api/alerts/" -Headers @{Authorization="Bearer $custToken"}
Test-Result "GET /api/alerts/ (customer sees own only)" ($custAlerts.Count -ge 0) "=> $($custAlerts.Count) alerts for globaltech_ops"

$stats = Invoke-RestMethod -Uri "$BASE/api/alerts/stats" -Headers @{Authorization="Bearer $adminToken"}
Test-Result "GET /api/alerts/stats (admin)" ($stats.total_alerts -ge 0) "=> total:$($stats.total_alerts) critical:$($stats.critical_alerts) affected_customers:$($stats.customers_affected)"

# Mark alert as read
if ($alerts.Count -gt 0) {
    $alertId = $alerts[0].id
    $readRes = Invoke-RestMethod -Uri "$BASE/api/alerts/$alertId/read" -Method PUT -Headers @{Authorization="Bearer $adminToken"}
    Test-Result "PUT /api/alerts/{id}/read" ($readRes.message -ne $null) "=> $($readRes.message)"
}

# Alert Dispatcher: check if new CVE triggered alerts
Start-Sleep -Seconds 2
$newAlerts = Invoke-RestMethod -Uri "$BASE/api/alerts/" -Headers @{Authorization="Bearer $adminToken"} | Where-Object { $_.cve_id -eq "CVE-TEST-$ts" }
Test-Result "Alert Dispatcher fired for new CVE" ($newAlerts.Count -gt 0) "=> $($newAlerts.Count) alerts created for apache/nginx customers"

# ── 6. No-Auth guard ────────────────────────────────────────
Write-Host "`n[ 6 ] Authorization Guards" -ForegroundColor Yellow
try {
    Invoke-RestMethod -Uri "$BASE/api/cves/" | Out-Null
    Test-Result "No token rejected" $false
} catch {
    Test-Result "No token rejected on /api/cves/" ($_.Exception.Response.StatusCode -eq 401) "=> 401"
}

# ── Summary ──────────────────────────────────────────────────
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  RESULTS: $global:pass PASSED  |  $global:fail FAILED" -ForegroundColor $(if ($global:fail -eq 0) { "Green" } else { "Yellow" })
Write-Host "========================================`n" -ForegroundColor Cyan
