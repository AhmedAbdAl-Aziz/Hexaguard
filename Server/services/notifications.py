"""
Notification helpers — email (SMTP) and Slack webhook dispatchers.
These are called by the alert_dispatcher after creating an alert record.
"""
import smtplib
import json
import logging
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

import requests

from config import Config

logger = logging.getLogger(__name__)


# ──────────────────────────────────────────────
#  Email Notification
# ──────────────────────────────────────────────

def send_email_alert(customer: dict, cve: dict, technology: str) -> bool:
    """
    Send an HTML threat alert email to the customer.
    Returns True on success, False on failure.
    """
    if not Config.SMTP_USER or not Config.SMTP_PASS:
        logger.warning("SMTP credentials not configured — skipping email alert.")
        return False

    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = f"[HexaGuard ALERT] {cve['severity']} Vulnerability — {cve['cve_id']}"
        msg["From"] = Config.SMTP_USER
        msg["To"] = customer["email"]

        severity_color = {
            "CRITICAL": "#ef4444",
            "HIGH": "#f97316",
            "MEDIUM": "#eab308",
            "LOW": "#3b82f6",
        }.get(cve["severity"], "#6b7280")

        html = f"""
        <html>
        <body style="font-family: monospace; background: #0a1228; color: #e2e8f0; padding: 24px;">
          <div style="max-width: 600px; margin: auto; border: 1px solid #1e3a5f; border-radius: 8px; padding: 24px;">
            <h2 style="color: #00f0ff; margin-bottom: 4px;">⬡ HEXAGUARD SECURITY ALERT</h2>
            <p style="color: #94a3b8; margin-top: 0;">Automated CVE Threat Notification</p>
            <hr style="border-color: #1e3a5f;">

            <p>Hello <strong>{customer['company_name']}</strong>,</p>
            <p>A new vulnerability has been identified that affects your monitored technology stack.</p>

            <table style="width:100%; border-collapse: collapse; margin: 16px 0;">
              <tr>
                <td style="padding:8px; border: 1px solid #1e3a5f; color:#94a3b8;">CVE ID</td>
                <td style="padding:8px; border: 1px solid #1e3a5f; color:#00f0ff; font-weight:bold;">{cve['cve_id']}</td>
              </tr>
              <tr>
                <td style="padding:8px; border: 1px solid #1e3a5f; color:#94a3b8;">Severity</td>
                <td style="padding:8px; border: 1px solid #1e3a5f; color:{severity_color}; font-weight:bold;">{cve['severity']}</td>
              </tr>
              <tr>
                <td style="padding:8px; border: 1px solid #1e3a5f; color:#94a3b8;">CVSS Score</td>
                <td style="padding:8px; border: 1px solid #1e3a5f;">{cve['cvss_score']}</td>
              </tr>
              <tr>
                <td style="padding:8px; border: 1px solid #1e3a5f; color:#94a3b8;">Affected Asset</td>
                <td style="padding:8px; border: 1px solid #1e3a5f;">{technology}</td>
              </tr>
            </table>

            <h4 style="color:#94a3b8;">Description</h4>
            <p>{cve['description']}</p>

            <h4 style="color:#00ff87;">Remediation Steps</h4>
            <div style="background:#0d1b2a; border-left: 3px solid #00ff87; padding: 12px; border-radius: 4px;">
              <p style="margin:0;">{cve['remediation']}</p>
            </div>

            <p style="margin-top: 24px; font-size: 12px; color: #475569;">
              This is an automated alert from HexaGuard CVE Tracker.<br>
              Manage your alert preferences in your portal settings.
            </p>
          </div>
        </body>
        </html>
        """

        msg.attach(MIMEText(html, "html"))

        with smtplib.SMTP(Config.SMTP_HOST, Config.SMTP_PORT) as server:
            server.ehlo()
            server.starttls()
            server.login(Config.SMTP_USER, Config.SMTP_PASS)
            server.sendmail(Config.SMTP_USER, customer["email"], msg.as_string())

        logger.info("Email alert sent to %s for %s", customer["email"], cve["cve_id"])
        return True

    except Exception as exc:
        logger.error("Failed to send email to %s: %s", customer["email"], exc)
        return False


# ──────────────────────────────────────────────
#  Slack Notification
# ──────────────────────────────────────────────

def send_slack_alert(webhook_url: str, customer: dict, cve: dict, technology: str) -> bool:
    """
    Send a Slack block-kit formatted alert to the customer's configured webhook URL.
    Returns True on success, False on failure.
    """
    if not webhook_url:
        logger.warning("No Slack webhook URL configured for %s — skipping.", customer["company_name"])
        return False

    severity_emoji = {
        "CRITICAL": "🔴",
        "HIGH": "🟠",
        "MEDIUM": "🟡",
        "LOW": "🔵",
    }.get(cve["severity"], "⚪")

    payload = {
        "blocks": [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"{severity_emoji} HexaGuard Alert — {cve['cve_id']}",
                },
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Severity:*\n{cve['severity']}"},
                    {"type": "mrkdwn", "text": f"*CVSS Score:*\n{cve['cvss_score']}"},
                    {"type": "mrkdwn", "text": f"*Affected Asset:*\n`{technology}`"},
                    {"type": "mrkdwn", "text": f"*Company:*\n{customer['company_name']}"},
                ],
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Description:*\n{cve['description'][:300]}{'...' if len(cve['description']) > 300 else ''}",
                },
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Remediation:*\n{cve['remediation']}",
                },
            },
            {"type": "divider"},
        ]
    }

    try:
        response = requests.post(webhook_url, json=payload, timeout=10)
        response.raise_for_status()
        logger.info("Slack alert sent for %s to %s", cve["cve_id"], customer["company_name"])
        return True
    except Exception as exc:
        logger.error("Slack notification failed for %s: %s", customer["company_name"], exc)
        return False


# ──────────────────────────────────────────────
#  Generic Webhook Notification
# ──────────────────────────────────────────────

def send_webhook_alert(endpoint_url: str, alert_payload: dict) -> bool:
    """
    POST the alert JSON payload to the customer's configured webhook endpoint.
    Returns True on success, False on failure.
    """
    if not endpoint_url:
        return False

    try:
        response = requests.post(endpoint_url, json=alert_payload, timeout=10)
        response.raise_for_status()
        logger.info("Webhook alert posted to %s", endpoint_url)
        return True
    except Exception as exc:
        logger.error("Webhook POST failed to %s: %s", endpoint_url, exc)
        return False
