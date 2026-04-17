"""
Security alert helpers: dynamic timestamp and IPs from ingest log lines, optional n8n webhook.

Environment:
  SECURITY_ALERT_WEBHOOK_URL — POST JSON here on alerts (e.g. n8n webhook).
  CRITICAL_ALERT_EMAIL — documented in main.py for the SMTP path.

Log line format from log_generator:
  timeline| src| dst| sport| dport| status| severity
"""

from __future__ import annotations

import datetime
import os
import sys
from typing import Any, Optional

import requests

_FIELD_MIN = 7


def parse_firewall_log_line(
    log_line: str,
) -> tuple[Optional[str], Optional[str], Optional[str], Optional[str]]:
    """Return (src_ip, dst_ip, status, severity) from a pipe-separated firewall log line."""
    parts = [p.strip() for p in log_line.split("|")]
    if len(parts) < _FIELD_MIN:
        return None, None, None, None
    return parts[1], parts[2], parts[5], parts[6]


def format_alert_timestamp(timeline: Optional[str] = None) -> str:
    """Prefer the event timeline from the log; otherwise UTC now."""
    if timeline:
        s = timeline.replace("T", " ", 1).rstrip("Z")
        return s[:19] if len(s) >= 19 else s
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def build_security_alert_payload(
    log_line: str,
    timeline: str,
    severity: str,
) -> dict[str, Any]:
    src_ip, dst_ip, status, parsed_severity = parse_firewall_log_line(log_line)
    alert_type = severity or parsed_severity or status or "unknown"
    return {
        "source_ip": src_ip or "unknown",
        "ip": src_ip or "unknown",
        "dst_ip": dst_ip or "unknown",
        "attack_type": alert_type,
        "timestamp": format_alert_timestamp(timeline),
        "severity": parsed_severity or severity or "unknown",
        "status": status or "unknown",
        "raw_log": log_line,
    }


def post_security_webhook(
    log_line: str,
    timeline: str,
    severity: str,
    webhook_url: Optional[str] = None,
    timeout: float = 10.0,
) -> Optional[requests.Response]:
    """POST alert JSON to n8n or another listener. No-op if URL is not configured."""
    url = webhook_url or os.environ.get("SECURITY_ALERT_WEBHOOK_URL")
    if not url:
        return None
    data = build_security_alert_payload(log_line, timeline, severity)
    return requests.post(url, json=data, timeout=timeout)


def notify_critical_webhook_safe(log_line: str, timeline: str, severity: str) -> None:
    """For FastAPI BackgroundTasks: swallow errors so a bad webhook does not break ingest."""
    try:
        post_security_webhook(log_line, timeline, severity)
    except Exception as exc:  # noqa: BLE001 — best-effort notification
        print(f"Security webhook failed: {exc}")


def _demo() -> None:
    """Manual test from backend dir with an explicit sample log line."""
    url = os.environ.get("SECURITY_ALERT_WEBHOOK_URL")
    sample = os.environ.get("SECURITY_ALERT_SAMPLE_LOG")
    if not url:
        print("Set SECURITY_ALERT_WEBHOOK_URL to test the webhook.")
        sys.exit(1)
    if not sample:
        print("Set SECURITY_ALERT_SAMPLE_LOG to a real log line to test the webhook.")
        sys.exit(1)

    parts = [p.strip() for p in sample.split("|")]
    timeline = parts[0] if parts else ""
    severity = parts[6] if len(parts) > 6 else "Critical"

    r = post_security_webhook(sample, timeline, severity, webhook_url=url)
    if r is None:
        print("No response (missing URL).")
        sys.exit(1)
    print(f"Status Code: {r.status_code}")
    print(f"Response: {r.text}")


if __name__ == "__main__":
    _demo()
