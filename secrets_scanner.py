#!/usr/bin/env python3

"""
Secrets Scanner with Slack Alerting

Features:
- Detect hardcoded secrets
- Slack notifications (summary + details)
- Recursive scanning
- Clean reporting

Author: Eric Paatey
"""

import os
import re
import argparse
import requests
import json

# ==========================
# CONFIGURATION
# ==========================

SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL", "")
MAX_SLACK_DETAILS = 10  # limit detailed findings sent to Slack

SECRET_PATTERNS = {
    "AWS Access Key": r"AKIA[0-9A-Z]{16}",
    "AWS Secret Key": r"(?i)aws(.{0,20})?(secret|key)[^a-zA-Z0-9]?[0-9a-zA-Z/+]{40}",
    "Generic API Key": r"(?i)(api_key|apikey|token)[^a-zA-Z0-9]?[0-9a-zA-Z]{16,}",
    "Password": r"(?i)(password|passwd|pwd)[^a-zA-Z0-9]?[^\s]{6,}",
    "Private Key": r"-----BEGIN PRIVATE KEY-----"
}

DEFAULT_EXCLUDE_DIRS = {".git", "__pycache__", "node_modules", "venv"}

# ==========================
# SCANNER
# ==========================

def scan_file(file_path):
    findings = []

    try:
        with open(file_path, "r", errors="ignore") as f:
            content = f.read()

        for name, pattern in SECRET_PATTERNS.items():
            matches = re.findall(pattern, content)
            if matches:
                findings.append((name, len(matches)))

    except Exception:
        pass

    return findings


def scan_directory(path):
    results = []

    for root, dirs, files in os.walk(path):
        dirs[:] = [d for d in dirs if d not in DEFAULT_EXCLUDE_DIRS]

        for file in files:
            file_path = os.path.join(root, file)

            findings = scan_file(file_path)
            if findings:
                results.append({
                    "file": file_path,
                    "findings": findings
                })

    return results


# ==========================
# SLACK ALERTING
# ==========================

def send_slack_alert(results):
    if not SLACK_WEBHOOK_URL:
        print("Slack webhook not configured. Skipping alerts.")
        return

    total_files = len(results)
    total_findings = sum(len(r["findings"]) for r in results)

    summary_text = f"""
    
     
 *Secrets Scanner Alert*
Files Affected: {total_files}
Total Findings: {total_findings}
"""

    details = ""
    for i, item in enumerate(results[:MAX_SLACK_DETAILS]):
        details += f"\n*File:* {item['file']}\n"
        for finding in item["findings"]:
            details += f"• {finding[0]} ({finding[1]})\n"

    if len(results) > MAX_SLACK_DETAILS:
        details += "\n...more findings truncated..."

    payload = {
        "text": summary_text + "\n" + details
    }

    try:
        response = requests.post(
            SLACK_WEBHOOK_URL,
            data=json.dumps(payload),
            headers={"Content-Type": "application/json"}
        )

        if response.status_code != 200:
            print(f"Slack error: {response.text}")

    except Exception as e:
        print(f"Slack notification failed: {e}")


# ==========================
# REPORTING
# ==========================

def print_report(results):
    if not results:
        print("No secrets detected.")
        return

    print("\n Potential Secrets Found:\n")

    for item in results:
        print(f"File: {item['file']}")
        for finding in item["findings"]:
            print(f"  - {finding[0]} ({finding[1]} matches)")
        print("-" * 50)


# ==========================
# MAIN
# ==========================

def main():
    parser = argparse.ArgumentParser(description="Scan repo for hardcoded secrets")
    parser.add_argument("path", help="Path to repository")

    args = parser.parse_args()

    print(f"Scanning: {args.path}...\n")

    results = scan_directory(args.path)

    print_report(results)

    if results:
        send_slack_alert(results)


if __name__ == "__main__":
    main()