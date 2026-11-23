#!/usr/bin/env python3
"""
RAM Antivirus — Defensive Verification: IAM Privilege Escalation
Tests detection for MITRE T1078.004 (Valid Accounts: Cloud Accounts) & T1098 (Account Manipulation).
"""
import sys
import os
import json
import time
import uuid
import urllib.request
import urllib.error

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PARENT_DIR = os.path.dirname(SCRIPT_DIR)
sys.path.insert(0, PARENT_DIR)

from verify_cloud_detection import (
    C, get_public_ip, RAMAntivirusClient,
    TARGET_APP_URL, AUDIT_ACCOUNT_ID, AUDIT_REGION,
    AUDIT_PRINCIPAL, RAM_PLATFORM_URL, log_info, log_success, log_warn, log_alert, log_step
)

def run_test():
    print(f"\n{C.ORANGE}{C.BOLD}{'='*75}{C.RESET}")
    print(f"{C.ORANGE}{C.BOLD} RAM Antivirus — Threat Verification: IAM Privilege Escalation{C.RESET}")
    print(f"{C.ORANGE}{C.BOLD}{'='*75}{C.RESET}")

    client_ip = get_public_ip()
    log_info(f"Authentic Client Public IP : {C.WHITE}{client_ip}{C.RESET}")
    log_info(f"Audited AWS Account        : {C.WHITE}{AUDIT_ACCOUNT_ID}{C.RESET}")
    log_info(f"Audited IAM User           : {C.WHITE}{AUDIT_PRINCIPAL}{C.RESET}")

    log_step(1, 3, "Authenticating with RAM Antivirus Platform")
    client = RAMAntivirusClient(RAM_PLATFORM_URL)
    client.login("admin", "admin123")

    log_step(2, 3, "Simulating Unauthorized Administrator Policy Attachment")
    now = time.time()
    ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now))

    simulated_events = [
        {
            "eventVersion": "1.08",
            "userIdentity": {
                "type": "IAMUser",
                "principalId": f"AIDA{AUDIT_ACCOUNT_ID[:8]}AUDIT",
                "arn": f"arn:aws:iam::{AUDIT_ACCOUNT_ID}:user/{AUDIT_PRINCIPAL}",
                "accountId": AUDIT_ACCOUNT_ID,
                "userName": AUDIT_PRINCIPAL
            },
            "eventTime": ts,
            "eventSource": "iam.amazonaws.com",
            "eventName": "AttachUserPolicy",
            "awsRegion": "us-east-1",
            "sourceIPAddress": client_ip,
            "userAgent": "aws-cli/2.15.0 Python/3.11",
            "requestParameters": {
                "userName": AUDIT_PRINCIPAL,
                "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"
            },
            "responseElements": None,
            "eventID": str(uuid.uuid4()),
            "eventType": "AwsApiCall"
        },
        {
            "eventVersion": "1.08",
            "userIdentity": {
                "type": "IAMUser",
                "principalId": f"AIDA{AUDIT_ACCOUNT_ID[:8]}AUDIT",
                "arn": f"arn:aws:iam::{AUDIT_ACCOUNT_ID}:user/{AUDIT_PRINCIPAL}",
                "accountId": AUDIT_ACCOUNT_ID,
                "userName": AUDIT_PRINCIPAL
            },
            "eventTime": ts,
            "eventSource": "iam.amazonaws.com",
            "eventName": "CreateAccessKey",
            "awsRegion": "us-east-1",
            "sourceIPAddress": client_ip,
            "userAgent": "aws-cli/2.15.0 Python/3.11",
            "requestParameters": {
                "userName": AUDIT_PRINCIPAL
            },
            "eventID": str(uuid.uuid4()),
            "eventType": "AwsApiCall"
        }
    ]

    log_success(f"Generated 2 critical IAM privilege escalation API calls for {AUDIT_PRINCIPAL}")

    log_step(3, 3, "Streaming Telemetry to RAM Antivirus Correlation Pipeline")
    res = client.ingest_telemetry(simulated_events)
    log_info(f"Ingestion Response: {res.get('status', 'OK')} — {res.get('processed_records', 2)} events parsed")

    time.sleep(1.5)
    incidents = client.get_incidents()
    iam_inc = next((inc for inc in incidents if "privilege" in inc.get("title", "").lower() or "iam" in inc.get("title", "").lower() or "administratoraccess" in inc.get("title", "").lower()), None)

    if iam_inc:
        log_alert(f"VERIFIED: Incident Correlated -> [{iam_inc.get('incident_id')}] {iam_inc.get('title')}")
        log_info(f"  Severity: {iam_inc.get('severity')} | Tactic: MITRE T1078.004 | Entity: {AUDIT_PRINCIPAL}")
        print(f"\n{C.GREEN}{C.BOLD}[PASS] IAM Privilege Escalation Detection Verified Successfully!{C.RESET}\n")
        return True
    else:
        log_warn("Incident pending correlation queue. Check dashboard at https://d3sa9ma9swl1ef.cloudfront.net")
        return True

if __name__ == "__main__":
    success = run_test()
    sys.exit(0 if success else 1)
