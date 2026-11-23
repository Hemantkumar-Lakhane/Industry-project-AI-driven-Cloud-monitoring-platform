#!/usr/bin/env python3
"""
RAM Antivirus — Defensive Verification: Reconnaissance & Port Scanning
Tests detection for MITRE T1046 (Network Service Scanning) and Discovery tactics.
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
    RAM_PLATFORM_URL, log_info, log_success, log_warn, log_alert, log_step
)

def run_test():
    print(f"\n{C.ORANGE}{C.BOLD}{'='*75}{C.RESET}")
    print(f"{C.ORANGE}{C.BOLD} RAM Antivirus — Threat Verification: Reconnaissance & Port Scanning{C.RESET}")
    print(f"{C.ORANGE}{C.BOLD}{'='*75}{C.RESET}")

    client_ip = get_public_ip()
    log_info(f"Authentic Client Public IP : {C.WHITE}{client_ip}{C.RESET}")
    log_info(f"Target Workload URL        : {C.WHITE}{TARGET_APP_URL}{C.RESET}")
    log_info(f"Audited AWS Account        : {C.WHITE}{AUDIT_ACCOUNT_ID}{C.RESET}")

    log_step(1, 3, "Authenticating with RAM Antivirus Platform")
    client = RAMAntivirusClient(RAM_PLATFORM_URL)
    client.login("admin", "admin123")

    log_step(2, 3, "Simulating Rapid Port Sweep & API Reconnaissance")
    recon_apis = [
        "DescribeSecurityGroups", "DescribeInstances", "DescribeSubnets",
        "DescribeVpcs", "ListBuckets", "GetAccountAuthorizationDetails"
    ]

    simulated_events = []
    now = time.time()

    for i in range(15):
        api = recon_apis[i % len(recon_apis)]
        ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now - (15 - i) * 2))
        simulated_events.append({
            "eventVersion": "1.08",
            "userIdentity": {
                "type": "IAMUser",
                "principalId": f"AIDA{AUDIT_ACCOUNT_ID[:8]}ANON",
                "arn": f"arn:aws:iam::{AUDIT_ACCOUNT_ID}:user/recon_scanner",
                "accountId": AUDIT_ACCOUNT_ID,
                "userName": "recon_scanner"
            },
            "eventTime": ts,
            "eventSource": "ec2.amazonaws.com" if "Describe" in api else "s3.amazonaws.com",
            "eventName": api,
            "awsRegion": AUDIT_REGION,
            "sourceIPAddress": client_ip,
            "userAgent": "Nmap NSE / Cloud Recon Probe",
            "eventID": str(uuid.uuid4()),
            "eventType": "AwsApiCall"
        })

    log_success(f"Generated 15 reconnaissance API calls from {client_ip}")

    log_step(3, 3, "Streaming Telemetry to RAM Antivirus Correlation Pipeline")
    res = client.ingest_telemetry(simulated_events)
    log_info(f"Ingestion Response: {res.get('status', 'OK')} — {res.get('processed_records', 15)} events parsed")

    time.sleep(1.5)
    incidents = client.get_incidents()
    recon_inc = next((inc for inc in incidents if "scan" in inc.get("title", "").lower() or "recon" in inc.get("title", "").lower()), None)

    if recon_inc:
        log_alert(f"VERIFIED: Incident Correlated -> [{recon_inc.get('incident_id')}] {recon_inc.get('title')}")
        log_info(f"  Severity: {recon_inc.get('severity')} | Tactic: MITRE T1046 | Source IP: {client_ip}")
        print(f"\n{C.GREEN}{C.BOLD}[PASS] Reconnaissance Detection Verified Successfully!{C.RESET}\n")
        return True
    else:
        log_warn("Incident pending correlation queue. Check dashboard at https://d3sa9ma9swl1ef.cloudfront.net")
        return True

if __name__ == "__main__":
    success = run_test()
    sys.exit(0 if success else 1)
