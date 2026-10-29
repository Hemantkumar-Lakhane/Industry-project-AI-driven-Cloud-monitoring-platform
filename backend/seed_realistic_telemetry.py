import sqlite3
import json
import uuid
import sys
import os
from datetime import datetime, timezone, timedelta

def clean_and_seed_realistic_db(db_path='backend/security.db'):
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()

    # Drop excessive duplicate synthetic rows
    cur.execute("DELETE FROM findings")
    cur.execute("DELETE FROM incidents")
    conn.commit()
    conn.close()

    now = datetime.now(timezone.utc)
    
    # 24 realistic findings covering the spectrum
    realistic_findings = [
        # CRITICAL (2)
        {
            "finding_id": "FIND-RW-101",
            "timestamp": (now - timedelta(minutes=14)).isoformat(),
            "attack_category": "malware_ransomware",
            "category_index": 4,
            "title": "Ransomware Precursor: Mass Rapid File Renames with .encrypted Extension",
            "description": "High-velocity filesystem modifications detected across shared EBS volume vol-0a81f3d matching Conti/LockBit ransomware behavioral patterns.",
            "severity": "critical",
            "confidence": 0.98,
            "detection_method": "behavioral_heuristics",
            "status": "open",
            "affected_resource": "vol-0a81f3d (prod-storage-ebs)",
            "affected_principal": "svc-backup",
            "playbook_id": "PB-RW-001",
            "data_source": "LIVE",
            "evidence": {
                "observed_facts": ["1,420 files renamed within 12 seconds", "Target directory /var/data/shared", "Wazuh Rule 60100 triggered"],
                "inferred_hypothesis": "Host compromised by ransomware payload encrypting corporate backups."
            }
        },
        {
            "finding_id": "FIND-EX-102",
            "timestamp": (now - timedelta(minutes=28)).isoformat(),
            "attack_category": "data_exfiltration",
            "category_index": 2,
            "title": "Data Exfiltration: High-Volume S3 GetObject Egress to Untrusted External IP",
            "description": "4.2 GB egress transferred from s3://customer-vault-prod to external IP 185.220.101.5 over non-standard TLS session.",
            "severity": "critical",
            "confidence": 0.94,
            "detection_method": "signature_and_correlation",
            "status": "open",
            "affected_resource": "s3://customer-vault-prod",
            "affected_principal": "alice",
            "playbook_id": "PB-EX-002",
            "data_source": "LIVE",
            "evidence": {
                "observed_facts": ["4.2 GB S3 egress transferred in 8 minutes", "Destination IP: 185.220.101.5 (Tor Exit Node)", "CloudTrail event GetObject"],
                "inferred_hypothesis": "Threat actor exfiltrating customer PII database via compromised IAM session."
            }
        },

        # HIGH (6)
        {
            "finding_id": "FIND-PE-201",
            "timestamp": (now - timedelta(minutes=45)).isoformat(),
            "attack_category": "iam_privilege_escalation",
            "category_index": 3,
            "title": "IAM Privilege Escalation: AdministratorAccess Attached to ReadOnly User",
            "description": "Principal 'dave' attached AWS managed policy AdministratorAccess to their own IAM profile without approval.",
            "severity": "high",
            "confidence": 0.96,
            "detection_method": "cloudtrail_audit",
            "status": "open",
            "affected_resource": "arn:aws:iam::123456789012:user/dave",
            "affected_principal": "dave",
            "playbook_id": "PB-PE-003",
            "data_source": "LIVE",
            "evidence": {
                "observed_facts": ["CloudTrail AttachUserPolicy invoked by dave", "Target policy: AdministratorAccess", "CIEM elevated risk trigger"],
                "inferred_hypothesis": "Insider privilege creep or hijacked credential performing administrative takeover."
            }
        },
        {
            "finding_id": "FIND-BF-202",
            "timestamp": (now - timedelta(minutes=52)).isoformat(),
            "attack_category": "brute_force",
            "category_index": 1,
            "title": "Brute Force Authentication Burst: SSH Credential Stuffing on Bastion Host",
            "description": "85 consecutive failed password attempts from external IP 103.21.1.4 targeting accounts 'root' and 'admin'.",
            "severity": "high",
            "confidence": 0.92,
            "detection_method": "signature_and_correlation",
            "status": "open",
            "affected_resource": "i-09ab12cd34ef (bastion-host-01)",
            "affected_principal": "admin",
            "playbook_id": "PB-BF-001",
            "data_source": "LIVE",
            "evidence": {
                "observed_facts": ["85 failed SSH attempts in 30 seconds", "Source IP 103.21.1.4", "Wazuh Rule 5710 (Auth Failure)"],
                "inferred_hypothesis": "Automated brute-force dictionary bot attempting perimeter breach."
            }
        },
        {
            "finding_id": "FIND-MIN-203",
            "timestamp": (now - timedelta(hours=1, minutes=15)).isoformat(),
            "attack_category": "cryptomining",
            "category_index": 12,
            "title": "Cryptomining Activity: Unauthorized Stratum Mining Protocol & 100% CPU",
            "description": "Worker node worker-03 executing binary 'xmrig' communicating with pool.hashvault.pro on TCP 4444.",
            "severity": "high",
            "confidence": 0.91,
            "detection_method": "behavioral_heuristics",
            "status": "open",
            "affected_resource": "i-08871abf4e (worker-node-03)",
            "affected_principal": "svc-worker",
            "playbook_id": "PB-MIN-001",
            "data_source": "LIVE",
            "evidence": {
                "observed_facts": ["CPU pegged at 99.8% for 45 minutes", "Outbound connection to pool.hashvault.pro:4444", "Process /tmp/.xmrig"],
                "inferred_hypothesis": "Host infected with cryptojacking payload monetizing cloud compute."
            }
        },
        {
            "finding_id": "FIND-ATO-204",
            "timestamp": (now - timedelta(hours=1, minutes=40)).isoformat(),
            "attack_category": "account_takeover",
            "category_index": 7,
            "title": "Account Takeover (ATO): Impossible Travel Velocity on Admin Session",
            "description": "Principal 'sarah.dev' authenticated from New York, then 14 minutes later from Frankfurt, Germany.",
            "severity": "high",
            "confidence": 0.89,
            "detection_method": "ml_anomaly_detection",
            "status": "open",
            "affected_resource": "arn:aws:iam::123456789012:user/sarah.dev",
            "affected_principal": "sarah.dev",
            "playbook_id": "PB-ATO-001",
            "data_source": "LIVE",
            "evidence": {
                "observed_facts": ["First login: US (198.51.100.22)", "Second login 14m later: DE (192.42.116.8)", "PyOD Anomaly Score: 0.88"],
                "inferred_hypothesis": "Session hijacking or credential compromise via compromised development machine."
            }
        },
        {
            "finding_id": "FIND-BOLA-205",
            "timestamp": (now - timedelta(hours=2, minutes=10)).isoformat(),
            "attack_category": "bola_ssrf",
            "category_index": 6,
            "title": "SSRF & BOLA Probe: AWS Instance Metadata Service Query from Web Application",
            "description": "Inbound HTTP request traversed ingress gateway requesting http://169.254.169.254/latest/meta-data/iam/.",
            "severity": "high",
            "confidence": 0.95,
            "detection_method": "signature_and_correlation",
            "status": "open",
            "affected_resource": "app-api-gateway",
            "affected_principal": "anonymous",
            "playbook_id": "PB-SSRF-001",
            "data_source": "LIVE",
            "evidence": {
                "observed_facts": ["Request URI targeted IMDSv1 metadata endpoint", "Inbound source IP 198.96.155.12", "WAF Block Rule 40012 triggered"],
                "inferred_hypothesis": "Attacker attempting SSRF credential theft of EC2 instance profile token."
            }
        },
        {
            "finding_id": "FIND-DT-206",
            "timestamp": (now - timedelta(hours=2, minutes=45)).isoformat(),
            "attack_category": "defense_tampering",
            "category_index": 8,
            "title": "Defense Tampering: CloudTrail Trail Disabled and Multi-Region Logging Suspended",
            "description": "Principal 'bob' invoked StopLogging on primary production audit trail 'corp-global-trail'.",
            "severity": "high",
            "confidence": 0.97,
            "detection_method": "cloudtrail_audit",
            "status": "open",
            "affected_resource": "arn:aws:cloudtrail:us-east-1:123456789012:trail/corp-global-trail",
            "affected_principal": "bob",
            "playbook_id": "PB-DT-001",
            "data_source": "LIVE",
            "evidence": {
                "observed_facts": ["CloudTrail StopLogging API call detected", "Initiated by principal 'bob'", "Target: corp-global-trail"],
                "inferred_hypothesis": "Adversary attempting evasion before executing destructive actions."
            }
        },

        # MEDIUM (11)
        {
            "finding_id": "FIND-SCAN-301",
            "timestamp": (now - timedelta(hours=3, minutes=10)).isoformat(),
            "attack_category": "network_scanning",
            "category_index": 5,
            "title": "Network Reconnaissance: External SYN Sweep Probing Closed Ports (22, 3389, 8080)",
            "description": "Sequential TCP connection attempts detected from 185.220.101.7 across subnet 10.0.0.0/24.",
            "severity": "medium",
            "confidence": 0.87,
            "detection_method": "signature_and_correlation",
            "status": "open",
            "affected_resource": "vpc-07a89b01 / subnet-public",
            "affected_principal": "anonymous",
            "playbook_id": "PB-NS-001",
            "data_source": "LIVE",
            "evidence": {
                "observed_facts": ["VPC Flow logs show 42 REJECT packets in 10s", "Ports probed: 22, 80, 443, 3389, 8080", "Source: 185.220.101.7"],
                "inferred_hypothesis": "Automated reconnaissance scanner mapping attack surface."
            }
        },
        {
            "finding_id": "FIND-SCAN-302",
            "timestamp": (now - timedelta(hours=3, minutes=35)).isoformat(),
            "attack_category": "network_scanning",
            "category_index": 5,
            "title": "Network Reconnaissance: ICMP & Port Sweep Against Database Subnet",
            "description": "Port scan activity targeting internal RDS PostgreSQL endpoint on port 5432.",
            "severity": "medium",
            "confidence": 0.85,
            "detection_method": "signature_and_correlation",
            "status": "open",
            "affected_resource": "subnet-private-db",
            "affected_principal": "anonymous",
            "playbook_id": "PB-NS-001",
            "data_source": "LIVE",
            "evidence": {
                "observed_facts": ["VPC Flow reject packets to port 5432", "Source IP 103.21.9.8", "18 packets within 5 seconds"],
                "inferred_hypothesis": "Internal or external actor attempting to discover database listening ports."
            }
        },
        {
            "finding_id": "FIND-CFG-303",
            "timestamp": (now - timedelta(hours=4, minutes=0)).isoformat(),
            "attack_category": "cloud_misconfiguration",
            "category_index": 14,
            "title": "CSPM Security Posture Issue: S3 Bucket Public Read Policy Enabled",
            "description": "Bucket 'customer-assets-staging' allows AllUsers read access via permissive bucket ACL.",
            "severity": "medium",
            "confidence": 0.95,
            "detection_method": "cspm_posture_scan",
            "status": "open",
            "affected_resource": "s3://customer-assets-staging",
            "affected_principal": "cloud-formation-deployer",
            "playbook_id": "PB-CFG-001",
            "data_source": "CLOUD",
            "evidence": {
                "observed_facts": ["S3 Bucket Policy contains Principal: * with s3:GetObject", "BlockPublicAcls set to False", "Evaluated by CSPM engine"],
                "inferred_hypothesis": "Misconfigured staging bucket publicly exposing internal assets."
            }
        },
        {
            "finding_id": "FIND-CFG-304",
            "timestamp": (now - timedelta(hours=4, minutes=20)).isoformat(),
            "attack_category": "cloud_misconfiguration",
            "category_index": 14,
            "title": "CSPM Security Posture Issue: Security Group Ingress 0.0.0.0/0 on Port 22",
            "description": "Security Group sg-089fa21 allows unrestricted SSH inbound access from public internet.",
            "severity": "medium",
            "confidence": 0.98,
            "detection_method": "cspm_posture_scan",
            "status": "open",
            "affected_resource": "sg-089fa21 (launch-wizard-1)",
            "affected_principal": "devops-admin",
            "playbook_id": "PB-CFG-002",
            "data_source": "CLOUD",
            "evidence": {
                "observed_facts": ["Security Group rule: Ingress 0.0.0.0/0:22 (SSH)", "Attached to 2 EC2 instances", "Evaluated by CSPM engine"],
                "inferred_hypothesis": "Unrestricted management port exposed directly to internet brute-force."
            }
        },
        {
            "finding_id": "FIND-API-305",
            "timestamp": (now - timedelta(hours=4, minutes=50)).isoformat(),
            "attack_category": "suspicious_api_activity",
            "category_index": 9,
            "title": "Suspicious API Activity: Off-Hours Bulk IAM Access Key Listing",
            "description": "Unusual volume of ListAccessKeys and ListUsers API calls executed at 03:15 AM UTC.",
            "severity": "medium",
            "confidence": 0.82,
            "detection_method": "ml_anomaly_detection",
            "status": "open",
            "affected_resource": "iam.amazonaws.com",
            "affected_principal": "svc-deploy",
            "playbook_id": "PB-API-001",
            "data_source": "LIVE",
            "evidence": {
                "observed_facts": ["60 IAM read calls within 2 minutes", "Execution time: 03:15 UTC (baseline deviation)", "PyOD Anomaly Score: 0.79"],
                "inferred_hypothesis": "Automated discovery script or credential enumerator harvesting IAM metadata."
            }
        },
        {
            "finding_id": "FIND-API-306",
            "timestamp": (now - timedelta(hours=5, minutes=15)).isoformat(),
            "attack_category": "suspicious_api_activity",
            "category_index": 9,
            "title": "Suspicious API Activity: DescribeSecurityGroups Sweeps Across All Regions",
            "description": "Single API principal queried DescribeSecurityGroups across 16 AWS regions in 40 seconds.",
            "severity": "medium",
            "confidence": 0.84,
            "detection_method": "ml_anomaly_detection",
            "status": "open",
            "affected_resource": "ec2.amazonaws.com",
            "affected_principal": "temp-auditor",
            "playbook_id": "PB-API-001",
            "data_source": "LIVE",
            "evidence": {
                "observed_facts": ["API calls to 16 AWS regions in rapid succession", "Principal: temp-auditor", "CloudTrail event DescribeSecurityGroups"],
                "inferred_hypothesis": "Reconnaissance tool assessing global perimeter defenses."
            }
        },
        {
            "finding_id": "FIND-BF-307",
            "timestamp": (now - timedelta(hours=5, minutes=40)).isoformat(),
            "attack_category": "brute_force",
            "category_index": 1,
            "title": "Low-Velocity Password Spray: 12 Failed Logins Across Distributed Accounts",
            "description": "Low-frequency authentication failures targeting service accounts to evade rate limits.",
            "severity": "medium",
            "confidence": 0.80,
            "detection_method": "signature_and_correlation",
            "status": "open",
            "affected_resource": "auth-service-01",
            "affected_principal": "svc-monitoring",
            "playbook_id": "PB-BF-001",
            "data_source": "LIVE",
            "evidence": {
                "observed_facts": ["12 failed logins over 25 minutes", "User-Agent: curl/7.88.1", "Source IP: 192.42.116.14"],
                "inferred_hypothesis": "Stealthy credential spray designed to bypass simple threshold alerts."
            }
        },
        {
            "finding_id": "FIND-K8S-308",
            "timestamp": (now - timedelta(hours=6, minutes=10)).isoformat(),
            "attack_category": "container_k8s",
            "category_index": 10,
            "title": "Container Security: Pod Scheduled with HostPID and HostNetwork Privileges",
            "description": "Kubernetes manifest deployed container with access to host process namespace.",
            "severity": "medium",
            "confidence": 0.90,
            "detection_method": "k8s_audit_scan",
            "status": "open",
            "affected_resource": "k8s-pod:monitoring-agent-v2",
            "affected_principal": "k8s-deployer",
            "playbook_id": "PB-K8S-001",
            "data_source": "LIVE",
            "evidence": {
                "observed_facts": ["hostPID: true specified in pod spec", "hostNetwork: true enabled", "Namespace: default"],
                "inferred_hypothesis": "Excessive container privileges allowing potential node escape."
            }
        },
        {
            "finding_id": "FIND-DB-309",
            "timestamp": (now - timedelta(hours=6, minutes=30)).isoformat(),
            "attack_category": "database_attacks",
            "category_index": 13,
            "title": "SQL Injection Probe: Malformed SQL Syntax in Inbound Query Parameter",
            "description": "Web request contained SQL escape sequence ' OR 1=1-- in search query filter.",
            "severity": "medium",
            "confidence": 0.86,
            "detection_method": "waf_inspection",
            "status": "open",
            "affected_resource": "db-proxy-internal",
            "affected_principal": "anonymous",
            "playbook_id": "PB-DB-001",
            "data_source": "LIVE",
            "evidence": {
                "observed_facts": ["Request parameter search=' OR 1=1--", "HTTP Status 400 Bad Request", "Source IP 198.96.155.8"],
                "inferred_hypothesis": "Web security scanner probing API parameters for SQL vulnerabilities."
            }
        },
        {
            "finding_id": "FIND-LAM-310",
            "timestamp": (now - timedelta(hours=7, minutes=0)).isoformat(),
            "attack_category": "serverless_abuse",
            "category_index": 11,
            "title": "Serverless Abuse: Lambda Concurrency Spike Exceeding Baseline by 300%",
            "description": "Function 'pdf-report-generator' spawned 180 concurrent instances within 60 seconds.",
            "severity": "medium",
            "confidence": 0.81,
            "detection_method": "ml_anomaly_detection",
            "status": "open",
            "affected_resource": "arn:aws:lambda:us-east-1:123456789012:function:pdf-report-gen",
            "affected_principal": "web-client",
            "playbook_id": "PB-LAM-001",
            "data_source": "LIVE",
            "evidence": {
                "observed_facts": ["180 concurrent executions in 1 minute", "Average execution duration: 4.2s", "PyOD Anomaly Score: 0.77"],
                "inferred_hypothesis": "Denial-of-wallet burst or recursive invocation loop."
            }
        },
        {
            "finding_id": "FIND-SC-311",
            "timestamp": (now - timedelta(hours=7, minutes=30)).isoformat(),
            "attack_category": "supply_chain",
            "category_index": 15,
            "title": "CI/CD Pipeline Security: Outbound Network Connection During Unit Test Execution",
            "description": "Build runner node initiated TCP connection to raw pastebin IP during dependency resolution.",
            "severity": "medium",
            "confidence": 0.83,
            "detection_method": "behavioral_heuristics",
            "status": "open",
            "affected_resource": "ci-runner-host-04",
            "affected_principal": "gitlab-runner",
            "playbook_id": "PB-SC-001",
            "data_source": "LIVE",
            "evidence": {
                "observed_facts": ["Outbound connection to 104.21.8.9:443 during 'npm install'", "Process node child_process", "Rule 5510 triggered"],
                "inferred_hypothesis": "Potentially compromised npm package executing telemetry in postinstall script."
            }
        },

        # LOW (5)
        {
            "finding_id": "FIND-LOW-401",
            "timestamp": (now - timedelta(hours=8, minutes=10)).isoformat(),
            "attack_category": "network_scanning",
            "category_index": 5,
            "title": "Single Isolated SYN Ping on Closed UDP Port 161 (SNMP)",
            "description": "Isolated single packet probe detected from external address, dropped by security group.",
            "severity": "low",
            "confidence": 0.70,
            "detection_method": "vpc_flow_audit",
            "status": "open",
            "affected_resource": "vpc-07a89b01",
            "affected_principal": "anonymous",
            "playbook_id": "PB-NS-001",
            "data_source": "LIVE",
            "evidence": {
                "observed_facts": ["Single REJECT packet for UDP:161", "No subsequent connections", "Source IP 192.42.116.3"],
                "inferred_hypothesis": "Internet background noise / passive port crawler."
            }
        },
        {
            "finding_id": "FIND-LOW-402",
            "timestamp": (now - timedelta(hours=8, minutes=40)).isoformat(),
            "attack_category": "suspicious_api_activity",
            "category_index": 9,
            "title": "Anomalous User-Agent in Read-Only GetCallerIdentity API Call",
            "description": "Principal 'charlie' invoked GetCallerIdentity with User-Agent 'python-requests/2.28.1'.",
            "severity": "low",
            "confidence": 0.72,
            "detection_method": "cloudtrail_audit",
            "status": "open",
            "affected_resource": "sts.amazonaws.com",
            "affected_principal": "charlie",
            "playbook_id": "PB-API-001",
            "data_source": "LIVE",
            "evidence": {
                "observed_facts": ["User-Agent: python-requests/2.28.1", "Action: sts:GetCallerIdentity", "Principal: charlie"],
                "inferred_hypothesis": "Developer running local Python test script."
            }
        },
        {
            "finding_id": "FIND-LOW-403",
            "timestamp": (now - timedelta(hours=9, minutes=10)).isoformat(),
            "attack_category": "cloud_misconfiguration",
            "category_index": 14,
            "title": "Minor CSPM Posture Notice: CloudWatch Log Retention Period Not Configured",
            "description": "Log group '/aws/lambda/image-processor' set to Never Expire.",
            "severity": "low",
            "confidence": 0.95,
            "detection_method": "cspm_posture_scan",
            "status": "open",
            "affected_resource": "log-group:/aws/lambda/image-processor",
            "affected_principal": "system",
            "playbook_id": "PB-CFG-003",
            "data_source": "CLOUD",
            "evidence": {
                "observed_facts": ["RetentionInDays: null (Never Expire)", "CSPM Best Practice CIS-AWS-2.4"],
                "inferred_hypothesis": "Cost optimization and data hygiene finding."
            }
        },
        {
            "finding_id": "FIND-LOW-404",
            "timestamp": (now - timedelta(hours=9, minutes=30)).isoformat(),
            "attack_category": "brute_force",
            "category_index": 1,
            "title": "Minor Authentication Typo: 2 Failed Password Attempts from Corporate VPN",
            "description": "Two consecutive failed logins for user 'emily' from internal VPN subnet 10.0.0.15 followed by success.",
            "severity": "low",
            "confidence": 0.65,
            "detection_method": "signature_and_correlation",
            "status": "open",
            "affected_resource": "auth-service-01",
            "affected_principal": "emily",
            "playbook_id": "PB-BF-001",
            "data_source": "LIVE",
            "evidence": {
                "observed_facts": ["2 failed attempts followed by successful MFA", "Internal VPN source IP: 10.0.0.15", "Wazuh Rule 5715"],
                "inferred_hypothesis": "Benign user typo resolved via MFA validation."
            }
        },
        {
            "finding_id": "FIND-LOW-405",
            "timestamp": (now - timedelta(hours=10, minutes=0)).isoformat(),
            "attack_category": "container_k8s",
            "category_index": 10,
            "title": "Container Posture: Container Running Without Explicit CPU Limit",
            "description": "Pod deployment 'redis-cache' omitted resources.limits.cpu configuration.",
            "severity": "low",
            "confidence": 0.90,
            "detection_method": "k8s_audit_scan",
            "status": "open",
            "affected_resource": "k8s-pod:redis-cache",
            "affected_principal": "devops-engineer",
            "playbook_id": "PB-K8S-002",
            "data_source": "LIVE",
            "evidence": {
                "observed_facts": ["resources.limits.cpu is undefined", "Workload: redis-cache", "Namespace: caching"],
                "inferred_hypothesis": "Best practice finding to prevent noisy neighbor starvation."
            }
        },

        # RESOLVED FINDINGS (5)
        {
            "finding_id": "FIND-RES-501",
            "timestamp": (now - timedelta(hours=12, minutes=0)).isoformat(),
            "attack_category": "brute_force",
            "category_index": 1,
            "title": "Remediated: Hostile Source IP 185.220.101.9 Blocked at AWS WAF",
            "description": "Automated playbook PB-BF-001 neutralized credential spray and added IP to perimeter blocklist.",
            "severity": "high",
            "confidence": 0.95,
            "detection_method": "signature_and_correlation",
            "status": "resolved",
            "affected_resource": "bastion-host-01",
            "affected_principal": "root",
            "playbook_id": "PB-BF-001",
            "data_source": "LIVE",
            "evidence": {
                "observed_facts": ["Automated containment executed successfully", "WAF IPSet rule applied"],
                "inferred_hypothesis": "Threat neutralized."
            }
        },
        {
            "finding_id": "FIND-RES-502",
            "timestamp": (now - timedelta(hours=14, minutes=0)).isoformat(),
            "attack_category": "cloud_misconfiguration",
            "category_index": 14,
            "title": "Remediated: S3 Public Bucket Policy Revoked (customer-reports-archive)",
            "description": "Playbook PB-CFG-001 enabled BlockPublicAccess and stripped wildcard principal.",
            "severity": "medium",
            "confidence": 0.99,
            "detection_method": "cspm_posture_scan",
            "status": "resolved",
            "affected_resource": "s3://customer-reports-archive",
            "affected_principal": "devops-admin",
            "playbook_id": "PB-CFG-001",
            "data_source": "CLOUD",
            "evidence": {
                "observed_facts": ["Policy removed", "Verified by secondary scan"],
                "inferred_hypothesis": "Remediation verified."
            }
        },
        {
            "finding_id": "FIND-RES-503",
            "timestamp": (now - timedelta(hours=16, minutes=0)).isoformat(),
            "attack_category": "iam_privilege_escalation",
            "category_index": 3,
            "title": "Remediated: Unauthorized AdministratorAccess Policy Detached from User 'eve'",
            "description": "Playbook PB-PE-003 revoked attached admin policy and quarantined active session credentials.",
            "severity": "high",
            "confidence": 0.98,
            "detection_method": "cloudtrail_audit",
            "status": "resolved",
            "affected_resource": "arn:aws:iam::123456789012:user/eve",
            "affected_principal": "eve",
            "playbook_id": "PB-PE-003",
            "data_source": "LIVE",
            "evidence": {
                "observed_facts": ["Policy detached", "Session revoked via STS"],
                "inferred_hypothesis": "Compromised privilege revoked."
            }
        },
        {
            "finding_id": "FIND-RES-504",
            "timestamp": (now - timedelta(hours=18, minutes=0)).isoformat(),
            "attack_category": "network_scanning",
            "category_index": 5,
            "title": "Remediated: Scanner IP 103.21.8.2 Added to NACL Ingress Blacklist",
            "description": "Network ACL updated to deny all traffic from hostile scanner subnet.",
            "severity": "medium",
            "confidence": 0.94,
            "detection_method": "signature_and_correlation",
            "status": "resolved",
            "affected_resource": "nacl-03487f91",
            "affected_principal": "anonymous",
            "playbook_id": "PB-NS-001",
            "data_source": "LIVE",
            "evidence": {
                "observed_facts": ["NACL rule 50 added DENY 103.21.8.2/32"],
                "inferred_hypothesis": "Scanner traffic blocked."
            }
        },
        {
            "finding_id": "FIND-RES-505",
            "timestamp": (now - timedelta(hours=20, minutes=0)).isoformat(),
            "attack_category": "cryptomining",
            "category_index": 12,
            "title": "Remediated: Malicious Mining Process Terminated and Host Quarantined",
            "description": "Host worker-node-01 isolated into containment security group and malicious cron killed.",
            "severity": "high",
            "confidence": 0.99,
            "detection_method": "behavioral_heuristics",
            "status": "resolved",
            "affected_resource": "i-011244ab77 (worker-node-01)",
            "affected_principal": "svc-worker",
            "playbook_id": "PB-MIN-001",
            "data_source": "LIVE",
            "evidence": {
                "observed_facts": ["Host isolated, CPU normalized to 8%"],
                "inferred_hypothesis": "Miner purged."
            }
        }
    ]

    # Realistic Correlated Incidents
    realistic_incidents = [
        {
            "incident_id": "INC-EX-1049",
            "title": "Multi-Stage Campaign: S3 Data Exfiltration & Ransomware Staging",
            "severity": "critical",
            "status": "open",
            "lead_attack_category": "data_exfiltration",
            "finding_count": 2,
            "principals": ["alice", "svc-backup"],
            "source_ips": ["185.220.101.5", "10.0.0.14"],
            "resources": ["s3://customer-vault-prod", "vol-0a81f3d"],
            "attack_categories": ["data_exfiltration", "malware_ransomware"],
            "attack_stages": ["Exfiltration", "Execution & Impact"],
            "correlation_score": 0.96,
            "primary_playbook_id": "PB-EX-002",
            "description": "Correlated high-velocity S3 bucket egress followed by rapid filesystem modification on attached EBS volumes. Demonstrates classic double-extortion ransomware behavior.",
            "start_time": (now - timedelta(minutes=30)).isoformat(),
            "last_seen": (now - timedelta(minutes=14)).isoformat(),
            "duration_seconds": 960.0
        },
        {
            "incident_id": "INC-PE-2081",
            "title": "Correlated IAM Privilege Escalation & Audit Defense Tampering",
            "severity": "high",
            "status": "open",
            "lead_attack_category": "iam_privilege_escalation",
            "finding_count": 2,
            "principals": ["dave", "bob"],
            "source_ips": ["10.0.0.18", "198.51.100.22"],
            "resources": ["arn:aws:iam::123456789012:user/dave", "corp-global-trail"],
            "attack_categories": ["iam_privilege_escalation", "defense_tampering"],
            "attack_stages": ["Privilege Escalation", "Defense Evasion"],
            "correlation_score": 0.94,
            "primary_playbook_id": "PB-PE-003",
            "description": "Unauthorized AdministratorAccess grant correlated with an immediate StopLogging action on CloudTrail audit logs.",
            "start_time": (now - timedelta(hours=2, minutes=45)).isoformat(),
            "last_seen": (now - timedelta(minutes=45)).isoformat(),
            "duration_seconds": 7200.0
        },
        {
            "incident_id": "INC-BF-3012",
            "title": "Perimeter Credential Stuffing & Distributed SSH Brute Force",
            "severity": "high",
            "status": "open",
            "lead_attack_category": "brute_force",
            "finding_count": 2,
            "principals": ["admin", "svc-monitoring"],
            "source_ips": ["103.21.1.4", "192.42.116.14"],
            "resources": ["bastion-host-01", "auth-service-01"],
            "attack_categories": ["brute_force"],
            "attack_stages": ["Initial Access & Credential Abuse"],
            "correlation_score": 0.88,
            "primary_playbook_id": "PB-BF-001",
            "description": "Aggressive password burst on perimeter bastion correlated with low-and-slow credential spraying across internal auth microservices.",
            "start_time": (now - timedelta(hours=5, minutes=40)).isoformat(),
            "last_seen": (now - timedelta(minutes=52)).isoformat(),
            "duration_seconds": 17280.0
        },
        {
            "incident_id": "INC-SCAN-4093",
            "title": "Network Reconnaissance Sweep & Port Probing Across Public Subnets",
            "severity": "medium",
            "status": "open",
            "lead_attack_category": "network_scanning",
            "finding_count": 3,
            "principals": ["anonymous"],
            "source_ips": ["185.220.101.7", "103.21.9.8", "192.42.116.3"],
            "resources": ["vpc-07a89b01", "subnet-private-db"],
            "attack_categories": ["network_scanning"],
            "attack_stages": ["Reconnaissance & Port Scanning"],
            "correlation_score": 0.82,
            "primary_playbook_id": "PB-NS-001",
            "description": "Correlated SYN scanning and ICMP discovery attempts targeting management and database ports from external IPs.",
            "start_time": (now - timedelta(hours=8, minutes=10)).isoformat(),
            "last_seen": (now - timedelta(hours=3, minutes=10)).isoformat(),
            "duration_seconds": 18000.0
        },
        {
            "incident_id": "INC-CFG-5044",
            "title": "Cloud Posture Exposure: Public S3 Bucket & Unrestricted SSH Ingress",
            "severity": "medium",
            "status": "open",
            "lead_attack_category": "cloud_misconfiguration",
            "finding_count": 2,
            "principals": ["cloud-formation-deployer", "devops-admin"],
            "source_ips": ["10.0.0.1"],
            "resources": ["s3://customer-assets-staging", "sg-089fa21"],
            "attack_categories": ["cloud_misconfiguration"],
            "attack_stages": ["Cloud Misconfiguration (CSPM)"],
            "correlation_score": 0.90,
            "primary_playbook_id": "PB-CFG-001",
            "description": "Correlated infrastructure-as-code deployment errors exposing both storage assets (public S3 bucket) and compute ingress (0.0.0.0/0:22).",
            "start_time": (now - timedelta(hours=4, minutes=20)).isoformat(),
            "last_seen": (now - timedelta(hours=4, minutes=0)).isoformat(),
            "duration_seconds": 1200.0
        },
        {
            "incident_id": "INC-API-6019",
            "title": "Anomalous CloudTrail API Enumeration & Off-Hours Token Usage",
            "severity": "low",
            "status": "open",
            "lead_attack_category": "suspicious_api_activity",
            "finding_count": 2,
            "principals": ["svc-deploy", "charlie"],
            "source_ips": ["10.0.0.50"],
            "resources": ["iam.amazonaws.com", "sts.amazonaws.com"],
            "attack_categories": ["suspicious_api_activity"],
            "attack_stages": ["Discovery & Anomaly"],
            "correlation_score": 0.76,
            "primary_playbook_id": "PB-API-001",
            "description": "Unusual off-hours IAM API queries and non-standard Python User-Agent calling AWS STS.",
            "start_time": (now - timedelta(hours=8, minutes=40)).isoformat(),
            "last_seen": (now - timedelta(hours=4, minutes=50)).isoformat(),
            "duration_seconds": 13800.0
        },
        {
            "incident_id": "INC-RES-7001",
            "title": "Neutralized Threat: Malicious Stratum Mining Bot on Worker Fleet",
            "severity": "high",
            "status": "resolved",
            "lead_attack_category": "cryptomining",
            "finding_count": 1,
            "principals": ["svc-worker"],
            "source_ips": ["10.0.0.12"],
            "resources": ["i-011244ab77"],
            "attack_categories": ["cryptomining"],
            "attack_stages": ["Impact"],
            "correlation_score": 0.98,
            "primary_playbook_id": "PB-MIN-001",
            "description": "Playbook PB-MIN-001 terminated malicious xmrig daemon and isolated the infected host.",
            "start_time": (now - timedelta(hours=20)).isoformat(),
            "last_seen": (now - timedelta(hours=19, minutes=50)).isoformat(),
            "duration_seconds": 600.0
        },
        {
            "incident_id": "INC-RES-7002",
            "title": "Neutralized Threat: Staging Bucket Public Exposure Sealed",
            "severity": "medium",
            "status": "resolved",
            "lead_attack_category": "cloud_misconfiguration",
            "finding_count": 1,
            "principals": ["devops-admin"],
            "source_ips": ["10.0.0.1"],
            "resources": ["s3://customer-reports-archive"],
            "attack_categories": ["cloud_misconfiguration"],
            "attack_stages": ["CSPM"],
            "correlation_score": 0.95,
            "primary_playbook_id": "PB-CFG-001",
            "description": "S3 Block Public Access applied and wildcard IAM policy removed.",
            "start_time": (now - timedelta(hours=14)).isoformat(),
            "last_seen": (now - timedelta(hours=13, minutes=55)).isoformat(),
            "duration_seconds": 300.0
        }
    ]

    # Insert findings using database helper
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from engines.db import save_findings_db, save_incidents_db
    
    save_findings_db(realistic_findings)
    save_incidents_db(realistic_incidents)

    print("Realistic enterprise database seeded successfully!")

if __name__ == "__main__":
    clean_and_seed_realistic_db()
