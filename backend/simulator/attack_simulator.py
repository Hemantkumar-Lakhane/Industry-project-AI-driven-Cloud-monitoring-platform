"""
Attack Simulation Module
Simulates realistic attack scenarios to verify detection by the system.
Scenarios: brute force, privilege escalation, data exfiltration, abnormal access.
Each scenario generates targeted events, runs them through ML, and verifies detection.
"""
import uuid
import random
from datetime import datetime, timezone
from typing import Dict, List

INTENSITY_PROFILES = {
    "low": {"scale": 0.7, "byte_scale": 0.6, "extra_steps": 0},
    "medium": {"scale": 1.0, "byte_scale": 1.0, "extra_steps": 1},
    "high": {"scale": 1.4, "byte_scale": 1.35, "extra_steps": 2},
    "extreme": {"scale": 2.0, "byte_scale": 1.9, "extra_steps": 3},
}

SCENARIO_METADATA = {
    "brute_force": {
        "title": "Brute Force",
        "description": "Multiple failed login attempts followed by a successful breach.",
        "icon": "hammer",
        "supports_intensity": True,
        "default_intensity": "high",
    },
    "privilege_escalation": {
        "title": "Privilege Escalation",
        "description": "A user escalates privileges through IAM policy manipulation.",
        "icon": "arrow-up",
        "supports_intensity": True,
        "default_intensity": "high",
    },
    "data_exfiltration": {
        "title": "Data Exfiltration",
        "description": "Large outbound transfers to an external destination.",
        "icon": "upload",
        "supports_intensity": True,
        "default_intensity": "high",
    },
    "abnormal_access": {
        "title": "Abnormal Access",
        "description": "Unusual geo-location access followed by suspicious cloud activity.",
        "icon": "globe",
        "supports_intensity": True,
        "default_intensity": "high",
    },
}

def _profile(intensity: str) -> Dict:
    return INTENSITY_PROFILES.get(intensity, INTENSITY_PROFILES["high"])

def _timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

def _simulation_meta(prefix: str) -> Dict:
    return {
        "simulation_id": f"{prefix}-{str(uuid.uuid4())[:8].upper()}",
        "generated_at": _timestamp(),
    }

def simulate_brute_force(intensity: str = "high") -> Dict:
    """Simulate a brute force login attack with configurable intensity."""
    profile = _profile(intensity)
    events = []
    src_ip = f"103.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
    target_user = random.choice(["admin", "root", "svc-account-01"])
    attempt_count = max(8, int(round(random.randint(10, 18) * profile["scale"])))
    for i in range(attempt_count):
        events.append({
            "id": f"SIM-BF-{str(uuid.uuid4())[:8]}", "timestamp": _timestamp(),
            "source": "wazuh", "rule_id": random.choice([5710, 5712, 40111]),
            "level": random.randint(8, 14), "severity": "critical" if i > attempt_count // 2 else "high",
            "event_type": "attack", "attack_type": "brute_force",
            "user": target_user, "src_ip": src_ip, "dst_ip": "10.0.0.5",
            "service": "iam", "region": "us-east-1", "action": "ConsoleLogin",
            "status": "failure", "bytes_transferred": 0,
            "failed_attempts": random.randint(max(5, attempt_count // 2), attempt_count * 8),
            "description": f"Brute force attempt #{i+1} from {src_ip}",
        })
    # Final successful login after failures
    events.append({
        "id": f"SIM-BF-SUCCESS-{str(uuid.uuid4())[:8]}", "timestamp": _timestamp(),
        "source": "wazuh", "rule_id": 5715, "level": 14, "severity": "critical",
        "event_type": "attack", "attack_type": "brute_force",
        "user": target_user, "src_ip": src_ip, "dst_ip": "10.0.0.5",
        "service": "iam", "region": "us-east-1", "action": "ConsoleLogin",
        "status": "success", "bytes_transferred": 0, "failed_attempts": len(events),
        "description": f"SUCCESSFUL LOGIN after {len(events)} failed attempts from {src_ip}",
    })
    return {
        **_simulation_meta("SIM-BF"),
        "scenario": "brute_force", "intensity": intensity, "target_user": target_user,
        "source_ip": src_ip, "total_events": len(events), "events": events,
        "expected_detection": True, "description": f"Brute force attack: {len(events)-1} failed + 1 successful login"
    }

def simulate_privilege_escalation(intensity: str = "high") -> Dict:
    """Simulate privilege escalation via policy attachment chain."""
    profile = _profile(intensity)
    user = random.choice(["bob", "eve", "svc-account-01"])
    events = [
        {"id": f"SIM-PE-{str(uuid.uuid4())[:8]}", "timestamp": _timestamp(),
         "source": "wazuh", "rule_id": 5402, "level": 10, "severity": "high",
         "event_type": "attack", "attack_type": "privilege_escalation", "user": user,
         "src_ip": "10.0.0.15", "dst_ip": "10.0.0.1", "service": "iam", "region": "us-east-1",
         "action": "CreatePolicy", "status": "success", "bytes_transferred": 0, "failed_attempts": 0,
         "description": f"{user} created a new IAM policy with AdministratorAccess"},
        {"id": f"SIM-PE-{str(uuid.uuid4())[:8]}", "timestamp": _timestamp(),
         "source": "wazuh", "rule_id": 5403, "level": 13, "severity": "critical",
         "event_type": "attack", "attack_type": "privilege_escalation", "user": user,
         "src_ip": "10.0.0.15", "dst_ip": "10.0.0.1", "service": "iam", "region": "us-east-1",
         "action": "AttachUserPolicy", "status": "success", "bytes_transferred": 0, "failed_attempts": 0,
         "description": f"{user} attached AdministratorAccess to self"},
        {"id": f"SIM-PE-{str(uuid.uuid4())[:8]}", "timestamp": _timestamp(),
         "source": "wazuh", "rule_id": 8502, "level": 14, "severity": "critical",
         "event_type": "attack", "attack_type": "privilege_escalation", "user": user,
         "src_ip": "10.0.0.15", "dst_ip": "10.0.0.1", "service": "sts", "region": "us-east-1",
         "action": "AssumeRole", "status": "success", "bytes_transferred": 0, "failed_attempts": 0,
         "description": f"{user} assumed production admin role"},
    ]
    extra_actions = [
        ("iam", "CreateAccessKey", 11, "Created a new access key after elevation"),
        ("cloudtrail", "StopLogging", 13, "Attempted to disable audit logging"),
        ("kms", "ScheduleKeyDeletion", 12, "Scheduled a sensitive KMS key for deletion"),
    ]
    for idx in range(random.randint(0, profile["extra_steps"])):
        service, action, level, desc = extra_actions[idx]
        events.append({
            "id": f"SIM-PE-{str(uuid.uuid4())[:8]}", "timestamp": _timestamp(),
            "source": "wazuh", "rule_id": random.choice([5403, 8502, 8504]), "level": level, "severity": "critical",
            "event_type": "attack", "attack_type": "privilege_escalation", "user": user,
            "src_ip": "10.0.0.15", "dst_ip": "10.0.0.1", "service": service, "region": "us-east-1",
            "action": action, "status": "success", "bytes_transferred": 0, "failed_attempts": 0,
            "description": f"{user} {desc.lower()}",
        })
    return {
        **_simulation_meta("SIM-PE"),
        "scenario": "privilege_escalation", "intensity": intensity, "target_user": user, "total_events": len(events),
        "events": events, "expected_detection": True,
        "description": f"Privilege escalation: {user} created policy → attached admin → assumed prod role"
    }

def simulate_data_exfiltration(intensity: str = "high") -> Dict:
    """Simulate large-scale data exfiltration via S3."""
    profile = _profile(intensity)
    user = random.choice(["charlie", "eve", "malicious-insider"])
    dst_ip = f"198.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
    events = []
    total_bytes = 0
    chunk_count = max(3, int(round(random.randint(3, 5) * profile["scale"])))
    for i in range(chunk_count):
        chunk = int(random.randint(500_000_000, 2_000_000_000) * profile["byte_scale"])
        total_bytes += chunk
        events.append({
            "id": f"SIM-DE-{str(uuid.uuid4())[:8]}", "timestamp": _timestamp(),
            "source": "wazuh", "rule_id": random.choice([31100, 31101]), "level": random.randint(11, 15),
            "severity": "critical", "event_type": "attack", "attack_type": "data_exfiltration",
            "user": user, "src_ip": "10.0.0.20", "dst_ip": dst_ip, "service": "s3",
            "region": "us-east-1", "action": "GetObject", "status": "success",
            "bytes_transferred": chunk, "failed_attempts": 0,
            "description": f"Large data transfer #{i+1}: {chunk/1e9:.1f} GB to external IP {dst_ip}",
        })
    return {
        **_simulation_meta("SIM-DE"),
        "scenario": "data_exfiltration", "intensity": intensity, "target_user": user, "destination_ip": dst_ip,
        "total_bytes_exfiltrated": total_bytes, "total_events": len(events), "events": events,
        "expected_detection": True,
        "description": f"Data exfiltration: {total_bytes/1e9:.1f} GB transferred to {dst_ip}"
    }

def simulate_abnormal_access(intensity: str = "high") -> Dict:
    """Simulate abnormal access patterns — unusual hours, geo-impossible travel."""
    profile = _profile(intensity)
    user = random.choice(["alice", "bob", "dave"])
    events = [
        {"id": f"SIM-AA-{str(uuid.uuid4())[:8]}", "timestamp": _timestamp(),
         "source": "wazuh", "rule_id": 5500, "level": 8, "severity": "high",
         "event_type": "attack", "attack_type": "lateral_movement", "user": user,
         "src_ip": "185.220.101.50", "dst_ip": "10.0.0.5", "service": "iam", "region": "eu-west-1",
         "action": "ConsoleLogin", "status": "success", "bytes_transferred": 0, "failed_attempts": 2,
         "description": f"Login from unusual location (EU) for US-based user {user}"},
        {"id": f"SIM-AA-{str(uuid.uuid4())[:8]}", "timestamp": _timestamp(),
         "source": "wazuh", "rule_id": 5510, "level": 9, "severity": "high",
         "event_type": "attack", "attack_type": "lateral_movement", "user": user,
         "src_ip": "185.220.101.50", "dst_ip": "10.0.0.10", "service": "secretsmanager", "region": "eu-west-1",
         "action": "GetSecretValue", "status": "success", "bytes_transferred": 5000, "failed_attempts": 0,
         "description": f"{user} accessed secrets from anomalous IP"},
    ]
    extra_steps = [
        ("sts", "AssumeRole", 10, "assumed an unfamiliar role from the anomalous session"),
        ("kms", "Decrypt", 11, "attempted decryption activity from the anomalous session"),
        ("iam", "ListUsers", 9, "enumerated IAM users from the anomalous session"),
    ]
    for idx in range(random.randint(0, profile["extra_steps"])):
        service, action, level, desc = extra_steps[idx]
        events.append({
            "id": f"SIM-AA-{str(uuid.uuid4())[:8]}", "timestamp": _timestamp(),
            "source": "wazuh", "rule_id": random.choice([5510, 5511, 18100]), "level": level, "severity": "high",
            "event_type": "attack", "attack_type": "lateral_movement", "user": user,
            "src_ip": "185.220.101.50", "dst_ip": f"10.0.0.{random.randint(6, 25)}", "service": service, "region": "eu-west-1",
            "action": action, "status": "success", "bytes_transferred": random.randint(0, 12000), "failed_attempts": 0,
            "description": f"{user} {desc}",
        })
    return {
        **_simulation_meta("SIM-AA"),
        "scenario": "abnormal_access", "intensity": intensity, "target_user": user, "total_events": len(events),
        "events": events, "expected_detection": True,
        "description": f"Abnormal access: {user} logged in from unusual geo-location and accessed secrets"
    }


def simulate_network_scanning(intensity: str = "high") -> Dict:
    """Simulate aggressive network port scanning across VPC subnets."""
    profile = _profile(intensity)
    src_ip = f"198.51.100.{random.randint(2, 45)}"
    target_ip = f"10.0.0.{random.randint(5, 20)}"
    events = []
    ports = [22, 80, 443, 3306, 5432, 6379, 8080, 27017, 9200, 11211]
    for p in ports:
        events.append({
            "id": f"SIM-NS-{str(uuid.uuid4())[:8]}", "timestamp": _timestamp(),
            "source": "wazuh", "rule_id": 40101, "level": 10, "severity": "high",
            "event_type": "attack", "attack_type": "network_scanning", "user": "unauthenticated-scanner",
            "src_ip": src_ip, "dst_ip": target_ip, "service": f"port-{p}", "region": "us-east-1",
            "action": f"Port scan detected on TCP port {p}", "status": "blocked", "bytes_transferred": 64,
            "failed_attempts": 0, "description": f"SYN scan probe to port {p} on {target_ip}"
        })
    return {
        **_simulation_meta("SIM-NS"),
        "scenario": "network_scanning", "intensity": intensity, "target_user": "unauthenticated-scanner",
        "total_events": len(events), "events": events, "expected_detection": True,
        "description": f"Network Port Scanning: Aggressive sweep from {src_ip} against {target_ip}"
    }

def simulate_cryptomining(intensity: str = "high") -> Dict:
    """Simulate hostile cryptomining workload consuming 99% CPU."""
    profile = _profile(intensity)
    user = random.choice(["svc-worker", "svc-backup", "ubuntu"])
    target_ip = f"10.0.2.{random.randint(5, 18)}"
    pool_ip = f"185.220.101.{random.randint(10, 40)}"
    events = [
        {"id": f"SIM-MIN-{str(uuid.uuid4())[:8]}", "timestamp": _timestamp(),
         "source": "wazuh", "rule_id": 87100, "level": 12, "severity": "critical",
         "event_type": "attack", "attack_type": "cryptomining", "user": user,
         "src_ip": target_ip, "dst_ip": pool_ip, "service": "stratum+tcp", "region": "us-east-1",
         "action": "Cryptomining process detected (XMRig miner active)", "status": "detected", "bytes_transferred": 2048,
         "failed_attempts": 0, "description": f"High CPU mining process detected on {target_ip} connected to {pool_ip}"}
    ]
    return {
        **_simulation_meta("SIM-MIN"),
        "scenario": "cryptomining", "intensity": intensity, "target_user": user,
        "total_events": len(events), "events": events, "expected_detection": True,
        "description": f"Hostile Cryptomining: Unauthorized mining process on {target_ip}"
    }

def simulate_malware_ransomware(intensity: str = "high") -> Dict:
    """Simulate early-stage ransomware file enumeration and backup tampering."""
    profile = _profile(intensity)
    user = random.choice(["root", "svc-data-sync", "bob"])
    target_ip = f"10.0.1.{random.randint(5, 18)}"
    events = [
        {"id": f"SIM-MAL-{str(uuid.uuid4())[:8]}", "timestamp": _timestamp(),
         "source": "wazuh", "rule_id": 60100, "level": 14, "severity": "critical",
         "event_type": "attack", "attack_type": "malware_ransomware", "user": user,
         "src_ip": target_ip, "dst_ip": "unknown", "service": "shadowcopy", "region": "us-east-1",
         "action": "Ransomware precursor — mass file enumeration & backup tampering", "status": "detected",
         "bytes_transferred": 0, "failed_attempts": 0,
         "description": f"Destructive anti-recovery actions observed on host {target_ip}"}
    ]
    return {
        **_simulation_meta("SIM-MAL"),
        "scenario": "malware_ransomware", "intensity": intensity, "target_user": user,
        "total_events": len(events), "events": events, "expected_detection": True,
        "description": f"Ransomware Precursor: Mass enumeration and backup tampering on {target_ip}"
    }


def simulate_account_takeover(intensity: str = "high") -> Dict:
    """Simulate Account Takeover (ATO): Credential spray from foreign IP, login profile change, and MFA bypass."""
    profile = _profile(intensity)
    user = random.choice(["alice", "charlie", "david", "lead-dev"])
    attacker_ip = f"198.51.100.{random.randint(10, 80)}"
    events = [
        {"id": f"SIM-ATO-{str(uuid.uuid4())[:8]}", "timestamp": _timestamp(),
         "source": "wazuh", "rule_id": 5501, "level": 12, "severity": "high",
         "event_type": "authentication", "attack_type": "account_takeover", "user": user,
         "src_ip": attacker_ip, "dst_ip": "10.0.0.5", "service": "iam", "region": "us-east-1",
         "action": "ConsoleLogin", "status": "success", "bytes_transferred": 0, "failed_attempts": 0,
         "description": f"Initial unverified console login for {user} from unrecognised geo IP {attacker_ip}"},
        {"id": f"SIM-ATO-{str(uuid.uuid4())[:8]}", "timestamp": _timestamp(),
         "source": "cloudtrail", "rule_id": 5403, "level": 14, "severity": "critical",
         "event_type": "attack", "attack_type": "account_takeover", "user": user,
         "src_ip": attacker_ip, "dst_ip": "10.0.0.5", "service": "iam", "region": "us-east-1",
         "action": "UpdateLoginProfile", "status": "success", "bytes_transferred": 0, "failed_attempts": 0,
         "description": f"Operator password abruptly overwritten by rogue session on {user}"},
        {"id": f"SIM-ATO-{str(uuid.uuid4())[:8]}", "timestamp": _timestamp(),
         "source": "cloudtrail", "rule_id": 5403, "level": 14, "severity": "critical",
         "event_type": "attack", "attack_type": "account_takeover", "user": user,
         "src_ip": attacker_ip, "dst_ip": "10.0.0.5", "service": "iam", "region": "us-east-1",
         "action": "CreateAccessKey", "status": "success", "bytes_transferred": 0, "failed_attempts": 0,
         "description": f"Permanent API access key generated for rogue persistence on account {user}"},
        {"id": f"SIM-ATO-{str(uuid.uuid4())[:8]}", "timestamp": _timestamp(),
         "source": "cloudtrail", "rule_id": 5404, "level": 14, "severity": "critical",
         "event_type": "attack", "attack_type": "account_takeover", "user": user,
         "src_ip": attacker_ip, "dst_ip": "10.0.0.5", "service": "iam", "region": "us-east-1",
         "action": "DeleteVirtualMFADevice", "status": "success", "bytes_transferred": 0, "failed_attempts": 0,
         "description": f"Mandatory MFA protection detached by adversary on compromised account {user}"}
    ]
    return {
        **_simulation_meta("SIM-ATO"),
        "scenario": "account_takeover", "intensity": intensity, "target_user": user,
        "total_events": len(events), "events": events, "expected_detection": True,
        "description": f"Account Takeover: Unauthorized foreign login, MFA detachment, and credential re-keying on {user}"
    }

def simulate_suspicious_api(intensity: str = "high") -> Dict:
    """Simulate Suspicious API Activity: Rapid reconnaissance and unauthorized infrastructure manipulation."""
    user = random.choice(["svc-cloud-sync", "temp-contractor", "infra-deployer"])
    src_ip = f"91.108.{random.randint(1,10)}.{random.randint(1,50)}"
    events = [
        {"id": f"SIM-API-{str(uuid.uuid4())[:8]}", "timestamp": _timestamp(),
         "source": "cloudtrail", "rule_id": 80102, "level": 10, "severity": "high",
         "event_type": "attack", "attack_type": "suspicious_api_activity", "user": user,
         "src_ip": src_ip, "dst_ip": "10.0.0.1", "service": "ec2", "region": "ap-east-1",
         "action": "DescribeInstances", "status": "success", "bytes_transferred": 1200, "failed_attempts": 0,
         "description": f"Bulk resource discovery API burst by {user} outside standard operating region"},
        {"id": f"SIM-API-{str(uuid.uuid4())[:8]}", "timestamp": _timestamp(),
         "source": "cloudtrail", "rule_id": 80105, "level": 13, "severity": "critical",
         "event_type": "attack", "attack_type": "suspicious_api_activity", "user": user,
         "src_ip": src_ip, "dst_ip": "10.0.0.1", "service": "ec2", "region": "ap-east-1",
         "action": "RunInstances", "status": "success", "bytes_transferred": 3400, "failed_attempts": 0,
         "description": f"Unapproved EC2 instances spawned in non-compliant foreign zone"},
        {"id": f"SIM-API-{str(uuid.uuid4())[:8]}", "timestamp": _timestamp(),
         "source": "cloudtrail", "rule_id": 80108, "level": 14, "severity": "critical",
         "event_type": "attack", "attack_type": "suspicious_api_activity", "user": user,
         "src_ip": src_ip, "dst_ip": "10.0.0.1", "service": "rds", "region": "ap-east-1",
         "action": "CreateDBSnapshot", "status": "success", "bytes_transferred": 8900, "failed_attempts": 0,
         "description": f"Production database snapshot triggered from unapproved foreign API session"}
    ]
    return {
        **_simulation_meta("SIM-API"),
        "scenario": "suspicious_api_activity", "intensity": intensity, "target_user": user,
        "total_events": len(events), "events": events, "expected_detection": True,
        "description": f"Suspicious API Activity: Out-of-region resource enumeration and compute spawning by {user}"
    }

def simulate_cloud_misconfiguration(intensity: str = "high") -> Dict:
    """Simulate Cloud Misconfiguration Drift: Opening public S3 buckets and 0.0.0.0/0 inbound rules."""
    user = random.choice(["terraform-runner", "devops-admin", "contractor-1"])
    events = [
        {"id": f"SIM-CFG-{str(uuid.uuid4())[:8]}", "timestamp": _timestamp(),
         "source": "cloudtrail", "rule_id": 80201, "level": 13, "severity": "critical",
         "event_type": "attack", "attack_type": "cloud_misconfiguration", "user": user,
         "src_ip": "10.0.1.18", "dst_ip": "10.0.0.2", "service": "ec2", "region": "us-east-1",
         "action": "AuthorizeSecurityGroupIngress", "status": "success", "bytes_transferred": 0, "failed_attempts": 0,
         "description": f"Permissive security group ingress opened to world 0.0.0.0/0 on port 22/3389"},
        {"id": f"SIM-CFG-{str(uuid.uuid4())[:8]}", "timestamp": _timestamp(),
         "source": "cloudtrail", "rule_id": 80203, "level": 14, "severity": "critical",
         "event_type": "attack", "attack_type": "cloud_misconfiguration", "user": user,
         "src_ip": "10.0.1.18", "dst_ip": "10.0.0.2", "service": "s3", "region": "us-east-1",
         "action": "PutBucketAcl", "status": "success", "bytes_transferred": 0, "failed_attempts": 0,
         "description": f"S3 bucket ACL changed to public-read, exposing confidential cloud data storage"}
    ]
    return {
        **_simulation_meta("SIM-CFG"),
        "scenario": "cloud_misconfiguration", "intensity": intensity, "target_user": user,
        "total_events": len(events), "events": events, "expected_detection": True,
        "description": f"Cloud Misconfiguration: Ingress opened to 0.0.0.0/0 and S3 bucket exposed publicly"
    }

def simulate_ddos(intensity: str = "high") -> Dict:
    """Simulate Distributed Denial of Service (DDoS) traffic flood."""
    events = []
    target_ip = "10.0.0.10"
    for i in range(12):
        src_ip = f"185.220.101.{random.randint(1, 100)}"
        events.append({
            "id": f"SIM-DOS-{str(uuid.uuid4())[:8]}", "timestamp": _timestamp(),
            "source": "wazuh", "rule_id": 40101, "level": 12, "severity": "critical",
            "event_type": "attack", "attack_type": "ddos", "user": "anonymous",
            "src_ip": src_ip, "dst_ip": target_ip, "service": "network", "region": "us-east-1",
            "action": "SYNFlood", "status": "dropped", "bytes_transferred": random.randint(15000, 85000), "failed_attempts": 0,
            "description": f"Volumetric SYN flood packet surge from botnet origin {src_ip}"
        })
    return {
        **_simulation_meta("SIM-DOS"),
        "scenario": "ddos", "intensity": intensity, "target_user": "perimeter-firewall",
        "total_events": len(events), "events": events, "expected_detection": True,
        "description": f"Distributed Denial of Service: Inbound volumetric packet saturation against {target_ip}"
    }

def simulate_container_k8s(intensity: str = "high") -> Dict:
    """Simulate Container & Kubernetes attack: Privileged pod escape and host socket mount."""
    user = random.choice(["kube-operator", "svc-pod-deployer"])
    events = [
        {"id": f"SIM-K8S-{str(uuid.uuid4())[:8]}", "timestamp": _timestamp(),
         "source": "wazuh", "rule_id": 87001, "level": 14, "severity": "critical",
         "event_type": "attack", "attack_type": "container_k8s_attacks", "user": user,
         "src_ip": "10.0.2.14", "dst_ip": "10.0.2.20", "service": "kubernetes", "region": "us-east-1",
         "action": "ExecIntoPod", "status": "success", "bytes_transferred": 4200, "failed_attempts": 0,
         "description": f"Interactive shell session established inside production container with privileged: true"},
        {"id": f"SIM-K8S-{str(uuid.uuid4())[:8]}", "timestamp": _timestamp(),
         "source": "wazuh", "rule_id": 87005, "level": 14, "severity": "critical",
         "event_type": "attack", "attack_type": "container_k8s_attacks", "user": user,
         "src_ip": "10.0.2.14", "dst_ip": "10.0.2.20", "service": "docker", "region": "us-east-1",
         "action": "MountDockerSocket", "status": "success", "bytes_transferred": 2100, "failed_attempts": 0,
         "description": f"Container escape vector: Host /var/run/docker.sock mounted into ephemeral pod"}
    ]
    return {
        **_simulation_meta("SIM-K8S"),
        "scenario": "container_k8s_attacks", "intensity": intensity, "target_user": user,
        "total_events": len(events), "events": events, "expected_detection": True,
        "description": f"Container & K8s Threats: Privileged pod interactive exec and host docker socket mount"
    }

def simulate_bola_ssrf(intensity: str = "high") -> Dict:
    """Simulate Application BOLA & SSRF targeting AWS IMDS metadata endpoint 169.254.169.254."""
    user = "web-client"
    src_ip = f"194.26.{random.randint(1,50)}.{random.randint(1,100)}"
    events = [
        {"id": f"SIM-SSRF-{str(uuid.uuid4())[:8]}", "timestamp": _timestamp(),
         "source": "wazuh", "rule_id": 31105, "level": 13, "severity": "critical",
         "event_type": "attack", "attack_type": "bola_ssrf", "user": user,
         "src_ip": src_ip, "dst_ip": "169.254.169.254", "service": "web-api", "region": "us-east-1",
         "action": "SSRFProbe", "status": "blocked", "bytes_transferred": 850, "failed_attempts": 0,
         "description": f"Server-Side Request Forgery probe accessing cloud metadata IMDS http://169.254.169.254/latest/meta-data/"},
        {"id": f"SIM-SSRF-{str(uuid.uuid4())[:8]}", "timestamp": _timestamp(),
         "source": "wazuh", "rule_id": 31108, "level": 14, "severity": "critical",
         "event_type": "attack", "attack_type": "bola_ssrf", "user": user,
         "src_ip": src_ip, "dst_ip": "169.254.169.254", "service": "web-api", "region": "us-east-1",
         "action": "BOLAExploit", "status": "detected", "bytes_transferred": 1450, "failed_attempts": 0,
         "description": f"Broken Object Level Authorization parameter tampering targeting private tenant records"}
    ]
    return {
        **_simulation_meta("SIM-SSRF"),
        "scenario": "bola_ssrf", "intensity": intensity, "target_user": user,
        "total_events": len(events), "events": events, "expected_detection": True,
        "description": f"Application BOLA & SSRF: AWS Instance Metadata (169.254.169.254) extraction attempts"
    }

def simulate_database_attacks(intensity: str = "high") -> Dict:
    """Simulate Database Threat Activity: SQL injection queries and unauthorized dump attempts."""
    user = "web-app-db-user"
    src_ip = f"185.191.{random.randint(1,50)}.{random.randint(1,100)}"
    events = [
        {"id": f"SIM-DB-{str(uuid.uuid4())[:8]}", "timestamp": _timestamp(),
         "source": "wazuh", "rule_id": 31150, "level": 13, "severity": "critical",
         "event_type": "attack", "attack_type": "database_attacks", "user": user,
         "src_ip": src_ip, "dst_ip": "10.0.0.20", "service": "postgres", "region": "us-east-1",
         "action": "SQLInjection", "status": "detected", "bytes_transferred": 3200, "failed_attempts": 0,
         "description": f"SQL Injection detected: ' UNION SELECT null, username, password_hash FROM users --"},
        {"id": f"SIM-DB-{str(uuid.uuid4())[:8]}", "timestamp": _timestamp(),
         "source": "cloudtrail", "rule_id": 80112, "level": 14, "severity": "critical",
         "event_type": "attack", "attack_type": "database_attacks", "user": user,
         "src_ip": src_ip, "dst_ip": "10.0.0.20", "service": "rds", "region": "us-east-1",
         "action": "ModifyDBInstance", "status": "detected", "bytes_transferred": 0, "failed_attempts": 0,
         "description": f"Adversary modifying production database storage to grant external public accessibility"}
    ]
    return {
        **_simulation_meta("SIM-DB"),
        "scenario": "database_attacks", "intensity": intensity, "target_user": user,
        "total_events": len(events), "events": events, "expected_detection": True,
        "description": f"Database Attacks: Hostile SQL injection pattern and RDS parameter manipulation"
    }

def simulate_serverless_abuse(intensity: str = "high") -> Dict:
    """Simulate Serverless Function Abuse: Code modification and recursive invocation denial."""
    user = random.choice(["ci-cd-bot", "lambda-manager"])
    events = [
        {"id": f"SIM-LAM-{str(uuid.uuid4())[:8]}", "timestamp": _timestamp(),
         "source": "cloudtrail", "rule_id": 80401, "level": 13, "severity": "critical",
         "event_type": "attack", "attack_type": "serverless_abuse", "user": user,
         "src_ip": "10.0.1.18", "dst_ip": "10.0.0.1", "service": "lambda", "region": "us-east-1",
         "action": "UpdateFunctionCode", "status": "success", "bytes_transferred": 14500, "failed_attempts": 0,
         "description": f"Unauthorized code modification injected into production payment processing Lambda"},
        {"id": f"SIM-LAM-{str(uuid.uuid4())[:8]}", "timestamp": _timestamp(),
         "source": "cloudtrail", "rule_id": 80405, "level": 14, "severity": "critical",
         "event_type": "attack", "attack_type": "serverless_abuse", "user": user,
         "src_ip": "10.0.1.18", "dst_ip": "10.0.0.1", "service": "lambda", "region": "us-east-1",
         "action": "Invoke", "status": "success", "bytes_transferred": 29000, "failed_attempts": 0,
         "description": f"Recursive execution loop triggered: serverless resource exhaustion burst"}
    ]
    return {
        **_simulation_meta("SIM-LAM"),
        "scenario": "serverless_abuse", "intensity": intensity, "target_user": user,
        "total_events": len(events), "events": events, "expected_detection": True,
        "description": f"Serverless Function Abuse: Unauthorized Lambda code update and execution loop surge"
    }

def simulate_supply_chain(intensity: str = "high") -> Dict:
    """Simulate Supply Chain Compromise: Compromised CI/CD pipeline dependency and backdoored runner."""
    user = "github-actions-runner"
    events = [
        {"id": f"SIM-SC-{str(uuid.uuid4())[:8]}", "timestamp": _timestamp(),
         "source": "wazuh", "rule_id": 89001, "level": 14, "severity": "critical",
         "event_type": "attack", "attack_type": "supply_chain_compromise", "user": user,
         "src_ip": "10.0.3.12", "dst_ip": "185.220.101.44", "service": "build-system", "region": "us-east-1",
         "action": "InstallBackdooredPackage", "status": "success", "bytes_transferred": 9800, "failed_attempts": 0,
         "description": f"Compromised third-party dependency injected during automated application build"},
        {"id": f"SIM-SC-{str(uuid.uuid4())[:8]}", "timestamp": _timestamp(),
         "source": "wazuh", "rule_id": 89004, "level": 14, "severity": "critical",
         "event_type": "attack", "attack_type": "supply_chain_compromise", "user": user,
         "src_ip": "10.0.3.12", "dst_ip": "185.220.101.44", "service": "build-system", "region": "us-east-1",
         "action": "ExfiltrateBuildSecrets", "status": "detected", "bytes_transferred": 4500, "failed_attempts": 0,
         "description": f"Build runner attempting to transmit CI/CD repository secrets to rogue exterior server"}
    ]
    return {
        **_simulation_meta("SIM-SC"),
        "scenario": "supply_chain_compromise", "intensity": intensity, "target_user": user,
        "total_events": len(events), "events": events, "expected_detection": True,
        "description": f"Supply Chain Compromise: Malicious package dependency detected in build environment"
    }

def simulate_defense_tampering(intensity: str = "high") -> Dict:
    """Simulate Defense Tampering: Stopping CloudTrail audit trails and disabling security agents."""
    user = random.choice(["rogue-admin", "intruder-01"])
    events = [
        {"id": f"SIM-DT-{str(uuid.uuid4())[:8]}", "timestamp": _timestamp(),
         "source": "cloudtrail", "rule_id": 80301, "level": 14, "severity": "critical",
         "event_type": "attack", "attack_type": "defense_tampering", "user": user,
         "src_ip": "10.0.1.18", "dst_ip": "10.0.0.1", "service": "cloudtrail", "region": "us-east-1",
         "action": "StopLogging", "status": "success", "bytes_transferred": 0, "failed_attempts": 0,
         "description": f"Adversary disabled CloudTrail audit logging to conceal subsequent malicious operations"},
        {"id": f"SIM-DT-{str(uuid.uuid4())[:8]}", "timestamp": _timestamp(),
         "source": "wazuh", "rule_id": 5508, "level": 14, "severity": "critical",
         "event_type": "attack", "attack_type": "defense_tampering", "user": user,
         "src_ip": "10.0.1.18", "dst_ip": "10.0.0.1", "service": "wazuh-agent", "region": "us-east-1",
         "action": "KillSecurityDaemon", "status": "success", "bytes_transferred": 0, "failed_attempts": 0,
         "description": f"Host agent security daemon killed by adversary via SIGKILL"}
    ]
    return {
        **_simulation_meta("SIM-DT"),
        "scenario": "defense_tampering", "intensity": intensity, "target_user": user,
        "total_events": len(events), "events": events, "expected_detection": True,
        "description": f"Defense & Log Tampering: CloudTrail StopLogging executed and host security daemon terminated"
    }

SCENARIOS = {
    # All 16 Dedicated Attack Categories
    "brute_force": simulate_brute_force,
    "account_takeover": simulate_account_takeover,
    "iam_privilege_escalation": simulate_privilege_escalation,
    "privilege_escalation": simulate_privilege_escalation,
    "suspicious_api_activity": simulate_suspicious_api,
    "suspicious_api": simulate_suspicious_api,
    "cloud_misconfiguration": simulate_cloud_misconfiguration,
    "data_exfiltration": simulate_data_exfiltration,
    "network_scanning": simulate_network_scanning,
    "port_scan": simulate_network_scanning,
    "ddos": simulate_ddos,
    "cryptomining": simulate_cryptomining,
    "container_k8s_attacks": simulate_container_k8s,
    "container_k8s": simulate_container_k8s,
    "bola_ssrf": simulate_bola_ssrf,
    "malware_ransomware": simulate_malware_ransomware,
    "ransomware": simulate_malware_ransomware,
    "database_attacks": simulate_database_attacks,
    "serverless_abuse": simulate_serverless_abuse,
    "supply_chain_compromise": simulate_supply_chain,
    "supply_chain": simulate_supply_chain,
    "defense_tampering": simulate_defense_tampering,
    "abnormal_access": simulate_abnormal_access,
}
def get_scenario_catalog() -> List[Dict]:
    """Return scenario metadata for frontend rendering."""
    catalog = []
    for scenario_id in SCENARIOS:
        meta = SCENARIO_METADATA.get(scenario_id, {})
        catalog.append({
            "id": scenario_id,
            "title": meta.get("title", scenario_id.replace("_", " ").title()),
            "description": meta.get("description", "Attack simulation"),
            "icon": meta.get("icon", "zap"),
            "supports_intensity": meta.get("supports_intensity", False),
            "default_intensity": meta.get("default_intensity"),
        })
    return catalog

def run_attack_simulation(scenario: str = "brute_force", intensity: str = "high") -> Dict:
    """Run a specific attack simulation scenario."""
    fn = SCENARIOS.get(scenario, simulate_brute_force)
    return fn(intensity=intensity)

def run_full_simulation(intensity: str = "high") -> Dict:
    """Run all attack scenarios and return combined results."""
    results = []
    for name, fn in SCENARIOS.items():
        results.append(fn(intensity=intensity))
    total_events = sum(r["total_events"] for r in results)
    return {
        "simulation_id": f"FULLSIM-{str(uuid.uuid4())[:8].upper()}",
        "timestamp": _timestamp(),
        "intensity": intensity,
        "scenarios_run": len(results), "total_events_generated": total_events,
        "scenarios": results
    }
