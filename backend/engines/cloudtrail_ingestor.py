"""
AWS CloudTrail Event Ingestion & Attack Correlation Pipeline
============================================================
Parses real AWS CloudTrail audit logs from S3, EventBridge, SQS, or direct JSON payloads,
maps them to the unified NormalizedEvent schema, and routes them through the 16 modular attack detectors.
"""
import uuid
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Union

from schemas.event import NormalizedEvent, PrincipalInfo, NetworkInfo, EventProvenance
from schemas.finding import SecurityFinding
from engines.base_detector import detector_registry
import engines.detectors  # Register all 16 modular attack detectors
from engines.db import save_findings_db


def normalize_cloudtrail_record(raw: Dict[str, Any]) -> NormalizedEvent:
    """
    Translates an authoritative AWS CloudTrail JSON record into a NormalizedEvent.
    Handles AWS user identities, request parameters, source IPs, and event verbs.
    """
    if not isinstance(raw, dict):
        return NormalizedEvent(description="Invalid CloudTrail payload", status="error")

    # If already a NormalizedEvent dictionary
    if "principal" in raw and "source_type" in raw:
        from schemas.event import normalize_event
        return normalize_event(raw)

    event_id = str(raw.get("eventID") or raw.get("id") or f"CT-{str(uuid.uuid4())[:8]}")

    # Timestamp parsing
    ts_val = raw.get("eventTime") or raw.get("timestamp") or datetime.now(timezone.utc)
    if isinstance(ts_val, str):
        try:
            clean_ts = ts_val.replace("Z", "+00:00")
            event_ts = datetime.fromisoformat(clean_ts)
            if not event_ts.tzinfo:
                event_ts = event_ts.replace(tzinfo=timezone.utc)
        except Exception:
            event_ts = datetime.now(timezone.utc)
    elif isinstance(ts_val, datetime):
        event_ts = ts_val if ts_val.tzinfo else ts_val.replace(tzinfo=timezone.utc)
    else:
        event_ts = datetime.now(timezone.utc)

    # Principal Extraction
    user_identity = raw.get("userIdentity", {})
    principal_id = (
        user_identity.get("userName") or
        user_identity.get("principalId") or
        user_identity.get("arn", "").split("/")[-1] or
        "unknown"
    )
    principal_arn = user_identity.get("arn")
    principal_type = user_identity.get("type", "IAMUser")

    principal = PrincipalInfo(
        identity=str(principal_id),
        principal_type=str(principal_type),
        arn=principal_arn
    )

    # Network
    src_ip = raw.get("sourceIPAddress", "unknown")
    network = NetworkInfo(
        src_ip=str(src_ip),
        dst_ip="aws.internal",
        protocol="HTTPS"
    )

    # Action & Service
    event_source = raw.get("eventSource", "aws.general")
    service_name = event_source.split(".")[0] if "." in event_source else event_source
    action_name = raw.get("eventName", "unknown")

    # Status & Error
    has_error = bool(raw.get("errorCode") or raw.get("errorMessage"))
    is_console_login_failure = (
        action_name.lower() == "consolelogin" and
        isinstance(raw.get("responseElements"), dict) and
        raw.get("responseElements", {}).get("ConsoleLogin") == "Failure"
    )
    status = "failure" if (has_error or is_console_login_failure) else "success"

    # Target Resource
    target_res = None
    resources = raw.get("resources", [])
    if resources and isinstance(resources, list):
        target_res = resources[0].get("ARN") or resources[0].get("resourceName")
    
    req_params = raw.get("requestParameters", {}) or {}
    if not target_res and isinstance(req_params, dict):
        target_res = (
            req_params.get("bucketName") or
            req_params.get("policyArn") or
            req_params.get("roleName") or
            req_params.get("userName") or
            req_params.get("groupName")
        )

    # Severity mapping
    severity = "low"
    act_lower = action_name.lower()
    if is_console_login_failure:
        severity = "medium"
    elif any(k in act_lower for k in ("attachuserpolicy", "putuserpolicy", "createpolicyversion", "attachrolepolicy")):
        severity = "high"
    elif any(k in act_lower for k in ("deleteflowlogs", "stoplogging", "deletetrail")):
        severity = "critical"
    elif any(k in act_lower for k in ("authorizesecuritygroupingress", "putbucketacl", "putbucketpolicy")):
        severity = "medium"

    provenance = EventProvenance(
        collector="aws_cloudtrail_connector",
        ingest_mode="live" if not raw.get("simulated") else "simulated"
    )

    return NormalizedEvent(
        event_id=event_id,
        timestamp=event_ts,
        source_type="cloudtrail",
        source_identifier=str(raw.get("awsRegion") or "us-east-1"),
        principal=principal,
        network=network,
        service=service_name,
        action=action_name,
        target_resource=str(target_res or f"aws:{service_name}:resource"),
        status=status,
        failed_attempts=1 if status == "failure" else 0,
        count=1,
        srv_count=1,
        description=f"AWS CloudTrail {action_name} executed by {principal_id} ({status})",
        severity=severity,
        provenance=provenance,
        raw_payload=raw
    )


def ingest_cloudtrail_events(
    records: Union[Dict[str, Any], List[Dict[str, Any]]],
    save_to_database: bool = True
) -> Dict[str, Any]:
    """
    Ingest a batch of CloudTrail records, normalize them, and execute the 16 attack detectors.
    Optionally saves generated findings to SQLite for dashboard display.
    """
    # Accept standard CloudTrail {"Records": [...]} wrapper or direct list
    if isinstance(records, dict):
        if "Records" in records and isinstance(records["Records"], list):
            raw_list = records["Records"]
        else:
            raw_list = [records]
    elif isinstance(records, list):
        raw_list = records
    else:
        return {"status": "error", "message": "Invalid records format", "findings": []}

    normalized_events: List[NormalizedEvent] = []
    for r in raw_list:
        if isinstance(r, dict):
            normalized_events.append(normalize_cloudtrail_record(r))

    if not normalized_events:
        return {"status": "success", "ingested_count": 0, "findings": []}

    # Run through the 16 modular attack detectors
    findings: List[SecurityFinding] = detector_registry.run_all(normalized_events)

    # Persist findings to database
    persisted_count = 0
    if save_to_database and findings:
        findings_payload = [f.model_dump() if hasattr(f, "model_dump") else dict(f) for f in findings]
        try:
            save_findings_db(findings_payload)
            persisted_count = len(findings_payload)
        except Exception as e:
            print(f"[CloudTrail Ingestor] Could not save findings: {e}")

    return {
        "status": "success",
        "ingested_count": len(normalized_events),
        "findings_count": len(findings),
        "persisted_count": persisted_count,
        "findings": [f.model_dump() if hasattr(f, "model_dump") else dict(f) for f in findings]
    }
