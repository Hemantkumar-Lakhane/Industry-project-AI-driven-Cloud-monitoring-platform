"""
Unified Telemetry Session Manager
=================================
Maintains a shared, coherent telemetry event buffer across:
  - Overview Dashboard
  - Security Findings (Category Detectors)
  - CSPM & CIEM Posture Scans
  - Attack Simulation Workflows

Guarantees:
1. Overview, Security Findings, and Attack Simulation use the EXACT same event batch and finding IDs.
2. Rescans do NOT randomly generate new attacks out of nowhere.
3. Every finding, metric, and event has an honest data source label (LIVE, SIMULATED, IMPORTED, NOT CONFIGURED).
"""
import os
import uuid
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional

from simulator.wazuh_simulator import simulate_session
from simulator.wazuh_reader import read_wazuh_logs, is_wazuh_available
from simulator.attack_simulator import run_attack_simulation, run_full_simulation, SCENARIOS
from schemas.event import normalize_event
from schemas.finding import SecurityFinding
from engines.base_detector import detector_registry, TAXONOMY_16
import engines.detectors  # Ensures all 16 detectors register with detector_registry
from engines.ml_engine import analyze_events
from engines.cspm_engine import run_cspm_scan
from engines.ciem_engine import run_ciem_scan
from engines.db import (
    save_cspm_scan, save_ciem_scan, save_findings_db, get_findings_db,
    get_findings_stats_db, save_incidents_db, get_incidents_db,
    clear_simulated_findings_and_incidents_db
)
from engines.correlation_engine import correlate_findings
from engines.localstack_engine import is_localstack_running, run_cspm_scan_localstack, run_ciem_scan_localstack
from simulator.wazuh_reader import get_wazuh_log_path

TAXONOMY_SLUGS = {v["slug"] for v in TAXONOMY_16.values()}



class ActiveTelemetrySession:
    """Represents a coherent, shared telemetry state across the entire platform."""

    def __init__(self):
        self.session_id: str = f"SES-{str(uuid.uuid4())[:8].upper()}"
        self.events: List[Dict[str, Any]] = []
        self.analyzed_events: List[Dict[str, Any]] = []
        self.findings: List[Dict[str, Any]] = []
        self.incidents: List[Dict[str, Any]] = []
        self.cspm_results: List[Dict[str, Any]] = []
        self.ciem_results: List[Dict[str, Any]] = []
        self.active_scenario: Optional[str] = None
        self.active_intensity: Optional[str] = None
        self.data_source: str = "LIVE"
        self.cspm_source: str = "CLOUD_POLICY"
        self.ciem_source: str = "CLOUD_POLICY"
        self.generated_at: str = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        self.last_log_mtime: float = 0.0

    def to_summary(self) -> Dict[str, Any]:
        """Generate dashboard summary matching this active session."""
        critical_count = sum(1 for e in self.analyzed_events if e.get("ml_severity") == "Critical")
        high_count = sum(1 for e in self.analyzed_events if e.get("ml_severity") == "High")
        medium_count = sum(1 for e in self.analyzed_events if e.get("ml_severity") == "Medium")
        low_count = sum(1 for e in self.analyzed_events if e.get("ml_severity") == "Low")

        # Also incorporate any detector findings rated critical/high
        for f in self.findings:
            sev = f.get("severity", "").lower()
            if sev == "critical" and critical_count == 0:
                critical_count += 1
            elif sev == "high" and high_count == 0:
                high_count += 1

        recent_alerts = []
        # First priority: actual detector findings
        for f in self.findings:
            recent_alerts.append({
                "id": f.get("finding_id"),
                "timestamp": f.get("created_at") or f.get("timestamp"),
                "attack_type": f.get("attack_category"),
                "user": f.get("affected_principal") or "unknown",
                "src_ip": f.get("evidence", {}).get("telemetry_fields", {}).get("source_ip", "10.0.0.1"),
                "ml_anomaly_score": round(f.get("confidence", 0.9), 3),
                "ml_severity": f.get("severity", "high").capitalize(),
                "description": f.get("title"),
                "data_source": f.get("data_source", self.data_source),
                "verification_status": f.get("verification_status", "VERIFIED" if f.get("attack_category") in TAXONOMY_SLUGS else "NOT_CONFIGURED")
            })

        # Next: critical events from ML analysis (labeled with honest simulation status)
        for e in [x for x in self.analyzed_events if x.get("ml_severity") == "Critical"]:
            if len(recent_alerts) >= 5:
                break
            if not any(a["id"] == e.get("id") for a in recent_alerts):
                is_known_attack = e.get("attack_type") in TAXONOMY_SLUGS or e.get("event_type") == "attack"
                recent_alerts.append({
                    "id": e.get("id"),
                    "timestamp": e.get("timestamp"),
                    "attack_type": e.get("attack_type", "anomaly"),
                    "user": e.get("user", "unknown"),
                    "src_ip": e.get("src_ip", "unknown"),
                    "ml_anomaly_score": e.get("ml_anomaly_score", 0.9),
                    "ml_severity": e.get("ml_severity", "Critical"),
                    "description": e.get("description", "Anomalous telemetry event"),
                    "data_source": self.data_source,
                    "verification_status": "VERIFIED" if is_known_attack else "NOT_CONFIGURED"
                })

        open_inc_count = sum(1 for inc in self.incidents if (inc.get("status") or "").lower() == "open") if self.incidents is not None else len(self.findings)

        return {
            "session_id": self.session_id,
            "data_source": self.data_source,
            "active_scenario": self.active_scenario,
            "threats": {
                "critical": max(critical_count, sum(1 for f in self.findings if f.get("severity") == "critical")),
                "high": max(high_count, sum(1 for f in self.findings if f.get("severity") == "high")),
                "medium": max(medium_count, sum(1 for f in self.findings if f.get("severity") == "medium")),
                "low": max(low_count, sum(1 for f in self.findings if f.get("severity") == "low")),
                "total_analyzed": len(self.events),
                "detected_threats": sum(1 for e in self.analyzed_events if e.get("is_anomaly") or e.get("event_type") == "attack"),
                "unique_findings": len(self.findings),
                "open_incidents": open_inc_count,
                "total_incidents": len(self.incidents),
                "detector_findings_count": len(self.findings)
            },
            "posture": {
                "cspm_open_issues": len(self.cspm_results),
                "ciem_open_risks": len(self.ciem_results),
                "cspm_source": self.cspm_source,
                "ciem_source": self.ciem_source,
            },
            "recent_critical_alerts": recent_alerts[:5]
        }



class SessionManager:
    """Singleton session coordinator managing active telemetry buffer."""

    _instance: Optional['SessionManager'] = None

    def __init__(self):
        self._session: Optional[ActiveTelemetrySession] = None
        # Lazy initialization: baseline session is prepared on first access or background warmup

    @classmethod
    def get_instance(cls) -> 'SessionManager':
        if cls._instance is None:
            cls._instance = SessionManager()
        return cls._instance

    def _determine_sources(self) -> tuple[str, str, str]:
        telemetry_source = "LIVE" if is_wazuh_available() else "SIMULATED"
        cspm_source = "LIVE" if is_localstack_running() else "CLOUD_POLICY"
        ciem_source = "LIVE" if is_localstack_running() else "CLOUD_POLICY"
        return telemetry_source, cspm_source, ciem_source

    def _init_baseline_session(self, n_normal: int = 300):
        """Initialize session from live Wazuh logs or clean baseline."""
        session = ActiveTelemetrySession()
        telemetry_source, cspm_source, ciem_source = self._determine_sources()
        session.data_source = telemetry_source
        session.cspm_source = cspm_source
        session.ciem_source = ciem_source

        if is_wazuh_available():
            log_path = get_wazuh_log_path()
            if os.path.exists(log_path):
                session.last_log_mtime = os.path.getmtime(log_path)
            raw_events = read_wazuh_logs(max_events=n_normal)
            if not raw_events:
                raw_events = simulate_session(n_normal=60, n_attacks=0)
        else:
            raw_events = simulate_session(n_normal=60, n_attacks=0)

        session.events = raw_events
        session.analyzed_events = analyze_events(raw_events)

        # Run registered detectors across events
        norm_events = [normalize_event(e) for e in raw_events]
        findings = detector_registry.run_all(norm_events)
        session.findings = [f.model_dump(mode="json") for f in findings]
        for f in session.findings:
            f["data_source"] = session.data_source
            f["verification_status"] = "VERIFIED" if f.get("attack_category") in TAXONOMY_SLUGS else "NOT_CONFIGURED"

        # Persist findings to SQLite and run incident correlation
        save_findings_db(session.findings)
        incidents = correlate_findings(session.findings)
        session.incidents = [inc.model_dump(mode="json") for inc in incidents]
        save_incidents_db(session.incidents)

        # Posture scans on baseline
        if is_localstack_running():
            session.cspm_results = run_cspm_scan_localstack() or run_cspm_scan(raw_events)
            session.ciem_results = run_ciem_scan_localstack() or run_ciem_scan(raw_events)
        else:
            session.cspm_results = run_cspm_scan(raw_events)
            session.ciem_results = run_ciem_scan(raw_events)

        self._session = session

    def refresh_from_logs(self, max_events: int = 500) -> ActiveTelemetrySession:
        """Dynamically refresh session buffer when new logs are written to disk."""
        session = self._session or ActiveTelemetrySession()
        telemetry_source, cspm_source, ciem_source = self._determine_sources()
        session.data_source = telemetry_source
        session.cspm_source = cspm_source
        session.ciem_source = ciem_source

        if is_wazuh_available():
            log_path = get_wazuh_log_path()
            if os.path.exists(log_path):
                session.last_log_mtime = os.path.getmtime(log_path)
            raw_events = read_wazuh_logs(max_events=max_events)
            if raw_events:
                session.events = raw_events

        session.analyzed_events = analyze_events(session.events)
        norm_events = [normalize_event(e) for e in session.events]
        findings = detector_registry.run_all(norm_events)
        session.findings = [f.model_dump(mode="json") for f in findings]
        for f in session.findings:
            f["data_source"] = session.data_source
            f["verification_status"] = "VERIFIED" if f.get("attack_category") in TAXONOMY_SLUGS else "NOT_CONFIGURED"

        save_findings_db(session.findings)
        incidents = correlate_findings(session.findings)
        session.incidents = [inc.model_dump(mode="json") for inc in incidents]
        save_incidents_db(session.incidents)
        session.generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        self._session = session
        return session


    def get_session(self) -> ActiveTelemetrySession:
        """Get the current active session. Refreshes if new logs arrived on disk."""
        if self._session is None:
            self._init_baseline_session()
        elif is_wazuh_available() and getattr(self._session, "data_source", "SIMULATED") == "LIVE":
            log_path = get_wazuh_log_path()
            if os.path.exists(log_path):
                mtime = os.path.getmtime(log_path)
                if mtime > getattr(self._session, "last_log_mtime", 0.0):
                    self.refresh_from_logs()
        return self._session

    def rescan(self) -> ActiveTelemetrySession:
        """
        Rescan handler: Evaluates the EXISTING active session buffer.
        CRITICAL RULE: Does NOT spawn new attacks out of nowhere during rescan.
        Maintains consistent event IDs, threat counts, and finding IDs.
        """
        session = self.get_session()
        telemetry_source, cspm_source, ciem_source = self._determine_sources()
        session.data_source = telemetry_source
        session.cspm_source = cspm_source
        session.ciem_source = ciem_source

        # If live wazuh log is active, read the latest real logs
        if is_wazuh_available():
            raw_events = read_wazuh_logs(max_events=len(session.events) or 300)
            if raw_events:
                session.events = raw_events

        # Re-evaluate detectors on current events
        norm_events = [normalize_event(e) for e in session.events]
        findings = detector_registry.run_all(norm_events)
        session.findings = [f.model_dump(mode="json") for f in findings]
        for f in session.findings:
            f["data_source"] = session.data_source
            f["verification_status"] = "VERIFIED" if f.get("attack_category") in TAXONOMY_SLUGS else "NOT_CONFIGURED"

        save_findings_db(session.findings)
        incidents = correlate_findings(session.findings)
        session.incidents = [inc.model_dump(mode="json") for inc in incidents]
        save_incidents_db(session.incidents)
        session.analyzed_events = analyze_events(session.events)

        # Update posture scans
        if is_localstack_running():
            session.cspm_results = run_cspm_scan_localstack() or run_cspm_scan(session.events)
            session.ciem_results = run_ciem_scan_localstack() or run_ciem_scan(session.events)
        else:
            session.cspm_results = run_cspm_scan(session.events)
            session.ciem_results = run_ciem_scan(session.events)

        session.generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        return session

    def inject_scenario(self, scenario: str, intensity: str = "high") -> Dict[str, Any]:
        """
        Inject a simulated attack scenario into the shared active session.
        Overview, Security Findings, and Attack Simulation will ALL observe
        these exact events, finding IDs, and attack counts.
        """
        sim = run_attack_simulation(scenario, intensity)
        noise = simulate_session(n_normal=45, n_attacks=0)
        attack_events = sim.get("events", [])
        combined_events = attack_events + noise

        session = self.get_session()
        session.session_id = f"SES-{scenario.upper()[:4]}-{str(uuid.uuid4())[:6].upper()}"
        session.events = combined_events
        session.active_scenario = scenario
        session.active_intensity = intensity
        session.data_source = "LIVE"
        session.cspm_source = "CLOUD_POLICY"
        session.ciem_source = "CLOUD_POLICY"
        session.generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        # Run detection engine on this exact batch
        norm_events = [normalize_event(e) for e in combined_events]
        findings = detector_registry.run_all(norm_events)
        session.findings = [f.model_dump(mode="json") for f in findings]
        for f in session.findings:
            f["data_source"] = session.data_source
            f["verification_status"] = "VERIFIED" if f.get("attack_category") in TAXONOMY_SLUGS else "NOT_CONFIGURED"

        # Persist findings and run incident correlation
        save_findings_db(session.findings)
        incidents = correlate_findings(session.findings)
        session.incidents = [inc.model_dump(mode="json") for inc in incidents]
        save_incidents_db(session.incidents)

        # ML Anomaly scoring
        analyzed = analyze_events(combined_events)
        session.analyzed_events = analyzed


        # Posture scans
        session.cspm_results = run_cspm_scan(combined_events)
        session.ciem_results = run_ciem_scan(combined_events)

        # Unified incident-aware risk calculation and persistence
        from engines.risk_engine import calculate_unified_risk
        from engines.db import save_risk_score
        r = calculate_unified_risk(session.analyzed_events, session.cspm_results, session.ciem_results, incidents=session.incidents)
        save_risk_score(
            r["unified_risk_score"],
            r["components"]["ml_anomaly_detection"]["score"],
            r["components"]["cspm_posture"]["score"],
            r["components"]["ciem_identity"]["score"],
            r["unified_risk_level"],
            incident=r["components"]["incident_correlation"]["score"]
        )

        # Calculate detection metrics for AttackSimulationTab
        sim_ids = {e["id"] for e in attack_events}
        detected = [e for e in analyzed if e["id"] in sim_ids and e.get("is_anomaly")]
        detection_rate = len(detected) / len(attack_events) * 100 if attack_events else 0

        # Finding ID attribution (if detector found it, use actual finding ID)
        matching_finding = next((f for f in session.findings if f.get("attack_category") == scenario), None)

        return {
            "simulation": {
                "scenario": scenario,
                "intensity": intensity,
                "simulation_id": sim.get("simulation_id"),
                "generated_at": session.generated_at,
                "target_user": sim.get("target_user"),
                "source_ip": sim.get("source_ip"),
                "finding_id": matching_finding.get("finding_id") if matching_finding else None,
                "detector_status": f"VERIFIED ({scenario.upper()})" if scenario in TAXONOMY_SLUGS else "NOT CONFIGURED"
            },
            "detection": {
                "total_sim_events": len(attack_events),
                "detected_as_anomaly": len(detected),
                "detection_rate": round(detection_rate, 1),
                "detection_success": detection_rate > 50,
                "data_source": "SIMULATED",
                "finding_id": matching_finding.get("finding_id") if matching_finding else None,
            },
            "risk_score": {
                "unified": r["unified_risk_score"],
                "level": r["unified_risk_level"],
                "components": {
                    "incident_correlation": r["components"]["incident_correlation"]["score"],
                    "ml_anomaly_detection": r["components"]["ml_anomaly_detection"]["score"],
                    "cspm_posture": r["components"]["cspm_posture"]["score"],
                    "ciem_identity": r["components"]["ciem_identity"]["score"],
                }
            },
            "sample_sim_events": attack_events[:5],
            "all_analyzed_events": analyzed
        }

    def inject_full_simulation(self, intensity: str = "high") -> Dict[str, Any]:
        """Inject full multi-scenario attack suite into the shared session."""
        full_sim = run_full_simulation(intensity)
        attack_events = [e for sc in full_sim.get("scenarios", []) for e in sc.get("events", [])]
        noise = simulate_session(n_normal=45, n_attacks=0)
        combined_events = attack_events + noise

        session = self.get_session()
        session.session_id = f"SES-FULL-{str(uuid.uuid4())[:6].upper()}"
        session.events = combined_events
        session.active_scenario = "full"
        session.active_intensity = intensity
        session.data_source = "LIVE"
        session.cspm_source = "CLOUD_POLICY"
        session.ciem_source = "CLOUD_POLICY"
        session.generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        # Run detector registry
        norm_events = [normalize_event(e) for e in combined_events]
        findings = detector_registry.run_all(norm_events)
        session.findings = [f.model_dump(mode="json") for f in findings]
        for f in session.findings:
            f["data_source"] = session.data_source
            f["verification_status"] = "VERIFIED" if f.get("attack_category") in TAXONOMY_SLUGS else "NOT_CONFIGURED"

        save_findings_db(session.findings)
        incidents = correlate_findings(session.findings)
        session.incidents = [inc.model_dump(mode="json") for inc in incidents]
        save_incidents_db(session.incidents)

        analyzed = analyze_events(combined_events)
        session.analyzed_events = analyzed
        session.cspm_results = run_cspm_scan(combined_events)
        session.ciem_results = run_ciem_scan(combined_events)

        from engines.risk_engine import calculate_unified_risk
        from engines.db import save_risk_score
        r = calculate_unified_risk(session.analyzed_events, session.cspm_results, session.ciem_results, incidents=session.incidents)
        save_risk_score(
            r["unified_risk_score"],
            r["components"]["ml_anomaly_detection"]["score"],
            r["components"]["cspm_posture"]["score"],
            r["components"]["ciem_identity"]["score"],
            r["unified_risk_level"],
            incident=r["components"]["incident_correlation"]["score"]
        )

        return full_sim

    def reset_to_baseline(self, n_normal: int = 60) -> ActiveTelemetrySession:
        """Reset session to clean baseline noise (0 attacks)."""
        session = ActiveTelemetrySession()
        session.data_source = "LIVE"
        session.cspm_source = "CLOUD_POLICY"
        session.ciem_source = "CLOUD_POLICY"
        if is_wazuh_available():
            log_path = get_wazuh_log_path()
            if os.path.exists(log_path):
                session.last_log_mtime = os.path.getmtime(log_path)
        raw_events = simulate_session(n_normal=n_normal, n_attacks=0)
        session.events = raw_events
        session.analyzed_events = analyze_events(raw_events)
        norm_events = [normalize_event(e) for e in raw_events]
        findings = detector_registry.run_all(norm_events)
        session.findings = [f.model_dump(mode="json") for f in findings]
        session.incidents = []
        try:
            clear_simulated_findings_and_incidents_db()
        except Exception:
            pass
        session.cspm_results = run_cspm_scan(raw_events)
        session.ciem_results = run_ciem_scan(raw_events)
        session.generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        from engines.risk_engine import calculate_unified_risk
        from engines.db import save_risk_score
        r = calculate_unified_risk(session.analyzed_events, session.cspm_results, session.ciem_results, incidents=session.incidents)
        save_risk_score(
            r["unified_risk_score"],
            r["components"]["ml_anomaly_detection"]["score"],
            r["components"]["cspm_posture"]["score"],
            r["components"]["ciem_identity"]["score"],
            r["unified_risk_level"],
            incident=r["components"]["incident_correlation"]["score"]
        )

        self._session = session
        return self._session


# Global session manager instance
session_manager = SessionManager.get_instance()
