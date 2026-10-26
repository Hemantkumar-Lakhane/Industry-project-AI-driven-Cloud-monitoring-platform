"""
Container & Kubernetes Attacks Detector (Attack Category 10)
============================================================
Identifies privileged pod execution, container escape attempts, docker.sock
host mounting, and interactive root exec sessions into production clusters.

Taxonomy Index: 10
Category Slug:  container_k8s_attacks
Playbook ID:    PB-RP-008
"""
from typing import Dict, Any, List, Optional, Union, Set
from schemas.event import NormalizedEvent
from schemas.finding import SecurityFinding
from engines.base_detector import BaseDetector, detector_registry

ESCAPE_MOUNTS: Set[str] = {"/var/run/docker.sock", "/proc", "/sys", "/etc/kubernetes", "/var/lib/kubelet"}
DANGEROUS_CAPS: Set[str] = {"cap_sys_admin", "cap_sys_ptrace", "cap_net_admin"}


class ContainerK8sDetector(BaseDetector):
    """
    Evaluates Kubernetes audit traces and container runtime events for:
    1. Privileged container creation (privileged: true).
    2. Host filesystem mounts (/var/run/docker.sock, /proc, /sys).
    3. Interactive shell exec into running containers (kubectl exec /bin/sh).
    """

    def __init__(self, enabled: bool = True):
        super().__init__(
            category="container_k8s_attacks",
            category_index=10,
            name="Container & Kubernetes Attacks Detector",
            description="Identifies container breakouts, dangerous hostPath mounts, privileged pods, and unauthorized cluster exec sessions.",
            supported_sources=["k8s_audit", "wazuh", "falco"],
            enabled=enabled
        )

    def detect(self, events: List[Union[NormalizedEvent, Dict[str, Any]]]) -> List[SecurityFinding]:
        norm_events = self._ensure_normalized(events)
        findings: List[SecurityFinding] = []

        for e in norm_events:
            desc = (e.description or "").lower()
            action = (e.action or "").lower()
            attack_type = (e.attack_type or "").lower()
            raw_meta = e.raw_data or {}
            audit_str = f"{desc} {action} {str(raw_meta).lower()}"

            is_k8s_attack = attack_type in ("container_k8s_attacks", "container_escape", "k8s_compromise")
            is_privileged_exec = (
                "privileged: true" in audit_str or
                '"privileged": true' in audit_str or
                "'privileged': true" in audit_str or
                "hostpid: true" in audit_str or
                "hostipc: true" in audit_str or
                "privileged pod" in desc or
                "privileged container" in desc
            )
            is_socket_mount = any(m in audit_str for m in ESCAPE_MOUNTS) or "docker.sock" in audit_str
            is_exec_session = "kubectl exec" in audit_str or "pod exec" in audit_str or action in ("createpodexec", "exec")

            if not (is_k8s_attack or is_privileged_exec or is_socket_mount or is_exec_session):
                continue

            principal = e.principal or e.user_id or "k8s-serviceaccount"
            pod_name = e.target_resource or "production-pod"

            is_critical = is_socket_mount or is_privileged_exec
            severity = "critical" if is_critical else "high"
            confidence = 0.96 if is_critical else 0.88

            facts = [
                f"Container security violation observed in cluster on pod/workload '{pod_name}'.",
                f"Action: '{e.action}', Description: '{e.description}'.",
            ]
            if is_socket_mount:
                facts.append("Identified hostPath mount to sensitive host sockets (/var/run/docker.sock).")

            finding = self.create_finding(
                title=f"Container Security Violation: Potential Breakout on Pod '{pod_name}'",
                severity=severity,
                confidence=confidence,
                detection_method="rule_based",
                triggering_events=[e],
                observed_facts=facts,
                inferred_hypothesis=f"Attacker attempting container breakout or privilege escalation to node level via host mounts or privileged capabilities.",
                affected_resource=f"k8s:pod:{pod_name}",
                affected_principal=principal,
                telemetry_fields={"pod": pod_name, "principal": principal, "action": e.action},
                action_summary=f"Evict and quarantine pod '{pod_name}', revoke associated ServiceAccount tokens, and enforce Pod Security Standards.",
                playbook_id="PB-RP-008",
                verification_status="VERIFIED"
            )
            findings.append(finding)

        return findings


container_k8s_detector = ContainerK8sDetector()
detector_registry.register(container_k8s_detector)
