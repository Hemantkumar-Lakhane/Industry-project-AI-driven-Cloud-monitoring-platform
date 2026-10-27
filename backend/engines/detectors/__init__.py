"""
RAM Antivirus Attack Detectors Package
=======================================
Implements the 16 modular attack detectors inheriting from BaseDetector.
All detectors are registered automatically with the global detector_registry.
"""
from engines.detectors.brute_force import BruteForceDetector, brute_force_detector
from engines.detectors.account_takeover import AccountTakeoverDetector, account_takeover_detector
from engines.detectors.iam_privilege_escalation import IAMPrivilegeEscalationDetector, iam_privilege_escalation_detector
from engines.detectors.suspicious_api_activity import SuspiciousAPIActivityDetector, suspicious_api_activity_detector
from engines.detectors.cloud_misconfiguration import CloudMisconfigurationDetector, cloud_misconfiguration_detector
from engines.detectors.data_exfiltration import DataExfiltrationDetector, data_exfiltration_detector
from engines.detectors.network_scanning import NetworkScanningDetector, network_scanning_detector
from engines.detectors.ddos import DDoSDetector, ddos_detector
from engines.detectors.cryptomining import CryptominingDetector, cryptomining_detector
from engines.detectors.container_k8s import ContainerK8sDetector, container_k8s_detector
from engines.detectors.bola_ssrf import BOLASSRFDetector, bola_ssrf_detector
from engines.detectors.malware_ransomware import MalwareRansomwareDetector, malware_ransomware_detector
from engines.detectors.database_attacks import DatabaseAttacksDetector, database_attacks_detector
from engines.detectors.serverless_abuse import ServerlessAbuseDetector, serverless_abuse_detector
from engines.detectors.supply_chain import SupplyChainDetector, supply_chain_detector
from engines.detectors.defense_tampering import DefenseTamperingDetector, defense_tampering_detector

__all__ = [
    "BruteForceDetector", "brute_force_detector",
    "AccountTakeoverDetector", "account_takeover_detector",
    "IAMPrivilegeEscalationDetector", "iam_privilege_escalation_detector",
    "SuspiciousAPIActivityDetector", "suspicious_api_activity_detector",
    "CloudMisconfigurationDetector", "cloud_misconfiguration_detector",
    "DataExfiltrationDetector", "data_exfiltration_detector",
    "NetworkScanningDetector", "network_scanning_detector",
    "DDoSDetector", "ddos_detector",
    "CryptominingDetector", "cryptomining_detector",
    "ContainerK8sDetector", "container_k8s_detector",
    "BOLASSRFDetector", "bola_ssrf_detector",
    "MalwareRansomwareDetector", "malware_ransomware_detector",
    "DatabaseAttacksDetector", "database_attacks_detector",
    "ServerlessAbuseDetector", "serverless_abuse_detector",
    "SupplyChainDetector", "supply_chain_detector",
    "DefenseTamperingDetector", "defense_tampering_detector",
]
