"""Detection modules for ThreatLens."""

from threatlens.detections.attack_chain import AttackChainDetector
from threatlens.detections.base import DetectionRule
from threatlens.detections.brute_force import BruteForceDetector
from threatlens.detections.credential_access import CredentialAccessDetector
from threatlens.detections.defense_evasion import DefenseEvasionDetector
from threatlens.detections.discovery import DiscoveryDetector
from threatlens.detections.exfiltration import ExfiltrationDetector
from threatlens.detections.initial_access import InitialAccessDetector
from threatlens.detections.kerberos_attacks import KerberosAttackDetector
from threatlens.detections.lateral_movement import LateralMovementDetector
from threatlens.detections.persistence import PersistenceDetector
from threatlens.detections.privilege_escalation import PrivilegeEscalationDetector
from threatlens.detections.suspicious_process import SuspiciousProcessDetector

ALL_DETECTORS: list[type[DetectionRule]] = [
    BruteForceDetector,
    LateralMovementDetector,
    PrivilegeEscalationDetector,
    SuspiciousProcessDetector,
    DefenseEvasionDetector,
    PersistenceDetector,
    DiscoveryDetector,
    ExfiltrationDetector,
    KerberosAttackDetector,
    CredentialAccessDetector,
    InitialAccessDetector,
    AttackChainDetector,
]

__all__ = [
    "ALL_DETECTORS",
    "AttackChainDetector",
    "BruteForceDetector",
    "CredentialAccessDetector",
    "DefenseEvasionDetector",
    "DetectionRule",
    "DiscoveryDetector",
    "ExfiltrationDetector",
    "InitialAccessDetector",
    "KerberosAttackDetector",
    "LateralMovementDetector",
    "PersistenceDetector",
    "PrivilegeEscalationDetector",
    "SuspiciousProcessDetector",
]
