"""Detection modules for ThreatLens."""

from threatlens.detections.attack_chain import AttackChainDetector
from threatlens.detections.base import DetectionRule
from threatlens.detections.brute_force import BruteForceDetector
from threatlens.detections.lateral_movement import LateralMovementDetector
from threatlens.detections.network_anomaly import NetworkAnomalyDetector
from threatlens.detections.privilege_escalation import PrivilegeEscalationDetector
from threatlens.detections.suspicious_process import SuspiciousProcessDetector

ALL_DETECTORS: list[type[DetectionRule]] = [
    BruteForceDetector,
    LateralMovementDetector,
    PrivilegeEscalationDetector,
    SuspiciousProcessDetector,
    NetworkAnomalyDetector,
    AttackChainDetector,
]

__all__ = [
    "ALL_DETECTORS",
    "AttackChainDetector",
    "BruteForceDetector",
    "DetectionRule",
    "LateralMovementDetector",
    "NetworkAnomalyDetector",
    "PrivilegeEscalationDetector",
    "SuspiciousProcessDetector",
]
