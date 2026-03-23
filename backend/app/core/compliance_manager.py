"""
Compliance Management System for Healthcare GenAI Application
Implements HIPAA compliance settings and GDPR data protection rules
"""

import json
import hashlib
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set
from enum import Enum
from pydantic import BaseModel
import logging
from dataclasses import dataclass, field

from app.core.config import settings


class ComplianceStandard(Enum):
    """Compliance standard enumeration"""
    HIPAA = "hipaa"
    GDPR = "gdpr"
    SOC2 = "soc2"
    ISO27001 = "iso27001"
    HITECH = "hitech"


class DataClassification(Enum):
    """Data classification levels"""
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"
    PHI = "phi"  # Protected Health Information


class DataRetentionPolicy(Enum):
    """Data retention policy types"""
    IMMEDIATE_DELETE = "immediate_delete"
    DAYS_7 = "7_days"
    DAYS_30 = "30_days"
    DAYS_90 = "90_days"
    YEARS_1 = "1_year"
    YEARS_7 = "7_years"  # HIPAA requirement
    INDEFINITE = "indefinite"


@dataclass
class ComplianceRule:
    """Compliance rule definition"""
    rule_id: str
    standard: ComplianceStandard
    category: str
    description: str
    is_enabled: bool = True
    last_audited: Optional[datetime] = None
    compliance_status: str = "pending"
    requirements: List[str] = field(default_factory=list)
    controls: List[str] = field(default_factory=list)


@dataclass
class DataProtectionRule:
    """Data protection rule definition"""
    rule_id: str
    classification: DataClassification
    retention_policy: DataRetentionPolicy
    encryption_required: bool = True
    access_logging: bool = True
    anonymization_required: bool = False
    consent_required: bool = False
    data_subject_rights: List[str] = field(default_factory=list)


class ComplianceManager:
    """Compliance management system for HIPAA and GDPR"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.compliance_rules = self._initialize_compliance_rules()
        self.data_protection_rules = self._initialize_data_protection_rules()
        self.audit_log = []
        
    def _initialize_compliance_rules(self) -> Dict[str, ComplianceRule]:
        """Initialize HIPAA and GDPR compliance rules"""
        rules = {}
        
        # HIPAA Rules
        hipaa_rules = [
            ComplianceRule(
                rule_id="hipaa_001",
                standard=ComplianceStandard.HIPAA,
                category="Privacy Rule",
                description="Protected Health Information (PHI) must be kept confidential",
                requirements=[
                    "Implement access controls",
                    "Audit logging for PHI access",
                    "Encryption of PHI at rest and in transit",
                    "Minimum necessary access principle"
                ],
                controls=[
                    "Role-based access control (RBAC)",
                    "Encryption of data at rest (AES-256)",
                    "TLS 1.3 for data in transit",
                    "Comprehensive audit logging"
                ]
            ),
            ComplianceRule(
                rule_id="hipaa_002",
                standard=ComplianceStandard.HIPAA,
                category="Security Rule",
                description="Implement technical safeguards for electronic PHI",
                requirements=[
                    "Unique user identification",
                    "Emergency access procedures",
                    "Automatic logoff",
                    "Encryption and decryption"
                ],
                controls=[
                    "Multi-factor authentication (MFA)",
                    "Session timeout management",
                    "Automatic session termination",
                    "End-to-end encryption"
                ]
            ),
            ComplianceRule(
                rule_id="hipaa_003",
                standard=ComplianceStandard.HIPAA,
                category="Breach Notification",
                description="Notify individuals and HHS of PHI breaches",
                requirements=[
                    "Breach detection and reporting",
                    "Risk assessment procedures",
                    "Notification within 60 days",
                    "Documentation of breach response"
                ],
                controls=[
                    "Automated breach detection",
                    "Incident response procedures",
                    "Notification workflows",
                    "Breach documentation system"
                ]
            )
        ]
        
        # GDPR Rules
        gdpr_rules = [
            ComplianceRule(
                rule_id="gdpr_001",
                standard=ComplianceStandard.GDPR,
                category="Data Processing",
                description="Lawful basis for processing personal data",
                requirements=[
                    "Explicit consent for data processing",
                    "Purpose limitation",
                    "Data minimization",
                    "Storage limitation"
                ],
                controls=[
                    "Consent management system",
                    "Purpose-based data access",
                    "Data retention policies",
                    "Automated data deletion"
                ]
            ),
            ComplianceRule(
                rule_id="gdpr_002",
                standard=ComplianceStandard.GDPR,
                category="Data Subject Rights",
                description="Individuals have rights over their personal data",
                requirements=[
                    "Right to access personal data",
                    "Right to rectification",
                    "Right to erasure (right to be forgotten)",
                    "Right to data portability"
                ],
                controls=[
                    "Data subject request portal",
                    "Automated data export",
                    "Data rectification workflows",
                    "Data deletion procedures"
                ]
            ),
            ComplianceRule(
                rule_id="gdpr_003",
                standard=ComplianceStandard.GDPR,
                category="Data Protection",
                description="Implement appropriate security measures",
                requirements=[
                    "Data protection by design",
                    "Data protection by default",
                    "Security of processing",
                    "Breach notification"
                ],
                controls=[
                    "Privacy by design principles",
                    "Default privacy settings",
                    "Security controls implementation",
                    "Breach notification procedures"
                ]
            )
        ]
        
        # Add all rules to dictionary
        for rule in hipaa_rules + gdpr_rules:
            rules[rule.rule_id] = rule
            
        return rules
    
    def _initialize_data_protection_rules(self) -> Dict[str, DataProtectionRule]:
        """Initialize data protection rules based on classification"""
        rules = {}
        
        # PHI (Protected Health Information) - HIPAA
        rules["phi"] = DataProtectionRule(
            rule_id="phi_protection",
            classification=DataClassification.PHI,
            retention_policy=DataRetentionPolicy.YEARS_7,
            encryption_required=True,
            access_logging=True,
            anonymization_required=True,
            consent_required=True,
            data_subject_rights=[
                "access", "rectification", "erasure", "portability", "restriction"
            ]
        )
        
        # Confidential data
        rules["confidential"] = DataProtectionRule(
            rule_id="confidential_protection",
            classification=DataClassification.CONFIDENTIAL,
            retention_policy=DataRetentionPolicy.YEARS_1,
            encryption_required=True,
            access_logging=True,
            anonymization_required=False,
            consent_required=True,
            data_subject_rights=["access", "rectification", "erasure"]
        )
        
        # Internal data
        rules["internal"] = DataProtectionRule(
            rule_id="internal_protection",
            classification=DataClassification.INTERNAL,
            retention_policy=DataRetentionPolicy.DAYS_90,
            encryption_required=False,
            access_logging=True,
            anonymization_required=False,
            consent_required=False,
            data_subject_rights=["access"]
        )
        
        return rules
    
    def get_compliance_status(self, standard: ComplianceStandard) -> Dict:
        """Get compliance status for a specific standard"""
        rules = [r for r in self.compliance_rules.values() if r.standard == standard]
        
        if not rules:
            return {"status": "unknown", "message": f"No rules found for {standard.value}"}
        
        total_rules = len(rules)
        enabled_rules = sum(1 for r in rules if r.is_enabled)
        compliant_rules = sum(1 for r in rules if r.compliance_status == "compliant")
        
        compliance_percentage = (compliant_rules / total_rules * 100) if total_rules > 0 else 0
        
        return {
            "standard": standard.value,
            "total_rules": total_rules,
            "enabled_rules": enabled_rules,
            "compliant_rules": compliant_rules,
            "compliance_percentage": round(compliance_percentage, 2),
            "status": "compliant" if compliance_percentage >= 90 else "partially_compliant" if compliance_percentage >= 70 else "non_compliant",
            "last_audited": max([r.last_audited for r in rules if r.last_audited], default=None),
            "rules": [
                {
                    "rule_id": r.rule_id,
                    "category": r.category,
                    "description": r.description,
                    "status": r.compliance_status,
                    "is_enabled": r.is_enabled
                }
                for r in rules
            ]
        }
    
    def get_overall_compliance_status(self) -> Dict:
        """Get overall compliance status across all standards"""
        standards = [ComplianceStandard.HIPAA, ComplianceStandard.GDPR]
        compliance_statuses = {}
        
        for standard in standards:
            compliance_statuses[standard.value] = self.get_compliance_status(standard)
        
        # Calculate overall compliance
        total_rules = sum(status["total_rules"] for status in compliance_statuses.values())
        total_compliant = sum(status["compliant_rules"] for status in compliance_statuses.values())
        
        overall_compliance = (total_compliant / total_rules * 100) if total_rules > 0 else 0
        
        return {
            "overall_compliance_percentage": round(overall_compliance, 2),
            "overall_status": "compliant" if overall_compliance >= 90 else "partially_compliant" if overall_compliance >= 70 else "non_compliant",
            "standards": compliance_statuses,
            "last_updated": datetime.utcnow().isoformat()
        }
    
    def get_data_protection_summary(self) -> Dict:
        """Get summary of data protection rules and compliance"""
        total_rules = len(self.data_protection_rules)
        encryption_required = sum(1 for r in self.data_protection_rules.values() if r.encryption_required)
        access_logging = sum(1 for r in self.data_protection_rules.values() if r.access_logging)
        consent_required = sum(1 for r in self.data_protection_rules.values() if r.consent_required)
        
        return {
            "total_protection_rules": total_rules,
            "encryption_required": encryption_required,
            "access_logging": access_logging,
            "consent_required": consent_required,
            "classifications": [
                {
                    "classification": rule.classification.value,
                    "retention_policy": rule.retention_policy.value,
                    "encryption_required": rule.encryption_required,
                    "access_logging": rule.access_logging
                }
                for rule in self.data_protection_rules.values()
            ]
        }
    
    def update_compliance_rule(self, rule_id: str, updates: Dict) -> bool:
        """Update compliance rule status"""
        if rule_id not in self.compliance_rules:
            return False
        
        rule = self.compliance_rules[rule_id]
        
        # Update allowed fields
        if "is_enabled" in updates:
            rule.is_enabled = updates["is_enabled"]
        if "compliance_status" in updates:
            rule.compliance_status = updates["compliance_status"]
        if "last_audited" in updates:
            rule.last_audited = datetime.fromisoformat(updates["last_audited"])
        
        # Log the update
        self.audit_log.append({
            "timestamp": datetime.utcnow().isoformat(),
            "action": "compliance_rule_update",
            "rule_id": rule_id,
            "updates": updates
        })
        
        self.logger.info(f"Updated compliance rule {rule_id}: {updates}")
        return True
    
    def get_compliance_recommendations(self) -> List[Dict]:
        """Get compliance improvement recommendations"""
        recommendations = []
        
        for rule in self.compliance_rules.values():
            if rule.compliance_status != "compliant" and rule.is_enabled:
                recommendations.append({
                    "rule_id": rule.rule_id,
                    "standard": rule.standard.value,
                    "category": rule.category,
                    "priority": "high" if rule.standard == ComplianceStandard.HIPAA else "medium",
                    "description": f"Address compliance gaps in {rule.category}",
                    "requirements": rule.requirements,
                    "controls": rule.controls
                })
        
        # Sort by priority (HIPAA first, then GDPR)
        priority_order = {ComplianceStandard.HIPAA: 1, ComplianceStandard.GDPR: 2}
        recommendations.sort(key=lambda x: priority_order.get(ComplianceStandard(x["standard"]), 3))
        
        return recommendations


# Global compliance manager instance
compliance_manager = ComplianceManager()
