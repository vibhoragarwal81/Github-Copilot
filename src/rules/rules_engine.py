"""
Security Rules Engine for AWS CSPM

This module provides a comprehensive rules engine for evaluating AWS resources
against security best practices and compliance frameworks including:
- CIS AWS Foundations Benchmark v1.5.0
- NIST Cybersecurity Framework
- PCI DSS v4.0
- SOC 2
- Custom organizational security policies

The engine supports dynamic rule loading, severity classification,
and detailed remediation guidance.
"""

import json
import logging
import re
from abc import ABC, abstractmethod
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Union

import boto3
from botocore.exceptions import ClientError


class Severity(Enum):
    """Security finding severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ComplianceFramework(Enum):
    """Supported compliance frameworks."""
    CIS_AWS = "CIS-AWS-v1.5.0"
    NIST_CSF = "NIST-CSF"
    PCI_DSS = "PCI-DSS-v4.0"
    SOC2 = "SOC2-Type2"
    AWS_FOUNDATIONAL = "AWS-Foundational"
    CUSTOM = "Custom"


class Rule(ABC):
    """Base class for security rules."""
    
    def __init__(self, rule_id: str, title: str, description: str, 
                 severity: Severity, compliance_frameworks: List[ComplianceFramework],
                 remediation: str):
        """
        Initialize a security rule.
        
        Args:
            rule_id: Unique identifier for the rule
            title: Short title describing the rule
            description: Detailed description of what the rule checks
            severity: Severity level of violations
            compliance_frameworks: List of applicable compliance frameworks
            remediation: Instructions for remediation
        """
        self.rule_id = rule_id
        self.title = title
        self.description = description
        self.severity = severity
        self.compliance_frameworks = compliance_frameworks
        self.remediation = remediation
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
    
    @abstractmethod
    def evaluate(self, resource: Dict[str, Any], context: Dict[str, Any] = None) -> List[Dict[str, Any]]:
        """
        Evaluate the rule against a resource.
        
        Args:
            resource: AWS resource data
            context: Additional context (account info, region, etc.)
            
        Returns:
            List[Dict]: List of findings (empty if compliant)
        """
        pass
    
    def create_finding(self, resource: Dict[str, Any], details: str, 
                      context: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Create a standardized finding.
        
        Args:
            resource: AWS resource that failed the rule
            details: Specific details about the violation
            context: Additional context
            
        Returns:
            Dict: Standardized finding
        """
        return {
            'rule_id': self.rule_id,
            'title': self.title,
            'description': self.description,
            'severity': self.severity.value,
            'compliance': [framework.value for framework in self.compliance_frameworks],
            'resource_id': resource.get('id', 'unknown'),
            'resource_type': resource.get('type', 'unknown'),
            'resource_region': context.get('region', 'unknown') if context else 'unknown',
            'account_id': context.get('account_id', 'unknown') if context else 'unknown',
            'finding_details': details,
            'remediation': self.remediation,
            'timestamp': datetime.utcnow().isoformat(),
            'metadata': {
                'resource': resource,
                'context': context or {}
            }
        }


class IAMRules:
    """IAM-specific security rules."""
    
    @staticmethod
    def get_rules() -> List[Rule]:
        """Get all IAM security rules."""
        return [
            IAMRootAccessKeyRule(),
            IAMUserMFARule(),
            IAMPasswordPolicyRule(),
            IAMUnusedCredentialsRule(),
            IAMWildcardPolicyRule(),
            IAMAssumeRolePolicyRule()
        ]


class IAMRootAccessKeyRule(Rule):
    """Rule to check for root account access key usage."""
    
    def __init__(self):
        super().__init__(
            rule_id="IAM-001",
            title="Root Account Access Keys Should Not Exist",
            description="Root account access keys should not be created or used. Root access should use temporary credentials through AWS SSO or IAM roles.",
            severity=Severity.CRITICAL,
            compliance_frameworks=[ComplianceFramework.CIS_AWS, ComplianceFramework.NIST_CSF, ComplianceFramework.PCI_DSS],
            remediation="Delete any existing root account access keys. Use AWS SSO or IAM roles with temporary credentials instead. Configure CloudTrail to monitor root account usage."
        )
    
    def evaluate(self, resource: Dict[str, Any], context: Dict[str, Any] = None) -> List[Dict[str, Any]]:
        """Evaluate root account access key usage."""
        findings = []
        
        if resource.get('type') == 'account':
            # Check for root account access key usage
            account_summary = resource.get('account_summary', {})
            
            # Check if root access keys exist
            if account_summary.get('access_keys_present', False):
                findings.append(self.create_finding(
                    resource,
                    "Root account has active access keys. This poses a critical security risk as root account has unrestricted access to all AWS resources.",
                    context
                ))
            
            # Check for recent root account usage
            if account_summary.get('recent_root_activity', False):
                findings.append(self.create_finding(
                    resource,
                    "Root account has been used recently. Root account should only be used for initial setup and emergency access.",
                    context
                ))
        
        return findings


class IAMUserMFARule(Rule):
    """Rule to check IAM users have MFA enabled."""
    
    def __init__(self):
        super().__init__(
            rule_id="IAM-002",
            title="IAM Users Should Have MFA Enabled",
            description="All IAM users should have Multi-Factor Authentication (MFA) enabled to provide an additional layer of security.",
            severity=Severity.HIGH,
            compliance_frameworks=[ComplianceFramework.CIS_AWS, ComplianceFramework.NIST_CSF, ComplianceFramework.SOC2],
            remediation="Enable MFA for all IAM users. Users can use virtual MFA devices (Google Authenticator, Authy) or hardware MFA devices (YubiKey)."
        )
    
    def evaluate(self, resource: Dict[str, Any], context: Dict[str, Any] = None) -> List[Dict[str, Any]]:
        """Evaluate IAM user MFA configuration."""
        findings = []
        
        if resource.get('type') == 'iam_user':
            user_name = resource.get('user_name', 'unknown')
            mfa_devices = resource.get('mfa_devices', [])
            has_console_access = resource.get('has_console_access', False)
            
            # Only check users with console access
            if has_console_access and not mfa_devices:
                findings.append(self.create_finding(
                    resource,
                    f"IAM user '{user_name}' has console access but no MFA device configured. This increases the risk of unauthorized access.",
                    context
                ))
        
        return findings


class IAMPasswordPolicyRule(Rule):
    """Rule to check account password policy compliance."""
    
    def __init__(self):
        super().__init__(
            rule_id="IAM-003",
            title="Account Password Policy Should Meet Security Requirements",
            description="Account password policy should enforce strong passwords with minimum length, complexity requirements, and password rotation.",
            severity=Severity.MEDIUM,
            compliance_frameworks=[ComplianceFramework.CIS_AWS, ComplianceFramework.NIST_CSF, ComplianceFramework.PCI_DSS],
            remediation="Configure account password policy with: minimum 14 characters, require uppercase/lowercase letters, numbers, and symbols. Enable password expiration and reuse prevention."
        )
    
    def evaluate(self, resource: Dict[str, Any], context: Dict[str, Any] = None) -> List[Dict[str, Any]]:
        """Evaluate account password policy."""
        findings = []
        
        if resource.get('type') == 'password_policy':
            policy = resource.get('policy', {})
            issues = []
            
            # Check minimum password length
            min_length = policy.get('minimum_password_length', 0)
            if min_length < 14:
                issues.append(f"Minimum password length is {min_length}, should be at least 14 characters")
            
            # Check complexity requirements
            if not policy.get('require_uppercase_characters', False):
                issues.append("Password policy should require uppercase characters")
            
            if not policy.get('require_lowercase_characters', False):
                issues.append("Password policy should require lowercase characters")
            
            if not policy.get('require_numbers', False):
                issues.append("Password policy should require numbers")
            
            if not policy.get('require_symbols', False):
                issues.append("Password policy should require symbols")
            
            # Check password expiration
            max_age = policy.get('max_password_age', 0)
            if max_age == 0 or max_age > 90:
                issues.append("Password policy should enforce password rotation within 90 days")
            
            # Check password reuse
            reuse_prevention = policy.get('password_reuse_prevention', 0)
            if reuse_prevention < 5:
                issues.append("Password policy should prevent reuse of last 5 passwords")
            
            if issues:
                findings.append(self.create_finding(
                    resource,
                    f"Account password policy does not meet security requirements: {'; '.join(issues)}",
                    context
                ))
        
        return findings


class IAMUnusedCredentialsRule(Rule):
    """Rule to check for unused IAM credentials."""
    
    def __init__(self):
        super().__init__(
            rule_id="IAM-004",
            title="Unused IAM Credentials Should Be Removed",
            description="IAM users and access keys that haven't been used for an extended period should be removed to reduce attack surface.",
            severity=Severity.MEDIUM,
            compliance_frameworks=[ComplianceFramework.CIS_AWS, ComplianceFramework.NIST_CSF, ComplianceFramework.SOC2],
            remediation="Remove or disable IAM users and access keys that haven't been used for more than 90 days. Implement regular access reviews."
        )
    
    def evaluate(self, resource: Dict[str, Any], context: Dict[str, Any] = None) -> List[Dict[str, Any]]:
        """Evaluate unused IAM credentials."""
        findings = []
        
        if resource.get('type') == 'iam_user':
            user_name = resource.get('user_name', 'unknown')
            last_activity = resource.get('last_activity')
            access_keys = resource.get('access_keys', [])
            
            # Check user last activity
            if last_activity:
                days_since_activity = (datetime.utcnow() - datetime.fromisoformat(last_activity.replace('Z', '+00:00'))).days
                if days_since_activity > 90:
                    findings.append(self.create_finding(
                        resource,
                        f"IAM user '{user_name}' has not been active for {days_since_activity} days. Consider removing unused accounts.",
                        context
                    ))
            
            # Check access key usage
            for access_key in access_keys:
                key_id = access_key.get('access_key_id', 'unknown')
                last_used = access_key.get('last_used_date')
                
                if last_used:
                    days_since_used = (datetime.utcnow() - datetime.fromisoformat(last_used.replace('Z', '+00:00'))).days
                    if days_since_used > 90:
                        findings.append(self.create_finding(
                            resource,
                            f"Access key '{key_id}' for user '{user_name}' hasn't been used for {days_since_used} days. Consider rotating or removing unused keys.",
                            context
                        ))
        
        return findings


class IAMWildcardPolicyRule(Rule):
    """Rule to check for overly permissive IAM policies."""
    
    def __init__(self):
        super().__init__(
            rule_id="IAM-005",
            title="IAM Policies Should Not Use Wildcard Permissions",
            description="IAM policies should follow the principle of least privilege and avoid wildcard (*) permissions that grant excessive access.",
            severity=Severity.HIGH,
            compliance_frameworks=[ComplianceFramework.CIS_AWS, ComplianceFramework.NIST_CSF, ComplianceFramework.PCI_DSS, ComplianceFramework.SOC2],
            remediation="Review IAM policies with wildcard permissions and replace them with specific, least-privilege permissions. Use AWS Access Analyzer to identify unused permissions."
        )
    
    def evaluate(self, resource: Dict[str, Any], context: Dict[str, Any] = None) -> List[Dict[str, Any]]:
        """Evaluate IAM policy permissions."""
        findings = []
        
        if resource.get('type') == 'iam_policy':
            policy_name = resource.get('policy_name', 'unknown')
            policy_document = resource.get('policy_document', {})
            
            # Check for wildcard permissions in statements
            statements = policy_document.get('Statement', [])
            if isinstance(statements, dict):
                statements = [statements]
            
            for statement in statements:
                actions = statement.get('Action', [])
                resources = statement.get('Resource', [])
                effect = statement.get('Effect', '')
                
                if effect == 'Allow':
                    # Check for wildcard actions
                    if isinstance(actions, str):
                        actions = [actions]
                    
                    for action in actions:
                        if action == '*':
                            findings.append(self.create_finding(
                                resource,
                                f"IAM policy '{policy_name}' contains wildcard action '*' which grants excessive permissions.",
                                context
                            ))
                    
                    # Check for wildcard resources
                    if isinstance(resources, str):
                        resources = [resources]
                    
                    for resource_arn in resources:
                        if resource_arn == '*':
                            findings.append(self.create_finding(
                                resource,
                                f"IAM policy '{policy_name}' contains wildcard resource '*' which may grant access to unintended resources.",
                                context
                            ))
        
        return findings


class IAMAssumeRolePolicyRule(Rule):
    """Rule to check IAM role trust policies."""
    
    def __init__(self):
        super().__init__(
            rule_id="IAM-006",
            title="IAM Role Trust Policies Should Be Restrictive",
            description="IAM role trust policies should restrict which principals can assume the role to prevent unauthorized access.",
            severity=Severity.MEDIUM,
            compliance_frameworks=[ComplianceFramework.CIS_AWS, ComplianceFramework.NIST_CSF, ComplianceFramework.SOC2],
            remediation="Review IAM role trust policies and ensure they only allow specific, trusted principals to assume the role. Avoid using wildcard principals or overly broad conditions."
        )
    
    def evaluate(self, resource: Dict[str, Any], context: Dict[str, Any] = None) -> List[Dict[str, Any]]:
        """Evaluate IAM role trust policy."""
        findings = []
        
        if resource.get('type') == 'iam_role':
            role_name = resource.get('role_name', 'unknown')
            trust_policy = resource.get('assume_role_policy_document', {})
            
            statements = trust_policy.get('Statement', [])
            if isinstance(statements, dict):
                statements = [statements]
            
            for statement in statements:
                effect = statement.get('Effect', '')
                principal = statement.get('Principal', {})
                
                if effect == 'Allow':
                    # Check for wildcard principals
                    if isinstance(principal, str) and principal == '*':
                        findings.append(self.create_finding(
                            resource,
                            f"IAM role '{role_name}' trust policy allows any principal ('*') to assume the role, which is a security risk.",
                            context
                        ))
                    
                    # Check for overly broad AWS principals
                    if isinstance(principal, dict):
                        aws_principals = principal.get('AWS', [])
                        if isinstance(aws_principals, str):
                            aws_principals = [aws_principals]
                        
                        for aws_principal in aws_principals:
                            if aws_principal == '*':
                                findings.append(self.create_finding(
                                    resource,
                                    f"IAM role '{role_name}' trust policy allows any AWS principal to assume the role.",
                                    context
                                ))
        
        return findings


class EC2Rules:
    """EC2-specific security rules."""
    
    @staticmethod
    def get_rules() -> List[Rule]:
        """Get all EC2 security rules."""
        return [
            EC2PublicInstanceRule(),
            EC2SecurityGroupRule(),
            EC2UnencryptedEBSRule(),
            EC2IMDSv1Rule(),
            EC2PublicAMIRule()
        ]


class EC2PublicInstanceRule(Rule):
    """Rule to check for publicly accessible EC2 instances."""
    
    def __init__(self):
        super().__init__(
            rule_id="EC2-001",
            title="EC2 Instances Should Not Be Publicly Accessible",
            description="EC2 instances should not have public IP addresses unless specifically required for public-facing services.",
            severity=Severity.HIGH,
            compliance_frameworks=[ComplianceFramework.CIS_AWS, ComplianceFramework.NIST_CSF, ComplianceFramework.PCI_DSS],
            remediation="Move EC2 instances to private subnets and use load balancers or NAT gateways for internet connectivity when needed."
        )
    
    def evaluate(self, resource: Dict[str, Any], context: Dict[str, Any] = None) -> List[Dict[str, Any]]:
        """Evaluate EC2 instance public accessibility."""
        findings = []
        
        if resource.get('type') == 'ec2_instance':
            instance_id = resource.get('instance_id', 'unknown')
            public_ip = resource.get('public_ip_address')
            state = resource.get('state', {}).get('Name', 'unknown')
            
            if state == 'running' and public_ip:
                findings.append(self.create_finding(
                    resource,
                    f"EC2 instance '{instance_id}' has a public IP address ({public_ip}) making it directly accessible from the internet.",
                    context
                ))
        
        return findings


class EC2SecurityGroupRule(Rule):
    """Rule to check for overly permissive security groups."""
    
    def __init__(self):
        super().__init__(
            rule_id="EC2-002",
            title="Security Groups Should Not Allow Unrestricted Access",
            description="Security groups should not allow unrestricted inbound access (0.0.0.0/0) on sensitive ports like SSH (22) and RDP (3389).",
            severity=Severity.HIGH,
            compliance_frameworks=[ComplianceFramework.CIS_AWS, ComplianceFramework.NIST_CSF, ComplianceFramework.PCI_DSS],
            remediation="Restrict security group rules to specific IP ranges or security groups. Use AWS Systems Manager Session Manager for secure instance access."
        )
    
    def evaluate(self, resource: Dict[str, Any], context: Dict[str, Any] = None) -> List[Dict[str, Any]]:
        """Evaluate security group rules."""
        findings = []
        
        if resource.get('type') == 'security_group':
            group_id = resource.get('group_id', 'unknown')
            ingress_rules = resource.get('ip_permissions', [])
            
            sensitive_ports = [22, 3389, 1433, 3306, 5432, 6379, 27017]
            
            for rule in ingress_rules:
                from_port = rule.get('FromPort')
                to_port = rule.get('ToPort')
                ip_protocol = rule.get('IpProtocol', '')
                ip_ranges = rule.get('IpRanges', [])
                
                # Check for unrestricted access
                for ip_range in ip_ranges:
                    cidr = ip_range.get('CidrIp', '')
                    if cidr == '0.0.0.0/0':
                        # Check if it's on a sensitive port
                        if from_port in sensitive_ports or to_port in sensitive_ports:
                            findings.append(self.create_finding(
                                resource,
                                f"Security group '{group_id}' allows unrestricted access (0.0.0.0/0) on port {from_port}-{to_port}, which includes sensitive ports.",
                                context
                            ))
                        elif from_port <= 22 <= to_port or from_port <= 3389 <= to_port:
                            findings.append(self.create_finding(
                                resource,
                                f"Security group '{group_id}' allows unrestricted SSH/RDP access (0.0.0.0/0) on port range {from_port}-{to_port}.",
                                context
                            ))
        
        return findings


class EC2UnencryptedEBSRule(Rule):
    """Rule to check for unencrypted EBS volumes."""
    
    def __init__(self):
        super().__init__(
            rule_id="EC2-003",
            title="EBS Volumes Should Be Encrypted",
            description="EBS volumes should be encrypted at rest to protect sensitive data from unauthorized access.",
            severity=Severity.MEDIUM,
            compliance_frameworks=[ComplianceFramework.CIS_AWS, ComplianceFramework.NIST_CSF, ComplianceFramework.PCI_DSS],
            remediation="Enable EBS encryption by default and encrypt existing unencrypted volumes. Use AWS KMS for key management."
        )
    
    def evaluate(self, resource: Dict[str, Any], context: Dict[str, Any] = None) -> List[Dict[str, Any]]:
        """Evaluate EBS volume encryption."""
        findings = []
        
        if resource.get('type') == 'ebs_volume':
            volume_id = resource.get('volume_id', 'unknown')
            encrypted = resource.get('encrypted', False)
            state = resource.get('state', 'unknown')
            
            if state == 'in-use' and not encrypted:
                findings.append(self.create_finding(
                    resource,
                    f"EBS volume '{volume_id}' is not encrypted. Unencrypted volumes may expose sensitive data.",
                    context
                ))
        
        return findings


class EC2IMDSv1Rule(Rule):
    """Rule to check for IMDSv1 usage."""
    
    def __init__(self):
        super().__init__(
            rule_id="EC2-004",
            title="EC2 Instances Should Use IMDSv2",
            description="EC2 instances should use Instance Metadata Service version 2 (IMDSv2) for improved security against SSRF attacks.",
            severity=Severity.MEDIUM,
            compliance_frameworks=[ComplianceFramework.AWS_FOUNDATIONAL, ComplianceFramework.NIST_CSF],
            remediation="Configure EC2 instances to require IMDSv2 by setting HttpTokens to 'required' in the instance metadata options."
        )
    
    def evaluate(self, resource: Dict[str, Any], context: Dict[str, Any] = None) -> List[Dict[str, Any]]:
        """Evaluate IMDS configuration."""
        findings = []
        
        if resource.get('type') == 'ec2_instance':
            instance_id = resource.get('instance_id', 'unknown')
            metadata_options = resource.get('metadata_options', {})
            http_tokens = metadata_options.get('HttpTokens', 'optional')
            state = resource.get('state', {}).get('Name', 'unknown')
            
            if state == 'running' and http_tokens != 'required':
                findings.append(self.create_finding(
                    resource,
                    f"EC2 instance '{instance_id}' is not configured to require IMDSv2. This may expose the instance to SSRF attacks.",
                    context
                ))
        
        return findings


class EC2PublicAMIRule(Rule):
    """Rule to check for public AMIs."""
    
    def __init__(self):
        super().__init__(
            rule_id="EC2-005",
            title="AMIs Should Not Be Public",
            description="Amazon Machine Images (AMIs) should not be made public unless specifically intended for public distribution.",
            severity=Severity.MEDIUM,
            compliance_frameworks=[ComplianceFramework.CIS_AWS, ComplianceFramework.NIST_CSF],
            remediation="Review public AMIs and make them private if they contain proprietary or sensitive configurations. Use cross-account sharing for controlled access."
        )
    
    def evaluate(self, resource: Dict[str, Any], context: Dict[str, Any] = None) -> List[Dict[str, Any]]:
        """Evaluate AMI public accessibility."""
        findings = []
        
        if resource.get('type') == 'ami':
            image_id = resource.get('image_id', 'unknown')
            public = resource.get('public', False)
            owner_id = resource.get('owner_id', '')
            account_id = context.get('account_id', '') if context else ''
            
            # Only check AMIs owned by this account
            if owner_id == account_id and public:
                findings.append(self.create_finding(
                    resource,
                    f"AMI '{image_id}' is publicly accessible. Verify this is intentional and doesn't expose sensitive configurations.",
                    context
                ))
        
        return findings


class RulesEngine:
    """
    Comprehensive security rules engine for AWS resources.
    
    This engine evaluates AWS resources against security best practices
    and compliance frameworks, providing detailed findings and remediation guidance.
    """
    
    def __init__(self):
        """Initialize the Rules Engine."""
        self.logger = logging.getLogger(__name__)
        self.rules = {}
        self._load_default_rules()
    
    def _load_default_rules(self):
        """Load default security rules."""
        # Load IAM rules
        for rule in IAMRules.get_rules():
            self.rules[rule.rule_id] = rule
        
        # Load EC2 rules
        for rule in EC2Rules.get_rules():
            self.rules[rule.rule_id] = rule
        
        self.logger.info(f"Loaded {len(self.rules)} default security rules")
    
    def add_rule(self, rule: Rule):
        """
        Add a custom rule to the engine.
        
        Args:
            rule: Rule instance to add
        """
        self.rules[rule.rule_id] = rule
        self.logger.info(f"Added custom rule: {rule.rule_id}")
    
    def remove_rule(self, rule_id: str):
        """
        Remove a rule from the engine.
        
        Args:
            rule_id: ID of the rule to remove
        """
        if rule_id in self.rules:
            del self.rules[rule_id]
            self.logger.info(f"Removed rule: {rule_id}")
    
    def get_rules_by_framework(self, framework: ComplianceFramework) -> List[Rule]:
        """
        Get all rules applicable to a compliance framework.
        
        Args:
            framework: Compliance framework
            
        Returns:
            List[Rule]: Rules applicable to the framework
        """
        return [
            rule for rule in self.rules.values()
            if framework in rule.compliance_frameworks
        ]
    
    def get_rules_by_severity(self, severity: Severity) -> List[Rule]:
        """
        Get all rules with a specific severity level.
        
        Args:
            severity: Severity level
            
        Returns:
            List[Rule]: Rules with the specified severity
        """
        return [
            rule for rule in self.rules.values()
            if rule.severity == severity
        ]
    
    def evaluate_resource(self, resource: Dict[str, Any], 
                         context: Dict[str, Any] = None,
                         rule_ids: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        """
        Evaluate a resource against applicable rules.
        
        Args:
            resource: AWS resource data
            context: Additional context (account info, region, etc.)
            rule_ids: Specific rules to evaluate (optional)
            
        Returns:
            List[Dict]: List of findings
        """
        findings = []
        rules_to_evaluate = []
        
        if rule_ids:
            rules_to_evaluate = [self.rules[rid] for rid in rule_ids if rid in self.rules]
        else:
            rules_to_evaluate = list(self.rules.values())
        
        for rule in rules_to_evaluate:
            try:
                rule_findings = rule.evaluate(resource, context)
                findings.extend(rule_findings)
            except Exception as e:
                self.logger.error(f"Error evaluating rule {rule.rule_id} for resource {resource.get('id', 'unknown')}: {e}")
        
        return findings
    
    def evaluate_resources(self, resources: List[Dict[str, Any]], 
                          context: Dict[str, Any] = None,
                          frameworks: Optional[List[ComplianceFramework]] = None) -> Dict[str, Any]:
        """
        Evaluate multiple resources against applicable rules.
        
        Args:
            resources: List of AWS resource data
            context: Additional context
            frameworks: Specific compliance frameworks to check (optional)
            
        Returns:
            Dict: Evaluation results with findings organized by severity and compliance
        """
        all_findings = []
        rules_to_use = list(self.rules.values())
        
        if frameworks:
            rules_to_use = []
            for framework in frameworks:
                rules_to_use.extend(self.get_rules_by_framework(framework))
            # Remove duplicates
            rules_to_use = list(set(rules_to_use))
        
        for resource in resources:
            for rule in rules_to_use:
                try:
                    rule_findings = rule.evaluate(resource, context)
                    all_findings.extend(rule_findings)
                except Exception as e:
                    self.logger.error(f"Error evaluating rule {rule.rule_id} for resource {resource.get('id', 'unknown')}: {e}")
        
        # Organize findings
        results = {
            'total_findings': len(all_findings),
            'summary': {
                'critical': len([f for f in all_findings if f['severity'] == 'critical']),
                'high': len([f for f in all_findings if f['severity'] == 'high']),
                'medium': len([f for f in all_findings if f['severity'] == 'medium']),
                'low': len([f for f in all_findings if f['severity'] == 'low']),
                'info': len([f for f in all_findings if f['severity'] == 'info'])
            },
            'findings': all_findings,
            'compliance': self._analyze_compliance(all_findings),
            'evaluation_timestamp': datetime.utcnow().isoformat(),
            'rules_evaluated': len(rules_to_use)
        }
        
        return results
    
    def _analyze_compliance(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Analyze compliance status based on findings.
        
        Args:
            findings: List of findings
            
        Returns:
            Dict: Compliance analysis
        """
        compliance_analysis = {}
        
        # Group findings by compliance framework
        for finding in findings:
            for framework in finding.get('compliance', []):
                if framework not in compliance_analysis:
                    compliance_analysis[framework] = {
                        'total_violations': 0,
                        'critical_violations': 0,
                        'high_violations': 0,
                        'medium_violations': 0,
                        'low_violations': 0,
                        'rules_with_violations': set()
                    }
                
                compliance_analysis[framework]['total_violations'] += 1
                compliance_analysis[framework][f"{finding['severity']}_violations"] += 1
                compliance_analysis[framework]['rules_with_violations'].add(finding['rule_id'])
        
        # Convert sets to counts
        for framework in compliance_analysis:
            compliance_analysis[framework]['rules_with_violations'] = len(compliance_analysis[framework]['rules_with_violations'])
        
        return compliance_analysis
    
    def get_rule_documentation(self, rule_id: str) -> Optional[Dict[str, Any]]:
        """
        Get detailed documentation for a specific rule.
        
        Args:
            rule_id: Rule identifier
            
        Returns:
            Optional[Dict]: Rule documentation
        """
        if rule_id not in self.rules:
            return None
        
        rule = self.rules[rule_id]
        return {
            'rule_id': rule.rule_id,
            'title': rule.title,
            'description': rule.description,
            'severity': rule.severity.value,
            'compliance_frameworks': [framework.value for framework in rule.compliance_frameworks],
            'remediation': rule.remediation,
            'rule_type': rule.__class__.__name__
        }
    
    def export_rules(self) -> Dict[str, Any]:
        """
        Export all rules configuration.
        
        Returns:
            Dict: Rules configuration
        """
        return {
            'rules': {
                rule_id: self.get_rule_documentation(rule_id)
                for rule_id in self.rules.keys()
            },
            'total_rules': len(self.rules),
            'export_timestamp': datetime.utcnow().isoformat()
        }
    
    def validate_rules(self) -> List[str]:
        """
        Validate all loaded rules.
        
        Returns:
            List[str]: List of validation errors
        """
        errors = []
        
        for rule_id, rule in self.rules.items():
            try:
                # Check required attributes
                if not hasattr(rule, 'rule_id') or not rule.rule_id:
                    errors.append(f"Rule {rule_id}: Missing or empty rule_id")
                
                if not hasattr(rule, 'title') or not rule.title:
                    errors.append(f"Rule {rule_id}: Missing or empty title")
                
                if not hasattr(rule, 'evaluate') or not callable(rule.evaluate):
                    errors.append(f"Rule {rule_id}: Missing or invalid evaluate method")
                
                # Check severity
                if not isinstance(rule.severity, Severity):
                    errors.append(f"Rule {rule_id}: Invalid severity type")
                
                # Check compliance frameworks
                if not isinstance(rule.compliance_frameworks, list):
                    errors.append(f"Rule {rule_id}: compliance_frameworks must be a list")
                
                for framework in rule.compliance_frameworks:
                    if not isinstance(framework, ComplianceFramework):
                        errors.append(f"Rule {rule_id}: Invalid compliance framework type")
                
            except Exception as e:
                errors.append(f"Rule {rule_id}: Validation error - {e}")
        
        return errors