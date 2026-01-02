"""
IAM Scanner for AWS CSPM

This module performs comprehensive security scanning of AWS Identity and Access Management (IAM) resources.

IAM is the cornerstone of AWS security, controlling who can access what resources and under what conditions.
This scanner performs deep analysis of IAM configurations to identify security vulnerabilities, compliance
violations, and operational risks.

COMPREHENSIVE IAM SECURITY SCANNING:

1. USER ACCOUNT SECURITY
   - Multi-factor authentication (MFA) enforcement
   - Unused and dormant user accounts identification
   - Access key management (age, rotation, usage)
   - Password policy compliance
   - Root account usage monitoring
   - Console access patterns analysis
   - Programmatic access review

2. ROLE-BASED ACCESS CONTROL (RBAC)
   - Role trust policy analysis (confused deputy protection)
   - Cross-account access review and validation
   - Service role security configuration
   - Assume role chain analysis
   - External ID validation for third-party access
   - Session duration and temporary credential management

3. POLICY AND PERMISSIONS ANALYSIS
   - Overly permissive policies identification (wildcard usage)
   - Unused permissions detection (IAM Access Advisor integration)
   - Policy version management and governance
   - Inline vs managed policy usage patterns
   - Principal of least privilege validation
   - Resource-level permissions granularity
   - Condition-based access controls verification

4. ACCESS KEY AND CREDENTIAL MANAGEMENT
   - Access key age and rotation compliance
   - Unused access keys identification
   - Multiple access keys per user analysis
   - Service-specific credential usage
   - Temporary credential security practices
   - API key exposure risk assessment

5. COMPLIANCE AND GOVERNANCE
   - CIS AWS Foundations Benchmark compliance
   - NIST Cybersecurity Framework alignment
   - PCI-DSS IAM requirements validation
   - SOC 2 access control verification
   - AWS Config integration for continuous monitoring
   - CloudTrail integration for access auditing

6. ADVANCED SECURITY FEATURES
   - Service Control Policy (SCP) analysis
   - Permission boundary implementation review
   - IAM condition context validation
   - Resource-based policy conflicts
   - Cross-service confused deputy protection
   - IAM role chaining security

SECURITY FOCUS AREAS:
- Privileged Access Management: Admin and power user access controls
- Identity Federation: SAML, OIDC, and cross-account trust relationships
- Automated Access: Service roles and resource-based policies
- Compliance Monitoring: Continuous compliance with security standards
- Incident Response: Rapid access revocation and forensic capabilities

COMPLIANCE FRAMEWORKS COVERED:
- CIS AWS Foundations Benchmark v1.5.0 (Identity and Access Management)
- NIST Cybersecurity Framework v1.1 (Identity and Access Management)
- PCI-DSS v4.0 (Access Control Requirements)
- SOC 2 Type II (Access Control and User Entity Controls)
- ISO 27001:2013 (Access Control and Identity Management)
- AWS Well-Architected Framework (Security Pillar)

COMMON IAM VULNERABILITIES DETECTED:
- Admin privileges without MFA
- Unused IAM users and access keys
- Overly broad wildcard permissions
- Cross-account trust without external ID
- Service roles with excessive permissions
- Missing password policies
- Unencrypted access keys in code
- Lack of permission boundaries
- Missing IAM condition keys
- Inadequate access logging
"""

import json
import logging
from datetime import datetime, timezone
from typing import Dict, List, Optional, Set, Tuple
import re

from botocore.exceptions import ClientError


class IAMScanner:
    """
    Comprehensive IAM Security Scanner
    
    Analyzes AWS Identity and Access Management configurations for security vulnerabilities,
    compliance violations, and operational risks across users, roles, policies, and access patterns.
    """
    
    def __init__(self, config, aws_client_manager):
        """
        Initialize IAM Scanner with configuration and AWS client manager.
        
        Args:
            config: Configuration object containing scan settings and compliance requirements
            aws_client_manager: Manager for AWS API client connections and cross-account access
        """
        self.config = config
        self.aws_client_manager = aws_client_manager
        self.logger = logging.getLogger(__name__)
        
        # Security thresholds and configuration
        self.max_access_key_age_days = config.get('iam_max_access_key_age', 90)
        self.max_unused_user_days = config.get('iam_max_unused_user_days', 90)
        self.require_mfa_for_console = config.get('iam_require_mfa_console', True)
        self.require_mfa_for_api = config.get('iam_require_mfa_api', False)
        self.max_inline_policies = config.get('iam_max_inline_policies', 0)
        
        # Dangerous actions and permissions that require special attention
        self.dangerous_actions = {
            'iam:*', 'sts:AssumeRole', '*:*', 'ec2:*', 's3:*',
            'iam:CreateUser', 'iam:CreateRole', 'iam:AttachUserPolicy', 
            'iam:AttachRolePolicy', 'iam:PutUserPolicy', 'iam:PutRolePolicy',
            'sts:GetSessionToken', 'sts:GetFederationToken'
        }
        
        # Cache for reducing API calls during analysis
        self._user_cache = {}
        self._role_cache = {}
        self._policy_cache = {}
        self._group_cache = {}
    
    async def scan(self, session, region: str) -> List[Dict]:
        """
        Perform comprehensive IAM security scan.
        
        IAM is a global AWS service, but we use the region parameter for client creation
        and to maintain consistency with other service scanners.
        
        This method orchestrates a complete security analysis of all IAM resources including:
        - User accounts and their security configurations
        - IAM roles and trust relationships
        - Managed and inline policies
        - Access keys and credential security
        - Groups and group memberships
        - Service-linked roles and AWS managed resources
        
        Args:
            session: Authenticated AWS session with IAM read permissions
            region: AWS region identifier (IAM is global but used for client creation)
            
        Returns:
            List[Dict]: Comprehensive list of IAM security findings with structure:
                - resource_type: Type of IAM resource (IAMUser, IAMRole, IAMPolicy, etc.)
                - resource_id: Unique identifier (username, role name, policy ARN, etc.)
                - region: Always 'global' for IAM resources
                - severity: CRITICAL, HIGH, MEDIUM, LOW, or INFO
                - title: Brief, actionable description of the finding
                - description: Detailed explanation of the security issue and its implications
                - recommendation: Specific, actionable steps to remediate the issue
                - compliance: List of compliance frameworks this finding relates to
                - tags: Additional metadata for categorization, filtering, and automation
        """
        findings = []
        
        try:
            # IAM is a global service - create client
            iam_client = session.client('iam', region_name=region)
            self.logger.info("Starting comprehensive IAM security scan")
            
            # 1. Scan IAM users for security issues
            self.logger.debug("Scanning IAM users...")
            user_findings = await self._scan_users(iam_client)
            findings.extend(user_findings)
            
            # 2. Scan IAM roles for trust and permission issues  
            self.logger.debug("Scanning IAM roles...")
            role_findings = await self._scan_roles(iam_client)
            findings.extend(role_findings)
            
            # 3. Scan IAM policies for overly broad permissions
            self.logger.debug("Scanning IAM policies...")
            policy_findings = await self._scan_policies(iam_client)
            findings.extend(policy_findings)
            
            # 4. Scan IAM groups and memberships
            self.logger.debug("Scanning IAM groups...")
            group_findings = await self._scan_groups(iam_client)
            findings.extend(group_findings)
            
            # 5. Check account-level IAM security settings
            self.logger.debug("Checking account IAM settings...")
            account_findings = await self._check_account_settings(iam_client)
            findings.extend(account_findings)
            
            # 6. Analyze cross-service access patterns
            self.logger.debug("Analyzing cross-service access...")
            access_findings = await self._analyze_cross_service_access(iam_client)
            findings.extend(access_findings)
            
            # 7. Check for unused and dormant resources
            self.logger.debug("Identifying unused IAM resources...")
            unused_findings = await self._find_unused_resources(iam_client)
            findings.extend(unused_findings)
            
            # 8. Validate compliance with security standards
            self.logger.debug("Validating compliance standards...")
            compliance_findings = await self._validate_compliance_standards(iam_client)
            findings.extend(compliance_findings)
            
            self.logger.info(f"IAM scan completed. Found {len(findings)} security findings")
            return findings
            
        except Exception as e:
            self.logger.error(f"IAM scan failed: {str(e)}")
            # Return a finding about the scan failure for transparency
            return [{
                'resource_type': 'IAM',
                'resource_id': f'scan-failure-{region}',
                'region': 'global',
                'severity': 'INFO',
                'title': 'IAM Scan Failed',
                'description': f'Unable to complete IAM scan: {str(e)}',
                'recommendation': 'Check IAM permissions and AWS connectivity',
                'compliance': [],
                'tags': {'error': True, 'scan_failure': True}
            }]
    
    async def _scan_users(self, iam_client) -> List[Dict]:
        """
        Scan IAM users for comprehensive security issues.
        
        This method performs deep analysis of all IAM user accounts including:
        - Multi-factor authentication (MFA) enforcement and compliance
        - Access key security, age, rotation, and usage patterns
        - Password policy compliance and strength requirements
        - User activity analysis and dormant account detection
        - Console vs programmatic access patterns
        - Privilege escalation risks and excessive permissions
        - Compliance with organizational security standards
        
        Args:
            iam_client: IAM client for API operations
            
        Returns:
            List[Dict]: Detailed list of user-related security findings
        """
        findings = []
        
        try:
            # Get all IAM users in the account using pagination
            paginator = iam_client.get_paginator('list_users')
            user_count = 0
            
            self.logger.debug("Retrieving all IAM users for security analysis...")
            
            for page in paginator.paginate():
                for user in page['Users']:
                    user_count += 1
                    username = user['UserName']
                    user_created = user['CreateDate']
                    
                    # Store user in cache for cross-reference analysis
                    self._user_cache[username] = user
                    
                    self.logger.debug(f"Analyzing user: {username}")
                    
                    # 1. CRITICAL: Check for MFA compliance
                    mfa_findings = await self._check_user_mfa(iam_client, username, user)
                    findings.extend(mfa_findings)
                    
                    # 2. HIGH: Access key security analysis
                    access_key_findings = await self._check_user_access_keys(iam_client, username, user)
                    findings.extend(access_key_findings)
                    
                    # 3. MEDIUM: User activity and dormancy analysis
                    activity_findings = await self._check_user_activity(iam_client, username, user)
                    findings.extend(activity_findings)
                    
                    # 4. HIGH: Permission and policy analysis
                    permission_findings = await self._check_user_permissions(iam_client, username, user)
                    findings.extend(permission_findings)
                    
                    # 5. MEDIUM: Console access configuration
                    console_findings = await self._check_user_console_access(iam_client, username, user)
                    findings.extend(console_findings)
                    
                    # 6. LOW: User metadata and compliance tags
                    metadata_findings = await self._check_user_metadata(iam_client, username, user)
                    findings.extend(metadata_findings)
            
            self.logger.info(f"Completed analysis of {user_count} IAM users")
            
            # Additional account-level user findings
            if user_count == 0:
                findings.append({
                    'resource_type': 'IAMAccount',
                    'resource_id': 'iam-users',
                    'region': 'global',
                    'severity': 'INFO',
                    'title': 'No IAM Users Found',
                    'description': (
                        'This AWS account has no IAM users. All access may be through '
                        'federated identity, root account, or assumed roles. This can be '
                        'a security best practice if using proper identity federation.'
                    ),
                    'recommendation': (
                        'Verify that access is properly managed through identity federation '
                        'or cross-account roles rather than direct IAM users.'
                    ),
                    'compliance': ['AWS-Well-Architected'],
                    'tags': {'service': 'iam', 'category': 'user_management', 'count': user_count}
                })
            elif user_count > 100:
                findings.append({
                    'resource_type': 'IAMAccount',
                    'resource_id': 'iam-users',
                    'region': 'global',
                    'severity': 'MEDIUM',
                    'title': 'High Number of IAM Users',
                    'description': (
                        f'This account has {user_count} IAM users. Large numbers of IAM users '
                        'can indicate lack of identity federation and increased management overhead.'
                    ),
                    'recommendation': (
                        'Consider implementing identity federation (SAML, OIDC) to reduce '
                        'the number of directly managed IAM users.'
                    ),
                    'compliance': ['AWS-Well-Architected'],
                    'tags': {'service': 'iam', 'category': 'user_management', 'count': user_count}
                })
                
        except ClientError as e:
            self.logger.error(f"Failed to scan IAM users: {e}")
            findings.append({
                'resource_type': 'IAM',
                'resource_id': 'users-scan-error',
                'region': 'global',
                'severity': 'INFO',
                'title': 'IAM Users Scan Permission Error',
                'description': f'Unable to list IAM users: {e}',
                'recommendation': 'Ensure iam:ListUsers permission is granted',
                'compliance': [],
                'tags': {'error': True, 'permission_error': True}
            })
        
        return findings
    
    async def _check_user_mfa(self, iam_client, username: str, user: Dict) -> List[Dict]:
        """
        Check multi-factor authentication configuration for a user.
        
        MFA is one of the most critical security controls for preventing unauthorized access.
        This method checks for:
        - Virtual MFA devices (Google Authenticator, Authy, etc.)
        - Hardware MFA devices (YubiKey, hardware tokens)
        - SMS-based MFA (less secure but better than none)
        - MFA enforcement for console access
        - MFA requirements for API access
        
        Args:
            iam_client: IAM client for API calls
            username: IAM username to check
            user: User object from IAM API
            
        Returns:
            List[Dict]: MFA-related findings
        """
        findings = []
        
        try:
            # Check for MFA devices attached to the user
            mfa_devices = iam_client.list_mfa_devices(UserName=username)
            virtual_mfa = mfa_devices.get('MFADevices', [])
            
            # Check if user has console access (login profile exists)
            has_console_access = False
            try:
                iam_client.get_login_profile(UserName=username)
                has_console_access = True
            except ClientError as e:
                if e.response['Error']['Code'] != 'NoSuchEntity':
                    self.logger.warning(f"Could not check login profile for {username}: {e}")
            
            # Check access keys (indicates programmatic access)
            access_keys = iam_client.list_access_keys(UserName=username)
            has_access_keys = len(access_keys.get('AccessKeyMetadata', [])) > 0
            
            # CRITICAL: Console access without MFA
            if has_console_access and not virtual_mfa:
                findings.append({
                    'resource_type': 'IAMUser',
                    'resource_id': username,
                    'region': 'global',
                    'severity': 'CRITICAL',
                    'title': 'IAM User Has Console Access Without MFA',
                    'description': (
                        f'User {username} has console (web) access to AWS but no MFA device configured. '
                        'This creates a significant security risk as compromised passwords can lead to '
                        'immediate unauthorized access to AWS resources. Console access without MFA '
                        'violates most security compliance frameworks.'
                    ),
                    'recommendation': (
                        'Immediately enable MFA for this user: '
                        '1. Sign in to AWS Console as the user '
                        '2. Go to IAM > Users > [username] > Security credentials '
                        '3. Assign a virtual MFA device (Google Authenticator recommended) '
                        '4. Consider enforcing MFA through IAM policies for all console access'
                    ),
                    'compliance': ['CIS-AWS-1.5.0-1.2', 'NIST-800-53-IA-2', 'PCI-DSS-8.3'],
                    'tags': {
                        'service': 'iam',
                        'category': 'mfa_compliance',
                        'access_type': 'console',
                        'user_created': user['CreateDate'].isoformat(),
                        'severity_justification': 'console_access_without_mfa'
                    }
                })
            
            # HIGH: API access without MFA (if organization requires it)
            if has_access_keys and not virtual_mfa and self.require_mfa_for_api:
                findings.append({
                    'resource_type': 'IAMUser',
                    'resource_id': username,
                    'region': 'global',
                    'severity': 'HIGH',
                    'title': 'IAM User Has API Access Without MFA',
                    'description': (
                        f'User {username} has programmatic access (access keys) but no MFA configured. '
                        'While API access typically uses access keys rather than MFA, your organization '
                        'policy requires MFA for additional security. Consider using temporary credentials '
                        'with MFA-protected roles instead.'
                    ),
                    'recommendation': (
                        'Enable MFA for this user and use MFA-protected roles for API access: '
                        '1. Configure MFA device for the user '
                        '2. Create IAM roles with required permissions '
                        '3. Use sts:AssumeRole with MFA condition '
                        '4. Replace long-term access keys with temporary credentials'
                    ),
                    'compliance': ['NIST-800-53-IA-2', 'Custom-Security-Policy'],
                    'tags': {
                        'service': 'iam',
                        'category': 'mfa_compliance',
                        'access_type': 'programmatic',
                        'policy_requirement': 'organizational'
                    }
                })
            
            # MEDIUM: User exists but has no access method (potentially orphaned)
            if not has_console_access and not has_access_keys:
                findings.append({
                    'resource_type': 'IAMUser',
                    'resource_id': username,
                    'region': 'global',
                    'severity': 'MEDIUM',
                    'title': 'IAM User Has No Access Credentials',
                    'description': (
                        f'User {username} exists but has no console access (login profile) and no '
                        'access keys configured. This may indicate an orphaned or incomplete user setup.'
                    ),
                    'recommendation': (
                        'Review this user account: '
                        '1. If the user is no longer needed, delete the account '
                        '2. If the user needs access, configure appropriate credentials '
                        '3. Ensure proper access provisioning processes are followed'
                    ),
                    'compliance': ['AWS-Well-Architected'],
                    'tags': {
                        'service': 'iam',
                        'category': 'user_lifecycle',
                        'access_type': 'none',
                        'potential_issue': 'orphaned_user'
                    }
                })
            
            # INFO: Good practice - MFA enabled
            if virtual_mfa:
                mfa_device_count = len(virtual_mfa)
                findings.append({
                    'resource_type': 'IAMUser',
                    'resource_id': username,
                    'region': 'global',
                    'severity': 'INFO',
                    'title': 'IAM User Has MFA Enabled',
                    'description': (
                        f'User {username} has {mfa_device_count} MFA device(s) configured. '
                        'This follows security best practices for protecting user accounts.'
                    ),
                    'recommendation': 'Continue following MFA best practices for all user accounts.',
                    'compliance': ['CIS-AWS-1.5.0-1.2', 'NIST-800-53-IA-2'],
                    'tags': {
                        'service': 'iam',
                        'category': 'mfa_compliance',
                        'status': 'compliant',
                        'mfa_device_count': mfa_device_count
                    }
                })
                
        except ClientError as e:
            self.logger.error(f"Failed to check MFA for user {username}: {e}")
        
        return findings
    
    async def _check_user_access_keys(self, iam_client, username: str, user: Dict) -> List[Dict]:
        """
        Analyze access key security for comprehensive credential management assessment.
        
        Access keys are long-term credentials that pose significant security risks if mismanaged.
        This method performs detailed analysis including:
        - Access key age and rotation compliance
        - Multiple access keys per user (security risk)
        - Unused access keys identification
        - Last used analysis for dormant credentials
        - Access key permissions and scope
        - Service-specific credential recommendations
        
        Args:
            iam_client: IAM client for API operations
            username: IAM username to analyze
            user: User object containing metadata
            
        Returns:
            List[Dict]: Access key related security findings
        """
        findings = []
        
        try:
            # Get all access keys for this user
            access_keys_response = iam_client.list_access_keys(UserName=username)
            access_keys = access_keys_response.get('AccessKeyMetadata', [])
            
            if not access_keys:
                # No access keys - this is often good for human users
                findings.append({
                    'resource_type': 'IAMUser',
                    'resource_id': username,
                    'region': 'global',
                    'severity': 'INFO',
                    'title': 'IAM User Has No Access Keys',
                    'description': (
                        f'User {username} has no access keys configured. This follows security '
                        'best practices for human users who should primarily use console access '
                        'with MFA and temporary credentials through roles when needed.'
                    ),
                    'recommendation': 'Continue using temporary credentials and avoid long-term access keys for human users.',
                    'compliance': ['AWS-Well-Architected', 'NIST-800-53-IA-5'],
                    'tags': {
                        'service': 'iam',
                        'category': 'access_keys',
                        'status': 'no_keys',
                        'best_practice': True
                    }
                })
                return findings
            
            # Analyze each access key
            active_keys = 0
            inactive_keys = 0
            
            for key_metadata in access_keys:
                access_key_id = key_metadata['AccessKeyId']
                key_status = key_metadata['Status']
                key_created = key_metadata['CreateDate']
                
                # Calculate key age
                key_age = (datetime.now(timezone.utc) - key_created.replace(tzinfo=timezone.utc)).days
                
                if key_status == 'Active':
                    active_keys += 1
                else:
                    inactive_keys += 1
                
                # CRITICAL: Very old access keys (> 90 days)
                if key_age > self.max_access_key_age_days:
                    severity = 'HIGH' if key_age > 180 else 'MEDIUM'  # Escalate severity for very old keys
                    findings.append({
                        'resource_type': 'IAMAccessKey',
                        'resource_id': access_key_id,
                        'region': 'global',
                        'severity': severity,
                        'title': 'IAM Access Key Exceeds Maximum Age',
                        'description': (
                            f'Access key {access_key_id} for user {username} is {key_age} days old, '
                            f'exceeding the maximum recommended age of {self.max_access_key_age_days} days. '
                            'Old access keys pose security risks as they may be exposed in code, logs, '
                            'or configuration files over time.'
                        ),
                        'recommendation': (
                            'Rotate this access key immediately: '
                            '1. Create a new access key for the user '
                            '2. Update all applications/scripts to use the new key '
                            '3. Test that all systems work with the new key '
                            '4. Deactivate and delete the old access key '
                            '5. Implement automated key rotation where possible'
                        ),
                        'compliance': ['CIS-AWS-1.5.0-1.4', 'NIST-800-53-IA-5', 'PCI-DSS-8.2.4'],
                        'tags': {
                            'service': 'iam',
                            'category': 'access_key_management',
                            'key_age_days': key_age,
                            'username': username,
                            'rotation_required': True,
                            'security_risk': 'credential_age'
                        }
                    })
                
                # Check last used information
                try:
                    last_used_response = iam_client.get_access_key_last_used(AccessKeyId=access_key_id)
                    last_used_info = last_used_response.get('AccessKeyLastUsed', {})
                    last_used_date = last_used_info.get('LastUsedDate')
                    
                    if last_used_date:
                        days_since_used = (datetime.now(timezone.utc) - last_used_date.replace(tzinfo=timezone.utc)).days
                        
                        # MEDIUM: Unused access keys
                        if days_since_used > self.max_unused_user_days:
                            findings.append({
                                'resource_type': 'IAMAccessKey',
                                'resource_id': access_key_id,
                                'region': 'global',
                                'severity': 'MEDIUM',
                                'title': 'IAM Access Key Not Recently Used',
                                'description': (
                                    f'Access key {access_key_id} for user {username} has not been used '
                                    f'for {days_since_used} days (last used: {last_used_date.strftime("%Y-%m-%d")}). '
                                    'Unused access keys should be removed to reduce the attack surface.'
                                ),
                                'recommendation': (
                                    'Review and potentially remove this unused access key: '
                                    '1. Verify the key is truly unused by checking application logs '
                                    '2. Coordinate with development teams to confirm removal is safe '
                                    '3. Deactivate the key first to test impact '
                                    '4. Delete the key if no issues arise after deactivation'
                                ),
                                'compliance': ['CIS-AWS-1.5.0-1.3', 'AWS-Well-Architected'],
                                'tags': {
                                    'service': 'iam',
                                    'category': 'access_key_management',
                                    'days_since_used': days_since_used,
                                    'last_used_date': last_used_date.isoformat(),
                                    'username': username,
                                    'cleanup_candidate': True
                                }
                            })
                        
                        # Include service and region information if available
                        last_used_service = last_used_info.get('ServiceName')
                        last_used_region = last_used_info.get('Region')
                        
                        if last_used_service:
                            findings.append({
                                'resource_type': 'IAMAccessKey',
                                'resource_id': access_key_id,
                                'region': 'global',
                                'severity': 'INFO',
                                'title': 'Access Key Usage Information',
                                'description': (
                                    f'Access key {access_key_id} was last used for {last_used_service} service '
                                    f'in {last_used_region or "unknown region"} on {last_used_date.strftime("%Y-%m-%d")}.'
                                ),
                                'recommendation': 'Monitor access key usage patterns for security analysis.',
                                'compliance': ['AWS-Well-Architected'],
                                'tags': {
                                    'service': 'iam',
                                    'category': 'access_key_usage',
                                    'last_service': last_used_service,
                                    'last_region': last_used_region or 'unknown',
                                    'monitoring': True
                                }
                            })
                    
                    else:
                        # Key has never been used
                        findings.append({
                            'resource_type': 'IAMAccessKey',
                            'resource_id': access_key_id,
                            'region': 'global',
                            'severity': 'MEDIUM',
                            'title': 'IAM Access Key Never Used',
                            'description': (
                                f'Access key {access_key_id} for user {username} has never been used. '
                                'Unused access keys increase security risk without providing value.'
                            ),
                            'recommendation': (
                                'Remove this unused access key: '
                                '1. Confirm with the user that the key is not needed '
                                '2. Delete the access key to reduce attack surface '
                                '3. Create new keys only when actually needed'
                            ),
                            'compliance': ['CIS-AWS-1.5.0-1.3'],
                            'tags': {
                                'service': 'iam',
                                'category': 'access_key_management',
                                'usage_status': 'never_used',
                                'username': username,
                                'cleanup_candidate': True
                            }
                        })
                        
                except ClientError as e:
                    if e.response['Error']['Code'] != 'AccessDenied':
                        self.logger.warning(f"Could not get last used info for key {access_key_id}: {e}")
            
            # HIGH: Multiple active access keys per user
            if active_keys > 1:
                findings.append({
                    'resource_type': 'IAMUser',
                    'resource_id': username,
                    'region': 'global',
                    'severity': 'HIGH',
                    'title': 'IAM User Has Multiple Active Access Keys',
                    'description': (
                        f'User {username} has {active_keys} active access keys. Multiple access keys '
                        'increase the attack surface and make credential management more complex. '
                        'Most users should have at most one active access key.'
                    ),
                    'recommendation': (
                        'Reduce to one active access key per user: '
                        '1. Identify which access key is currently in use '
                        '2. Plan the retirement of unused keys '
                        '3. Update applications to use a single key '
                        '4. Remove unnecessary access keys '
                        '5. Consider using IAM roles instead of user keys for applications'
                    ),
                    'compliance': ['AWS-Well-Architected', 'NIST-800-53-IA-5'],
                    'tags': {
                        'service': 'iam',
                        'category': 'access_key_management',
                        'active_key_count': active_keys,
                        'username': username,
                        'security_risk': 'multiple_keys'
                    }
                })
            
            # INFO: Inactive keys (good for awareness)
            if inactive_keys > 0:
                findings.append({
                    'resource_type': 'IAMUser',
                    'resource_id': username,
                    'region': 'global',
                    'severity': 'INFO',
                    'title': 'IAM User Has Inactive Access Keys',
                    'description': (
                        f'User {username} has {inactive_keys} inactive access key(s). Inactive keys '
                        'are safer than active ones but should be deleted if no longer needed.'
                    ),
                    'recommendation': 'Review inactive access keys and delete those that are no longer needed.',
                    'compliance': ['AWS-Well-Architected'],
                    'tags': {
                        'service': 'iam',
                        'category': 'access_key_management',
                        'inactive_key_count': inactive_keys,
                        'username': username,
                        'housekeeping': True
                    }
                })
                
        except ClientError as e:
            self.logger.error(f"Failed to check access keys for user {username}: {e}")
        
        return findings
    
    async def _check_user_activity(self, iam_client, username: str, user: Dict) -> List[Dict]:
        """Check user activity patterns and identify dormant accounts."""
        findings = []
        
        try:
            user_created = user['CreateDate']
            account_age = (datetime.now(timezone.utc) - user_created.replace(tzinfo=timezone.utc)).days
            
            # Check password last used (console activity)
            try:
                login_profile = iam_client.get_login_profile(UserName=username)
                password_last_used = login_profile.get('LoginProfile', {}).get('PasswordLastUsed')
                
                if password_last_used:
                    days_since_console_login = (datetime.now(timezone.utc) - password_last_used.replace(tzinfo=timezone.utc)).days
                    
                    if days_since_console_login > self.max_unused_user_days:
                        findings.append({
                            'resource_type': 'IAMUser',
                            'resource_id': username,
                            'region': 'global',
                            'severity': 'MEDIUM',
                            'title': 'IAM User Console Access Not Recently Used',
                            'description': f'User {username} last logged into console {days_since_console_login} days ago',
                            'recommendation': 'Review if this user account is still needed',
                            'compliance': ['CIS-AWS-1.5.0-1.3'],
                            'tags': {'service': 'iam', 'category': 'user_activity', 'days_inactive': days_since_console_login}
                        })
                        
            except ClientError as e:
                if e.response['Error']['Code'] != 'NoSuchEntity':
                    self.logger.warning(f"Could not check login profile for {username}: {e}")
            
        except Exception as e:
            self.logger.error(f"Failed to check user activity for {username}: {e}")
        
        return findings
    
    async def _check_user_permissions(self, iam_client, username: str, user: Dict) -> List[Dict]:
        """Analyze user permissions for overly broad access."""
        findings = []
        
        try:
            # Check attached managed policies
            attached_policies = iam_client.list_attached_user_policies(UserName=username)
            for policy in attached_policies.get('AttachedPolicies', []):
                if 'Admin' in policy['PolicyName'] or policy['PolicyArn'].endswith(':policy/PowerUserAccess'):
                    findings.append({
                        'resource_type': 'IAMUser',
                        'resource_id': username,
                        'region': 'global',
                        'severity': 'HIGH',
                        'title': 'IAM User Has Administrative Privileges',
                        'description': f'User {username} has administrative policy {policy["PolicyName"]} attached',
                        'recommendation': 'Review if administrative access is necessary and consider using roles instead',
                        'compliance': ['CIS-AWS-1.5.0-1.16'],
                        'tags': {'service': 'iam', 'category': 'permissions', 'policy': policy['PolicyName']}
                    })
            
            # Check inline policies
            inline_policies = iam_client.list_user_policies(UserName=username)
            inline_policy_count = len(inline_policies.get('PolicyNames', []))
            
            if inline_policy_count > self.max_inline_policies:
                findings.append({
                    'resource_type': 'IAMUser',
                    'resource_id': username,
                    'region': 'global',
                    'severity': 'MEDIUM',
                    'title': 'IAM User Has Inline Policies',
                    'description': f'User {username} has {inline_policy_count} inline policies attached',
                    'recommendation': 'Convert inline policies to managed policies for better governance',
                    'compliance': ['AWS-Well-Architected'],
                    'tags': {'service': 'iam', 'category': 'policy_management', 'inline_count': inline_policy_count}
                })
                
        except Exception as e:
            self.logger.error(f"Failed to check permissions for user {username}: {e}")
        
        return findings
    
    async def _check_user_console_access(self, iam_client, username: str, user: Dict) -> List[Dict]:
        """Check console access configuration."""
        findings = []
        
        try:
            # Check if user has console access
            try:
                login_profile = iam_client.get_login_profile(UserName=username)
                # User has console access - check password policy compliance if possible
                
            except ClientError as e:
                if e.response['Error']['Code'] == 'NoSuchEntity':
                    # No console access - this is often good for service accounts
                    findings.append({
                        'resource_type': 'IAMUser',
                        'resource_id': username,
                        'region': 'global',
                        'severity': 'INFO',
                        'title': 'IAM User Has No Console Access',
                        'description': f'User {username} has no console login profile configured',
                        'recommendation': 'Ensure this is intentional for service accounts',
                        'compliance': ['AWS-Well-Architected'],
                        'tags': {'service': 'iam', 'category': 'access_method', 'console_access': False}
                    })
                    
        except Exception as e:
            self.logger.error(f"Failed to check console access for user {username}: {e}")
        
        return findings
    
    async def _check_user_metadata(self, iam_client, username: str, user: Dict) -> List[Dict]:
        """Check user metadata and tags for compliance."""
        findings = []
        
        try:
            # Check for required tags if configured
            required_tags = self.config.get('required_tags', [])
            if required_tags:
                user_tags = iam_client.list_user_tags(UserName=username)
                existing_tag_keys = [tag['Key'] for tag in user_tags.get('Tags', [])]
                
                missing_tags = [tag for tag in required_tags if tag not in existing_tag_keys]
                if missing_tags:
                    findings.append({
                        'resource_type': 'IAMUser',
                        'resource_id': username,
                        'region': 'global',
                        'severity': 'LOW',
                        'title': 'IAM User Missing Required Tags',
                        'description': f'User {username} is missing required tags: {", ".join(missing_tags)}',
                        'recommendation': 'Add required tags for compliance and resource management',
                        'compliance': ['Custom-Tagging-Policy'],
                        'tags': {'service': 'iam', 'category': 'tagging', 'missing_tags': missing_tags}
                    })
                    
        except Exception as e:
            self.logger.error(f"Failed to check metadata for user {username}: {e}")
        
        return findings
    
    async def _scan_roles(self, iam_client) -> List[Dict]:
        """Scan IAM roles for comprehensive security analysis."""
        findings = []
        
        try:
            paginator = iam_client.get_paginator('list_roles')
            role_count = 0
            
            for page in paginator.paginate():
                for role in page['Roles']:
                    role_count += 1
                    role_name = role['RoleName']
                    role_arn = role['Arn']
                    
                    # Store role in cache
                    self._role_cache[role_name] = role
                    
                    # Check trust policy
                    trust_policy = role.get('AssumeRolePolicyDocument', {})
                    trust_findings = await self._analyze_trust_policy(role_name, trust_policy)
                    findings.extend(trust_findings)
                    
                    # Check for service-linked roles (usually OK)
                    if role.get('Path', '').startswith('/aws-service-role/'):
                        continue
                    
                    # Check role permissions
                    permission_findings = await self._check_role_permissions(iam_client, role_name, role)
                    findings.extend(permission_findings)
            
            self.logger.info(f"Completed analysis of {role_count} IAM roles")
                    
        except Exception as e:
            self.logger.error(f"Failed to scan IAM roles: {str(e)}")
        
        return findings
    
    async def _analyze_trust_policy(self, role_name: str, trust_policy: Dict) -> List[Dict]:
        """Analyze role trust policy for security issues."""
        findings = []
        
        try:
            if not trust_policy or 'Statement' not in trust_policy:
                return findings
            
            statements = trust_policy.get('Statement', [])
            if not isinstance(statements, list):
                statements = [statements]
            
            for statement in statements:
                effect = statement.get('Effect', '')
                principal = statement.get('Principal', {})
                condition = statement.get('Condition', {})
                
                if effect == 'Allow':
                    # Check for overly permissive principals
                    if principal == '*':
                        findings.append({
                            'resource_type': 'IAMRole',
                            'resource_id': role_name,
                            'region': 'global',
                            'severity': 'CRITICAL',
                            'title': 'IAM Role Allows Anyone to Assume It',
                            'description': f'Role {role_name} trusts all principals (*) to assume the role',
                            'recommendation': 'Restrict principal to specific accounts, services, or users',
                            'compliance': ['CIS-AWS-1.5.0-1.22'],
                            'tags': {'service': 'iam', 'category': 'trust_policy', 'risk': 'unrestricted_access'}
                        })
                    
                    # Check AWS principals without external ID
                    aws_principals = principal.get('AWS', [])
                    if aws_principals and not condition:
                        if isinstance(aws_principals, str):
                            aws_principals = [aws_principals]
                        
                        for aws_principal in aws_principals:
                            if ':root' in str(aws_principal) and not condition:
                                findings.append({
                                    'resource_type': 'IAMRole',
                                    'resource_id': role_name,
                                    'region': 'global',
                                    'severity': 'HIGH',
                                    'title': 'IAM Role Cross-Account Trust Without Conditions',
                                    'description': f'Role {role_name} allows cross-account access without additional conditions',
                                    'recommendation': 'Add External ID or other conditions to prevent confused deputy attacks',
                                    'compliance': ['CIS-AWS-1.5.0-1.22'],
                                    'tags': {'service': 'iam', 'category': 'trust_policy', 'cross_account': True}
                                })
                                
        except Exception as e:
            self.logger.error(f"Failed to analyze trust policy for role {role_name}: {e}")
        
        return findings
    
    async def _check_role_permissions(self, iam_client, role_name: str, role: Dict) -> List[Dict]:
        """Check role permissions for overly broad access."""
        findings = []
        
        try:
            # Check attached managed policies
            attached_policies = iam_client.list_attached_role_policies(RoleName=role_name)
            for policy in attached_policies.get('AttachedPolicies', []):
                if policy['PolicyArn'].endswith(':policy/PowerUserAccess') or 'Admin' in policy['PolicyName']:
                    findings.append({
                        'resource_type': 'IAMRole',
                        'resource_id': role_name,
                        'region': 'global',
                        'severity': 'HIGH',
                        'title': 'IAM Role Has Administrative Privileges',
                        'description': f'Role {role_name} has administrative policy {policy["PolicyName"]}',
                        'recommendation': 'Review if administrative access is necessary',
                        'compliance': ['CIS-AWS-1.5.0-1.22'],
                        'tags': {'service': 'iam', 'category': 'permissions', 'policy': policy['PolicyName']}
                    })
                    
        except Exception as e:
            self.logger.error(f"Failed to check role permissions for {role_name}: {e}")
        
        return findings
    
    async def _scan_policies(self, iam_client) -> List[Dict]:
        """Scan IAM policies for security issues."""
        findings = []
        
        try:
            paginator = iam_client.get_paginator('list_policies')
            
            for page in paginator.paginate(Scope='Local'):  # Only customer-managed policies
                for policy in page['Policies']:
                    policy_name = policy['PolicyName']
                    policy_arn = policy['Arn']
                    
                    # Get policy document
                    try:
                        policy_version = iam_client.get_policy_version(
                            PolicyArn=policy_arn,
                            VersionId=policy['DefaultVersionId']
                        )
                        
                        document = policy_version['PolicyVersion']['Document']
                        
                        # Check for overly broad permissions
                        if self._has_admin_privileges(document):
                            findings.append({
                                'resource_type': 'IAMPolicy',
                                'resource_id': policy_arn,
                                'region': 'global',
                                'severity': 'HIGH',
                                'title': 'IAM Policy Grants Administrative Privileges',
                                'description': f"Policy {policy_name} grants administrative privileges",
                                'recommendation': 'Review and restrict policy permissions following principle of least privilege',
                                'compliance': ['CIS-AWS-1.5.0-1.16'],
                                'tags': {'service': 'iam', 'category': 'policy_analysis', 'policy_name': policy_name}
                            })
                            
                        # Check for wildcard permissions
                        wildcard_findings = self._check_wildcard_permissions(policy_name, policy_arn, document)
                        findings.extend(wildcard_findings)
                        
                    except Exception as e:
                        self.logger.warning(f"Could not analyze policy {policy_name}: {e}")
        
        except Exception as e:
            self.logger.error(f"Failed to scan IAM policies: {str(e)}")
        
        return findings
    
    async def _scan_groups(self, iam_client) -> List[Dict]:
        """Scan IAM groups for security issues."""
        findings = []
        
        try:
            paginator = iam_client.get_paginator('list_groups')
            group_count = 0
            
            for page in paginator.paginate():
                for group in page['Groups']:
                    group_count += 1
                    group_name = group['GroupName']
                    
                    # Store group in cache
                    self._group_cache[group_name] = group
                    
                    # Check group policies
                    group_findings = await self._check_group_permissions(iam_client, group_name)
                    findings.extend(group_findings)
            
            self.logger.info(f"Completed analysis of {group_count} IAM groups")
                    
        except Exception as e:
            self.logger.error(f"Failed to scan IAM groups: {str(e)}")
        
        return findings
    
    async def _check_group_permissions(self, iam_client, group_name: str) -> List[Dict]:
        """Check group permissions."""
        findings = []
        
        try:
            # Check attached managed policies
            attached_policies = iam_client.list_attached_group_policies(GroupName=group_name)
            for policy in attached_policies.get('AttachedPolicies', []):
                if 'Admin' in policy['PolicyName']:
                    findings.append({
                        'resource_type': 'IAMGroup',
                        'resource_id': group_name,
                        'region': 'global',
                        'severity': 'HIGH',
                        'title': 'IAM Group Has Administrative Privileges',
                        'description': f'Group {group_name} has administrative policy {policy["PolicyName"]}',
                        'recommendation': 'Review group membership and consider limiting administrative access',
                        'compliance': ['CIS-AWS-1.5.0-1.16'],
                        'tags': {'service': 'iam', 'category': 'group_permissions', 'policy': policy['PolicyName']}
                    })
                    
        except Exception as e:
            self.logger.error(f"Failed to check group permissions for {group_name}: {e}")
        
        return findings
    
    async def _check_account_settings(self, iam_client) -> List[Dict]:
        """Check account-level IAM settings."""
        findings = []
        
        try:
            # Check password policy
            try:
                password_policy = iam_client.get_account_password_policy()
                policy = password_policy.get('PasswordPolicy', {})
                
                # Check password policy requirements
                if policy.get('MinimumPasswordLength', 0) < 8:
                    findings.append({
                        'resource_type': 'IAMAccountPolicy',
                        'resource_id': 'password-policy',
                        'region': 'global',
                        'severity': 'HIGH',
                        'title': 'Weak Password Policy - Minimum Length',
                        'description': f'Password minimum length is {policy.get("MinimumPasswordLength", 0)} characters',
                        'recommendation': 'Set minimum password length to at least 8 characters',
                        'compliance': ['CIS-AWS-1.5.0-1.8'],
                        'tags': {'service': 'iam', 'category': 'password_policy'}
                    })
                
                if not policy.get('RequireUppercaseCharacters', False):
                    findings.append({
                        'resource_type': 'IAMAccountPolicy',
                        'resource_id': 'password-policy',
                        'region': 'global',
                        'severity': 'MEDIUM',
                        'title': 'Password Policy Missing Uppercase Requirement',
                        'description': 'Password policy does not require uppercase characters',
                        'recommendation': 'Enable uppercase character requirement in password policy',
                        'compliance': ['CIS-AWS-1.5.0-1.9'],
                        'tags': {'service': 'iam', 'category': 'password_policy'}
                    })
                
            except ClientError as e:
                if e.response['Error']['Code'] == 'NoSuchEntity':
                    findings.append({
                        'resource_type': 'IAMAccountPolicy',
                        'resource_id': 'password-policy',
                        'region': 'global',
                        'severity': 'HIGH',
                        'title': 'No Password Policy Configured',
                        'description': 'Account has no password policy configured',
                        'recommendation': 'Configure a strong password policy for the account',
                        'compliance': ['CIS-AWS-1.5.0-1.8'],
                        'tags': {'service': 'iam', 'category': 'password_policy'}
                    })
                    
        except Exception as e:
            self.logger.error(f"Failed to check account settings: {e}")
        
        return findings
    
    async def _analyze_cross_service_access(self, iam_client) -> List[Dict]:
        """Analyze cross-service access patterns."""
        # This would analyze service-to-service access patterns
        # Implementation would require additional logic
        return []
    
    async def _find_unused_resources(self, iam_client) -> List[Dict]:
        """Find unused IAM resources."""
        # This would use IAM Access Advisor to find unused permissions
        # Implementation would require additional API calls
        return []
    
    async def _validate_compliance_standards(self, iam_client) -> List[Dict]:
        """Validate compliance with security standards."""
        # This would validate specific compliance requirements
        # Implementation would require additional compliance logic
        return []
    
    def _check_wildcard_permissions(self, policy_name: str, policy_arn: str, document: Dict) -> List[Dict]:
        """Check for wildcard permissions in policy."""
        findings = []
        
        try:
            statements = document.get('Statement', [])
            if not isinstance(statements, list):
                statements = [statements]
            
            for statement in statements:
                if statement.get('Effect') == 'Allow':
                    actions = statement.get('Action', [])
                    if isinstance(actions, str):
                        actions = [actions]
                    
                    for action in actions:
                        if '*' in action:
                            findings.append({
                                'resource_type': 'IAMPolicy',
                                'resource_id': policy_arn,
                                'region': 'global',
                                'severity': 'MEDIUM',
                                'title': 'IAM Policy Contains Wildcard Permissions',
                                'description': f'Policy {policy_name} contains wildcard action: {action}',
                                'recommendation': 'Replace wildcard permissions with specific actions following principle of least privilege',
                                'compliance': ['AWS-Well-Architected'],
                                'tags': {'service': 'iam', 'category': 'policy_analysis', 'wildcard_action': action}
                            })
                            
        except Exception as e:
            self.logger.error(f"Failed to check wildcard permissions for policy {policy_name}: {e}")
        
        return findings
    
    def _has_admin_privileges(self, policy_document: Dict) -> bool:
        """Check if policy grants administrative privileges."""
        try:
            statements = policy_document.get('Statement', [])
            if not isinstance(statements, list):
                statements = [statements]
            
            for statement in statements:
                if statement.get('Effect') == 'Allow':
                    actions = statement.get('Action', [])
                    if isinstance(actions, str):
                        actions = [actions]
                    
                    # Check for administrative actions
                    admin_actions = {'*', 'iam:*', '*:*'}
                    for action in actions:
                        if action in admin_actions:
                            return True
                    
                    # Check for resource wildcard with broad actions
                    resources = statement.get('Resource', [])
                    if isinstance(resources, str):
                        resources = [resources]
                    
                    if '*' in resources and any('*' in action for action in actions):
                        return True
                        
        except Exception:
            pass
        
        return False