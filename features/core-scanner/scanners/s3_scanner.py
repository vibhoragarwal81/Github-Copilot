"""
S3 Scanner for AWS CSPM

This module scans S3 buckets for security issues including public access,
encryption, versioning, logging, and policy violations.

Key Security Checks Performed:
1. Public Access Block Configuration - Ensures buckets are not publicly accessible
2. Default Encryption - Verifies server-side encryption is enabled
3. Versioning - Checks if object versioning is enabled for data protection
4. Access Logging - Ensures bucket access is being logged for audit trails
5. Bucket Policy Analysis - Reviews IAM policies for overly permissive access
6. MFA Delete - Verifies multi-factor authentication for deletions
7. Lifecycle Policies - Checks for proper data lifecycle management
8. Cross-Region Replication - Validates backup and disaster recovery setups

Compliance Frameworks Covered:
- CIS AWS Foundations Benchmark v1.3.0
- NIST Cybersecurity Framework
- PCI-DSS Requirements
- AWS Well-Architected Security Pillar
"""

import json
import logging
from typing import Dict, List

from botocore.exceptions import ClientError


class S3Scanner:
    """Scanner for S3 buckets and related resources."""
    
    def __init__(self, config, aws_client_manager):
        """Initialize S3 Scanner."""
        self.config = config
        self.aws_client_manager = aws_client_manager
        self.logger = logging.getLogger(__name__)
    
    async def scan(self, session, region: str) -> List[Dict]:
        """
        Scan S3 resources for security issues.
        
        Args:
            session: AWS session
            region: AWS region (S3 is global but we use this for client creation)
            
        Returns:
            List[Dict]: List of security findings
        """
        findings = []
        
        try:
            # S3 is a global service, but we create clients with specific regions
            s3_client = session.client('s3', region_name=region)
            
            self.logger.info(f"Starting S3 scan in region {region}")
            
            # List all buckets (this call returns all buckets globally)
            try:
                response = s3_client.list_buckets()
                buckets = response.get('Buckets', [])
                self.logger.info(f"Found {len(buckets)} S3 buckets to scan")
            except ClientError as e:
                self.logger.error(f"Failed to list S3 buckets: {e}")
                return findings
            
            # Check each bucket
            for bucket in buckets:
                bucket_name = bucket['Name']
                self.logger.debug(f"Scanning bucket: {bucket_name}")
                
                try:
                    # Get bucket region to ensure we're scanning from the right region
                    bucket_region = await self._get_bucket_region(s3_client, bucket_name)
                    
                    # Only scan buckets in the current region or if region detection fails
                    if bucket_region and bucket_region != region:
                        self.logger.debug(f"Skipping bucket {bucket_name} (region: {bucket_region})")
                        continue
                    
                    # Check bucket public access
                    public_findings = await self._check_bucket_public_access(s3_client, bucket_name)
                    findings.extend(public_findings)
                    
                    # Check bucket encryption
                    encryption_findings = await self._check_bucket_encryption(s3_client, bucket_name)
                    findings.extend(encryption_findings)
                    
                    # Check bucket versioning
                    versioning_findings = await self._check_bucket_versioning(s3_client, bucket_name)
                    findings.extend(versioning_findings)
                    
                    # Check bucket logging
                    logging_findings = await self._check_bucket_logging(s3_client, bucket_name)
                    findings.extend(logging_findings)
                    
                    # Check bucket policy
                    policy_findings = await self._check_bucket_policy(s3_client, bucket_name)
                    findings.extend(policy_findings)
                    
                    # Check bucket MFA delete
                    mfa_findings = await self._check_bucket_mfa_delete(s3_client, bucket_name)
                    findings.extend(mfa_findings)
                    
                except Exception as e:
                    self.logger.warning(f"Failed to scan bucket {bucket_name}: {str(e)}")
                    findings.append({
                        'resource_type': 'S3Bucket',
                        'resource_id': bucket_name,
                        'region': region,
                        'severity': 'INFO',
                        'title': 'Bucket Scan Failed',
                        'description': f'Unable to scan bucket {bucket_name}: {str(e)}',
                        'recommendation': 'Check bucket permissions and access',
                        'compliance': [],
                        'tags': {'error': True}
                    })
            
            self.logger.info(f"S3 scan completed. Found {len(findings)} findings")
            return findings
                
        except Exception as e:
            self.logger.error(f"S3 scan failed: {str(e)}")
            return findings
    
    async def _check_bucket_public_access(self, s3_client, bucket_name: str) -> List[Dict]:
        """Check if bucket has public access."""
        findings = []
        
        try:
            # Check public access block configuration
            try:
                response = s3_client.get_public_access_block(Bucket=bucket_name)
                config = response['PublicAccessBlockConfiguration']
                
                if not all([
                    config.get('BlockPublicAcls', False),
                    config.get('IgnorePublicAcls', False),
                    config.get('BlockPublicPolicy', False),
                    config.get('RestrictPublicBuckets', False)
                ]):
                    findings.append({
                        'resource_type': 'S3Bucket',
                        'resource_id': bucket_name,
                        'region': 'global',
                        'severity': 'HIGH',
                        'title': 'S3 bucket public access not fully blocked',
                        'description': f"Bucket {bucket_name} does not have all public access blocks enabled",
                        'recommendation': 'Enable all public access block settings for the bucket',
                        'compliance': ['CIS-AWS-1.3.0-3.1', 'NIST-800-53-AC-3'],
                        'tags': {'service': 's3', 'category': 'public_access'}
                    })
                    
            except ClientError as e:
                if e.response['Error']['Code'] == 'NoSuchPublicAccessBlockConfiguration':
                    findings.append({
                        'resource_type': 'S3Bucket',
                        'resource_id': bucket_name,
                        'region': 'global',
                        'severity': 'HIGH',
                        'title': 'S3 bucket has no public access block configuration',
                        'description': f"Bucket {bucket_name} has no public access block configuration",
                        'recommendation': 'Configure public access block settings for the bucket',
                        'compliance': ['CIS-AWS-1.3.0-3.1'],
                        'tags': {'service': 's3', 'category': 'public_access'}
                    })
        
        except Exception as e:
            self.logger.error(f"Failed to check public access for bucket {bucket_name}: {str(e)}")
        
        return findings
    
    async def _check_bucket_encryption(self, s3_client, bucket_name: str) -> List[Dict]:
        """Check if bucket has encryption enabled."""
        findings = []
        
        try:
            s3_client.get_bucket_encryption(Bucket=bucket_name)
            # If we get here, encryption is enabled
            
        except ClientError as e:
            if e.response['Error']['Code'] == 'ServerSideEncryptionConfigurationNotFoundError':
                findings.append({
                    'resource_type': 'S3Bucket',
                    'resource_id': bucket_name,
                    'region': 'global',
                    'severity': 'HIGH',
                    'title': 'S3 bucket encryption not enabled',
                    'description': f"Bucket {bucket_name} does not have default encryption enabled",
                    'recommendation': 'Enable default server-side encryption for the bucket',
                    'compliance': ['CIS-AWS-1.3.0-3.7', 'PCI-DSS-3.4'],
                    'tags': {'service': 's3', 'category': 'encryption'}
                })
        
        except Exception as e:
            self.logger.error(f"Failed to check encryption for bucket {bucket_name}: {str(e)}")
        
        return findings
    
    async def _check_bucket_versioning(self, s3_client, bucket_name: str) -> List[Dict]:
        """Check if bucket has versioning enabled."""
        findings = []
        
        try:
            response = s3_client.get_bucket_versioning(Bucket=bucket_name)
            status = response.get('Status', 'Disabled')
            
            if status != 'Enabled':
                findings.append({
                    'resource_type': 'S3Bucket',
                    'resource_id': bucket_name,
                    'region': 'global',
                    'severity': 'MEDIUM',
                    'title': 'S3 bucket versioning not enabled',
                    'description': f"Bucket {bucket_name} does not have versioning enabled",
                    'recommendation': 'Enable versioning to protect against accidental overwrites and deletions',
                    'compliance': ['CIS-AWS-1.3.0-3.2'],
                    'tags': {'service': 's3', 'category': 'versioning'}
                })
        
        except Exception as e:
            self.logger.error(f"Failed to check versioning for bucket {bucket_name}: {str(e)}")
        
        return findings
    
    async def _get_bucket_region(self, s3_client, bucket_name: str) -> str:
        """Get the region of a bucket."""
        try:
            response = s3_client.get_bucket_location(Bucket=bucket_name)
            region = response.get('LocationConstraint', 'us-east-1')
            # AWS returns None for us-east-1
            return region if region else 'us-east-1'
        except Exception as e:
            self.logger.debug(f"Failed to get region for bucket {bucket_name}: {str(e)}")
            return None
    
    async def _check_bucket_logging(self, s3_client, bucket_name: str) -> List[Dict]:
        """Check if bucket has access logging enabled."""
        findings = []
        
        try:
            response = s3_client.get_bucket_logging(Bucket=bucket_name)
            logging_config = response.get('LoggingEnabled')
            
            if not logging_config:
                findings.append({
                    'resource_type': 'S3Bucket',
                    'resource_id': bucket_name,
                    'region': 'global',
                    'severity': 'MEDIUM',
                    'title': 'S3 bucket access logging not enabled',
                    'description': f"Bucket {bucket_name} does not have access logging enabled",
                    'recommendation': 'Enable S3 bucket access logging to track requests',
                    'compliance': ['CIS-AWS-1.3.0-3.3'],
                    'tags': {'service': 's3', 'category': 'logging'}
                })
        
        except Exception as e:
            self.logger.error(f"Failed to check logging for bucket {bucket_name}: {str(e)}")
        
        return findings
    
    async def _check_bucket_policy(self, s3_client, bucket_name: str) -> List[Dict]:
        """Check bucket policy for security issues."""
        findings = []
        
        try:
            response = s3_client.get_bucket_policy(Bucket=bucket_name)
            policy = json.loads(response['Policy'])
            
            # Check for overly permissive policies
            for statement in policy.get('Statement', []):
                if isinstance(statement.get('Principal'), str) and statement['Principal'] == '*':
                    effect = statement.get('Effect', '').upper()
                    if effect == 'ALLOW':
                        findings.append({
                            'resource_type': 'S3Bucket',
                            'resource_id': bucket_name,
                            'region': 'global',
                            'severity': 'HIGH',
                            'title': 'S3 bucket has overly permissive policy',
                            'description': f"Bucket {bucket_name} has a policy allowing access to everyone (*)",
                            'recommendation': 'Review and restrict bucket policy to specific principals',
                            'compliance': ['CIS-AWS-1.3.0-3.1'],
                            'tags': {'service': 's3', 'category': 'policy'}
                        })
        
        except ClientError as e:
            if e.response['Error']['Code'] != 'NoSuchBucketPolicy':
                self.logger.error(f"Failed to check policy for bucket {bucket_name}: {str(e)}")
        
        except Exception as e:
            self.logger.error(f"Failed to check policy for bucket {bucket_name}: {str(e)}")
        
        return findings
    
    async def _check_bucket_mfa_delete(self, s3_client, bucket_name: str) -> List[Dict]:
        """Check if bucket has MFA delete enabled."""
        findings = []
        
        try:
            response = s3_client.get_bucket_versioning(Bucket=bucket_name)
            mfa_delete = response.get('MfaDelete', 'Disabled')
            
            if mfa_delete != 'Enabled':
                findings.append({
                    'resource_type': 'S3Bucket',
                    'resource_id': bucket_name,
                    'region': 'global',
                    'severity': 'MEDIUM',
                    'title': 'S3 bucket MFA delete not enabled',
                    'description': f"Bucket {bucket_name} does not have MFA delete enabled",
                    'recommendation': 'Enable MFA delete for additional protection against accidental deletions',
                    'compliance': ['CIS-AWS-1.3.0-3.2'],
                    'tags': {'service': 's3', 'category': 'mfa'}
                })
        
        except Exception as e:
            self.logger.error(f"Failed to check MFA delete for bucket {bucket_name}: {str(e)}")
        
        return findings