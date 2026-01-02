"""
Organization Scanner for AWS CSPM

This module handles scanning of AWS accounts within an organization.
It discovers accounts and orchestrates scanning across multiple accounts.
"""

import asyncio
import logging
from typing import Dict, List, Optional

import boto3
from botocore.exceptions import ClientError, NoCredentialsError

from src.scanners.ec2_scanner import EC2Scanner
from src.scanners.s3_scanner import S3Scanner
from src.scanners.iam_scanner import IAMScanner
from src.scanners.vpc_scanner import VPCScanner
from src.utils.aws_client import AWSClientManager
from src.utils.config import Config


class OrganizationScanner:
    """Scanner for AWS Organizations to perform multi-account security scanning."""
    
    def __init__(self, config: Config, aws_client_manager: AWSClientManager):
        """
        Initialize the Organization Scanner.
        
        Args:
            config: Configuration object
            aws_client_manager: AWS client manager for handling cross-account access
        """
        self.config = config
        self.aws_client_manager = aws_client_manager
        self.logger = logging.getLogger(__name__)
        
        # Initialize service scanners
        self.ec2_scanner = EC2Scanner(config, aws_client_manager)
        self.s3_scanner = S3Scanner(config, aws_client_manager)
        self.iam_scanner = IAMScanner(config, aws_client_manager)
        self.vpc_scanner = VPCScanner(config, aws_client_manager)
    
    async def discover_accounts(self) -> List[Dict]:
        """
        Discover all AWS accounts in the organization.
        
        Returns:
            List[Dict]: List of account information dictionaries
        
        Raises:
            Exception: If unable to access AWS Organizations
        """
        self.logger.info("Discovering AWS accounts in organization")
        
        try:
            # Get the organizations client for the master account
            org_client = self.aws_client_manager.get_client('organizations')
            
            # List all accounts in the organization
            paginator = org_client.get_paginator('list_accounts')
            accounts = []
            
            for page in paginator.paginate():
                for account in page['Accounts']:
                    if account['Status'] == 'ACTIVE':
                        accounts.append({
                            'Id': account['Id'],
                            'Name': account['Name'],
                            'Email': account['Email'],
                            'Status': account['Status'],
                            'JoinedMethod': account.get('JoinedMethod', 'UNKNOWN'),
                            'JoinedTimestamp': account.get('JoinedTimestamp', '').isoformat() if account.get('JoinedTimestamp') else None
                        })
            
            self.logger.info(f"Discovered {len(accounts)} active accounts")
            return accounts
            
        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code == 'AccessDeniedException':
                self.logger.error("Access denied to AWS Organizations. Ensure the role has organizations:ListAccounts permission")
            elif error_code == 'AWSOrganizationsNotInUseException':
                self.logger.error("AWS Organizations is not enabled for this account")
            else:
                self.logger.error(f"AWS Organizations error: {error_code} - {e.response['Error']['Message']}")
            raise
        
        except NoCredentialsError:
            self.logger.error("AWS credentials not found. Please configure AWS credentials")
            raise
        
        except Exception as e:
            self.logger.error(f"Unexpected error discovering accounts: {str(e)}")
            raise
    
    async def scan_account(self, account: Dict) -> Dict:
        """
        Scan a single AWS account for security posture.
        
        Args:
            account: Account information dictionary
            
        Returns:
            Dict: Scan results for the account
        """
        account_id = account['Id']
        account_name = account['Name']
        
        self.logger.info(f"Starting scan for account {account_id} ({account_name})")
        
        findings = {
            'account_id': account_id,
            'account_name': account_name,
            'services': {},
            'summary': {
                'total_findings': 0,
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0,
                'info': 0
            }
        }
        
        try:
            # Get regions to scan
            regions = self.config.get('aws_regions', ['us-east-1', 'us-west-2', 'eu-west-1'])
            
            # Scan each service across all regions
            scan_tasks = []
            
            # EC2 scanning
            if self.config.get('scan_ec2', True):
                for region in regions:
                    scan_tasks.append(self._scan_service('ec2', account_id, region, self.ec2_scanner))
            
            # S3 scanning (global service, scan once)
            if self.config.get('scan_s3', True):
                scan_tasks.append(self._scan_service('s3', account_id, 'us-east-1', self.s3_scanner))
            
            # IAM scanning (global service, scan once)
            if self.config.get('scan_iam', True):
                scan_tasks.append(self._scan_service('iam', account_id, 'us-east-1', self.iam_scanner))
            
            # VPC scanning
            if self.config.get('scan_vpc', True):
                for region in regions:
                    scan_tasks.append(self._scan_service('vpc', account_id, region, self.vpc_scanner))
            
            # Execute all scans concurrently
            scan_results = await asyncio.gather(*scan_tasks, return_exceptions=True)
            
            # Process results
            for result in scan_results:
                if isinstance(result, Exception):
                    self.logger.warning(f"Service scan failed: {str(result)}")
                    continue
                
                service_name, region, service_findings = result
                
                # Initialize service in findings if not exists
                if service_name not in findings['services']:
                    findings['services'][service_name] = {}
                
                findings['services'][service_name][region] = service_findings
                
                # Update summary counts
                for finding in service_findings:
                    severity = finding.get('severity', 'info').lower()
                    findings['summary']['total_findings'] += 1
                    findings['summary'][severity] = findings['summary'].get(severity, 0) + 1
            
            self.logger.info(f"Completed scan for account {account_id}. Found {findings['summary']['total_findings']} findings")
            return findings
            
        except Exception as e:
            self.logger.error(f"Failed to scan account {account_id}: {str(e)}")
            raise
    
    async def _scan_service(self, service_name: str, account_id: str, region: str, scanner) -> tuple:
        """
        Scan a specific AWS service in a specific region.
        
        Args:
            service_name: Name of the AWS service
            account_id: AWS account ID
            region: AWS region
            scanner: Scanner instance for the service
            
        Returns:
            tuple: (service_name, region, findings)
        """
        try:
            self.logger.debug(f"Scanning {service_name} in {region} for account {account_id}")
            
            # Assume role in the target account
            session = await self.aws_client_manager.assume_role(account_id, region)
            
            # Perform the scan
            findings = await scanner.scan(session, region)
            
            self.logger.debug(f"Completed {service_name} scan in {region} for account {account_id}: {len(findings)} findings")
            return service_name, region, findings
            
        except Exception as e:
            self.logger.warning(f"Failed to scan {service_name} in {region} for account {account_id}: {str(e)}")
            return service_name, region, []
    
    async def get_organization_info(self) -> Dict:
        """
        Get information about the AWS Organization.
        
        Returns:
            Dict: Organization information
        """
        try:
            org_client = self.aws_client_manager.get_client('organizations')
            
            org_info = org_client.describe_organization()['Organization']
            
            return {
                'id': org_info['Id'],
                'arn': org_info['Arn'],
                'feature_set': org_info['FeatureSet'],
                'master_account_id': org_info['MasterAccountId'],
                'master_account_email': org_info['MasterAccountEmail']
            }
            
        except Exception as e:
            self.logger.warning(f"Could not retrieve organization info: {str(e)}")
            return {}