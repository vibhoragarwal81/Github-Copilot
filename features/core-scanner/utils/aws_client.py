"""
AWS Client Manager for CSPM

This module manages AWS client connections and cross-account role assumptions
for the CSPM scanner.
"""

import logging
from typing import Dict, Optional

import boto3
from botocore.exceptions import ClientError, NoCredentialsError
from botocore.session import Session

from src.utils.config import Config


class AWSClientManager:
    """Manages AWS client connections and cross-account access."""
    
    def __init__(self, config: Config):
        """
        Initialize the AWS Client Manager.
        
        Args:
            config: Configuration object
        """
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.session = boto3.Session()
        self._cached_clients = {}
        
        # Configuration for cross-account access
        self.cross_account_role_name = config.get('aws_organization_role_name', 'CSPMScanRole')
        self.external_id = config.get('aws_external_id', None)
        self.session_duration = config.get('aws_session_duration', 3600)  # 1 hour default
    
    def get_client(self, service_name: str, region: str = None) -> object:
        """
        Get an AWS client for the specified service.
        
        Args:
            service_name: AWS service name (e.g., 'ec2', 's3', 'iam')
            region: AWS region (optional, uses default if not specified)
            
        Returns:
            boto3 client object
        """
        region = region or self.config.get('aws_default_region', 'us-east-1')
        cache_key = f"{service_name}:{region}"
        
        if cache_key not in self._cached_clients:
            try:
                client = self.session.client(service_name, region_name=region)
                self._cached_clients[cache_key] = client
                self.logger.debug(f"Created {service_name} client for region {region}")
            except Exception as e:
                self.logger.error(f"Failed to create {service_name} client: {str(e)}")
                raise
        
        return self._cached_clients[cache_key]
    
    async def assume_role(self, account_id: str, region: str = None) -> Session:
        """
        Assume a role in the target account for cross-account access.
        
        Args:
            account_id: Target AWS account ID
            region: AWS region (optional)
            
        Returns:
            boto3 Session with assumed role credentials
        """
        region = region or self.config.get('aws_default_region', 'us-east-1')
        
        try:
            # Get current account ID to avoid assuming role in same account
            current_account_id = self._get_current_account_id()
            
            if account_id == current_account_id:
                # Same account, return current session
                return self.session
            
            # Construct role ARN
            role_arn = f"arn:aws:iam::{account_id}:role/{self.cross_account_role_name}"
            
            # Get STS client
            sts_client = self.get_client('sts', region)
            
            # Assume role parameters
            assume_role_params = {
                'RoleArn': role_arn,
                'RoleSessionName': f'CSPMScan-{account_id}-{region}',
                'DurationSeconds': self.session_duration
            }
            
            # Add external ID if configured
            if self.external_id:
                assume_role_params['ExternalId'] = self.external_id
            
            # Assume the role
            response = sts_client.assume_role(**assume_role_params)
            credentials = response['Credentials']
            
            # Create new session with assumed role credentials
            assumed_session = boto3.Session(
                aws_access_key_id=credentials['AccessKeyId'],
                aws_secret_access_key=credentials['SecretAccessKey'],
                aws_session_token=credentials['SessionToken'],
                region_name=region
            )
            
            self.logger.debug(f"Successfully assumed role in account {account_id}")
            return assumed_session
            
        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code == 'AccessDenied':
                self.logger.error(f"Access denied when assuming role in account {account_id}. Check cross-account trust relationships.")
            elif error_code == 'InvalidUserID.NotFound':
                self.logger.error(f"Role {self.cross_account_role_name} not found in account {account_id}")
            else:
                self.logger.error(f"Failed to assume role in account {account_id}: {error_code} - {e.response['Error']['Message']}")
            raise
        
        except Exception as e:
            self.logger.error(f"Unexpected error assuming role in account {account_id}: {str(e)}")
            raise
    
    def _get_current_account_id(self) -> str:
        """
        Get the current AWS account ID.
        
        Returns:
            str: Current AWS account ID
        """
        try:
            sts_client = self.get_client('sts')
            response = sts_client.get_caller_identity()
            return response['Account']
        
        except Exception as e:
            self.logger.error(f"Failed to get current account ID: {str(e)}")
            raise
    
    def validate_credentials(self) -> Dict:
        """
        Validate current AWS credentials and return account information.
        
        Returns:
            Dict: Account information including account ID, user ARN, etc.
        """
        try:
            sts_client = self.get_client('sts')
            response = sts_client.get_caller_identity()
            
            account_info = {
                'account_id': response['Account'],
                'user_id': response['UserId'],
                'arn': response['Arn']
            }
            
            self.logger.info(f"Validated credentials for account {account_info['account_id']}")
            return account_info
            
        except NoCredentialsError:
            self.logger.error("No AWS credentials found. Please configure AWS credentials.")
            raise
        
        except ClientError as e:
            self.logger.error(f"Invalid AWS credentials: {e.response['Error']['Message']}")
            raise
        
        except Exception as e:
            self.logger.error(f"Failed to validate credentials: {str(e)}")
            raise
    
    def test_organizations_access(self) -> bool:
        """
        Test if current credentials have access to AWS Organizations.
        
        Returns:
            bool: True if access is available, False otherwise
        """
        try:
            org_client = self.get_client('organizations')
            org_client.describe_organization()
            return True
        
        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code == 'AccessDeniedException':
                self.logger.warning("No access to AWS Organizations")
            elif error_code == 'AWSOrganizationsNotInUseException':
                self.logger.warning("AWS Organizations is not enabled")
            else:
                self.logger.warning(f"Organizations access test failed: {error_code}")
            return False
        
        except Exception as e:
            self.logger.warning(f"Organizations access test failed: {str(e)}")
            return False
    
    def get_available_regions(self, service_name: str = 'ec2') -> list:
        """
        Get list of available AWS regions for a service.
        
        Args:
            service_name: AWS service name to check regions for
            
        Returns:
            list: List of available region names
        """
        try:
            session = Session()
            return session.get_available_regions(service_name)
        
        except Exception as e:
            self.logger.warning(f"Failed to get available regions for {service_name}: {str(e)}")
            # Return common regions as fallback
            return ['us-east-1', 'us-west-2', 'eu-west-1', 'ap-southeast-1']