"""
AWS Client utility for IAMCloud
Provides consistent AWS client creation and session management
"""

import boto3
from botocore.exceptions import ClientError, NoCredentialsError
from typing import Optional, Dict, Any


class AWSClient:
    """
    AWS client wrapper for consistent session and client management.
    """
    
    def __init__(self, session: Optional[boto3.Session] = None, region: str = 'us-east-1'):
        """
        Initialize AWS client wrapper.
        
        Args:
            session: Boto3 session (uses default if None)
            region: AWS region (default: us-east-1)
        """
        self.session = session or boto3.Session()
        self.region = region
    
    def get_client(self, service_name: str, region: str = None) -> boto3.client:
        """
        Get AWS service client.
        
        Args:
            service_name: AWS service name (e.g., 'ec2', 's3', 'iam')
            region: AWS region (uses instance default if None)
        
        Returns:
            Boto3 client for the service
        """
        region = region or self.region
        return self.session.client(service_name, region_name=region)
    
    def get_resource(self, service_name: str, region: str = None) -> boto3.resource:
        """
        Get AWS service resource.
        
        Args:
            service_name: AWS service name (e.g., 'ec2', 's3')
            region: AWS region (uses instance default if None)
        
        Returns:
            Boto3 resource for the service
        """
        region = region or self.region
        return self.session.resource(service_name, region_name=region)
    
    def get_current_identity(self) -> Dict[str, Any]:
        """
        Get current AWS identity information.
        
        Returns:
            Dictionary with Account, Arn, and UserId
        """
        sts_client = self.get_client('sts')
        return sts_client.get_caller_identity()
    
    def test_credentials(self) -> bool:
        """
        Test if current credentials are valid.
        
        Returns:
            True if credentials work, False otherwise
        """
        try:
            self.get_current_identity()
            return True
        except (ClientError, NoCredentialsError):
            return False
    
    def list_regions(self) -> list:
        """
        Get list of available AWS regions.
        
        Returns:
            List of region names
        """
        try:
            ec2_client = self.get_client('ec2')
            response = ec2_client.describe_regions()
            return [region['RegionName'] for region in response['Regions']]
        except Exception:
            # Fallback to common regions if API call fails
            return [
                'us-east-1', 'us-east-2', 'us-west-1', 'us-west-2',
                'eu-west-1', 'eu-west-2', 'eu-central-1',
                'ap-southeast-1', 'ap-southeast-2', 'ap-northeast-1'
            ]


def create_client(service_name: str, session: Optional[boto3.Session] = None, 
                 region: str = 'us-east-1') -> boto3.client:
    """
    Create AWS service client with consistent configuration.
    
    Args:
        service_name: AWS service name
        session: Boto3 session (optional)
        region: AWS region
    
    Returns:
        Configured boto3 client
    """
    aws_client = AWSClient(session, region)
    return aws_client.get_client(service_name)