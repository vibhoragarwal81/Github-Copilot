#!/usr/bin/env python3
"""
Quick AWS Connection Test for CSPM

This script tests if AWS credentials are properly configured
and the CSMP system can connect to AWS services.
"""

import sys
from src.utils.aws_client import AWSClientManager
from src.utils.config import Config

def test_aws_connection():
    """Test AWS connection and display account information."""
    try:
        print("🔍 Testing AWS connection...")
        
        # Create configuration
        config = Config({'aws': {'regions': ['us-east-1']}})
        
        # Create AWS client manager
        client_manager = AWSClientManager(config)
        
        # Get STS client and test connection
        sts_client = client_manager.get_client('sts', 'us-east-1')
        identity = sts_client.get_caller_identity()
        
        print("✅ CSPM AWS connection successful!")
        print(f"📋 Account: {identity.get('Account')}")
        print(f"👤 User: {identity.get('Arn')}")
        print(f"🆔 User ID: {identity.get('UserId')}")
        
        # Test additional services that CSPM will need
        print("\n🧪 Testing required AWS service permissions...")
        
        # Test IAM access
        try:
            iam_client = client_manager.get_client('iam', 'us-east-1')
            account_summary = iam_client.get_account_summary()
            print("✅ IAM access: OK")
        except Exception as e:
            print(f"⚠️ IAM access: Limited - {str(e)[:50]}...")
        
        # Test EC2 access
        try:
            ec2_client = client_manager.get_client('ec2', 'us-east-1')
            regions = ec2_client.describe_regions()
            print("✅ EC2 access: OK")
        except Exception as e:
            print(f"⚠️ EC2 access: Limited - {str(e)[:50]}...")
        
        # Test S3 access
        try:
            s3_client = client_manager.get_client('s3', 'us-east-1')
            buckets = s3_client.list_buckets()
            print("✅ S3 access: OK")
        except Exception as e:
            print(f"⚠️ S3 access: Limited - {str(e)[:50]}...")
        
        print("\n🎉 AWS connectivity test completed!")
        print("🚀 Your CSPM system is ready to scan AWS resources!")
        return True
        
    except Exception as e:
        print(f"❌ AWS connection failed: {e}")
        print("\n🔧 Troubleshooting steps:")
        print("1. Check: aws sts get-caller-identity")
        print("2. Reconfigure: aws configure")
        print("3. Verify credentials in AWS Console")
        print("4. See: AWS_CREDENTIALS_TROUBLESHOOTING.md")
        return False

if __name__ == "__main__":
    success = test_aws_connection()
    sys.exit(0 if success else 1)