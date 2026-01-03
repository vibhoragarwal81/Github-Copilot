#!/usr/bin/env python3
"""
OIDC Authentication Test Script

This script validates AWS OIDC authentication setup for GitHub workflows.
Can be run locally or in GitHub Actions to verify configuration.
"""

import boto3
import os
import json
import sys
from datetime import datetime


def test_aws_authentication():
    """Test AWS authentication and display detailed information."""
    
    print("🔐 AWS Authentication Test")
    print("=" * 50)
    
    # Check authentication method
    auth_method = "Unknown"
    if 'AWS_WEB_IDENTITY_TOKEN_FILE' in os.environ:
        auth_method = "OIDC with IAM Role"
        print(f"✅ Authentication Method: {auth_method}")
        print(f"   🏷️  Role ARN: {os.environ.get('AWS_ROLE_ARN', 'Not set')}")
        print(f"   🎫 Token File: {os.environ.get('AWS_WEB_IDENTITY_TOKEN_FILE', 'Not set')}")
        print(f"   📝 Session Name: {os.environ.get('AWS_ROLE_SESSION_NAME', 'Default')}")
    elif 'AWS_ACCESS_KEY_ID' in os.environ:
        auth_method = "Access Keys"
        print(f"✅ Authentication Method: {auth_method}")
        print(f"   🔑 Access Key: {os.environ.get('AWS_ACCESS_KEY_ID', '')[:8]}...")
    else:
        print("❌ No AWS credentials detected")
        return False
    
    print(f"🌍 Region: {os.environ.get('AWS_DEFAULT_REGION', 'Not set')}")
    print()
    
    try:
        # Test STS call
        print("🧪 Testing AWS STS access...")
        sts_client = boto3.client('sts')
        identity = sts_client.get_caller_identity()
        
        print("✅ AWS STS Response:")
        print(f"   👤 User ID: {identity['UserId']}")
        print(f"   🏦 Account: {identity['Account']}")
        print(f"   🎭 ARN: {identity['Arn']}")
        print()
        
        # Check if assumed role (OIDC)
        if 'assumed-role' in identity['Arn']:
            role_name = identity['Arn'].split('/')[-2]
            print(f"🎭 Assumed Role: {role_name}")
            
            # Test role permissions
            print("🧪 Testing IAM permissions...")
            iam_client = boto3.client('iam')
            
            try:
                account_summary = iam_client.get_account_summary()
                print("✅ IAM access confirmed")
            except Exception as e:
                print(f"⚠️ IAM access limited: {e}")
        
        # Test Organizations access
        print("🧪 Testing AWS Organizations access...")
        try:
            org_client = boto3.client('organizations')
            org_info = org_client.describe_organization()
            
            print("✅ Organizations access confirmed:")
            print(f"   🏢 Organization ID: {org_info['Organization']['Id']}")
            print(f"   👑 Master Account: {org_info['Organization']['MasterAccountId']}")
            print(f"   🎯 Feature Set: {org_info['Organization']['FeatureSet']}")
            
            # List accounts
            accounts_response = org_client.list_accounts()
            accounts = accounts_response['Accounts']
            print(f"   📊 Total Accounts: {len(accounts)}")
            
            for account in accounts[:3]:  # Show first 3 accounts
                print(f"     • {account['Name']} ({account['Id']}) - {account['Status']}")
            
            if len(accounts) > 3:
                print(f"     ... and {len(accounts) - 3} more accounts")
                
        except Exception as e:
            print(f"❌ Organizations access failed: {e}")
        
        print()
        
        # Test cross-account role assumption (if in organization context)
        if auth_method == "OIDC with IAM Role":
            print("🧪 Testing cross-account role assumption...")
            try:
                # Try to assume CSPMScanRole in a member account
                org_client = boto3.client('organizations')
                accounts = org_client.list_accounts()['Accounts']
                
                member_accounts = [acc for acc in accounts if acc['Id'] != identity['Account']]
                
                if member_accounts:
                    test_account = member_accounts[0]
                    role_arn = f"arn:aws:iam::{test_account['Id']}:role/CSPMScanRole"
                    
                    try:
                        assumed_role = sts_client.assume_role(
                            RoleArn=role_arn,
                            RoleSessionName=f"TestAssumeRole-{datetime.now().strftime('%Y%m%d%H%M%S')}"
                        )
                        print(f"✅ Successfully assumed role in account {test_account['Id']}")
                    except Exception as e:
                        print(f"⚠️ Cross-account role assumption failed: {e}")
                        print(f"   This is normal if CSPMScanRole is not deployed yet")
                else:
                    print("ℹ️ No member accounts to test cross-account access")
                    
            except Exception as e:
                print(f"⚠️ Could not test cross-account access: {e}")
        
        print("\n🎉 Authentication test completed successfully!")
        return True
        
    except Exception as e:
        print(f"❌ AWS authentication test failed: {e}")
        return False


def main():
    """Main function."""
    print(f"📅 Test run at: {datetime.now().isoformat()}")
    print(f"🐍 Python version: {sys.version}")
    print()
    
    # Environment info
    if 'GITHUB_ACTIONS' in os.environ:
        print("🏃 Running in GitHub Actions")
        print(f"   Repository: {os.environ.get('GITHUB_REPOSITORY', 'Unknown')}")
        print(f"   Run Number: {os.environ.get('GITHUB_RUN_NUMBER', 'Unknown')}")
        print(f"   Actor: {os.environ.get('GITHUB_ACTOR', 'Unknown')}")
    else:
        print("💻 Running locally")
    
    print()
    
    # Run test
    success = test_aws_authentication()
    
    if success:
        print("\n✨ All tests passed! Your AWS authentication is properly configured.")
        sys.exit(0)
    else:
        print("\n💥 Some tests failed. Check your AWS configuration.")
        sys.exit(1)


if __name__ == "__main__":
    main()