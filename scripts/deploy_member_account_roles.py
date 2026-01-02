#!/usr/bin/env python3
"""
Cross-Account Role Deployment Guide for CSPM

This script provides the proper deployment commands and instructions
for creating CSPMScanRole in member accounts so the master account
can assume these roles for organization-wide scanning.

The deployment must happen IN each member account, not from the master account.
"""

import boto3
import json
import sys
from botocore.exceptions import ClientError


def get_current_account_info():
    """Get information about the current AWS account."""
    try:
        sts = boto3.client('sts')
        identity = sts.get_caller_identity()
        return {
            'account_id': identity['Account'],
            'user_arn': identity['Arn'],
            'user_id': identity['UserId']
        }
    except Exception as e:
        print(f"Error getting account info: {e}")
        return None


def generate_deployment_commands(master_account_id="872515281040", master_user_arn="arn:aws:iam::872515281040:user/vibhor"):
    """Generate the deployment commands for member accounts."""
    
    print("🔧 CSPM Cross-Account Role Deployment Guide")
    print("=" * 60)
    print()
    
    # Get current account info
    current_account = get_current_account_info()
    if current_account:
        current_id = current_account['account_id']
        print(f"📍 Current Account: {current_id}")
        print(f"👤 Current User: {current_account['user_arn']}")
        print()
        
        if current_id == master_account_id:
            print("⚠️  You are in the MASTER account!")
            print("   This deployment must run in the MEMBER accounts.")
            print(f"   Target member accounts: 871007551509, 968382677077")
            print()
            print("🔄 Please switch to a member account and run this again.")
            print()
            print("Required member account access methods:")
            print("1. AWS Console -> Switch Role to member account")
            print("2. AWS CLI with member account credentials")
            print("3. AWS SSO to member account")
            print()
            return
        else:
            print(f"✅ Ready to deploy in member account: {current_id}")
    
    print("📋 Deployment Steps:")
    print()
    
    # Step 1: Verify CloudFormation template
    print("1. Verify CloudFormation Template Exists:")
    print("   aws s3 cp cspm-cross-account-role.yaml . --region us-east-1")
    print("   (or ensure the template file is available in current directory)")
    print()
    
    # Step 2: Deploy the role
    print("2. Deploy CSPMScanRole in this member account:")
    print("   aws cloudformation deploy \\")
    print("     --template-file cspm-cross-account-role.yaml \\")
    print("     --stack-name CSPM-CrossAccount-Role \\")
    print("     --parameter-overrides \\")
    print(f"       MasterAccountId={master_account_id} \\")
    print(f"       MasterUserArn='{master_user_arn}' \\")
    print("       ExternalId=cspm-security-scan \\")
    print("     --capabilities CAPABILITY_NAMED_IAM \\")
    print("     --region us-east-1")
    print()
    
    # Step 3: Verify deployment
    print("3. Verify Role Creation:")
    print("   aws iam get-role --role-name CSPMScanRole --region us-east-1")
    print()
    
    # Step 4: Test role assumption from master account
    print("4. Test Role Assumption (run this from MASTER account):")
    if current_account:
        test_role_arn = f"arn:aws:iam::{current_account['account_id']}:role/CSPMScanRole"
    else:
        test_role_arn = "arn:aws:iam::{MEMBER_ACCOUNT_ID}:role/CSPMScanRole"
    
    print("   aws sts assume-role \\")
    print(f"     --role-arn '{test_role_arn}' \\")
    print("     --role-session-name 'CSPMTest' \\")
    print("     --external-id 'cspm-security-scan' \\")
    print("     --region us-east-1")
    print()


def check_role_exists():
    """Check if CSPMScanRole already exists in current account."""
    try:
        iam = boto3.client('iam')
        role = iam.get_role(RoleName='CSPMScanRole')
        
        print("✅ CSPMScanRole already exists!")
        print("Role Details:")
        print(f"   ARN: {role['Role']['Arn']}")
        print(f"   Created: {role['Role']['CreateDate']}")
        print()
        
        # Check trust policy
        trust_policy = role['Role']['AssumeRolePolicyDocument']
        print("🔒 Trust Policy:")
        print(json.dumps(trust_policy, indent=2))
        print()
        
        return True
        
    except ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchEntity':
            print("❌ CSPMScanRole does NOT exist in this account")
            return False
        else:
            print(f"Error checking role: {e}")
            return False


def test_role_assumption_from_master():
    """Test assuming the role from master account (only if we're in master account)."""
    current_account = get_current_account_info()
    if not current_account:
        return
        
    if current_account['account_id'] != "872515281040":
        print("💡 To test role assumption, run this from the master account (872515281040)")
        return
        
    # We're in master account, test assumption of roles in member accounts
    member_accounts = ["871007551509", "968382677077"]
    
    print("🧪 Testing Role Assumption from Master Account")
    print("=" * 50)
    
    for account_id in member_accounts:
        role_arn = f"arn:aws:iam::{account_id}:role/CSPMScanRole"
        print(f"\n📋 Testing {account_id}...")
        
        try:
            sts = boto3.client('sts')
            response = sts.assume_role(
                RoleArn=role_arn,
                RoleSessionName='CSPMTest',
                ExternalId='cspm-security-scan',
                DurationSeconds=900
            )
            
            if response.get('Credentials'):
                print(f"   ✅ Success: Can assume role in {account_id}")
                print(f"   🔑 Access Key: {response['Credentials']['AccessKeyId'][:8]}...")
            else:
                print(f"   ❌ Failed: No credentials returned for {account_id}")
                
        except ClientError as e:
            error_code = e.response['Error']['Code']
            print(f"   ❌ Failed: {error_code} - {e.response['Error']['Message']}")
        except Exception as e:
            print(f"   ❌ Error: {str(e)}")


def main():
    """Main function."""
    if len(sys.argv) > 1:
        action = sys.argv[1].lower()
        
        if action == "check":
            print("🔍 Checking if CSPMScanRole exists in current account...")
            print()
            check_role_exists()
            
        elif action == "test":
            test_role_assumption_from_master()
            
        elif action == "deploy":
            generate_deployment_commands()
            
        else:
            print("Usage:")
            print(f"  {sys.argv[0]} deploy  - Show deployment commands")
            print(f"  {sys.argv[0]} check   - Check if role exists")
            print(f"  {sys.argv[0]} test    - Test role assumption")
    else:
        # Default: show deployment guide
        generate_deployment_commands()


if __name__ == "__main__":
    main()