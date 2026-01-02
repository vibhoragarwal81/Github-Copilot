#!/usr/bin/env python3
"""
Manual Cross-Account Role Deployment Guide and Validator
This script provides instructions for manual deployment and then validates the setup.

Since we don't have cross-account deployment permissions, this approach is:
1. Show manual deployment instructions
2. Provide easy copy-paste CloudFormation parameters
3. Validate deployment after manual setup
4. Test role assumption

Usage:
    python manual_deploy_guide.py --show-instructions
    python manual_deploy_guide.py --validate-deployment
    python manual_deploy_guide.py --test-roles
"""

import boto3
import json
import sys
import argparse
from typing import List, Dict
from botocore.exceptions import ClientError, NoCredentialsError
from datetime import datetime

class ManualDeploymentGuide:
    def __init__(self):
        """Initialize AWS clients"""
        try:
            self.session = boto3.Session()
            self.sts_client = boto3.client('sts')
            self.org_client = boto3.client('organizations', region_name='us-east-1')
            
            # Get current identity
            self.identity = self.sts_client.get_caller_identity()
            self.master_account = self.identity['Account']
            self.master_arn = self.identity['Arn']
            
        except Exception as e:
            print(f"❌ ERROR: Failed to initialize AWS session: {e}")
            sys.exit(1)
    
    def get_organization_accounts(self) -> List[Dict]:
        """Get member accounts from organization"""
        try:
            response = self.org_client.list_accounts()
            accounts = []
            
            for account in response['Accounts']:
                if account['Status'] == 'ACTIVE' and account['Id'] != self.master_account:
                    accounts.append({
                        'id': account['Id'],
                        'name': account['Name'],
                        'email': account['Email']
                    })
            
            return accounts
            
        except ClientError as e:
            print(f"❌ Error getting organization accounts: {e}")
            return []
    
    def show_deployment_instructions(self):
        """Show detailed manual deployment instructions"""
        accounts = self.get_organization_accounts()
        
        print(f"🔐 CSPM CROSS-ACCOUNT ROLE DEPLOYMENT GUIDE")
        print(f"=" * 60)
        print(f"Master Account: {self.master_account}")
        print(f"Master User/Role: {self.master_arn}")
        print(f"Region: us-east-1")
        print()
        
        if not accounts:
            print("❌ No member accounts found or insufficient permissions")
            return
        
        print(f"📋 MEMBER ACCOUNTS TO CONFIGURE:")
        for acc in accounts:
            print(f"   • {acc['id']} ({acc['name']})")
        print()
        
        print(f"🚀 DEPLOYMENT STEPS:")
        print(f"=" * 30)
        
        for i, account in enumerate(accounts, 1):
            print(f"\n{i}. DEPLOY TO ACCOUNT {account['id']} ({account['name']}):")
            print(f"   ----------------------------------------")
            print(f"   a) Open AWS Console and switch to account {account['id']}")
            print(f"   b) Go to CloudFormation → Create Stack → With new resources")
            print(f"   c) Choose 'Upload a template file'")
            print(f"   d) Upload: cspm-cross-account-role.yaml")
            print(f"   e) Use these stack parameters:")
            print()
            print(f"      Stack Name: CSPM-CrossAccount-Role")
            print(f"      MasterAccountId: {self.master_account}")
            print(f"      MasterUserArn: {self.master_arn}")
            print(f"      ExternalId: cspm-security-scan")
            print()
            print(f"   f) Check 'I acknowledge that AWS CloudFormation might create IAM resources with custom names'")
            print(f"   g) Click 'Create Stack'")
            print(f"   h) Wait for CREATE_COMPLETE status")
            print()
        
        print(f"✅ VERIFICATION STEPS:")
        print(f"=" * 25)
        print(f"After deploying to all accounts, run:")
        print(f"   python manual_deploy_guide.py --validate-deployment")
        print(f"   python manual_deploy_guide.py --test-roles")
        print()
        print(f"Or run the organization scan:")
        print(f"   python run_organization_scan.py")
        print()
    
    def validate_deployment(self):
        """Validate that roles were deployed correctly"""
        accounts = self.get_organization_accounts()
        
        print(f"🔍 VALIDATING CROSS-ACCOUNT ROLE DEPLOYMENT")
        print(f"=" * 50)
        
        validation_results = []
        
        for account in accounts:
            print(f"\\n🔍 Checking account {account['id']} ({account['name']})...")
            
            try:
                # Try to assume the role
                role_arn = f"arn:aws:iam::{account['id']}:role/CSPMScanRole"
                
                response = self.sts_client.assume_role(
                    RoleArn=role_arn,
                    RoleSessionName='CSPMValidation',
                    ExternalId='cspm-security-scan'
                )
                
                print(f"   ✅ Successfully assumed CSPMScanRole")
                print(f"   📋 Session ARN: {response['AssumedRoleUser']['Arn']}")
                
                # Test basic IAM permissions with assumed role
                temp_credentials = response['Credentials']
                temp_iam_client = boto3.client(
                    'iam',
                    aws_access_key_id=temp_credentials['AccessKeyId'],
                    aws_secret_access_key=temp_credentials['SecretAccessKey'],
                    aws_session_token=temp_credentials['SessionToken']
                )
                
                # Test a basic IAM call
                account_summary = temp_iam_client.get_account_summary()
                user_count = account_summary['SummaryMap'].get('Users', 0)
                print(f"   ✅ IAM permissions verified (Users: {user_count})")
                
                validation_results.append({
                    'account_id': account['id'],
                    'account_name': account['name'],
                    'status': 'SUCCESS',
                    'role_arn': role_arn
                })
                
            except ClientError as e:
                error_code = e.response['Error']['Code']
                error_msg = e.response['Error']['Message']
                
                print(f"   ❌ Failed to assume role: {error_code}")
                
                if error_code == 'NoSuchEntity':
                    print(f"   💡 Role CSPMScanRole doesn't exist - needs to be created")
                elif error_code == 'AccessDenied':
                    print(f"   💡 Role exists but access denied - check trust policy")
                else:
                    print(f"   💡 Error: {error_msg}")
                
                validation_results.append({
                    'account_id': account['id'],
                    'account_name': account['name'],
                    'status': 'FAILED',
                    'error': f"{error_code}: {error_msg}"
                })
        
        # Summary
        print(f"\\n📊 VALIDATION SUMMARY")
        print(f"=" * 25)
        
        successful = [r for r in validation_results if r['status'] == 'SUCCESS']
        failed = [r for r in validation_results if r['status'] == 'FAILED']
        
        print(f"✅ Successful: {len(successful)}")
        print(f"❌ Failed: {len(failed)}")
        
        if successful:
            print(f"\\n✅ READY FOR SCANNING:")
            for result in successful:
                print(f"   📋 {result['account_id']} ({result['account_name']})")
        
        if failed:
            print(f"\\n❌ NEEDS DEPLOYMENT:")
            for result in failed:
                print(f"   📋 {result['account_id']} ({result['account_name']}) - {result['error']}")
        
        if len(successful) == len(accounts):
            print(f"\\n🎉 ALL ACCOUNTS READY!")
            print(f"You can now run: python run_organization_scan.py")
        
        return validation_results
    
    def test_organization_scan(self):
        """Test if organization scan is ready"""
        print(f"🧪 TESTING ORGANIZATION SCAN READINESS")
        print(f"=" * 40)
        
        validation_results = self.validate_deployment()
        successful = [r for r in validation_results if r['status'] == 'SUCCESS']
        
        if len(successful) == len(validation_results):
            print(f"\\n🚀 Organization scan ready! Running test scan...")
            
            # Test import of organization scanner
            try:
                import sys
                import os
                sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))
                
                from scanners.organization_scanner import OrganizationScanner
                from utils.config import load_config
                
                config = load_config()
                org_scanner = OrganizationScanner(config)
                
                # Get accounts (should work now)
                accounts = org_scanner.get_member_accounts()
                print(f"✅ Organization scanner can access {len(accounts)} member accounts")
                
                # Test role assumption for each account
                for account in accounts:
                    try:
                        org_scanner.assume_member_role(account['Id'])
                        print(f"   ✅ Can assume role in {account['Id']} ({account['Name']})")
                    except Exception as e:
                        print(f"   ❌ Cannot assume role in {account['Id']}: {e}")
                
                print(f"\\n🎉 Organization scanning is fully configured!")
                print(f"Run: python run_organization_scan.py")
                
            except ImportError as e:
                print(f"❌ Cannot import organization scanner: {e}")
            except Exception as e:
                print(f"❌ Organization scanner test failed: {e}")
        else:
            print(f"\\n⚠️  Organization scan not ready - some accounts need role deployment")

def main():
    parser = argparse.ArgumentParser(description='Manual deployment guide for CSPM cross-account roles')
    parser.add_argument('--show-instructions', action='store_true', help='Show manual deployment instructions')
    parser.add_argument('--validate-deployment', action='store_true', help='Validate role deployment')
    parser.add_argument('--test-roles', action='store_true', help='Test role assumption and permissions')
    
    args = parser.parse_args()
    
    guide = ManualDeploymentGuide()
    
    if args.show_instructions:
        guide.show_deployment_instructions()
    elif args.validate_deployment:
        guide.validate_deployment()
    elif args.test_roles:
        guide.test_organization_scan()
    else:
        # Show all by default
        guide.show_deployment_instructions()
        print(f"\\n" + "="*60 + "\\n")
        guide.validate_deployment()

if __name__ == "__main__":
    main()