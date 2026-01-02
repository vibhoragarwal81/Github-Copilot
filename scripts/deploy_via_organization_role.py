#!/usr/bin/env python3
"""
Automated Cross-Account Role Deployment using OrganizationAccountAccessRole
This script uses the OrganizationAccountAccessRole to deploy CloudFormation templates
to member accounts automatically.

Usage:
    python deploy_via_organization_role.py --accounts 871007551509,968382677077
    python deploy_via_organization_role.py --accounts all
"""

import boto3
import json
import time
import sys
import argparse
from typing import List, Dict, Optional
from datetime import datetime
from botocore.exceptions import ClientError, NoCredentialsError

class OrganizationRoleDeployer:
    def __init__(self):
        """Initialize the deployer with AWS session"""
        try:
            self.session = boto3.Session()
            self.sts_client = boto3.client('sts')
            self.org_client = boto3.client('organizations', region_name='us-east-1')
            
            # Get current identity
            self.identity = self.sts_client.get_caller_identity()
            self.master_account = self.identity['Account']
            self.master_arn = self.identity['Arn']
            print(f"🔍 Running as: {self.master_arn}")
            print(f"📍 Master Account: {self.master_account}")
            
        except Exception as e:
            print(f"❌ ERROR: Failed to initialize AWS session: {e}")
            sys.exit(1)
    
    def load_cloudformation_template(self) -> str:
        """Load the CloudFormation template"""
        template_path = "cspm-cross-account-role.yaml"
        try:
            with open(template_path, 'r') as f:
                return f.read()
        except FileNotFoundError:
            print(f"❌ ERROR: Template file {template_path} not found!")
            sys.exit(1)
        except Exception as e:
            print(f"❌ ERROR: Failed to read template: {e}")
            sys.exit(1)
    
    def get_organization_accounts(self) -> List[Dict]:
        """Get all member accounts from AWS Organizations"""
        try:
            print("🔍 Discovering organization accounts...")
            response = self.org_client.list_accounts()
            accounts = []
            
            for account in response['Accounts']:
                if account['Status'] == 'ACTIVE' and account['Id'] != self.master_account:
                    accounts.append({
                        'id': account['Id'],
                        'name': account['Name'],
                        'email': account['Email'],
                        'status': account['Status']
                    })
                    print(f"  📋 Found member account: {account['Id']} ({account['Name']})")
            
            return accounts
            
        except ClientError as e:
            print(f"❌ ERROR: Failed to list accounts: {e}")
            return []
    
    def assume_organization_role(self, account_id: str) -> Optional[Dict]:
        """Assume OrganizationAccountAccessRole in member account"""
        role_arn = f"arn:aws:iam::{account_id}:role/OrganizationAccountAccessRole"
        
        try:
            print(f"  🔑 Assuming OrganizationAccountAccessRole in {account_id}...")
            
            response = self.sts_client.assume_role(
                RoleArn=role_arn,
                RoleSessionName='CSPMDeployment',
                DurationSeconds=3600  # 1 hour
            )
            
            credentials = response['Credentials']
            print(f"  ✅ Successfully assumed role")
            return credentials
            
        except ClientError as e:
            error_code = e.response['Error']['Code']
            error_msg = e.response['Error']['Message']
            print(f"  ❌ Failed to assume role: {error_code} - {error_msg}")
            return None
    
    def deploy_cloudformation_stack(self, account_id: str, account_name: str, 
                                  credentials: Dict, template_body: str) -> bool:
        """Deploy CloudFormation stack in member account"""
        stack_name = "CSPM-CrossAccount-Role"
        
        try:
            # Create CloudFormation client with assumed role credentials
            cf_client = boto3.client(
                'cloudformation',
                region_name='us-east-1',
                aws_access_key_id=credentials['AccessKeyId'],
                aws_secret_access_key=credentials['SecretAccessKey'],
                aws_session_token=credentials['SessionToken']
            )
            
            print(f"  🚀 Deploying CloudFormation stack: {stack_name}")
            
            # Deploy stack
            response = cf_client.create_stack(
                StackName=stack_name,
                TemplateBody=template_body,
                Parameters=[
                    {
                        'ParameterKey': 'MasterAccountId',
                        'ParameterValue': self.master_account
                    },
                    {
                        'ParameterKey': 'MasterUserArn',
                        'ParameterValue': self.master_arn
                    },
                    {
                        'ParameterKey': 'ExternalId',
                        'ParameterValue': 'cspm-security-scan'
                    }
                ],
                Capabilities=['CAPABILITY_NAMED_IAM'],
                Tags=[
                    {
                        'Key': 'Purpose',
                        'Value': 'CSPM-CrossAccount-Access'
                    },
                    {
                        'Key': 'CreatedBy',
                        'Value': 'CSPM-OrganizationDeployer'
                    },
                    {
                        'Key': 'CreatedAt',
                        'Value': datetime.now().isoformat()
                    }
                ]
            )
            
            stack_id = response['StackId']
            print(f"  📋 Stack ID: {stack_id}")
            
            # Wait for stack creation to complete
            return self.wait_for_stack_completion(cf_client, stack_name, account_id)
            
        except ClientError as e:
            error_code = e.response['Error']['Code']
            error_msg = e.response['Error']['Message']
            
            if error_code == 'AlreadyExistsException':
                print(f"  ⚠️  Stack {stack_name} already exists in account {account_id}")
                print(f"  🔄 Checking if update is needed...")
                return self.check_and_update_stack(cf_client, stack_name, template_body, account_id)
            else:
                print(f"  ❌ Failed to create stack: {error_code} - {error_msg}")
                return False
        except Exception as e:
            print(f"  ❌ Unexpected error: {e}")
            return False
    
    def wait_for_stack_completion(self, cf_client, stack_name: str, account_id: str) -> bool:
        """Wait for CloudFormation stack to complete"""
        print(f"  ⏳ Waiting for stack deployment to complete...")
        
        while True:
            try:
                response = cf_client.describe_stacks(StackName=stack_name)
                stack = response['Stacks'][0]
                status = stack['StackStatus']
                
                if status in ['CREATE_COMPLETE', 'UPDATE_COMPLETE']:
                    print(f"  ✅ Stack deployment completed successfully! Status: {status}")
                    return True
                elif status in ['CREATE_FAILED', 'UPDATE_FAILED', 'ROLLBACK_COMPLETE', 'ROLLBACK_FAILED']:
                    print(f"  ❌ Stack deployment failed with status: {status}")
                    if 'StatusReason' in stack:
                        print(f"     Reason: {stack['StatusReason']}")
                    return False
                elif status in ['CREATE_IN_PROGRESS', 'UPDATE_IN_PROGRESS', 'ROLLBACK_IN_PROGRESS']:
                    print(f"  ⏳ Status: {status}")
                    time.sleep(15)
                else:
                    print(f"  ⚠️  Unexpected status: {status}")
                    time.sleep(15)
                    
            except ClientError as e:
                print(f"  ❌ Error checking stack status: {e}")
                return False
            except KeyboardInterrupt:
                print(f"  ⏹️  Deployment monitoring interrupted by user")
                return False
    
    def check_and_update_stack(self, cf_client, stack_name: str, template_body: str, account_id: str) -> bool:
        """Check if existing stack needs update"""
        try:
            response = cf_client.describe_stacks(StackName=stack_name)
            stack = response['Stacks'][0]
            status = stack['StackStatus']
            
            if status in ['CREATE_COMPLETE', 'UPDATE_COMPLETE']:
                print(f"  ✅ Existing stack is in good state: {status}")
                # Could add template drift detection here
                return True
            else:
                print(f"  ⚠️  Existing stack status: {status}")
                print(f"  💡 Manual intervention may be required")
                return False
                
        except ClientError:
            print(f"  ❌ Failed to describe existing stack")
            return False
    
    def test_role_assumption(self, account_id: str, account_name: str) -> bool:
        """Test that we can assume the deployed CSPMScanRole"""
        try:
            print(f"  🧪 Testing CSPMScanRole assumption...")
            
            role_arn = f"arn:aws:iam::{account_id}:role/CSPMScanRole"
            
            response = self.sts_client.assume_role(
                RoleArn=role_arn,
                RoleSessionName='CSPMTest',
                ExternalId='cspm-security-scan'
            )
            
            print(f"  ✅ Successfully assumed CSPMScanRole")
            
            # Test basic IAM permissions
            temp_credentials = response['Credentials']
            temp_iam_client = boto3.client(
                'iam',
                aws_access_key_id=temp_credentials['AccessKeyId'],
                aws_secret_access_key=temp_credentials['SecretAccessKey'],
                aws_session_token=temp_credentials['SessionToken']
            )
            
            account_summary = temp_iam_client.get_account_summary()
            user_count = account_summary['SummaryMap'].get('Users', 0)
            print(f"  ✅ IAM permissions verified (Users: {user_count})")
            
            return True
            
        except ClientError as e:
            error_code = e.response['Error']['Code']
            error_msg = e.response['Error']['Message']
            print(f"  ❌ Failed to test role assumption: {error_code} - {error_msg}")
            return False
    
    def deploy_to_accounts(self, target_accounts: List[str]) -> Dict[str, bool]:
        """Deploy CSPMScanRole to target accounts"""
        template_body = self.load_cloudformation_template()
        results = {}
        
        # Get account information
        org_accounts = self.get_organization_accounts()
        account_map = {acc['id']: acc for acc in org_accounts}
        
        print(f"\n🎯 TARGET ACCOUNTS:")
        for account_id in target_accounts:
            account_info = account_map.get(account_id, {'name': 'Unknown'})
            print(f"   📋 {account_id} ({account_info['name']})")
        
        print(f"\n🚀 DEPLOYMENT STARTING...")
        
        successful_deployments = []
        failed_deployments = []
        
        for account_id in target_accounts:
            account_info = account_map.get(account_id, {'name': 'Unknown'})
            print(f"\n🔧 Deploying to account {account_id} ({account_info['name']})...")
            
            # Step 1: Assume OrganizationAccountAccessRole
            credentials = self.assume_organization_role(account_id)
            if not credentials:
                results[account_id] = False
                failed_deployments.append(account_id)
                continue
            
            # Step 2: Deploy CloudFormation stack
            deployment_success = self.deploy_cloudformation_stack(
                account_id, account_info['name'], credentials, template_body
            )
            
            if deployment_success:
                # Step 3: Test role assumption
                test_success = self.test_role_assumption(account_id, account_info['name'])
                
                if test_success:
                    print(f"  🎉 Complete deployment successful for {account_id}")
                    successful_deployments.append(account_id)
                    results[account_id] = True
                else:
                    print(f"  ⚠️  Deployment completed but role test failed for {account_id}")
                    failed_deployments.append(account_id)
                    results[account_id] = False
            else:
                failed_deployments.append(account_id)
                results[account_id] = False
        
        # Summary
        print(f"\n📊 DEPLOYMENT SUMMARY")
        print(f"=" * 30)
        print(f"✅ Successful: {len(successful_deployments)}")
        print(f"❌ Failed: {len(failed_deployments)}")
        
        if successful_deployments:
            print(f"\n✅ Successfully deployed to:")
            for account_id in successful_deployments:
                account_info = account_map.get(account_id, {'name': 'Unknown'})
                print(f"   📋 {account_id} ({account_info['name']})")
        
        if failed_deployments:
            print(f"\n❌ Failed deployments:")
            for account_id in failed_deployments:
                account_info = account_map.get(account_id, {'name': 'Unknown'})
                print(f"   📋 {account_id} ({account_info['name']})")
        
        if len(successful_deployments) == len(target_accounts):
            print(f"\n🎉 ALL DEPLOYMENTS SUCCESSFUL!")
            print(f"You can now run organization-wide CSPM scan:")
            print(f"   python run_organization_scan.py")
        
        return results

def main():
    parser = argparse.ArgumentParser(
        description='Deploy CSMP cross-account roles using OrganizationAccountAccessRole'
    )
    parser.add_argument(
        '--accounts', 
        required=True,
        help='Comma-separated list of account IDs, or "all" for all member accounts'
    )
    
    args = parser.parse_args()
    
    deployer = OrganizationRoleDeployer()
    
    # Determine target accounts
    if args.accounts.lower() == 'all':
        org_accounts = deployer.get_organization_accounts()
        target_accounts = [acc['id'] for acc in org_accounts]
    else:
        target_accounts = [acc.strip() for acc in args.accounts.split(',')]
    
    if not target_accounts:
        print("❌ No target accounts specified or found")
        sys.exit(1)
    
    # Deploy to accounts
    results = deployer.deploy_to_accounts(target_accounts)
    
    # Exit with appropriate code
    if all(results.values()):
        print(f"\n✅ All deployments completed successfully!")
        sys.exit(0)
    else:
        print(f"\n⚠️  Some deployments failed. Check the output above for details.")
        sys.exit(1)

if __name__ == "__main__":
    main()