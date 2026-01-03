#!/usr/bin/env python3
"""
CloudFormation Deployment Script for GitHub OIDC and CSPM Infrastructure

This script automates the deployment of:
1. GitHub OIDC Identity Provider and IAM Role (master account)
2. Cross-account CSMP scan roles (member accounts)
"""

import boto3
import json
import time
import sys
import os
from typing import Dict, List, Optional
import argparse
from botocore.exceptions import ClientError


class CSPMCloudFormationDeployer:
    """Deploy CSPM CloudFormation infrastructure."""
    
    def __init__(self, profile_name: Optional[str] = None, region: str = 'us-east-1'):
        """Initialize the deployer."""
        self.region = region
        self.session = boto3.Session(profile_name=profile_name)
        self.cf_client = self.session.client('cloudformation', region_name=region)
        self.sts_client = self.session.client('sts', region_name=region)
        self.orgs_client = self.session.client('organizations', region_name=region)
        
        # Get current account info
        try:
            identity = self.sts_client.get_caller_identity()
            self.account_id = identity['Account']
            self.user_arn = identity['Arn']
            print(f"🔐 Connected to AWS Account: {self.account_id}")
            print(f"👤 User/Role: {self.user_arn}")
        except Exception as e:
            print(f"❌ Failed to get AWS identity: {e}")
            sys.exit(1)

    def deploy_oidc_infrastructure(self, 
                                   github_org: str, 
                                   github_repo: str,
                                   role_name: str = 'GitHubActionsCSPMRole',
                                   allow_all_branches: bool = False,
                                   stack_name: str = 'github-oidc-cspm') -> Dict:
        """Deploy the GitHub OIDC infrastructure to the master account."""
        
        print(f"\n🚀 Deploying GitHub OIDC Infrastructure...")
        print(f"   📂 Repository: {github_org}/{github_repo}")
        print(f"   🎭 Role Name: {role_name}")
        print(f"   🌿 All Branches: {allow_all_branches}")
        
        # Read the CloudFormation template
        template_path = os.path.join(os.path.dirname(__file__), '..', 'templates', 'github-oidc-cloudformation.yaml')
        
        try:
            with open(template_path, 'r') as f:
                template_body = f.read()
        except FileNotFoundError:
            print(f"❌ Template not found: {template_path}")
            return {}
        
        # Prepare parameters
        parameters = [
            {'ParameterKey': 'GitHubOrg', 'ParameterValue': github_org},
            {'ParameterKey': 'GitHubRepo', 'ParameterValue': github_repo},
            {'ParameterKey': 'RoleName', 'ParameterValue': role_name},
            {'ParameterKey': 'AllowAllBranches', 'ParameterValue': str(allow_all_branches).lower()},
            {'ParameterKey': 'SessionDuration', 'ParameterValue': '3600'}
        ]
        
        try:
            # Check if stack exists
            try:
                self.cf_client.describe_stacks(StackName=stack_name)
                print(f"   📝 Updating existing stack: {stack_name}")
                operation = 'update'
                response = self.cf_client.update_stack(
                    StackName=stack_name,
                    TemplateBody=template_body,
                    Parameters=parameters,
                    Capabilities=['CAPABILITY_NAMED_IAM']
                )
            except ClientError as e:
                if 'does not exist' in str(e):
                    print(f"   📝 Creating new stack: {stack_name}")
                    operation = 'create'
                    response = self.cf_client.create_stack(
                        StackName=stack_name,
                        TemplateBody=template_body,
                        Parameters=parameters,
                        Capabilities=['CAPABILITY_NAMED_IAM'],
                        Tags=[
                            {'Key': 'Purpose', 'Value': 'GitHubOIDC'},
                            {'Key': 'Repository', 'Value': f"{github_org}/{github_repo}"},
                            {'Key': 'ManagedBy', 'Value': 'CSPMDeploymentScript'}
                        ]
                    )
                else:
                    raise
            
            stack_id = response['StackId']
            print(f"   ⏳ Stack operation initiated: {stack_id}")
            
            # Wait for completion
            self._wait_for_stack_completion(stack_name, operation)
            
            # Get outputs
            outputs = self._get_stack_outputs(stack_name)
            
            print(f"   ✅ OIDC infrastructure deployed successfully!")
            print(f"   🎭 Role ARN: {outputs.get('GitHubActionsRoleArn', 'Unknown')}")
            
            return outputs
            
        except Exception as e:
            print(f"   ❌ Failed to deploy OIDC infrastructure: {e}")
            return {}

    def deploy_member_account_roles(self, 
                                    master_account_id: str,
                                    github_role_name: str = 'GitHubActionsCSPMRole',
                                    cspm_role_name: str = 'CSPMScanRole',
                                    stack_name_prefix: str = 'csmp-member-role') -> List[Dict]:
        """Deploy CSPM scan roles to all member accounts."""
        
        print(f"\n🏢 Deploying CSPM roles to member accounts...")
        
        # Get organization accounts
        try:
            org_info = self.orgs_client.describe_organization()
            print(f"   🏢 Organization: {org_info['Organization']['Id']}")
            
            accounts_response = self.orgs_client.list_accounts()
            accounts = accounts_response['Accounts']
            
            member_accounts = [
                acc for acc in accounts 
                if acc['Id'] != master_account_id and acc['Status'] == 'ACTIVE'
            ]
            
            print(f"   📊 Found {len(member_accounts)} member accounts to configure")
            
        except Exception as e:
            print(f"   ❌ Failed to get organization info: {e}")
            return []
        
        # Read the member account template
        template_path = os.path.join(os.path.dirname(__file__), '..', 'templates', 'cspm-member-account-role.yaml')
        
        try:
            with open(template_path, 'r') as f:
                template_body = f.read()
        except FileNotFoundError:
            print(f"❌ Member account template not found: {template_path}")
            return []
        
        results = []
        
        for account in member_accounts:
            account_id = account['Id']
            account_name = account['Name']
            stack_name = f"{stack_name_prefix}-{account_id}"
            
            print(f"\n   🎯 Deploying to Account: {account_name} ({account_id})")
            
            try:
                # For cross-account deployment, we would need to assume a role
                # in the target account. For now, this provides the template.
                print(f"      📝 Template ready for account {account_id}")
                print(f"      ℹ️  Manual deployment required with admin access to account {account_id}")
                
                result = {
                    'account_id': account_id,
                    'account_name': account_name,
                    'template_path': template_path,
                    'stack_name': stack_name,
                    'status': 'template_ready'
                }
                
                results.append(result)
                
            except Exception as e:
                print(f"      ❌ Error preparing template for account {account_id}: {e}")
                results.append({
                    'account_id': account_id,
                    'account_name': account_name,
                    'status': 'error',
                    'error': str(e)
                })
        
        return results

    def _wait_for_stack_completion(self, stack_name: str, operation: str):
        """Wait for CloudFormation stack operation to complete."""
        
        if operation == 'create':
            waiter = self.cf_client.get_waiter('stack_create_complete')
        else:
            waiter = self.cf_client.get_waiter('stack_update_complete')
        
        print(f"      ⏳ Waiting for {operation} to complete...")
        
        try:
            waiter.wait(
                StackName=stack_name,
                WaiterConfig={'Delay': 10, 'MaxAttempts': 60}
            )
        except Exception as e:
            print(f"      ❌ Stack {operation} failed: {e}")
            # Get stack events for debugging
            self._print_stack_events(stack_name)
            raise

    def _get_stack_outputs(self, stack_name: str) -> Dict:
        """Get CloudFormation stack outputs."""
        
        try:
            response = self.cf_client.describe_stacks(StackName=stack_name)
            stack = response['Stacks'][0]
            
            outputs = {}
            for output in stack.get('Outputs', []):
                outputs[output['OutputKey']] = output['OutputValue']
            
            return outputs
            
        except Exception as e:
            print(f"Failed to get stack outputs: {e}")
            return {}

    def _print_stack_events(self, stack_name: str, limit: int = 10):
        """Print recent stack events for debugging."""
        
        try:
            response = self.cf_client.describe_stack_events(StackName=stack_name)
            events = response['StackEvents'][:limit]
            
            print(f"\n📋 Recent stack events for {stack_name}:")
            for event in events:
                status = event.get('ResourceStatus', 'Unknown')
                reason = event.get('ResourceStatusReason', '')
                resource = event.get('LogicalResourceId', 'Unknown')
                timestamp = event.get('Timestamp', 'Unknown')
                
                print(f"   {timestamp} | {resource} | {status} | {reason}")
                
        except Exception as e:
            print(f"Failed to get stack events: {e}")

    def generate_deployment_summary(self, oidc_outputs: Dict, member_results: List[Dict]):
        """Generate a summary of the deployment."""
        
        print(f"\n" + "="*60)
        print(f"🎉 CSPM CloudFormation Deployment Summary")
        print(f"="*60)
        
        # OIDC Infrastructure Summary
        print(f"\n🔐 GitHub OIDC Infrastructure:")
        if oidc_outputs:
            print(f"   ✅ Status: Successfully deployed")
            print(f"   🎭 Role ARN: {oidc_outputs.get('GitHubActionsRoleArn', 'Unknown')}")
            print(f"   🆔 OIDC Provider: {oidc_outputs.get('OIDCProviderArn', 'Unknown')}")
            print(f"   📝 Repository Variable: AWS_ROLE_ARN = {oidc_outputs.get('RepositoryVariable', 'Unknown')}")
        else:
            print(f"   ❌ Status: Deployment failed")
        
        # Member Accounts Summary
        print(f"\n🏢 Member Account Roles:")
        if member_results:
            successful = len([r for r in member_results if r['status'] == 'template_ready'])
            print(f"   📊 Total Accounts: {len(member_results)}")
            print(f"   ✅ Templates Ready: {successful}")
            
            for result in member_results:
                status_icon = "✅" if result['status'] == 'template_ready' else "❌"
                print(f"      {status_icon} {result['account_name']} ({result['account_id']})")
        
        # Next Steps
        print(f"\n🚀 Next Steps:")
        print(f"   1. Set repository variable in GitHub:")
        print(f"      Name: AWS_ROLE_ARN")
        print(f"      Value: {oidc_outputs.get('GitHubActionsRoleArn', 'See CloudFormation outputs')}")
        print(f"   2. Deploy member account roles using provided templates")
        print(f"   3. Test authentication: python scripts/test_aws_auth.py")
        print(f"   4. Run GitHub Actions workflows")
        
        print(f"\n" + "="*60)


def main():
    """Main function."""
    parser = argparse.ArgumentParser(description='Deploy CSPM CloudFormation Infrastructure')
    parser.add_argument('--github-org', required=True, help='GitHub organization or username')
    parser.add_argument('--github-repo', required=True, help='GitHub repository name')
    parser.add_argument('--role-name', default='GitHubActionsCSPMRole', help='Name for GitHub Actions role')
    parser.add_argument('--all-branches', action='store_true', help='Allow access from all branches')
    parser.add_argument('--profile', help='AWS profile to use')
    parser.add_argument('--region', default='us-east-1', help='AWS region')
    parser.add_argument('--stack-name', default='github-oidc-cspm', help='CloudFormation stack name')
    
    args = parser.parse_args()
    
    print(f"🚀 CSPM CloudFormation Deployment")
    print(f"   Repository: {args.github_org}/{args.github_repo}")
    print(f"   Region: {args.region}")
    print(f"   Profile: {args.profile or 'default'}")
    
    # Initialize deployer
    deployer = CSPMCloudFormationDeployer(profile_name=args.profile, region=args.region)
    
    # Deploy OIDC infrastructure
    oidc_outputs = deployer.deploy_oidc_infrastructure(
        github_org=args.github_org,
        github_repo=args.github_repo,
        role_name=args.role_name,
        allow_all_branches=args.all_branches,
        stack_name=args.stack_name
    )
    
    # Deploy member account roles
    member_results = deployer.deploy_member_account_roles(
        master_account_id=deployer.account_id,
        github_role_name=args.role_name
    )
    
    # Generate summary
    deployer.generate_deployment_summary(oidc_outputs, member_results)
    
    print(f"\n✨ Deployment completed!")


if __name__ == '__main__':
    main()