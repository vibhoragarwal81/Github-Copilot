#!/usr/bin/env python3
"""
AWS CSPM Setup Cleanup Script

This script helps identify and clean up existing CSMP-related AWS resources
before testing the new acquired entity setup package.
"""

import boto3
import json
import sys
from botocore.exceptions import ClientError, NoCredentialsError


def check_aws_access():
    """Check if we have AWS access."""
    try:
        sts = boto3.client('sts')
        identity = sts.get_caller_identity()
        print(f"✅ AWS Access confirmed: {identity['Arn']}")
        print(f"   Account: {identity['Account']}")
        return True
    except NoCredentialsError:
        print("❌ No AWS credentials found - this is expected for cleanup testing!")
        return False
    except Exception as e:
        print(f"❌ AWS access error: {e}")
        return False


def list_oidc_providers():
    """List existing OIDC providers."""
    try:
        iam = boto3.client('iam')
        response = iam.list_open_id_connect_providers()
        
        providers = response.get('OpenIDConnectProviderList', [])
        github_providers = [p for p in providers if 'token.actions.githubusercontent.com' in p['Arn']]
        
        if github_providers:
            print(f"\n🔍 Found {len(github_providers)} GitHub OIDC Provider(s):")
            for provider in github_providers:
                print(f"   • {provider['Arn']}")
                
                # Get provider details
                try:
                    details = iam.get_open_id_connect_provider(
                        OpenIDConnectProviderArn=provider['Arn']
                    )
                    print(f"     URL: {details['Url']}")
                    print(f"     Clients: {details['ClientIDList']}")
                    print(f"     Thumbprints: {details['ThumbprintList']}")
                except Exception as e:
                    print(f"     ❌ Error getting details: {e}")
            
            print(f"\n🗑️  To remove these providers:")
            for provider in github_providers:
                print(f"aws iam delete-open-id-connect-provider --open-id-connect-provider-arn {provider['Arn']}")
        else:
            print("\n✅ No GitHub OIDC providers found")
            
    except Exception as e:
        print(f"❌ Error listing OIDC providers: {e}")


def list_cspm_roles():
    """List CSPM-related IAM roles."""
    try:
        iam = boto3.client('iam')
        paginator = iam.get_paginator('list_roles')
        
        cspm_roles = []
        keywords = ['cspm', 'github', 'scanner', 'audit', 'security']
        
        for page in paginator.paginate():
            for role in page['Roles']:
                role_name = role['RoleName'].lower()
                if any(keyword in role_name for keyword in keywords):
                    csmp_roles.append(role)
        
        if csmp_roles:
            print(f"\n🔍 Found {len(csmp_roles)} potential CSMP-related role(s):")
            for role in csmp_roles:
                print(f"   • {role['RoleName']} - {role['Arn']}")
                
                # Check trust policy
                try:
                    trust_doc = role['AssumeRolePolicyDocument']
                    if 'token.actions.githubusercontent.com' in json.dumps(trust_doc):
                        print(f"     🎭 GitHub OIDC trust policy detected")
                except:
                    pass
            
            print(f"\n🗑️  To remove these roles (check carefully first!):")
            for role in csmp_roles:
                print(f"# Check role: aws iam get-role --role-name {role['RoleName']}")
                print(f"# Delete role: aws iam delete-role --role-name {role['RoleName']}")
                print(f"# (First detach policies: aws iam list-attached-role-policies --role-name {role['RoleName']})")
                print()
        else:
            print("\n✅ No obvious CSMP-related roles found")
            
    except Exception as e:
        print(f"❌ Error listing roles: {e}")


def list_cloudformation_stacks():
    """List CloudFormation stacks that might be CSMP-related."""
    try:
        cf = boto3.client('cloudformation')
        response = cf.list_stacks(
            StackStatusFilter=[
                'CREATE_COMPLETE', 'UPDATE_COMPLETE', 'UPDATE_ROLLBACK_COMPLETE'
            ]
        )
        
        cspm_stacks = []
        keywords = ['csmp', 'github', 'oidc', 'scanner']
        
        for stack in response['StackSummaries']:
            stack_name = stack['StackName'].lower()
            if any(keyword in stack_name for keyword in keywords):
                csmp_stacks.append(stack)
        
        if csmp_stacks:
            print(f"\n🔍 Found {len(csmp_stacks)} potential CSMP CloudFormation stack(s):")
            for stack in csmp_stacks:
                print(f"   • {stack['StackName']} - {stack['StackStatus']}")
                print(f"     Created: {stack['CreationTime']}")
            
            print(f"\n🗑️  To remove these stacks:")
            for stack in csmp_stacks:
                print(f"aws cloudformation delete-stack --stack-name {stack['StackName']}")
        else:
            print("\n✅ No obvious CSMP CloudFormation stacks found")
            
    except Exception as e:
        print(f"❌ Error listing CloudFormation stacks: {e}")


def check_organization_info():
    """Check if we're in an AWS Organization."""
    try:
        org = boto3.client('organizations')
        org_info = org.describe_organization()
        
        print(f"\n🏢 AWS Organization detected:")
        print(f"   Organization ID: {org_info['Organization']['Id']}")
        print(f"   Master Account: {org_info['Organization']['MasterAccountId']}")
        print(f"   Feature Set: {org_info['Organization']['FeatureSet']}")
        
        # List accounts
        accounts = org.list_accounts()['Accounts']
        print(f"   Total Accounts: {len(accounts)}")
        
        for account in accounts:
            print(f"     • {account['Name']} ({account['Id']}) - {account['Status']}")
        
        return org_info['Organization']
        
    except ClientError as e:
        if 'AWSOrganizationsNotInUseException' in str(e):
            print(f"\n✅ Not in an AWS Organization (single account)")
        else:
            print(f"❌ Error checking organization: {e}")
        return None
    except Exception as e:
        print(f"❌ Error checking organization: {e}")
        return None


def main():
    """Main function."""
    print("🧹 CSMP Setup Cleanup Analysis")
    print("=" * 50)
    
    # Check AWS access
    if not check_aws_access():
        print("\n⚠️  No AWS credentials detected - this is expected if you've already cleaned them up!")
        print("   You can skip the AWS resource cleanup and proceed with testing.")
        sys.exit(0)
    
    # Check for existing resources
    list_oidc_providers()
    list_cspm_roles()
    list_cloudformation_stacks()
    org_info = check_organization_info()
    
    print("\n" + "=" * 50)
    print("📋 CLEANUP SUMMARY")
    print("=" * 50)
    
    print("\n✅ Manual steps completed (if needed):")
    print("   • GitHub repository secrets/variables removed")
    print("   • Local AWS credentials cleared")
    print("   • Environment variables cleared")
    
    print("\n⚠️  AWS resources to review and remove:")
    print("   • GitHub OIDC Identity Providers (see above)")
    print("   • CSMP-related IAM roles (see above)")
    print("   • CloudFormation stacks (see above)")
    
    print("\n🎯 Member account cleanup:")
    if org_info:
        print("   • CSPMScanRole in each member account")
        print("   • Any cross-account trust relationships")
        print("   • Organization-related IAM policies")
    else:
        print("   • Not applicable (single account setup)")
    
    print("\n🧪 Ready for testing when AWS resources are cleaned up!")


if __name__ == '__main__':
    main()