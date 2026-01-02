#!/usr/bin/env python3
"""
CSPM Cross-Account Role Setup Script

This script helps set up the necessary IAM roles in member AWS accounts 
for cross-account CSPM security scanning.
"""

import json
import sys
import boto3
from botocore.exceptions import ClientError

def create_cspm_role(master_account_id="872515281040", external_id="cspm-security-scan"):
    """Create CSPM role with proper trust and permissions policies."""
    
    # Get current account info
    sts = boto3.client('sts')
    current_account = sts.get_caller_identity()['Account']
    
    print(f"🏢 Setting up CSPM role in account: {current_account}")
    print(f"🔗 Master account: {master_account_id}")
    
    # Trust policy - allows master account to assume this role
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {
                    "AWS": f"arn:aws:iam::{master_account_id}:user/vibhor"
                },
                "Action": "sts:AssumeRole",
                "Condition": {
                    "StringEquals": {
                        "sts:ExternalId": external_id
                    }
                }
            }
        ]
    }
    
    # Permissions policy - read-only CSPM scanning permissions
    permissions_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    # IAM Permissions
                    "iam:GetAccountSummary",
                    "iam:ListUsers",
                    "iam:ListRoles", 
                    "iam:ListGroups",
                    "iam:ListPolicies",
                    "iam:ListMFADevices",
                    "iam:ListAccessKeys",
                    "iam:GetUser",
                    "iam:GetRole",
                    "iam:GetPolicy",
                    "iam:GetPolicyVersion",
                    "iam:ListAttachedUserPolicies",
                    "iam:ListAttachedRolePolicies",
                    "iam:ListUserPolicies",
                    "iam:ListRolePolicies",
                    "iam:GetAccountPasswordPolicy",
                    
                    # EC2 Permissions
                    "ec2:DescribeInstances",
                    "ec2:DescribeImages",
                    "ec2:DescribeSecurityGroups", 
                    "ec2:DescribeVolumes",
                    "ec2:DescribeSnapshots",
                    "ec2:DescribeVpcs",
                    "ec2:DescribeSubnets",
                    "ec2:DescribeRouteTables",
                    "ec2:DescribeNetworkAcls",
                    "ec2:DescribeFlowLogs",
                    "ec2:DescribeRegions",
                    
                    # S3 Permissions
                    "s3:ListAllMyBuckets",
                    "s3:GetBucketLocation",
                    "s3:GetBucketPolicy",
                    "s3:GetBucketAcl",
                    "s3:GetBucketEncryption",
                    "s3:GetBucketVersioning",
                    "s3:GetBucketLogging",
                    "s3:GetBucketNotification",
                    "s3:GetBucketPublicAccessBlock",
                    
                    # VPC Permissions
                    "vpc:DescribeVpcs",
                    "vpc:DescribeSubnets",
                    "vpc:DescribeRouteTables",
                    "vpc:DescribeNetworkAcls",
                    "vpc:DescribeFlowLogs"
                ],
                "Resource": "*"
            }
        ]
    }
    
    iam = boto3.client('iam')
    
    try:
        # Create the permissions policy
        print("📋 Creating CSPM permissions policy...")
        policy_name = "CSPMScanPolicy"
        
        try:
            policy_response = iam.create_policy(
                PolicyName=policy_name,
                PolicyDocument=json.dumps(permissions_policy),
                Description="CSPM cross-account security scanning permissions"
            )
            policy_arn = policy_response['Policy']['Arn']
            print(f"✅ Policy created: {policy_arn}")
        except ClientError as e:
            if e.response['Error']['Code'] == 'EntityAlreadyExists':
                # Policy already exists, get its ARN
                policy_arn = f"arn:aws:iam::{current_account}:policy/{policy_name}"
                print(f"ℹ️  Policy already exists: {policy_arn}")
            else:
                raise
        
        # Create the role
        print("🔧 Creating CSMP role...")
        role_name = "CSPMScanRole"
        
        try:
            role_response = iam.create_role(
                RoleName=role_name,
                AssumeRolePolicyDocument=json.dumps(trust_policy),
                Description="CSPM cross-account security scanning role"
            )
            role_arn = role_response['Role']['Arn']
            print(f"✅ Role created: {role_arn}")
        except ClientError as e:
            if e.response['Error']['Code'] == 'EntityAlreadyExists':
                # Role already exists, get its ARN
                role_arn = f"arn:aws:iam::{current_account}:role/{role_name}"
                print(f"ℹ️  Role already exists: {role_arn}")
                
                # Update trust policy in case it changed
                iam.update_assume_role_policy(
                    RoleName=role_name,
                    PolicyDocument=json.dumps(trust_policy)
                )
                print("✅ Trust policy updated")
            else:
                raise
        
        # Attach the policy to the role
        print("🔗 Attaching policy to role...")
        iam.attach_role_policy(
            RoleName=role_name,
            PolicyArn=policy_arn
        )
        print("✅ Policy attached successfully")
        
        # Verify the setup
        print("\n🧪 Verifying role setup...")
        role_info = iam.get_role(RoleName=role_name)
        print(f"✅ Role ARN: {role_info['Role']['Arn']}")
        print(f"✅ Created: {role_info['Role']['CreateDate']}")
        
        print(f"\n🎉 CSMP role setup completed successfully!")
        print(f"🔗 Role ARN: {role_info['Role']['Arn']}")
        print(f"🔑 External ID: {external_id}")
        print(f"\nThis account is now ready for cross-account CSMP scanning from master account {master_account_id}")
        
        return True
        
    except ClientError as e:
        print(f"❌ Error setting up CSPM role: {e}")
        return False
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        return False

def test_role_assumption(role_arn, external_id="csmp-security-scan"):
    """Test if the role can be assumed (run this from master account)."""
    print(f"🧪 Testing role assumption: {role_arn}")
    
    try:
        sts = boto3.client('sts')
        response = sts.assume_role(
            RoleArn=role_arn,
            RoleSessionName='cspm-test',
            ExternalId=external_id
        )
        
        print("✅ Role assumption successful!")
        print(f"📋 Session: {response['AssumedRoleUser']['Arn']}")
        return True
        
    except ClientError as e:
        print(f"❌ Role assumption failed: {e}")
        return False

if __name__ == "__main__":
    print("🔧 CSPM Cross-Account Role Setup")
    print("=" * 50)
    
    if len(sys.argv) > 1:
        command = sys.argv[1]
        
        if command == "create":
            # Create role in current account
            success = create_cspm_role()
            sys.exit(0 if success else 1)
            
        elif command == "test" and len(sys.argv) > 2:
            # Test role assumption from master account
            role_arn = sys.argv[2]
            success = test_role_assumption(role_arn)
            sys.exit(0 if success else 1)
        else:
            print("❌ Invalid command")
    
    print("Usage:")
    print("  python setup_cross_account.py create          # Create role in current account")
    print("  python setup_cross_account.py test <role-arn> # Test role assumption")
    print()
    print("Example:")
    print("  python setup_cross_account.py create")
    print("  python setup_cross_account.py test arn:aws:iam::871007551509:role/CSPMScanRole")