# AWS Cross-Account CSPM Setup Guide

## 🎯 Problem Identified
Your organization scan discovered 3 AWS accounts but could only access 1 (the master account). The member accounts need proper IAM roles configured for cross-account CSPM scanning.

## 📋 Current Status
- ✅ **Organization Discovery**: Working - found 3 accounts
- ❌ **Cross-Account Access**: Failed - missing CSPMScanRole in member accounts  
- ✅ **Master Account Scan**: Working - 101 findings from account 872515281040
- ❌ **Member Account Scans**: Blocked - accounts 871007551509, 968382677077

## 🔧 Solution: Set Up Cross-Account IAM Roles

### **Step 1: Create CSPM Role in Each Member Account**

**For each member account (871007551509, 968382677077), create this IAM role:**

#### **Role Name:** `CSPMScanRole`

#### **Trust Policy:** (Replace `872515281040` with your master account ID)
```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {
                "AWS": "arn:aws:iam::872515281040:user/vibhor"
            },
            "Action": "sts:AssumeRole",
            "Condition": {
                "StringEquals": {
                    "sts:ExternalId": "cspm-security-scan"
                }
            }
        }
    ]
}
```

#### **Permissions Policy:** `CSPMScanPolicy`
```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
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
                "s3:ListAllMyBuckets",
                "s3:GetBucketLocation",
                "s3:GetBucketPolicy",
                "s3:GetBucketAcl",
                "s3:GetBucketEncryption",
                "s3:GetBucketVersioning",
                "s3:GetBucketLogging",
                "s3:GetBucketNotification",
                "s3:GetBucketPublicAccessBlock",
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
```

---

## 🚀 **Quick Setup Commands**

### **Option A: AWS CLI Setup (Run in each member account)**

```bash
# 1. Create the trust policy file
cat > cspm-trust-policy.json << 'EOF'
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {
                "AWS": "arn:aws:iam::872515281040:user/vibhor"
            },
            "Action": "sts:AssumeRole",
            "Condition": {
                "StringEquals": {
                    "sts:ExternalId": "cspm-security-scan"
                }
            }
        }
    ]
}
EOF

# 2. Create the permissions policy file  
cat > csmp-scan-policy.json << 'EOF'
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "iam:GetAccountSummary", "iam:ListUsers", "iam:ListRoles", 
                "iam:ListGroups", "iam:ListPolicies", "iam:ListMFADevices",
                "iam:ListAccessKeys", "iam:GetUser", "iam:GetRole", 
                "iam:GetPolicy", "iam:GetPolicyVersion", "iam:ListAttachedUserPolicies",
                "iam:ListAttachedRolePolicies", "iam:ListUserPolicies", 
                "iam:ListRolePolicies", "iam:GetAccountPasswordPolicy",
                "ec2:DescribeInstances", "ec2:DescribeImages", "ec2:DescribeSecurityGroups",
                "ec2:DescribeVolumes", "ec2:DescribeSnapshots", "ec2:DescribeVpcs",
                "ec2:DescribeSubnets", "ec2:DescribeRouteTables", "ec2:DescribeNetworkAcls",
                "ec2:DescribeFlowLogs", "ec2:DescribeRegions", "s3:ListAllMyBuckets",
                "s3:GetBucketLocation", "s3:GetBucketPolicy", "s3:GetBucketAcl",
                "s3:GetBucketEncryption", "s3:GetBucketVersioning", "s3:GetBucketLogging",
                "s3:GetBucketNotification", "s3:GetBucketPublicAccessBlock",
                "vpc:DescribeVpcs", "vpc:DescribeSubnets", "vpc:DescribeRouteTables",
                "vpc:DescribeNetworkAcls", "vpc:DescribeFlowLogs"
            ],
            "Resource": "*"
        }
    ]
}
EOF

# 3. Create the IAM policy
aws iam create-policy \
    --policy-name CSPMScanPolicy \
    --policy-document file://cspm-scan-policy.json \
    --description "CSPM cross-account security scanning permissions"

# 4. Create the IAM role
aws iam create-role \
    --role-name CSPMScanRole \
    --assume-role-policy-document file://cspm-trust-policy.json \
    --description "CSPM cross-account security scanning role"

# 5. Attach the policy to the role
aws iam attach-role-policy \
    --role-name CSPMScanRole \
    --policy-arn arn:aws:iam::$(aws sts get-caller-identity --query Account --output text):policy/CSPMScanPolicy

# 6. Verify the role was created
aws iam get-role --role-name CSPMScanRole
```

### **Option B: AWS Console Setup**
1. Go to **IAM Console** > **Roles** > **Create Role**
2. Select **AWS Account** > **Another AWS Account**
3. Enter Account ID: `872515281040`
4. Check **Require external ID**: `cspm-security-scan`
5. Attach the permissions policy above
6. Name the role: `CSPMScanRole`

---

## ✅ **Verification Steps**

### **Test Cross-Account Access:**
```bash
# From master account, test assuming role in member account
aws sts assume-role \
    --role-arn arn:aws:iam::871007551509:role/CSPMScanRole \
    --role-session-name cspm-test \
    --external-id cspm-security-scan
```

### **Expected Success Response:**
```json
{
    "Credentials": {
        "AccessKeyId": "ASIA...",
        "SecretAccessKey": "...",
        "SessionToken": "...",
        "Expiration": "..."
    },
    "AssumedRoleUser": {
        "AssumedRoleId": "...:cspm-test",
        "Arn": "arn:aws:sts::871007551509:assumed-role/CSPMScanRole/cspm-test"
    }
}
```

---

## 🔄 **After Setup: Re-run Organization Scan**

Once you've set up the roles in both member accounts:

```powershell
# Re-run the organization scan
python run_organization_scan.py
```

**Expected Results:**
- ✅ Account 871007551509: Full scan with findings
- ✅ Account 872515281040: Full scan with findings  
- ✅ Account 968382677077: Full scan with findings
- ✅ Comprehensive organization report with all accounts

---

## 📊 **What You'll Get After Proper Setup**

### **Complete Organization Coverage:**
- **3 accounts** × **4 regions** = **12 scoped assessments**
- **Estimated findings**: 200-500+ across organization
- **True enterprise dashboard** with multi-account security posture

### **Executive Value:**
- **Risk aggregation** across business units
- **Compliance gaps** organization-wide
- **Resource optimization** opportunities
- **Security ROI** measurements

---

## ⚠️ **Current State vs. Target State**

### **Current (Without Cross-Account Roles):**
- 🟡 **Partial Success**: Only master account scanned
- 🔴 **Limited Value**: Missing 67% of organization
- 🟡 **Demo Ready**: Shows capability but not full scope

### **Target (With Cross-Account Roles):**
- ✅ **Full Success**: All 3 accounts scanned
- ✅ **Complete Value**: Entire organization assessed  
- ✅ **Enterprise Ready**: True multi-account CSPM

Would you like me to help you set up the cross-account roles, or would you prefer to demonstrate the current single-account capability and explain the cross-account setup as a "next phase" during your demo?