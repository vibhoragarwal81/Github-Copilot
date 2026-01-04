# Quick AWS CLI Setup for CSPM Testing

## Step 1: Create OIDC Provider
```bash
aws iam create-open-id-connect-provider \
  --url https://token.actions.githubusercontent.com \
  --client-id-list sts.amazonaws.com \
  --thumbprint-list 6938fd4d98bab03faadb97b34396831e3780aea1 \
  --thumbprint-list 1c58a3a8518e8759bf075b76b750d4f2df264fcd
```

## Step 2: Create Trust Policy File
Create `trust-policy.json`:
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::871007551509:oidc-provider/token.actions.githubusercontent.com"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "token.actions.githubusercontent.com:aud": "sts.amazonaws.com"
        },
        "StringLike": {
          "token.actions.githubusercontent.com:sub": "repo:vibhoragarwal81/Github-Copilot:*"
        }
      }
    }
  ]
}
```

## Step 3: Create IAM Role
```bash
aws iam create-role \
  --role-name CSPMScannerRole \
  --assume-role-policy-document file://trust-policy.json \
  --description "CSPM scanning role for GitHub Actions testing"
```

## Step 4: Attach Policies
```bash
# Attach AWS managed policies
aws iam attach-role-policy \
  --role-name CSPMScannerRole \
  --policy-arn arn:aws:iam::aws:policy/SecurityAudit

aws iam attach-role-policy \
  --role-name CSPMScannerRole \
  --policy-arn arn:aws:iam::aws:policy/job-function/ViewOnlyAccess
```

## Step 5: Create Custom Policy
Create `cspm-policy.json`:
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "iam:GetAccountSummary",
        "iam:GetCredentialReport",
        "iam:GenerateCredentialReport",
        "iam:ListAccountAliases",
        "iam:GetAccountPasswordPolicy",
        "iam:ListMFADevices",
        "iam:SimulatePrincipalPolicy",
        "sts:GetCallerIdentity",
        "sts:GetSessionToken",
        "cloudtrail:DescribeTrails",
        "cloudtrail:GetTrailStatus",
        "guardduty:ListDetectors",
        "guardduty:GetDetector",
        "securityhub:GetEnabledStandards",
        "securityhub:DescribeHub",
        "config:DescribeConfigRules",
        "kms:DescribeKey",
        "kms:ListKeys",
        "logs:DescribeLogGroups"
      ],
      "Resource": "*"
    }
  ]
}
```

```bash
# Create and attach custom policy
aws iam create-policy \
  --policy-name CSPMScanningPolicy \
  --policy-document file://cspm-policy.json

aws iam attach-role-policy \
  --role-name CSPMScannerRole \
  --policy-arn arn:aws:iam::871007551509:policy/CSPMScanningPolicy
```

## Step 6: Get Role ARN
```bash
aws iam get-role --role-name CSPMScannerRole --query 'Role.Arn' --output text
```

## Result
Set the returned ARN as GitHub repository variable: `AWS_ROLE_ARN`

## Cleanup
```bash
# To remove everything later
aws iam detach-role-policy --role-name CSPMScannerRole --policy-arn arn:aws:iam::aws:policy/SecurityAudit
aws iam detach-role-policy --role-name CSPMScannerRole --policy-arn arn:aws:iam::aws:policy/job-function/ViewOnlyAccess
aws iam detach-role-policy --role-name CSPMScannerRole --policy-arn arn:aws:iam::871007551509:policy/CSPMScanningPolicy
aws iam delete-policy --policy-arn arn:aws:iam::871007551509:policy/CSPMScanningPolicy
aws iam delete-role --role-name CSPMScannerRole
aws iam delete-open-id-connect-provider --open-id-connect-provider-arn arn:aws:iam::871007551509:oidc-provider/token.actions.githubusercontent.com
```