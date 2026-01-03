# OIDC IAM Role Setup for GitHub Workflows

This guide provides step-by-step instructions for configuring AWS IAM roles with GitHub OIDC for secure, keyless authentication in your CSPM workflows.

## 🏗️ Architecture Overview

```
GitHub Actions Workflow
├── GitHub OIDC Identity Provider
├── Temporary JWT Token
└── AWS IAM Role Assumption
    ├── SecurityAudit Permissions
    ├── ViewOnlyAccess Permissions
    ├── Organizations Access (if needed)
    └── Cross-Account Role Assumption
```

## 🚀 Setup Options

You can set up OIDC authentication using either:

### 🏗️ Option A: CloudFormation (Recommended)
**Automated infrastructure deployment with single command:**
```bash
python scripts/deploy_cloudformation.py \
  --github-org vibhoragarwal81 \
  --github-repo Github-Copilot
```

📋 **See [CloudFormation Deployment Guide](cloudformation-deployment.md) for complete automation**

### 🔧 Option B: Manual Setup
Follow the detailed manual steps below if you prefer hands-on configuration.

---

## 🚀 Complete Setup Process (Manual)

### Step 1: Create GitHub OIDC Identity Provider in AWS

1. **Navigate to AWS IAM Console**:
   - Go to **IAM** → **Identity providers** → **Add provider**

2. **Configure OIDC Provider**:
   ```
   Provider type: OpenID Connect
   Provider URL: https://token.actions.githubusercontent.com
   Audience: sts.amazonaws.com
   ```

3. **Get Thumbprint** (AWS will auto-populate):
   - Thumbprint: `6938fd4d98bab03faadb97b34396831e3780aea1`

4. **Click "Add provider"**

### Step 2: Create IAM Role for GitHub Actions

1. **Create New Role**:
   - Go to **IAM** → **Roles** → **Create role**
   - Select **Web identity**
   - Identity provider: `token.actions.githubusercontent.com`
   - Audience: `sts.amazonaws.com`

2. **Configure Trust Policy**:
   
   Replace the auto-generated trust policy with:
   
   ```json
   {
     "Version": "2012-10-17",
     "Statement": [
       {
         "Effect": "Allow",
         "Principal": {
           "Federated": "arn:aws:iam::872515281040:oidc-provider/token.actions.githubusercontent.com"
         },
         "Action": "sts:AssumeRole",
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

   **Important**: Replace `872515281040` with your AWS account ID and adjust the repository path if different.

3. **Add Permissions Policies**:
   
   Attach the following AWS managed policies:
   - ✅ `arn:aws:iam::aws:policy/SecurityAudit`
   - ✅ `arn:aws:iam::aws:policy/job-function/ViewOnlyAccess` 
   - ✅ `arn:aws:iam::aws:policy/AWSOrganizationsReadOnlyAccess`

4. **Add Custom Inline Policy** for cross-account access:
   
   Create inline policy named `CSPMCrossAccountAccess`:
   ```json
   {
     "Version": "2012-10-17",
     "Statement": [
       {
         "Effect": "Allow",
         "Action": [
           "sts:AssumeRole"
         ],
         "Resource": [
           "arn:aws:iam::871007551509:role/CSPMScanRole",
           "arn:aws:iam::968382677077:role/CSPMScanRole",
           "arn:aws:iam::*:role/CSPMScanRole"
         ]
       },
       {
         "Effect": "Allow",
         "Action": [
           "organizations:ListAccounts",
           "organizations:DescribeOrganization",
           "organizations:ListRoots",
           "organizations:ListOrganizationalUnitsForParent",
           "organizations:ListAccountsForParent"
         ],
         "Resource": "*"
       }
     ]
   }
   ```

5. **Name the Role**: `GitHubActionsCSPMRole`

6. **Copy the Role ARN**: You'll need this for GitHub configuration
   - Example: `arn:aws:iam::872515281040:role/GitHubActionsCSPMRole`

### Step 3: Configure GitHub Repository

1. **Set Repository Variables**:
   
   Go to your repository **Settings** → **Secrets and variables** → **Actions** → **Variables** tab:
   
   | Variable Name | Value | Description |
   |---------------|-------|-------------|
   | `AWS_ROLE_ARN` | `arn:aws:iam::872515281040:role/GitHubActionsCSPMRole` | Your IAM role ARN |
   | `S3_REPORTS_BUCKET` | `your-reports-bucket` | Optional: S3 bucket for reports |
   | `S3_REGION` | `us-east-1` | Optional: S3 bucket region |

2. **Optional: Remove Old Secrets** (if migrating from access keys):
   
   Go to **Secrets** tab and optionally remove:
   - `AWS_ACCESS_KEY_ID` (will be ignored if role ARN is provided)
   - `AWS_SECRET_ACCESS_KEY` (will be ignored if role ARN is provided)

### Step 4: Test the Configuration

1. **Run Manual Workflow**:
   - Go to **Actions** → **AWS CSPM Security Scan**
   - Click **Run workflow**
   - Use default parameters
   - Monitor the "Configure AWS credentials" step

2. **Expected Success Output**:
   ```
   🔍 Validating AWS connectivity...
   {
       "UserId": "AROABC123DEFGHIJKLMN:GitHubActions-CSPM-Scan-123",
       "Account": "872515281040",
       "Arn": "arn:aws:sts::872515281040:assumed-role/GitHubActionsCSPMRole/GitHubActions-CSPM-Scan-123"
   }
   ✅ AWS connection successful
   ```

3. **Verify Organization Access**:
   ```
   ✅ Organization ID: o-zfqct64bxw
   ✅ Master Account: 872515281040
   ✅ Organization ARN: arn:aws:organizations::872515281040:organization/o-zfqct64bxw
   ```

## 🔒 Security Benefits

### OIDC vs Access Keys Comparison

| Aspect | OIDC with IAM Roles | Access Keys |
|--------|-------------------|-------------|
| **Credential Lifetime** | ✅ 1 hour (auto-expires) | ❌ Permanent until rotated |
| **Rotation Required** | ✅ Automatic | ❌ Manual |
| **GitHub Storage** | ✅ No secrets stored | ❌ Long-term secrets in repo |
| **Audit Trail** | ✅ Clear role assumption logs | ⚠️ Generic access key usage |
| **Permission Scope** | ✅ Repository-specific | ❌ Account-wide access |
| **Compromise Impact** | ✅ Limited window | ❌ Persistent until discovered |

### Additional Security Measures

1. **Restrict by Branch** (optional):
   ```json
   "StringEquals": {
     "token.actions.githubusercontent.com:sub": "repo:vibhoragarwal81/Github-Copilot:ref:refs/heads/main"
   }
   ```

2. **Add External ID** (optional):
   ```json
   "StringEquals": {
     "sts:ExternalId": "unique-external-id-12345"
   }
   ```
   
   Then set GitHub secret: `AWS_EXTERNAL_ID = unique-external-id-12345`

3. **Time-Based Restrictions** (optional):
   ```json
   "DateGreaterThan": {
     "aws:CurrentTime": "2026-01-01T00:00:00Z"
   },
   "DateLessThan": {
     "aws:CurrentTime": "2026-12-31T23:59:59Z"
   }
   ```

## 🐛 Troubleshooting

### Common OIDC Setup Issues

#### Issue 1: Role ARN Not Found
**Error**: `User: arn:aws:sts::123456789012:assumed-role/GitHubActionsRole/GitHubActions is not authorized to perform: sts:AssumeRole`

**Solution**:
- Verify `AWS_ROLE_ARN` variable is set correctly in GitHub
- Check role name spelling and account ID
- Ensure role exists and is not deleted

#### Issue 2: Repository Mismatch
**Error**: `AssumeRoleWithWebIdentity failed`

**Solution**:
- Verify repository name in trust policy exactly matches: `vibhoragarwal81/Github-Copilot`
- Check for typos in username or repository name
- Ensure you're running from the correct repository

#### Issue 3: OIDC Provider Missing
**Error**: `Invalid identity token`

**Solution**:
- Verify OIDC provider exists in AWS IAM
- Check provider URL: `https://token.actions.githubusercontent.com`
- Ensure audience is `sts.amazonaws.com`

#### Issue 4: Permission Denied During Scan
**Error**: `AccessDenied` when accessing AWS services

**Solution**:
- Verify SecurityAudit and ViewOnlyAccess policies are attached
- Check custom inline policy for cross-account access
- Ensure organization permissions are included

## 🔄 Migration from Access Keys

If you're migrating from access key authentication:

1. **Set up OIDC first** (following this guide)
2. **Test OIDC authentication** with a trial workflow run
3. **Keep access key secrets** as fallback during transition
4. **Remove access key secrets** once OIDC is confirmed working

The workflows are configured to automatically prefer OIDC when `AWS_ROLE_ARN` is provided, falling back to access keys if not.

## 📊 Verification Commands

### Verify OIDC Provider
```bash
aws iam list-open-id-connect-providers --query 'OpenIDConnectProviderList[?contains(Arn, `token.actions.githubusercontent.com`)]'
```

### Verify Role Configuration
```bash
aws iam get-role --role-name GitHubActionsCSPMRole --query 'Role.AssumeRolePolicyDocument'
```

### Test Role Assumption (from local AWS CLI)
```bash
# This won't work directly due to OIDC token requirements, 
# but can verify the role exists and permissions
aws iam list-attached-role-policies --role-name GitHubActionsCSPMRole
```

## ✅ Success Criteria

Your OIDC setup is working correctly when:

1. ✅ GitHub workflow runs without credential errors
2. ✅ AWS connectivity validation shows assumed role ARN
3. ✅ Organization discovery succeeds
4. ✅ Cross-account role assumption works for member accounts
5. ✅ CSPM scan completes with findings
6. ✅ HTML reports are generated successfully

---

---

## 🧪 Testing Your OIDC Setup

### Local Testing

Use the authentication test script to validate your setup locally:

```bash
# Test AWS authentication
python scripts/test_aws_auth.py
```

This script will:
- ✅ Detect your authentication method (OIDC vs access keys)
- ✅ Verify AWS credentials and permissions
- ✅ Test AWS Organizations access
- ✅ Check cross-account role assumption capabilities

### GitHub Actions Testing

1. **Quick Test Workflow**
   - Go to your repository's Actions tab
   - Run the "Test AWS OIDC Authentication" workflow
   - Choose "quick" mode for basic validation

2. **Detailed Test Workflow**
   - Run the same workflow with "detailed" mode
   - This will perform a full organization scan test

### Expected Test Results

**Successful OIDC Setup:**
```
🔐 AWS Authentication Test
==================================================
✅ Authentication Method: OIDC with IAM Role
   🏷️  Role ARN: arn:aws:iam::871007551509:role/GitHubActionsCSPMRole
   🎫 Token File: /tmp/aws-web-identity-token
   📝 Session Name: GitHubActions-123
🌍 Region: us-east-1

✅ AWS STS Response:
   👤 User ID: AROA...
   🏦 Account: 871007551509
   🎭 ARN: arn:aws:sts::871007551509:assumed-role/GitHubActionsCSPMRole/GitHubActions-123

✅ Organizations access confirmed:
   🏢 Organization ID: o-zfqct64bxw
   👑 Master Account: 871007551509
   🎯 Feature Set: ALL
   📊 Total Accounts: 3

✨ All tests passed! Your AWS authentication is properly configured.
```

## 📈 Additional Debug Steps

If you encounter issues, enable detailed GitHub Actions logging:

```yaml
env:
  ACTIONS_STEP_DEBUG: true
  ACTIONS_RUNNER_DEBUG: true
```

🎯 **Ready to Go!** Your GitHub workflows now use secure, short-lived credentials with no permanent secrets stored in GitHub! 🔐