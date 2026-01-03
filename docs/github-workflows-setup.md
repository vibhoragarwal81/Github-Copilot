# GitHub Workflows Setup Guide

This guide explains how to configure and use the GitHub Actions workflows for automated CSPM scanning.

## 🚀 Workflow Overview

The repository includes two GitHub Action workflows that provide automated AWS security scanning:

1. **`cspm-scan.yml`** - Main workflow with comprehensive features
2. **`cspm-scan-updated.yml`** - Alternative workflow version

## 📋 Prerequisites

### 1. GitHub Repository Setup

1. Fork or clone this repository to your GitHub account
2. Ensure the `.github/workflows/` directory contains the workflow files

### 2. AWS Authentication Configuration

Choose one of the following authentication methods:

#### Method A: OIDC with IAM Roles (Recommended - Most Secure)

This method uses short-lived credentials through AWS IAM roles and GitHub's OIDC identity provider.

**Benefits**:
- ✅ **No long-term credentials** stored in GitHub
- ✅ **Automatic credential rotation** (tokens expire in 1 hour)
- ✅ **Fine-grained permissions** per repository/branch
- ✅ **Audit trail** in AWS CloudTrail
- ✅ **No secret management** overhead

**Setup Steps**:

1. **Create GitHub OIDC Identity Provider in AWS**:
   
   Navigate to AWS IAM Console → Identity providers → Add provider:
   
   ```
   Provider type: OpenID Connect
   Provider URL: https://token.actions.githubusercontent.com
   Audience: sts.amazonaws.com
   ```

2. **Create IAM Role for GitHub Actions**:
   
   Create a new IAM role with the following trust policy:
   
   ```json
   {
     "Version": "2012-10-17",
     "Statement": [
       {
         "Effect": "Allow",
         "Principal": {
           "Federated": "arn:aws:iam::YOUR_ACCOUNT_ID:oidc-provider/token.actions.githubusercontent.com"
         },
         "Action": "sts:AssumeRole",
         "Condition": {
           "StringEquals": {
             "token.actions.githubusercontent.com:aud": "sts.amazonaws.com"
           },
           "StringLike": {
             "token.actions.githubusercontent.com:sub": "repo:YOUR_GITHUB_USERNAME/YOUR_REPO_NAME:*"
           }
         }
       }
     ]
   }
   ```
   
   **Replace**:
   - `YOUR_ACCOUNT_ID` with your AWS account ID (e.g., `872515281040`)
   - `YOUR_GITHUB_USERNAME` with your GitHub username (e.g., `vibhoragarwal81`)
   - `YOUR_REPO_NAME` with your repository name (e.g., `Github-Copilot`)

3. **Attach Required Policies to the Role**:
   
   Attach the following AWS managed policies:
   - `arn:aws:iam::aws:policy/SecurityAudit`
   - `arn:aws:iam::aws:policy/job-function/ViewOnlyAccess`
   
   For organization-wide scanning, also attach:
   - `arn:aws:iam::aws:policy/AWSOrganizationsReadOnlyAccess`
   
   **Custom inline policy for cross-account access**:
   ```json
   {
     "Version": "2012-10-17",
     "Statement": [
       {
         "Effect": "Allow",
         "Action": [
           "sts:AssumeRole"
         ],
         "Resource": "arn:aws:iam::*:role/CSPMScanRole"
       }
     ]
   }
   ```

4. **Optional: Add S3 Permissions for Report Archiving**:
   
   If you want to store reports in S3, add this inline policy:
   ```json
   {
     "Version": "2012-10-17",
     "Statement": [
       {
         "Effect": "Allow",
         "Action": [
           "s3:PutObject",
           "s3:PutObjectAcl"
         ],
         "Resource": "arn:aws:s3:::YOUR_REPORTS_BUCKET/cspm-reports/*"
       }
     ]
   }
   ```

5. **Configure GitHub Repository Variables**:
   
   Go to your repository **Settings** → **Secrets and variables** → **Actions** → **Variables**:
   
   | Variable Name | Value | Description |
   |---------------|-------|-------------|
   | `AWS_ROLE_ARN` | `arn:aws:iam::YOUR_ACCOUNT_ID:role/GitHubActionsCSPMRole` | IAM role ARN for OIDC |
   | `S3_REPORTS_BUCKET` | `your-reports-bucket` | S3 bucket name (optional) |
   | `S3_REGION` | `us-east-1` | S3 bucket region (optional) |

**Optional Secrets** (for enhanced security):
   | Secret Name | Description |
   |-------------|-------------|
   | `AWS_EXTERNAL_ID` | Additional security for role assumption |

#### Method B: Access Keys (Fallback - Less Secure)

Use this method only if OIDC setup is not possible.

**Setup Steps**:

1. Go to your repository **Settings** → **Secrets and variables** → **Actions**
2. Add the following **Repository Secrets**:

   | Secret Name | Description | Example Value |
   |-------------|-------------|---------------|
   | `AWS_ACCESS_KEY_ID` | AWS Access Key ID | `AKIAIOSFODNN7EXAMPLE` |
   | `AWS_SECRET_ACCESS_KEY` | AWS Secret Access Key | `wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY` |

**⚠️ Security Considerations**:
- Regular rotation of access keys required
- Long-term credentials stored in GitHub
- Broader permissions typically required

### 3. Optional Configuration

For enhanced features, configure these optional secrets:

| Secret Name | Description | Required |
|-------------|-------------|----------|
| `SLACK_WEBHOOK_URL` | Slack webhook for notifications | Optional |
| `TEAMS_WEBHOOK_URL` | Microsoft Teams webhook | Optional |
| `S3_ACCESS_KEY_ID` | S3 credentials for report archiving | Optional |
| `S3_SECRET_ACCESS_KEY` | S3 secret for report archiving | Optional |

For S3 archiving, also set these **Variables** (Settings → Variables → Actions):

| Variable Name | Description | Example |
|---------------|-------------|---------|
| `S3_REPORTS_BUCKET` | S3 bucket for report storage | `my-cspm-reports-bucket` |
| `S3_REGION` | S3 bucket region | `us-east-1` |

## 🔧 Workflow Configuration

### Manual Trigger (Recommended for Testing)

1. Go to your repository **Actions** tab
2. Select **AWS CSPM Security Scan** workflow
3. Click **Run workflow**
4. Configure the scan parameters:

   | Parameter | Description | Default | Options |
   |-----------|-------------|---------|---------|
   | **AWS Regions** | Comma-separated regions to scan | `us-east-1,us-west-2` | Any valid AWS regions |
   | **AWS Accounts** | Account IDs or "organization" | `organization` | Account IDs or `organization` |
   | **Services** | Services to scan | `iam,ec2,vpc,s3` | `iam,ec2,vpc,s3`, `all`, etc. |
   | **Report Formats** | Output formats | `json,html,csv` | `html`, `json,html`, etc. |
   | **Compliance Frameworks** | Frameworks to include | `CIS-AWS,NIST-CSF,PCI-DSS` | Any supported frameworks |
   | **Severity Filter** | Minimum severity level | `info` | `critical`, `high`, `medium`, `low`, `info` |

### Automated Schedule

The workflow is configured to run automatically:
- **Weekly** on Sundays at 2:00 AM UTC
- **On code changes** to scanning modules (push to main branch)

### Single Account vs Organization Scanning

#### Organization-Wide Scan (Default)
```yaml
AWS Accounts: organization
```
This scans all accounts in your AWS Organization using cross-account roles.

#### Single Account Scan
```yaml
AWS Accounts: 872515281040
```
This scans only the specified account ID.

#### Multiple Specific Accounts
```yaml
AWS Accounts: 872515281040,871007551509,968382677077
```
This scans the specified account IDs (not yet fully implemented).

## 📊 Understanding Workflow Results

### GitHub Actions UI

After workflow completion, you'll see:

1. **Workflow Summary**:
   - Scan status (✅ Success / ❌ Failed)
   - Total findings count
   - Critical and high severity findings
   - Scan duration and account coverage

2. **Step-by-Step Logs**:
   - AWS connectivity validation
   - Account discovery (for organization scans)
   - Service-by-service scan progress
   - Report generation status

3. **Artifacts**:
   - **CSPM Reports**: HTML, JSON, and CSV reports
   - **Scan Logs**: Detailed execution logs

### Downloaded Reports

The workflow generates the same reports as command-line execution:

- **HTML Report**: Interactive dashboard for executive review
- **JSON Report**: Machine-readable data for integration
- **CSV Report**: Spreadsheet format for bulk analysis

### Notifications

If configured, you'll receive notifications for:
- **Critical findings** (immediate alert)
- **High findings** above threshold (5+ findings)
- **Scan failures** or errors

## 🔍 Example Workflow Runs

### Organization-Wide Security Assessment
```yaml
Regions: us-east-1
Accounts: organization  
Services: iam,ec2,vpc,s3
Report Formats: json,html
```

**Expected Output**:
```
📊 Scan Results:
✅ Total Accounts: 3
✅ Successful Scans: 3
❌ Failed Scans: 0
🔍 Total Findings: 112

🚨 Severity Breakdown:
🔴 Critical: 11
🟠 High: 45
🟡 Medium: 33
🟢 Low: 3
ℹ️ Info: 20
```

### Compliance-Focused Scan
```yaml
Regions: us-east-1,us-west-2
Accounts: organization
Services: all
Compliance Frameworks: PCI-DSS,SOC-2
Severity Filter: high
```

### Single Account Deep Dive
```yaml
Regions: us-east-1,us-west-2,eu-west-1
Accounts: 872515281040
Services: all
Report Formats: json,html,csv
```

## 🐛 Troubleshooting

### Common Issues

#### 1. OIDC Authentication Failures
**Error**: `Unable to get OIDC token` or `AssumeRoleWithWebIdentity failed`

**Solution Steps**:

1. **Check GitHub OIDC Identity Provider**:
   ```bash
   # Verify OIDC provider exists in AWS IAM
   aws iam list-open-id-connect-providers
   ```
   Should show: `https://token.actions.githubusercontent.com`

2. **Verify IAM Role Trust Policy**:
   ```bash
   aws iam get-role --role-name GitHubActionsCSPMRole --query 'Role.AssumeRolePolicyDocument'
   ```
   Check the `sub` condition matches your repository.

3. **Repository Configuration**:
   - Verify `AWS_ROLE_ARN` variable is set correctly
   - Ensure repository name in trust policy matches exactly
   - Check if running from the correct branch

4. **Common Trust Policy Issues**:
   ```json
   // ❌ Incorrect - missing asterisk for branch matching
   "token.actions.githubusercontent.com:sub": "repo:username/repo-name"
   
   // ✅ Correct - allows all branches and pull requests  
   "token.actions.githubusercontent.com:sub": "repo:username/repo-name:*"
   
   // ✅ More restrictive - only main branch
   "token.actions.githubusercontent.com:sub": "repo:username/repo-name:ref:refs/heads/main"
   ```

5. **Debug OIDC Token**:
   Add this step to your workflow for debugging:
   ```yaml
   - name: Debug OIDC Claims
     run: |
       curl -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
         "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=sts.amazonaws.com" | \
         jq '.value' | cut -d. -f2 | base64 -d | jq
   ```

#### 2. AWS Access Key Authentication Issues
**Error**: `AccessDenied` or `Invalid credentials`

**Solution**: 
- Verify `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` secrets
- Ensure the IAM user has required permissions (SecurityAudit, ViewOnlyAccess)
- Check if access keys are expired or deactivated

#### 3. Role Permission Issues
**Error**: `AccessDenied` when scanning specific services

**Solution**:
- Ensure the IAM role has `SecurityAudit` and `ViewOnlyAccess` policies
- For organization scans, add `AWSOrganizationsReadOnlyAccess`
- Verify cross-account role permissions for member account scanning

#### 4. Organization Access Denied
**Error**: `Organizations access denied`

**Solution**:
- Ensure you're using management account credentials/role
- Verify organization has "All features" enabled
- Check cross-account roles are deployed (`CSPMScanRole`)

#### 5. No Findings in Reports
**Issue**: Scan completes but shows 0 findings

**Solution**:
- Check if services are actually present in the scanned regions
- Verify the severity filter isn't too restrictive
- Review scan logs for service-specific errors

#### 4. Workflow Timeouts
**Error**: Workflow exceeds 60-minute timeout
**Solution**:
- Reduce the number of regions scanned
- Scan fewer accounts in a single run
- Use service-specific scans instead of `all`

### Debug Mode

Enable verbose logging by setting the workflow input:
```yaml
Verbose: true
```

This provides detailed step-by-step execution logs for troubleshooting.

## 🔄 Migration from Command Line

If you're currently using command-line scripts, workflows provide these additional benefits:

| Feature | Command Line | GitHub Workflow |
|---------|--------------|-----------------|
| **Execution** | Manual local run | Automated scheduling |
| **Credentials** | Local AWS config | Secure GitHub Secrets |
| **Reports** | Local files only | Artifacts + S3 archiving |
| **Notifications** | Manual review | Slack/Teams integration |
| **Audit Trail** | Local logs | GitHub Actions history |
| **Team Collaboration** | Individual access | Shared team visibility |

## 📈 Best Practices

### Regular Scanning
- Run weekly organization-wide scans
- Daily scans for critical environments
- Ad-hoc scans after infrastructure changes

### Report Management
- Configure S3 archiving for long-term storage
- Set appropriate artifact retention (default: 30 days)
- Use severity filtering for focused alerts

### Security
- Use IAM roles with minimal necessary permissions
- Regularly rotate AWS access keys
- Monitor workflow execution logs for anomalies

### Team Workflow
- Use branch protection for workflow changes
- Review and approve workflow modifications
- Document custom configurations and exceptions

---

🎯 **Ready to Start?** Configure your AWS credentials in repository secrets and run your first workflow! 🚀