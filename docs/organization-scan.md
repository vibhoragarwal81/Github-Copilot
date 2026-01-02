# Organization-Wide CSPM Scanning Guide

This guide provides comprehensive instructions for deploying and running AWS CSPM security scans across your entire AWS Organization.

## 📋 Overview

Organization-wide scanning provides:
- **Complete Visibility**: Security posture across all AWS accounts
- **Centralized Management**: Single pane of glass for security findings
- **Compliance Reporting**: Organization-wide compliance framework mapping
- **Scalable Operations**: Parallel scanning across hundreds of accounts
- **Executive Dashboards**: Consolidated security metrics for leadership

## 🏗️ Architecture Overview

```
Master Account (Organization Management)
├── CSPM Scanner
├── Organization Scanner
├── Cross-Account Role Management
└── Consolidated Reporting

Member Account 1, 2, ..., N
├── CSPMScanRole (deployed via CloudFormation)
├── SecurityAudit permissions
├── ViewOnlyAccess permissions
└── Additional scanning permissions
```

## 🔧 Prerequisites

### AWS Organization Setup

1. **AWS Organizations Enabled**: Your AWS account must be the organization's management account
2. **All Features Enabled**: The organization must have "All features" enabled (not just consolidated billing)
3. **Member Accounts**: Active member accounts to scan
4. **Management Account Permissions**: Appropriate permissions in the management account

### Required Permissions

The management account user/role needs:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "organizations:ListAccounts",
                "organizations:DescribeOrganization",
                "organizations:ListDelegatedAdministrators",
                "sts:AssumeRole",
                "cloudformation:CreateStack",
                "cloudformation:UpdateStack",
                "cloudformation:DescribeStacks",
                "cloudformation:DescribeStackEvents",
                "iam:CreateRole",
                "iam:AttachRolePolicy",
                "iam:PassRole"
            ],
            "Resource": "*"
        },
        {
            "Effect": "Allow",
            "Action": [
                "sts:AssumeRole"
            ],
            "Resource": "arn:aws:iam::*:role/OrganizationAccountAccessRole"
        },
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

### Python Environment

- Python 3.8 or higher
- pip package manager
- Virtual environment (recommended)

## 🚀 Setup Instructions

### 1. Initial Setup

```bash
# Clone the repository
git clone <repository-url>
cd aws-cspm-scanner

# Create and activate virtual environment
python -m venv .venv
# Windows:
.venv\Scripts\activate
# macOS/Linux:
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 2. AWS Configuration

Configure AWS credentials for the management account:

```bash
# Option 1: AWS CLI
aws configure
# Enter management account credentials

# Option 2: Environment variables
export AWS_ACCESS_KEY_ID=your_management_account_key
export AWS_SECRET_ACCESS_KEY=your_management_account_secret
export AWS_DEFAULT_REGION=us-east-1
```

### 3. Verify Organization Access

```bash
# Test organization access
aws organizations describe-organization
aws organizations list-accounts
```

Expected output:
```json
{
    "Organization": {
        "Id": "o-123456789",
        "Arn": "arn:aws:organizations::123456789012:organization/o-123456789",
        "FeatureSet": "ALL",
        "MasterAccountId": "123456789012"
    }
}
```

## 🔐 Cross-Account Role Deployment

### Automated Deployment (Recommended)

Use the automated deployment script to deploy `CSPMScanRole` to all member accounts:

```bash
# Deploy to all member accounts
python scripts/deploy_via_organization_role.py --accounts all

# Deploy to specific accounts
python scripts/deploy_via_organization_role.py --accounts 111111111111,222222222222
```

The script will:
1. ✅ Discover all active member accounts
2. ✅ Assume `OrganizationAccountAccessRole` in each account
3. ✅ Deploy CloudFormation stack with `CSPMScanRole`
4. ✅ Verify role creation and permissions
5. ✅ Test role assumption from management account

### Manual Deployment (Alternative)

If automated deployment fails, use manual deployment:

```bash
# Generate deployment instructions
python scripts/manual_deploy_guide.py --show-instructions
```

This will provide step-by-step instructions for manually deploying the CloudFormation template to each member account.

### Deployment Verification

```bash
# Verify all deployments
python scripts/deploy_member_account_roles.py --test-all

# Validate specific accounts
python scripts/manual_deploy_guide.py --validate-deployment
```

## 🔍 Running Organization-Wide Scans

### Basic Organization Scan

```bash
python scripts/run_organization_scan.py
```

### Configuration Customization

Edit `config/config.yaml` for organization-specific settings:

```yaml
# AWS Configuration
aws:
  default_region: us-east-1
  regions:
    - us-east-1
    - us-west-2
    - eu-west-1
  organization_role_name: CSPMScanRole
  external_id: cspm-security-scan
  session_duration: 43200  # 12 hours

# Service Scanning Configuration
scanning:
  services:
    iam: true
    ec2: true
    s3: true
    vpc: true
    
  behavior:
    max_concurrent_accounts: 5  # Parallel account scanning
    max_concurrent_regions: 3   # Parallel region scanning
    timeout: 3600              # 1 hour timeout
    retry_attempts: 3          # Retry failed scans

# Security Rules Configuration
rules:
  severity_threshold: LOW      # Report all findings
  
  categories:
    encryption: true
    access_control: true
    network_security: true
    compliance: true
```

## 📊 Understanding Organization Scan Results

### Console Output

```
🏢 Starting AWS Organization-Wide CSPM Security Scan
======================================================================
🔍 Testing AWS Organizations access...
✅ Organization ID: o-123456789
✅ Master Account: 123456789012
✅ Organization ARN: arn:aws:organizations::123456789012:organization/o-123456789

🏢 Discovering AWS accounts in organization...
✅ Discovered 15 accounts in organization
   1. Production (111111111111) - ACTIVE
   2. Staging (222222222222) - ACTIVE
   3. Development (333333333333) - ACTIVE
   ...

🔍 Starting security scan across 15 accounts...
📊 [1/15] Scanning Production (111111111111)...
   ✅ Found 45 findings
📊 [2/15] Scanning Staging (222222222222)...
   ✅ Found 23 findings
...

======================================================================
🏢 ORGANIZATION-WIDE SECURITY ASSESSMENT COMPLETE
======================================================================

📊 Scan Summary:
   Total Accounts: 15
   Successful Scans: 15
   Failed Scans: 0
   Total Security Findings: 387

🚨 Severity Breakdown:
   🔴 CRITICAL: 12
   🟠 HIGH: 89
   🟡 MEDIUM: 156
   🟢 LOW: 87
   🔵 INFO: 43
```

### Generated Reports

Organization scans generate enhanced reports:

1. **Organization HTML Report**: `reports/cspm_report_YYYYMMDD_HHMMSS.html`
   - Executive dashboard with organization-wide metrics
   - Account-by-account breakdown
   - Cross-account security trends
   - Compliance summary across all frameworks

2. **Consolidated JSON**: Machine-readable organization data
3. **CSV Export**: Spreadsheet format for bulk analysis

### Report Features

- **Account Filtering**: Filter findings by specific accounts
- **Service Analysis**: Cross-account service security comparison
- **Compliance Mapping**: Organization-wide compliance posture
- **Trend Analysis**: Historical security posture tracking
- **Risk Prioritization**: Critical findings across all accounts

## 🔧 Advanced Configuration

### Account Scope Management

```yaml
# Scan specific account types
scanning:
  account_filters:
    include_suspended: false
    include_master: true
    account_tags:
      Environment: [Production, Staging]
      BusinessUnit: [Engineering, Security]
```

### Service-Specific Configuration

```yaml
# Fine-tune service scanning
scanning:
  services:
    iam:
      enabled: true
      check_mfa: true
      check_password_policy: true
      analyze_unused_users: true
      
    ec2:
      enabled: true
      check_security_groups: true
      check_public_instances: true
      analyze_snapshots: true
      
    s3:
      enabled: true
      check_public_buckets: true
      analyze_encryption: true
      check_versioning: true
```

### Performance Optimization

```yaml
scanning:
  behavior:
    max_concurrent_accounts: 10  # Increase for more parallelism
    max_concurrent_regions: 5    # Balance with API rate limits
    region_priority:             # Scan priority regions first
      - us-east-1
      - us-west-2
      - eu-west-1
```

## 🐛 Troubleshooting

### Common Issues

#### Organization Access Denied
```
Error: AccessDeniedException when calling Organizations:ListAccounts
```
**Solutions**:
- Verify you're using management account credentials
- Check organization permissions
- Ensure organization has "All features" enabled

#### Cross-Account Role Assumption Failed
```
Error: Access denied when assuming role in account 111111111111
```
**Solutions**:
- Verify `CSPMScanRole` is deployed in member account
- Check trust relationship in the role
- Validate external ID configuration

#### Partial Account Failures
```
Warning: 3 accounts failed to scan
```
**Solutions**:
- Check individual account status (ACTIVE vs SUSPENDED)
- Verify role deployment in failed accounts
- Review account-specific permission issues

### Debug Mode

Enable detailed logging:

```bash
export CSPM_LOG_LEVEL=DEBUG
python scripts/run_organization_scan.py
```

### Account-Specific Testing

Test individual accounts:

```bash
# Test specific account role assumption
python scripts/deploy_member_account_roles.py --test-account 111111111111

# Validate specific account deployment
python scripts/manual_deploy_guide.py --validate-deployment
```

## 🔄 Operational Best Practices

### Scheduling Organization Scans

#### Using AWS Lambda (Recommended)
```python
# Deploy as Lambda function
# Configure CloudWatch Events for scheduling
# Store reports in S3 with lifecycle policies
```

#### Using EC2/Container
```bash
# Weekly scan via cron
0 2 * * 1 cd /opt/aws-cspm-scanner && python scripts/run_organization_scan.py
```

### Report Management

```yaml
# Configure report retention
reporting:
  retention_days: 90
  archive_location: s3://security-reports-bucket
  notification:
    slack_webhook: https://hooks.slack.com/...
    email_recipients:
      - security-team@company.com
```

### Performance Monitoring

- **Scan Duration**: Monitor total scan time trends
- **Account Coverage**: Track successful vs failed scans
- **Finding Trends**: Monitor security posture improvements
- **Resource Usage**: Monitor API call consumption

## 🚨 Alerting and Integration

### Critical Finding Alerts

```yaml
alerting:
  critical_threshold: 5      # Alert if >5 critical findings
  high_threshold: 20         # Alert if >20 high findings
  channels:
    - slack
    - email
    - sns
```

### SIEM Integration

Export findings to security tools:

```bash
# Export to Splunk
python scripts/export_to_splunk.py --report latest

# Export to Elasticsearch
python scripts/export_to_elasticsearch.py --report latest
```

### Ticket Creation

Automatically create remediation tickets:

```python
# Integrate with Jira/ServiceNow
python scripts/create_remediation_tickets.py --severity critical,high
```

## 📈 Compliance Reporting

### Framework Support

- **CIS AWS Benchmarks**: Comprehensive CIS control mapping
- **NIST Cybersecurity Framework**: Core security function alignment
- **PCI-DSS**: Payment card security requirements
- **SOC 2**: Trust services criteria mapping

### Compliance Dashboard

The organization report includes:
- Compliance score by framework
- Control-specific findings
- Remediation priorities
- Historical compliance trends

## 🔗 Next Steps

1. **Regular Scanning**: Establish weekly organization scans
2. **Remediation Workflows**: Create processes for finding resolution
3. **Custom Rules**: Develop organization-specific security rules
4. **Integration**: Connect with existing security tools
5. **Training**: Educate teams on using security findings

---

For additional help, see [setup for different organizations](setup-for-different-org.md) or contact support.