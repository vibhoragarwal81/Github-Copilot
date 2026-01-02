# Single Account CSPM Scanning Guide

This guide provides detailed instructions for running AWS CSPM security scans on a single AWS account.

## 📋 Overview

Single account scanning is ideal for:
- **Initial Testing**: Testing the scanner before deploying across your organization
- **Standalone Accounts**: Accounts not part of an AWS Organization
- **Targeted Analysis**: Deep-dive security analysis of specific accounts
- **Development/Staging**: Testing environments with isolated security requirements

## 🔧 Prerequisites

### AWS Permissions Required

The user/role running the scan must have the following permissions:

1. **AWS Managed Policies** (Recommended):
   - `arn:aws:iam::aws:policy/SecurityAudit`
   - `arn:aws:iam::aws:policy/job-function/ViewOnlyAccess`

2. **Additional Permissions** (if not using managed policies):
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
                   "ec2:Describe*",
                   "ec2:GetEbsEncryptionByDefault",
                   "s3:ListAllMyBuckets",
                   "s3:GetBucketLocation",
                   "s3:GetBucketAcl",
                   "s3:GetBucketPolicy",
                   "s3:GetBucketVersioning",
                   "s3:GetBucketEncryption",
                   "s3:GetBucketLogging",
                   "s3:GetBucketPublicAccessBlock",
                   "s3:GetAccountPublicAccessBlock"
               ],
               "Resource": "*"
           }
       ]
   }
   ```

### Python Environment

- Python 3.8 or higher
- pip package manager
- Virtual environment (recommended)

## 🚀 Setup Instructions

### 1. Environment Setup

```bash
# Clone the repository
git clone <repository-url>
cd aws-cspm-scanner

# Create virtual environment
python -m venv .venv

# Activate virtual environment
# On Windows:
.venv\Scripts\activate
# On macOS/Linux:
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 2. AWS Configuration

Choose one of the following methods:

#### Method A: AWS CLI Configuration
```bash
aws configure
# Enter your AWS Access Key ID, Secret Access Key, and region
```

#### Method B: Environment Variables
```bash
export AWS_ACCESS_KEY_ID=your_access_key_id
export AWS_SECRET_ACCESS_KEY=your_secret_access_key
export AWS_DEFAULT_REGION=us-east-1
```

#### Method C: IAM Role (EC2/Lambda)
If running on EC2 or Lambda, ensure the instance/function role has the required permissions.

### 3. Configuration File Setup

Edit `config/config.yaml` to customize the scan:

```yaml
# AWS Configuration
aws:
  default_region: us-east-1
  regions:
    - us-east-1
    - us-west-2
    # Add more regions as needed

# Service Scanning Configuration
scanning:
  services:
    iam: true      # IAM security analysis
    ec2: true      # EC2 security analysis
    s3: true       # S3 security analysis
    vpc: true      # VPC security analysis
    
  behavior:
    max_concurrent_regions: 3
    timeout: 3600
    retry_attempts: 3
```

## 🔍 Running the Scan

### Basic Scan

Run a basic security scan with default settings:

```bash
python scripts/run_cspm_scan.py
```

### Advanced Options

The scanner automatically:
- Detects the current AWS account
- Scans configured services across specified regions
- Applies security rules and compliance checks
- Generates comprehensive reports

## 📊 Understanding the Results

### Console Output

During the scan, you'll see progress indicators:

```
🏠 AWS Single Account CSPM Scanner
🕒 2024-01-02 15:30:45
📋 Account: 123456789012
👤 User: arn:aws:iam::123456789012:user/security-scanner

🔍 Running security scans...
  📊 Scanning IAM...
     Found 25 IAM findings
  📊 Scanning EC2...
     Found 8 EC2 findings
  📊 Scanning S3...
     Found 3 S3 findings
  📊 Scanning VPC...
     Found 12 VPC findings

📝 Generating HTML report...
✅ Single account scan completed!
```

### Generated Reports

The scanner generates reports in the `reports/` directory:

1. **HTML Report**: `cspm_report_YYYYMMDD_HHMMSS.html`
   - Interactive dashboard with charts and filters
   - Detailed findings with remediation steps
   - Executive summary for management

2. **JSON Report**: `cspm_report_YYYYMMDD_HHMMSS.json`
   - Machine-readable structured data
   - API integration friendly
   - Programmatic analysis support

3. **CSV Report**: `cspm_report_YYYYMMDD_HHMMSS.csv`
   - Spreadsheet-compatible format
   - Bulk analysis and filtering
   - Custom reporting workflows

### Report Structure

The HTML report includes:

- **Executive Dashboard**: High-level security metrics
- **Findings by Severity**: Critical, High, Medium, Low breakdown
- **Service Analysis**: Per-service security findings
- **Compliance Mapping**: CIS, NIST, PCI-DSS framework alignment
- **Remediation Guidance**: Step-by-step fix instructions

## 🔧 Customization

### Selecting Specific Services

To scan only specific services, modify `config/config.yaml`:

```yaml
scanning:
  services:
    iam: true      # Enable IAM scanning
    ec2: false     # Disable EC2 scanning
    s3: true       # Enable S3 scanning
    vpc: false     # Disable VPC scanning
```

### Regional Scope

Configure which regions to scan:

```yaml
aws:
  regions:
    - us-east-1    # Primary region
    - us-west-2    # Secondary region
    # Add more as needed
```

### Severity Filtering

Set minimum severity threshold:

```yaml
rules:
  severity_threshold: MEDIUM  # Only report MEDIUM and above
```

## 🐛 Troubleshooting

### Common Issues

#### Permission Denied Errors
```
Error: Access Denied when calling IAM:ListUsers
```
**Solution**: Ensure your AWS credentials have the required IAM permissions.

#### Region Access Issues
```
Error: UnauthorizedOperation in region eu-central-1
```
**Solution**: Remove unsupported regions from configuration or verify regional permissions.

#### No Findings Generated
```
Warning: 0 findings generated
```
**Solutions**:
- Verify AWS credentials are working: `aws sts get-caller-identity`
- Check service enablement in configuration
- Ensure account has resources to scan

#### Connection Timeouts
```
Error: Connection timeout
```
**Solutions**:
- Check internet connectivity
- Verify AWS endpoint accessibility
- Increase timeout in configuration

### Debug Mode

Run with additional logging:

```bash
# Set debug environment variable
export CSPM_LOG_LEVEL=DEBUG
python scripts/run_cspm_scan.py
```

### Validation Commands

Verify setup before scanning:

```bash
# Test AWS connectivity
aws sts get-caller-identity

# Test IAM permissions
aws iam get-account-summary

# Test EC2 access
aws ec2 describe-regions
```

## 🔄 Scheduling Regular Scans

### Using Cron (Linux/macOS)

```bash
# Edit crontab
crontab -e

# Add daily scan at 2 AM
0 2 * * * cd /path/to/aws-cspm-scanner && python scripts/run_cspm_scan.py
```

### Using Windows Task Scheduler

1. Open Task Scheduler
2. Create Basic Task
3. Set trigger (daily/weekly)
4. Set action to run Python script
5. Configure to run whether user is logged on or not

### Using AWS Lambda

Deploy the scanner as a Lambda function for serverless scanning:

1. Package the scanner code
2. Create Lambda function with appropriate IAM role
3. Set up CloudWatch Events trigger for scheduling
4. Configure output to S3 for report storage

## 📈 Best Practices

1. **Regular Scanning**: Run scans weekly or after major changes
2. **Baseline Establishment**: Document initial findings for comparison
3. **Alert Integration**: Set up notifications for critical findings
4. **Remediation Tracking**: Use reports to track security improvements
5. **Access Control**: Limit scanner permissions to read-only operations
6. **Report Security**: Protect generated reports as they contain sensitive information

## 🔗 Next Steps

- **Organization Scanning**: Upgrade to [multi-account scanning](organization-scan.md)
- **Custom Rules**: Develop organization-specific security rules
- **CI/CD Integration**: Integrate scanning into deployment pipelines
- **Automated Remediation**: Build automated responses to findings

---

Need help? Check our [troubleshooting guide](setup-for-different-org.md) or open an issue.