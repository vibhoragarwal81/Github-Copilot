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
```

#### 1.1 Verify Project Directory Structure

Before proceeding, verify your project directory structure looks like this:

```
aws-cspm-scanner/
├── README.md
├── requirements.txt
├── config/
│   ├── config.yaml
│   └── config_detailed.yaml
├── docs/
│   ├── single-account-scan.md
│   ├── organization-scan.md
│   └── setup-for-different-org.md
├── scripts/
│   ├── run_cspm_scan.py
│   ├── run_organization_scan.py
│   └── deploy_via_organization_role.py
├── src/
│   ├── __init__.py
│   ├── main.py
│   ├── utils/
│   │   ├── __init__.py
│   │   ├── aws_client.py
│   │   ├── config.py
│   │   └── logger.py
│   ├── scanners/
│   │   ├── __init__.py
│   │   ├── iam_scanner.py
│   │   ├── ec2_scanner.py
│   │   ├── s3_scanner.py
│   │   └── vpc_scanner.py
│   ├── rules/
│   │   ├── __init__.py
│   │   └── rules_engine.py
│   └── reports/
│       ├── __init__.py
│       └── report_generator.py
├── templates/
│   └── cspm-cross-account-role.yaml
└── reports/
```

**If any directories or files are missing**, create them or verify you're in the correct project directory.

#### 1.2 Python Virtual Environment Setup

```bash
# Create virtual environment
python -m venv .venv

# Activate virtual environment
# Windows PowerShell:
.venv\Scripts\Activate.ps1
# Windows Command Prompt:
.venv\Scripts\activate.bat
# macOS/Linux:
source .venv/bin/activate
```

#### 1.3 Install Required Python Packages

Install all required dependencies including the missing modules:

```bash
# Core AWS and data processing packages
pip install boto3 botocore

# Configuration and data handling
pip install pyyaml

# Report generation
pip install jinja2

# Optional: Install all from requirements.txt (if available)
pip install -r requirements.txt
```

**Required Package List**:
- `boto3` - AWS SDK for Python
- `botocore` - Low-level AWS SDK core
- `pyyaml` - YAML configuration file parsing
- `jinja2` - HTML report template engine

#### 1.4 Verify Python Environment

After activation, verify your environment is working:

```bash
# Check Python version (should be 3.8+)
python --version

# Verify virtual environment is active (should show .venv path)
which python    # macOS/Linux
where python    # Windows

# Test package imports
python -c "import boto3, yaml, jinja2; print('All required packages installed successfully')"
```

### 2. AWS Configuration and Verification

Choose one of the following methods to configure AWS credentials:

#### Method A: AWS CLI Configuration (Recommended)
```bash
# Install AWS CLI if not already installed
pip install awscli

# Configure AWS credentials
aws configure
# Enter your AWS Access Key ID, Secret Access Key, and region (e.g., us-east-1)
```

#### Method B: Environment Variables
```bash
# Windows PowerShell:
$env:AWS_ACCESS_KEY_ID = "your_access_key_id"
$env:AWS_SECRET_ACCESS_KEY = "your_secret_access_key"
$env:AWS_DEFAULT_REGION = "us-east-1"

# Windows Command Prompt:
set AWS_ACCESS_KEY_ID=your_access_key_id
set AWS_SECRET_ACCESS_KEY=your_secret_access_key
set AWS_DEFAULT_REGION=us-east-1

# macOS/Linux:
export AWS_ACCESS_KEY_ID=your_access_key_id
export AWS_SECRET_ACCESS_KEY=your_secret_access_key
export AWS_DEFAULT_REGION=us-east-1
```

#### Method C: IAM Role (EC2/Lambda)
If running on EC2 or Lambda, ensure the instance/function role has the required permissions.

#### 2.1 Verify AWS Credentials and Connectivity

**IMPORTANT**: After configuring AWS credentials and activating your virtual environment, verify everything is working:

```bash
# Test AWS CLI connectivity
aws sts get-caller-identity

# Expected output:
# {
#     "UserId": "AIDAXXXXXXXXXXXXXXXXX",
#     "Account": "123456789012",
#     "Arn": "arn:aws:iam::123456789012:user/your-username"
# }
```

If the above command fails, check these common issues:

**Issue 1: Invalid Profile Error**
```bash
# Error: The config profile (some_profile_name) could not be found

# Solution: Clear any existing AWS_PROFILE environment variable
# Windows PowerShell:
$env:AWS_PROFILE = $null

# Windows Command Prompt:
set AWS_PROFILE=

# macOS/Linux:
unset AWS_PROFILE

# Then retry: aws sts get-caller-identity
```

**Issue 2: No Credentials Error**
```bash
# Error: Unable to locate credentials

# Solution: Verify AWS configuration
aws configure list

# If no credentials are shown, reconfigure:
aws configure
```

**Issue 3: Access Denied Error**
```bash
# Error: AccessDenied when calling GetCallerIdentity

# Solution: Verify your AWS user has the required permissions listed in Prerequisites section
```

#### 2.2 Test Python AWS SDK Access

Verify boto3 can access AWS:

```bash
# Test boto3 connectivity
python -c "
import boto3
try:
    sts = boto3.client('sts')
    identity = sts.get_caller_identity()
    print(f'✅ AWS Access Verified')
    print(f'Account ID: {identity[\"Account\"]}')
    print(f'User/Role: {identity[\"Arn\"]}')
except Exception as e:
    print(f'❌ AWS Access Failed: {e}')
"
```

**Expected Output**:
```
✅ AWS Access Verified
Account ID: 123456789012
User/Role: arn:aws:iam::123456789012:user/your-username
```

#### 2.3 Verify Required AWS Permissions

Test key permissions needed for scanning:

```bash
# Test IAM permissions
aws iam get-account-summary

# Test EC2 permissions  
aws ec2 describe-regions --region us-east-1

# Test S3 permissions
aws s3api list-buckets

# If any command fails with AccessDenied, review the Prerequisites section for required permissions
```

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

### Pre-Flight Checklist

Before running the scan, ensure all prerequisites are met:

#### 1. Verify Working Directory

**CRITICAL**: Always run the scanner from the project root directory. Verify you're in the correct location:

```bash
# Check current directory
pwd                    # macOS/Linux
Get-Location          # Windows PowerShell

# You should see the project root path like:
# /path/to/aws-cspm-scanner or C:\path\to\aws-cspm-scanner

# Verify required files exist
ls scripts/run_cspm_scan.py    # macOS/Linux  
dir scripts\run_cspm_scan.py   # Windows

# Verify src directory structure
ls src/                        # macOS/Linux
dir src\                      # Windows
```

#### 2. Activate Virtual Environment (If Not Already Active)

```bash
# Windows PowerShell:
.venv\Scripts\Activate.ps1

# Windows Command Prompt:
.venv\Scripts\activate.bat

# macOS/Linux:
source .venv/bin/activate

# Verify activation (prompt should show (.venv))
```

#### 3. Final AWS Connectivity Test

```bash
# Clear any problematic environment variables
# Windows PowerShell:
$env:AWS_PROFILE = $null

# Quick connectivity test
aws sts get-caller-identity
```

### Running the Scanner

#### Method 1: Standard Python Execution

```bash
# From project root directory with virtual environment activated
python scripts/run_cspm_scan.py
```

#### Method 2: Using Virtual Environment Python Directly

If you encounter import path issues, use the virtual environment Python directly:

```bash
# Windows:
.venv\Scripts\python.exe scripts/run_cspm_scan.py

# macOS/Linux:
.venv/bin/python scripts/run_cspm_scan.py
```

#### Method 3: PowerShell with Environment Reset (Windows)

For Windows users experiencing AWS profile issues:

```powershell
# Clear AWS profile and run scan in one command
$env:AWS_PROFILE = $null; .venv\Scripts\python.exe scripts/run_cspm_scan.py
```

### Troubleshooting Common Issues

#### Issue 1: ModuleNotFoundError: No module named 'src'

**Symptom**:
```
ModuleNotFoundError: No module named 'src'
```

**Solutions**:
1. **Verify working directory**: Ensure you're in the project root (not in scripts/ subdirectory)
2. **Check path resolution**: The script automatically adjusts paths, but verify your directory structure matches the expected layout
3. **Use absolute Python path**: Try Method 2 above with direct virtual environment Python

**Debug Commands**:
```bash
# Check current directory contains expected files
ls -la                     # macOS/Linux
dir                       # Windows

# Verify Python path resolution
python -c "import sys; print(sys.path)"
```

#### Issue 2: ModuleNotFoundError: No module named 'boto3'

**Symptom**:
```
ModuleNotFoundError: No module named 'boto3'
```

**Solutions**:
1. **Verify virtual environment**: Ensure you've activated the virtual environment
2. **Reinstall packages**: 
```bash
pip install boto3 botocore pyyaml jinja2
```
3. **Check package installation**:
```bash
pip list | grep boto3
python -c "import boto3; print('boto3 installed successfully')"
```

#### Issue 3: AWS Profile/Credential Errors

**Symptom**:
```
The config profile (some_profile_name) could not be found
```

**Solutions**:
```bash
# Windows PowerShell:
$env:AWS_PROFILE = $null

# Windows Command Prompt:
set AWS_PROFILE=

# macOS/Linux:
unset AWS_PROFILE

# Verify default profile exists
aws configure list-profiles
```

#### Issue 4: Permission Denied Errors

**Symptom**:
```
AccessDenied when calling ListUsers/DescribeInstances/etc.
```

**Solutions**:
1. **Verify permissions**: Ensure your AWS user has SecurityAudit and ViewOnlyAccess policies
2. **Test specific permissions**:
```bash
aws iam get-account-summary
aws ec2 describe-regions --region us-east-1
```

### Expected Scan Output

When successful, you should see output like:

```
🚀 Starting CSPM Security Scan...
📋 Scanning Account: 123456789012
👤 User: arn:aws:iam::123456789012:user/your-username

🔍 Running security scans...
  📊 Scanning IAM...
     Found 25 IAM findings
  📊 Scanning EC2...
     Found 8 EC2 findings
  📊 Scanning S3...
     Found 3 S3 findings
  📊 Scanning VPC...
     Found 12 VPC findings

📈 Total findings: 48
🔧 Applying security rules...

📊 Security Findings Summary:
  CRITICAL: 2
  HIGH: 8
  MEDIUM: 20
  LOW: 18

📝 Generating HTML report...
📄 HTML Report generated: reports\cspm_report_20240102_153045.html
🌐 Open in browser: file:///path/to/reports/csmp_report_20240102_153045.html

✅ CSPM scan completed successfully!
🎉 Your AWS environment security assessment is ready!
```

### Advanced Execution Options

#### Scan Specific Regions
```bash
# Edit config/config.yaml before running
python scripts/run_cspm_scan.py
```

#### Debug Mode
```bash
# Enable verbose logging for troubleshooting
CSPM_LOG_LEVEL=DEBUG python scripts/run_csmp_scan.py
```

#### Batch Execution Script

Create `run_scan.bat` (Windows) for repeated use:

```batch
@echo off
cd /d "C:\path\to\aws-cspm-scanner"
call .venv\Scripts\activate.bat
set AWS_PROFILE=
.venv\Scripts\python.exe scripts/run_cspm_scan.py
pause
```

Create `run_scan.sh` (macOS/Linux):

```bash
#!/bin/bash
cd /path/to/aws-cspm-scanner
source .venv/bin/activate
unset AWS_PROFILE
python scripts/run_cspm_scan.py
```

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