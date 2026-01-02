# AWS CSPM Production Validation Guide

## 🚀 Complete Step-by-Step Instructions for Real AWS Environment Testing

---

## 📋 **PART 1: Pre-requisites Setup**

### 1.1 AWS Account Requirements
```bash
# Ensure you have:
- AWS CLI installed and configured
- Appropriate IAM permissions for the services to scan
- Access to target AWS accounts (single or multi-account setup)
```

### 1.2 Verify Local Installation
```powershell
# Navigate to your project directory
Set-Location "C:\Users\vagarw35\Documents\Technical documents\Technologies\Github\Github Copilot"

# Activate virtual environment
.\.venv\Scripts\Activate.ps1

# Verify all components work
python -c "
from src.main import CSPMScanner
from src.utils.config import Config
from src.rules.rules_engine import RulesEngine
from src.reports.report_generator import ReportGenerator
print('✅ All components validated successfully')
"
```

---

## 🔧 **PART 2: Configuration for Real AWS Environment**

### 2.1 Create Production Configuration
```powershell
# Create a production config file
New-Item -ItemType File -Path "config/production.yaml" -Force
```

Add this content to `config/production.yaml`:
```yaml
# Production AWS CSPM Configuration
aws:
  # Target regions to scan
  regions:
    - "us-east-1"
    - "us-west-2"
    - "eu-west-1"
  
  # AWS accounts to scan (add your real account IDs)
  accounts:
    - "123456789012"  # Replace with your AWS account ID
    - "123456789013"  # Add additional accounts if needed
  
  # IAM role for cross-account access (if using Organization setup)
  role_name: "CSPMScannerRole"
  
  # External ID for additional security (optional)
  external_id: "your-unique-external-id"

# Services to scan
scanning:
  services:
    - "iam"
    - "ec2" 
    - "vpc"
    - "s3"
    - "organization"
  
  # Concurrent processing limits
  max_concurrent_accounts: 3
  max_concurrent_regions: 2
  
  # Timeout settings (seconds)
  timeout: 600

# Output configuration
output:
  directory: "reports"
  formats:
    - "json"
    - "html"
    - "csv"

# Security rules configuration
rules:
  enabled: true
  frameworks:
    - "CIS-AWS-v1.5.0"
    - "NIST-CSF"
    - "PCI-DSS-v4.0"
    - "SOC2"

# Logging configuration
logging:
  level: "INFO"
  file: "logs/cspm-scan.log"
```

### 2.2 Set Up AWS Credentials
```powershell
# Option 1: Use AWS CLI profiles
aws configure --profile cspm-scanner
# Enter your Access Key ID, Secret Access Key, and default region

# Option 2: Use environment variables
$env:AWS_ACCESS_KEY_ID = "your-access-key"
$env:AWS_SECRET_ACCESS_KEY = "your-secret-key"
$env:AWS_DEFAULT_REGION = "us-east-1"

# Option 3: Use IAM roles (recommended for production)
# Ensure your EC2 instance or environment has appropriate IAM role attached
```

### 2.3 Create Required AWS IAM Permissions
Create an IAM policy with these permissions:
```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "iam:List*",
                "iam:Get*",
                "ec2:Describe*",
                "s3:List*",
                "s3:Get*",
                "vpc:Describe*",
                "organizations:List*",
                "organizations:Describe*",
                "sts:AssumeRole"
            ],
            "Resource": "*"
        }
    ]
}
```

---

## 🧪 **PART 3: Local Testing and Validation**

### 3.1 Run Unit Tests
```powershell
# Run comprehensive test suite
python run_tests.py --all --verbose --coverage

# Run specific test categories
python run_tests.py --unit --verbose
python run_tests.py --integration --verbose
python run_tests.py --performance --verbose
```

### 3.2 Test Individual Components
```powershell
# Test configuration loading
python -c "
from src.utils.config import Config
config = Config.from_file('config/production.yaml')
print('Config loaded successfully')
print(f'Regions: {config.get(\"aws.regions\")}')
print(f'Services: {config.get(\"scanning.services\")}')
"

# Test AWS connectivity
python -c "
from src.utils.aws_client import AWSClientManager
from src.utils.config import Config
config = Config.from_file('config/production.yaml')
client_manager = AWSClientManager(config)
client = client_manager.get_client('sts', 'us-east-1')
identity = client.get_caller_identity()
print(f'✅ AWS Connection successful: {identity}')
"
```

### 3.3 Test Single Service Scanner
```powershell
# Test IAM scanner specifically
python -c "
import asyncio
from src.scanners.iam_scanner import IAMScanner
from src.utils.aws_client import AWSClientManager
from src.utils.config import Config

async def test_iam():
    config = Config.from_file('config/production.yaml')
    client_manager = AWSClientManager(config)
    scanner = IAMScanner(client_manager, config)
    
    # Test a single region scan
    results = await scanner.scan_account('123456789012')  # Use your account ID
    print(f'✅ IAM scan completed: {len(results)} findings')
    return results

results = asyncio.run(test_iam())
"
```

---

## 🎯 **PART 4: Full Production Scan**

### 4.1 Run Complete CSPM Scan
```powershell
# Create logs directory
New-Item -ItemType Directory -Path "logs" -Force

# Run full production scan
python -m src.main --config config/production.yaml --output-dir reports/production

# Alternative: Run with specific parameters
python -m src.main `
  --regions us-east-1,us-west-2 `
  --services iam,ec2,vpc,s3 `
  --output-format json,html,csv `
  --output-dir reports/production-$(Get-Date -Format 'yyyyMMdd-HHmmss')
```

### 4.2 Monitor Scan Progress
```powershell
# Monitor logs in real-time
Get-Content -Path "logs/csmp-scan.log" -Wait -Tail 50

# Check scan status
python -c "
import os
report_dir = 'reports'
if os.path.exists(report_dir):
    files = os.listdir(report_dir)
    print(f'Reports generated: {len(files)}')
    for file in files:
        print(f'  - {file}')
"
```

---

## 🐙 **PART 5: GitHub Organization Setup**

### 5.1 Clone Repository to Your GitHub Organization

#### Option A: Fork and Transfer
```bash
# 1. Fork the repository to your personal account first
# 2. Then transfer to your organization via GitHub web interface:
#    - Go to repository Settings
#    - Scroll down to "Transfer ownership"
#    - Select your organization

# 3. Clone to your local machine
git clone https://github.com/YOUR-ORG/aws-cspm-scanner.git
cd aws-cspm-scanner
```

#### Option B: Create New Repository in Organization
```bash
# 1. Create new repository in your GitHub organization
# 2. Add remote and push existing code
cd "C:\Users\vagarw35\Documents\Technical documents\Technologies\Github\Github Copilot"

# Add your organization repository as remote
git remote add origin https://github.com/YOUR-ORG/aws-cspm-scanner.git

# Push to organization repository
git branch -M main
git push -u origin main
```

### 5.2 Set Up GitHub Secrets for AWS Access
```bash
# In your GitHub repository settings, add these secrets:
# Settings > Secrets and variables > Actions > New repository secret

# Required secrets:
AWS_ACCESS_KEY_ID          # Your AWS access key
AWS_SECRET_ACCESS_KEY      # Your AWS secret key  
AWS_DEFAULT_REGION         # Default AWS region (e.g., us-east-1)

# Optional secrets for multi-account:
AWS_ROLE_ARN              # Cross-account role ARN
AWS_EXTERNAL_ID           # External ID for role assumption
```

### 5.3 Configure GitHub Workflow
The workflow file at `.github/workflows/cspm-scan.yml` is already configured. Update it for your organization:

```powershell
# Edit the workflow file to match your requirements
```

Update the workflow with your specific configuration:
```yaml
# In .github/workflows/cspm-scan.yml
name: AWS CSPM Security Scan

on:
  # Run on demand
  workflow_dispatch:
    inputs:
      aws_regions:
        description: 'AWS regions to scan (comma-separated)'
        required: true
        default: 'us-east-1,us-west-2'
      
      aws_accounts:
        description: 'AWS account IDs to scan (comma-separated)'  
        required: true
        default: '123456789012'  # Update with your account ID
      
      services:
        description: 'Services to scan'
        required: true
        default: 'iam,ec2,vpc,s3'
      
      report_formats:
        description: 'Report formats'
        required: true
        default: 'json,html,csv'

  # Run on schedule (weekly on Sundays at 2 AM UTC)
  schedule:
    - cron: '0 2 * * 0'
  
  # Run on push to main branch
  push:
    branches: [ main ]
    paths:
      - 'src/**'
      - 'config/**'

jobs:
  cspm-scan:
    runs-on: ubuntu-latest
    
    steps:
    - name: Checkout code
      uses: actions/checkout@v4
    
    - name: Set up Python
      uses: actions/setup-python@v4
      with:
        python-version: '3.9'
    
    - name: Install dependencies
      run: |
        python -m pip install --upgrade pip
        pip install -r requirements.txt
    
    - name: Configure AWS credentials
      uses: aws-actions/configure-aws-credentials@v4
      with:
        aws-access-key-id: ${{ secrets.AWS_ACCESS_KEY_ID }}
        aws-secret-access-key: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
        aws-region: ${{ secrets.AWS_DEFAULT_REGION }}
    
    - name: Run CSPM Scan
      run: |
        mkdir -p reports logs
        python -m src.main \
          --regions ${{ github.event.inputs.aws_regions || 'us-east-1' }} \
          --accounts ${{ github.event.inputs.aws_accounts || '123456789012' }} \
          --services ${{ github.event.inputs.services || 'iam,ec2,vpc,s3' }} \
          --output-format ${{ github.event.inputs.report_formats || 'json,html' }} \
          --output-dir reports/scan-$(date +%Y%m%d-%H%M%S)
    
    - name: Upload scan reports
      uses: actions/upload-artifact@v4
      with:
        name: cspm-reports-${{ github.run_number }}
        path: reports/
        retention-days: 30
    
    - name: Upload scan logs  
      uses: actions/upload-artifact@v4
      with:
        name: cspm-logs-${{ github.run_number }}
        path: logs/
        retention-days: 7
    
    - name: Generate scan summary
      run: |
        echo "## CSPM Scan Summary" >> $GITHUB_STEP_SUMMARY
        echo "- **Scan Date**: $(date)" >> $GITHUB_STEP_SUMMARY
        echo "- **Regions**: ${{ github.event.inputs.aws_regions || 'us-east-1' }}" >> $GITHUB_STEP_SUMMARY
        echo "- **Accounts**: ${{ github.event.inputs.aws_accounts || '123456789012' }}" >> $GITHUB_STEP_SUMMARY
        echo "- **Services**: ${{ github.event.inputs.services || 'iam,ec2,vpc,s3' }}" >> $GITHUB_STEP_SUMMARY
        
        # Add report statistics if JSON report exists
        if [ -f reports/scan-*/cspm_report_*.json ]; then
          echo "- **Reports Generated**: $(ls reports/scan-*/cspm_report_*.* | wc -l)" >> $GITHUB_STEP_SUMMARY
        fi
```

---

## 🏃‍♂️ **PART 6: Running GitHub Workflow On Demand**

### 6.1 Manual Workflow Execution
```bash
# Method 1: GitHub Web Interface
# 1. Go to your repository on GitHub
# 2. Click "Actions" tab
# 3. Select "AWS CSPM Security Scan" workflow
# 4. Click "Run workflow" button
# 5. Fill in the parameters:
#    - AWS regions: us-east-1,us-west-2
#    - AWS accounts: YOUR-ACCOUNT-ID
#    - Services: iam,ec2,vpc,s3
#    - Report formats: json,html,csv
# 6. Click "Run workflow"
```

### 6.2 GitHub CLI Workflow Execution
```bash
# Install GitHub CLI if not already installed
# Windows: winget install GitHub.cli

# Authenticate with GitHub
gh auth login

# Run workflow manually
gh workflow run "AWS CSPM Security Scan" \
  --repo YOUR-ORG/aws-cspm-scanner \
  --field aws_regions="us-east-1,us-west-2" \
  --field aws_accounts="123456789012" \
  --field services="iam,ec2,vpc,s3" \
  --field report_formats="json,html,csv"

# Check workflow status
gh run list --repo YOUR-ORG/aws-cspm-scanner

# Watch workflow in real-time
gh run watch --repo YOUR-ORG/aws-cspm-scanner
```

### 6.3 Scheduled Workflow
The workflow is configured to run automatically:
- **Weekly**: Every Sunday at 2 AM UTC
- **On Code Changes**: When pushing to main branch
- **Manual Triggers**: On-demand execution

---

## 📊 **PART 7: Viewing Results and HTML Dashboard**

### 7.1 Local Report Viewing
```powershell
# After running a local scan, open HTML dashboard
$latestReport = Get-ChildItem -Path "reports" -Filter "*.html" | Sort-Object LastWriteTime -Descending | Select-Object -First 1
Start-Process $latestReport.FullName

# Or use Python to serve the report
cd reports
python -m http.server 8000
# Then open http://localhost:8000 in your browser
```

### 7.2 GitHub Actions Report Viewing

#### Download Reports via GitHub Web Interface:
```bash
# 1. Go to your repository on GitHub
# 2. Click "Actions" tab  
# 3. Click on a completed workflow run
# 4. Scroll down to "Artifacts" section
# 5. Download "cspm-reports-[run-number]" artifact
# 6. Extract the ZIP file
# 7. Open the HTML file in your browser
```

#### Download Reports via GitHub CLI:
```bash
# List recent workflow runs
gh run list --repo YOUR-ORG/aws-cspm-scanner

# Download artifacts from latest run
gh run download --repo YOUR-ORG/aws-cspm-scanner

# Open HTML report
open cspm-reports-*/scan-*/cspm_report_*.html
```

### 7.3 Interactive Dashboard Features

The HTML dashboard includes:

#### **Executive Summary**
- Total accounts scanned
- Critical/High/Medium/Low finding counts
- Compliance score overview
- Account-level summaries

#### **Interactive Filtering**
```javascript
// Available filters in the dashboard:
- Severity: Critical, High, Medium, Low, Info
- Service: IAM, EC2, VPC, S3, Organization
- Account: Multi-account filtering
- Free-text search across all findings
```

#### **Charts and Visualizations**
- Pie chart: Findings by severity
- Pie chart: Findings by service  
- Compliance framework scoring
- Trend analysis (if historical data available)

#### **Detailed Findings Table**
- Sortable columns
- Expandable finding details
- Remediation guidance
- Compliance framework mapping

---

## 📁 **PART 8: Accessing Stored Artifacts**

### 8.1 Local Artifact Storage
```powershell
# Reports are stored in organized directory structure:
reports/
├── scan-20260102-143022/          # Timestamp-based directory
│   ├── cspm_report_20260102_143022.json     # Machine-readable data
│   ├── cspm_report_20260102_143022.html     # Interactive dashboard  
│   ├── cspm_report_20260102_143022.csv      # Spreadsheet format
│   └── scan_metadata.json                    # Scan configuration and metadata

logs/
├── cspm-scan-20260102-143022.log            # Detailed scan logs
└── error-20260102-143022.log                # Error logs (if any)

# Access latest reports programmatically
$latestScanDir = Get-ChildItem -Path "reports" -Directory | Sort-Object LastWriteTime -Descending | Select-Object -First 1
Write-Host "Latest scan directory: $($latestScanDir.FullName)"
```

### 8.2 GitHub Actions Artifact Storage

#### **Artifact Retention**:
- **Reports**: Stored for 30 days
- **Logs**: Stored for 7 days  
- **Automated cleanup**: GitHub automatically removes expired artifacts

#### **Programmatic Access**:
```bash
# Using GitHub API to access artifacts
curl -H "Authorization: token YOUR-GITHUB-TOKEN" \
  "https://api.github.com/repos/YOUR-ORG/aws-cspm-scanner/actions/artifacts"

# Using GitHub CLI for easier access
gh api repos/YOUR-ORG/aws-cspm-scanner/actions/artifacts
```

### 8.3 Long-term Storage Solutions

#### **Option 1: AWS S3 Integration** (Recommended)
Add to your workflow:
```yaml
- name: Upload to S3
  run: |
    aws s3 cp reports/ s3://your-cspm-reports-bucket/$(date +%Y/%m/%d)/ --recursive
  env:
    AWS_ACCESS_KEY_ID: ${{ secrets.S3_ACCESS_KEY_ID }}
    AWS_SECRET_ACCESS_KEY: ${{ secrets.S3_SECRET_ACCESS_KEY }}
```

#### **Option 2: Azure Storage Integration**
```yaml
- name: Upload to Azure
  uses: azure/CLI@v1
  with:
    azcliversion: 2.34.1
    inlineScript: |
      az storage blob upload-batch \
        --destination cspm-reports \
        --source reports/ \
        --account-name yourstorageaccount
```

---

## 🔍 **PART 9: Monitoring and Alerting**

### 9.1 Set Up Slack/Teams Notifications
Add to your GitHub workflow:
```yaml
- name: Notify Slack on Critical Findings  
  if: contains(steps.scan.outputs.critical_count, '1')  # If critical findings found
  uses: 8398a7/action-slack@v3
  with:
    status: custom
    custom_payload: |
      {
        "channel": "#security-alerts",
        "username": "CSPM Scanner",
        "text": "🚨 Critical security findings detected in AWS scan!",
        "attachments": [{
          "color": "danger", 
          "fields": [
            {"title": "Critical Findings", "value": "${{ steps.scan.outputs.critical_count }}", "short": true},
            {"title": "High Findings", "value": "${{ steps.scan.outputs.high_count }}", "short": true},
            {"title": "Report", "value": "Download from GitHub Actions artifacts", "short": false}
          ]
        }]
      }
  env:
    SLACK_WEBHOOK_URL: ${{ secrets.SLACK_WEBHOOK_URL }}
```

### 9.2 Email Notifications
```yaml
- name: Send Email Report
  uses: dawidd6/action-send-mail@v3
  with:
    server_address: smtp.gmail.com
    server_port: 587
    username: ${{ secrets.EMAIL_USERNAME }}
    password: ${{ secrets.EMAIL_PASSWORD }}
    subject: "AWS CSPM Scan Results - ${{ github.run_number }}"
    to: security-team@yourcompany.com
    from: cspm-scanner@yourcompany.com
    html_body: |
      <h2>AWS CSPM Scan Completed</h2>
      <p><strong>Scan Date:</strong> $(date)</p>
      <p><strong>Critical Findings:</strong> ${{ steps.scan.outputs.critical_count }}</p>
      <p><strong>High Findings:</strong> ${{ steps.scan.outputs.high_count }}</p>
      <p>Download detailed reports from GitHub Actions artifacts.</p>
    attachments: reports/scan-*/cspm_report_*.html
```

---

## 📈 **PART 10: Advanced Usage Scenarios**

### 10.1 Multi-Account Organization Scanning
```yaml
# For AWS Organizations with multiple accounts
- name: Scan Organization Accounts
  run: |
    # Get all organization accounts
    aws organizations list-accounts --query 'Accounts[].Id' --output text | tr '\t' ',' > accounts.txt
    
    # Run scan against all accounts
    python -m src.main \
      --accounts $(cat accounts.txt) \
      --regions us-east-1,us-west-2,eu-west-1 \
      --services iam,ec2,vpc,s3,organization \
      --output-dir reports/org-scan-$(date +%Y%m%d)
```

### 10.2 Compliance-Specific Scanning
```bash
# Scan for specific compliance framework
python -m src.main \
  --compliance-framework CIS-AWS-v1.5.0 \
  --severity critical,high \
  --output-format html \
  --output-dir reports/cis-compliance

# Generate executive summary report
python -m src.main \
  --executive-summary-only \
  --output-format html \
  --output-dir reports/executive
```

### 10.3 Continuous Integration Pipeline
```yaml
# Add to your application CI/CD pipeline
- name: Security Baseline Scan
  run: |
    python -m src.main \
      --quick-scan \
      --fail-on-critical \
      --output-format json \
      --output-dir security-baseline
    
    # Fail pipeline if critical issues found
    if [ $? -ne 0 ]; then
      echo "❌ Critical security issues detected! Failing pipeline."
      exit 1
    fi
```

---

## ✅ **PART 11: Verification Checklist**

### Pre-Production Checklist:
- [ ] ✅ Unit tests pass (`python run_tests.py --unit`)
- [ ] ✅ Integration tests pass (`python run_tests.py --integration`)
- [ ] ✅ AWS credentials configured correctly
- [ ] ✅ IAM permissions verified for target accounts
- [ ] ✅ Configuration file updated with your account IDs
- [ ] ✅ GitHub secrets configured for workflow
- [ ] ✅ Local scan completed successfully
- [ ] ✅ HTML dashboard opens and displays correctly
- [ ] ✅ GitHub workflow runs without errors
- [ ] ✅ Artifacts download and extract properly

### Production Readiness Checklist:
- [ ] ✅ Multi-region scanning tested
- [ ] ✅ Multi-account scanning tested (if applicable)
- [ ] ✅ Report storage and retention configured
- [ ] ✅ Alerting and notifications set up
- [ ] ✅ Scheduled scanning configured
- [ ] ✅ Security team trained on dashboard usage
- [ ] ✅ Compliance requirements mapped to rules
- [ ] ✅ Incident response process defined

---

## 🎉 **You're Ready to Go!**

Your AWS CSPM system is now fully implemented and ready for production use. The system provides:

- **✅ Comprehensive Security Scanning**: IAM, EC2, VPC, S3, and Organization analysis
- **✅ Modern Interactive Dashboard**: HTML reports with filtering and charts
- **✅ Compliance Framework Integration**: CIS, NIST, PCI-DSS, SOC 2 mapping
- **✅ GitHub Actions Integration**: Automated scanning and artifact storage
- **✅ Production-Grade Monitoring**: Alerts, notifications, and reporting

Start with a single account and gradually expand to your full AWS environment. The system is designed to scale with your needs and provide actionable security insights for your cloud infrastructure.

**Happy Scanning! 🚀🔒**