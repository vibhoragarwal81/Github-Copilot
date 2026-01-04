# CSPM Setup Guide for Acquired Entities

This guide provides comprehensive instructions for setting up and using the Cloud Security Posture Management (CSPM) scanner in acquired entity AWS environments.

## Overview

The CSPM solution provides two ways to scan your AWS infrastructure:

1. **Workflow-based scanning**: Automated scanning through GitHub Actions workflows
2. **CLI-based scanning**: Local/manual scanning using command-line tools

Both approaches use the same underlying security scanning engine and require minimal setup.

## Prerequisites

- AWS CLI configured with appropriate permissions
- GitHub repository access (for workflow approach)
- Python 3.8+ installed (for CLI approach)

## Step 1: Deploy CloudFormation Infrastructure

The acquired entity administrator needs to deploy the CloudFormation template to set up the necessary IAM roles and OIDC identity provider.

### 1.1 Deploy the Template

```bash
# Download the CloudFormation template
aws cloudformation deploy \
  --template-file templates/cspm-single-account-test.yaml \
  --stack-name cspm-scanner-setup \
  --capabilities CAPABILITY_IAM \
  --parameter-overrides \
    GitHubRepositoryOwner=vibhoragarwal81 \
    GitHubRepositoryName=Github-Copilot
```

### 1.2 Get the Role ARN

After successful deployment, retrieve the IAM role ARN:

```bash
# Get the role ARN from the stack outputs
aws cloudformation describe-stacks \
  --stack-name cspm-scanner-setup \
  --query 'Stacks[0].Outputs[?OutputKey==`CSMPRoleArn`].OutputValue' \
  --output text
```

**Example output:**
```
arn:aws:iam::871007551509:role/CSPMScannerRole
```

**Save this ARN - you'll need it for both workflow and CLI setup.**

## Step 2: Configure Repository Variables (For Workflow Approach)

If you plan to use GitHub Actions workflows for automated scanning:

### 2.1 Set Repository Variable

1. Go to your GitHub repository
2. Navigate to Settings → Secrets and variables → Actions
3. Click on the "Variables" tab
4. Click "New repository variable"
5. Set:
   - **Name**: `AWS_ROLE_ARN`
   - **Value**: `arn:aws:iam::YOUR_ACCOUNT_ID:role/CSPMScannerRole` (from Step 1.2)

### 2.2 Verify Workflow Setup

The repository includes the following workflows:
- `.github/workflows/cspm-user-input.yml` - Manual workflow with input parameters
- `.github/workflows/test-aws-auth.yml` - Authentication testing workflow

## Step 3: Configure CLI Environment (For CLI Approach)

If you plan to use the CLI tool for local scanning:

### 3.1 Install Dependencies

```bash
pip install boto3 pyyaml jinja2
```

### 3.2 Create Configuration File

Create a local configuration file with your role ARN:

```bash
# Create sample config file
python scripts/cspm_cli.py --create-config

# Edit the created .github-config.yaml file
# Update AWS_ROLE_ARN with your actual role ARN from Step 1.2
```

**Example `.github-config.yaml`:**
```yaml
variables:
  AWS_ROLE_ARN: arn:aws:iam::871007551509:role/CSPMScannerRole
  AWS_DEFAULT_REGION: us-east-1
```

### 3.3 Configure AWS Credentials

Ensure you have AWS credentials configured that can assume the CSPM role:

```bash
# Option 1: AWS CLI configure
aws configure

# Option 2: Environment variables
export AWS_ACCESS_KEY_ID=your_access_key
export AWS_SECRET_ACCESS_KEY=your_secret_key
export AWS_DEFAULT_REGION=us-east-1

# Option 3: Use IAM role or instance profile (if running on EC2)
```

## Usage Guide

### Workflow-Based Scanning

#### Manual Workflow with Custom Parameters

1. Go to your GitHub repository
2. Click "Actions" → "CSMP Scanner - User Input"
3. Click "Run workflow"
4. Configure parameters:
   - **Scan Mode**: `single-account` or `organization`
   - **Target Account**: Leave empty for current account or specify account ID
   - **Regions**: `us-east-1` or `us-east-1,us-west-2`
   - **Services**: `iam,s3,ec2` or specific services
   - **Output Format**: `html`, `json`, or `csv`

#### Example Workflow Runs

**Single Account Scan:**
- Scan Mode: `single-account`
- Target Account: (empty - uses current account)
- Regions: `us-east-1,us-west-2`
- Services: `iam,s3,ec2,vpc`
- Output Format: `html`

**Organization-Wide Scan:**
- Scan Mode: `organization`
- Target Account: (ignored)
- Regions: `us-east-1`
- Services: `iam,s3,ec2`
- Output Format: `html`

**Specific Account Scan:**
- Scan Mode: `single-account`
- Target Account: `123456789012`
- Regions: `us-east-1`
- Services: `iam,s3`
- Output Format: `json`

### CLI-Based Scanning

#### Basic Usage

```bash
# Single account scan (current account)
python scripts/cspm_cli.py \
  --regions us-east-1 \
  --accounts current \
  --services iam,s3,ec2

# Multiple regions
python scripts/cspm_cli.py \
  --regions us-east-1,us-west-2 \
  --accounts current \
  --services iam,s3,ec2,vpc

# Specific account scan
python scripts/cspm_cli.py \
  --regions us-east-1 \
  --accounts 123456789012 \
  --services iam,s3,ec2

# Organization-wide scan
python scripts/cspm_cli.py \
  --regions us-east-1 \
  --accounts organization \
  --services iam,s3,ec2,vpc

# All services scan
python scripts/cspm_cli.py \
  --regions us-east-1 \
  --accounts current \
  --services all
```

#### Advanced Options

```bash
# Custom output directory and format
python scripts/cspm_cli.py \
  --regions us-east-1 \
  --accounts current \
  --services iam,s3,ec2 \
  --output-format json \
  --output-dir /path/to/custom/reports

# Use specific role ARN (override config file)
python scripts/cspm_cli.py \
  --regions us-east-1 \
  --accounts current \
  --services iam,s3,ec2 \
  --use-role-arn arn:aws:iam::ACCOUNT:role/CustomRole

# Verbose logging
python scripts/cspm_cli.py \
  --regions us-east-1 \
  --accounts current \
  --services iam,s3,ec2 \
  --verbose
```

## Output and Results

### Report Locations

**Workflow-based scans:**
- Results are uploaded as GitHub Actions artifacts
- Available in the workflow run page for download
- Retention: 30 days

**CLI-based scans:**
- Default location: `reports/cli-scan/`
- Custom location: Specified via `--output-dir`

### Report Formats

**HTML Reports:**
- Interactive dashboards with charts and graphs
- Compliance status summaries
- Detailed finding descriptions
- Remediation recommendations

**JSON Reports:**
- Machine-readable format
- Detailed metadata for each finding
- Suitable for integration with other tools

**CSV Reports:**
- Tabular format for spreadsheet analysis
- Summary of findings with key details

### Sample Report Structure

```
reports/
├── cli-scan/
│   ├── cspm_report_20260104_120000.html
│   ├── cspm_report_20260104_120000.json
│   └── compliance_summary.csv
└── workflow-scan/
    ├── csmp_report_20260104_130000.html
    └── findings_detail.json
```

## Troubleshooting

### Common Issues

#### 1. "AWS_ROLE_ARN repository variable is not set"
- **Solution**: Ensure you've set the `AWS_ROLE_ARN` repository variable in GitHub (Step 2.1)

#### 2. "Unable to locate credentials" (CLI)
- **Solution**: Configure AWS credentials using `aws configure` or environment variables (Step 3.3)

#### 3. "Access denied when assuming role"
- **Solution**: Verify your AWS credentials have permission to assume the CSPM role
- Check the trust policy in the CloudFormation template

#### 4. "Invalid AWS account ID" (CLI)
- **Solution**: Ensure account IDs are exactly 12 digits
- Use "current" for current account or "organization" for org-wide scans

#### 5. "Module import errors" (CLI)
- **Solution**: Install required dependencies: `pip install boto3 pyyaml jinja2`
- Ensure you're running from the project root directory

### Validation Steps

#### Test CloudFormation Deployment

```bash
# Verify the stack was deployed successfully
aws cloudformation describe-stacks --stack-name cspm-scanner-setup

# Test the OIDC identity provider
aws iam list-open-id-connect-providers

# Verify the IAM role exists
aws iam get-role --role-name CSMPScannerRole
```

#### Test GitHub Actions Authentication

1. Run the "Test AWS OIDC Authentication" workflow
2. Check the workflow logs for successful authentication
3. Verify AWS STS get-caller-identity output

#### Test CLI Authentication

```bash
# Test with current credentials
python scripts/cspm_cli.py \
  --regions us-east-1 \
  --accounts current \
  --services iam \
  --verbose

# Check the logs for successful role assumption
```

## Security Considerations

### IAM Role Permissions

The deployed IAM role includes:
- `SecurityAudit` managed policy (read-only access to security-related resources)
- Specific permissions for compliance checking
- No write or modify permissions

### OIDC Trust Policy

The OIDC identity provider restricts access to:
- Specific GitHub repository
- Specific GitHub organization
- Only workflow-initiated requests

### Data Handling

- Scan results contain security findings and compliance data
- Results are stored temporarily and cleaned up automatically
- No sensitive data (like credentials) is exposed in reports

## Support and Maintenance

### Regular Updates

- Monitor for CloudFormation template updates
- Update workflow files when new versions are available
- Keep CLI dependencies up to date: `pip install --upgrade boto3 pyyaml jinja2`

### Monitoring

- Set up CloudWatch alarms for failed scans
- Monitor GitHub Actions workflow execution
- Review scan results regularly for new findings

### Contact

For technical support or questions:
- Create GitHub issues in the repository
- Check the existing documentation in the `docs/` directory
- Review workflow logs for detailed error messages

---

**Next Steps:**
1. Complete CloudFormation deployment (Step 1)
2. Choose your preferred scanning method (Workflow or CLI)
3. Run your first scan following the usage guide
4. Set up regular scanning schedules based on your compliance requirements