# CLI Tool Feature

## Overview

The CLI Tool feature provides a command-line interface for running IAMCloud scans locally. This allows developers and security teams to perform AWS security scans directly from their workstation.

## Features

- ✅ Local AWS credential support
- ✅ IAM role assumption for cross-account scanning
- ✅ Multiple output formats (HTML, JSON, CSV)
- ✅ Configurable scanning regions and services
- ✅ Authentication testing and validation
- ✅ Integration with repository configuration files

## Structure

```
cli-tool/
├── scripts/
│   └── iamcloud_cli.py          # Main CLI application
├── docs/
│   └── README.md                # This file
└── tests/
    └── (CLI-specific tests)
```

## Quick Start

### 1. Install Dependencies

Make sure you have the requirements installed:
```bash
pip install boto3 pyyaml
```

### 2. Configure AWS Credentials

You have several options for AWS authentication:

#### Option A: AWS CLI Configuration
```bash
aws configure
```

#### Option B: Environment Variables
```bash
export AWS_ACCESS_KEY_ID=your_access_key
export AWS_SECRET_ACCESS_KEY=your_secret_key
export AWS_DEFAULT_REGION=us-east-1
```

#### Option C: IAM Role (for EC2/Lambda)
If running on EC2 or Lambda, IAM roles will be automatically detected.

### 3. Test Authentication

```bash
python features/cli-tool/scripts/iamcloud_cli.py --test-auth
```

This will:
- ✅ Test your AWS credentials
- ✅ Check repository configuration
- ✅ Test role assumption (if configured)
- ✅ Verify CLI functionality

### 4. Create Configuration (Optional)

```bash
python features/cli-tool/scripts/iamcloud_cli.py --create-config
```

This creates `shared/config/.github-config.yaml` with sample configuration.

### 5. Run a Scan

```bash
python features/cli-tool/scripts/iamcloud_cli.py \
  --regions us-east-1 \
  --accounts current \
  --services iam,s3,ec2
```

## Usage Examples

### Basic Single-Account Scan
```bash
python features/cli-tool/scripts/iamcloud_cli.py \
  --regions us-east-1 \
  --accounts current \
  --services iam,s3,ec2 \
  --output-format html
```

### Multi-Region Scan
```bash
python features/cli-tool/scripts/iamcloud_cli.py \
  --regions us-east-1,us-west-2,eu-west-1 \
  --accounts current \
  --services iam,s3,ec2,vpc \
  --output-format json
```

### Cross-Account Scan with Role
```bash
python features/cli-tool/scripts/iamcloud_cli.py \
  --regions us-east-1 \
  --accounts 123456789012 \
  --services all \
  --use-role-arn arn:aws:iam::123456789012:role/IAMCloudScannerRole
```

### Organization-Wide Scan
```bash
python features/cli-tool/scripts/iamcloud_cli.py \
  --regions us-east-1 \
  --accounts organization \
  --services iam,s3,ec2 \
  --verbose
```

## Configuration

The CLI tool uses configuration from:

1. **Command line arguments** (highest priority)
2. **Environment variables**
3. **Repository config**: `shared/config/.github-config.yaml`
4. **AWS credentials**: `~/.aws/credentials`

### Repository Configuration

Create `shared/config/.github-config.yaml`:
```yaml
variables:
  AWS_DEFAULT_REGION: us-east-1
  AWS_ROLE_ARN: arn:aws:iam::ACCOUNT_ID:role/IAMCloudScannerRole
```

## AWS Credentials Setup Instructions

### For Local Development

1. **Install AWS CLI**:
   ```bash
   # Windows
   msiexec.exe /i https://awscli.amazonaws.com/AWSCLIV2.msi
   
   # macOS
   curl "https://awscli.amazonaws.com/AWSCLIV2.pkg" -o "AWSCLIV2.pkg"
   sudo installer -pkg AWSCLIV2.pkg -target /
   
   # Linux
   curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
   unzip awscliv2.zip
   sudo ./aws/install
   ```

2. **Configure Credentials**:
   ```bash
   aws configure
   ```
   
   Enter:
   - AWS Access Key ID
   - AWS Secret Access Key  
   - Default region (e.g., us-east-1)
   - Output format (json)

3. **Test Configuration**:
   ```bash
   aws sts get-caller-identity
   ```

### For PowerShell Users (Windows)

Set credentials in current terminal session:
```powershell
$env:AWS_ACCESS_KEY_ID = "your_access_key"
$env:AWS_SECRET_ACCESS_KEY = "your_secret_key"  
$env:AWS_DEFAULT_REGION = "us-east-1"
```

### For Cross-Account Access

1. **Deploy IAM Role**: Use CloudFormation template from infrastructure feature
2. **Update Configuration**: Set role ARN in `.github-config.yaml`
3. **Test Role Assumption**: Run `--test-auth` to verify

## Troubleshooting

### Authentication Issues

- **No credentials error**: Run `aws configure` or set environment variables
- **Access denied**: Check IAM permissions for your user/role
- **Role assumption fails**: Verify role trust policy and External ID

### Common Solutions

```bash
# Test basic AWS access
aws sts get-caller-identity

# Test CLI tool auth
python features/cli-tool/scripts/iamcloud_cli.py --test-auth --verbose

# Create sample config
python features/cli-tool/scripts/iamcloud_cli.py --create-config
```

## Output

Scan results are saved to `reports/cli-scan/` by default:
- **HTML**: Interactive web report
- **JSON**: Machine-readable results
- **CSV**: Spreadsheet-compatible format

## Status

✅ **Ready for Production**
- All core functionality implemented
- Authentication flows working  
- Error handling in place
- Documentation complete

## Dependencies

- **Python 3.8+**
- **boto3**: AWS SDK
- **pyyaml**: Configuration parsing
- **AWS credentials**: Configured locally

## Next Steps

1. ✅ Feature complete and tested
2. 🔄 Ready to merge to main branch
3. 📋 Integration testing with other features