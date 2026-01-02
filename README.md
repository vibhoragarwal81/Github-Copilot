# AWS Cloud Security Posture Management (CSPM)

This project provides automated scanning of AWS resources across all accounts within an AWS organization for cloud security posture management using GitHub Actions.

## Features

- **Multi-Account Scanning**: Automatically discover and scan all AWS accounts in your organization
- **Security Posture Assessment**: Evaluate resources against security best practices and compliance standards
- **Automated Reporting**: Generate comprehensive security reports with findings and recommendations
- **GitHub Actions Integration**: Fully automated CI/CD pipeline for continuous security monitoring
- **Customizable Rules**: Define and customize security rules based on your organization's requirements

## Architecture

```
├── src/
│   ├── scanners/          # AWS resource scanners
│   ├── rules/             # Security rules and policies
│   ├── reports/           # Report generation
│   └── utils/             # Utility functions
├── .github/
│   └── workflows/         # GitHub Actions workflows
├── config/                # Configuration files
├── tests/                 # Unit and integration tests
└── docs/                  # Documentation
```

## Prerequisites

- Python 3.9+
- AWS CLI configured with appropriate permissions
- AWS Organizations access
- Cross-account IAM roles configured

## Quick Start

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd aws-cspm
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Configure AWS credentials**
   ```bash
   aws configure
   # or set environment variables
   export AWS_ACCESS_KEY_ID=your-access-key
   export AWS_SECRET_ACCESS_KEY=your-secret-key
   export AWS_DEFAULT_REGION=us-east-1
   ```

4. **Run a scan**
   ```bash
   python -m src.main --scan-organization
   ```

## Configuration

### AWS IAM Setup

The following IAM permissions are required:

- `organizations:ListAccounts`
- `organizations:DescribeOrganization`
- `sts:AssumeRole` (for cross-account access)
- Service-specific read permissions (EC2, S3, IAM, etc.)

### Environment Variables

- `AWS_ORGANIZATION_ROLE_NAME`: Name of the cross-account role (default: `CSPMScanRole`)
- `AWS_REGIONS`: Comma-separated list of regions to scan (default: all regions)
- `SCAN_INTERVAL`: Scan interval in hours (default: 24)

## GitHub Actions Setup

1. **Configure repository secrets**:
   - `AWS_ACCESS_KEY_ID`
   - `AWS_SECRET_ACCESS_KEY`
   - `AWS_REGION`

2. **Enable GitHub Actions** in your repository settings

3. **Customize the workflow** in `.github/workflows/cspm-scan.yml`

## Security Rules

The scanner includes pre-built rules for:

- EC2 instances (security groups, public IPs, encryption)
- S3 buckets (public access, encryption, versioning)
- IAM (overly permissive policies, unused credentials)
- VPC (security groups, NACLs, flow logs)
- CloudTrail (logging enabled, encryption)
- And many more...

## Reports

Reports are generated in multiple formats:
- JSON (machine-readable)
- HTML (human-readable dashboard)
- CSV (spreadsheet import)
- PDF (executive summary)

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

For support and questions, please open an issue in the GitHub repository.