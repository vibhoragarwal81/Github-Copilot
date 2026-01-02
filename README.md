# AWS Cloud Security Posture Management (CSPM) Scanner# AWS Cloud Security Posture Management (CSPM)



A comprehensive multi-account AWS security scanning solution that identifies misconfigurations, compliance violations, and security risks across your AWS Organization.This project provides automated scanning of AWS resources across all accounts within an AWS organization for cloud security posture management using GitHub Actions.



## 🔧 Features## Features



- **Multi-Account Scanning**: Scan all AWS accounts in your organization simultaneously- **Multi-Account Scanning**: Automatically discover and scan all AWS accounts in your organization

- **Cross-Account Role Management**: Automated deployment of security scanning roles- **Security Posture Assessment**: Evaluate resources against security best practices and compliance standards

- **Comprehensive Service Coverage**: IAM, EC2, S3, VPC security analysis- **Automated Reporting**: Generate comprehensive security reports with findings and recommendations

- **Compliance Framework Mapping**: CIS, NIST, PCI-DSS, SOC2 compliance checks- **GitHub Actions Integration**: Fully automated CI/CD pipeline for continuous security monitoring

- **Interactive HTML Reports**: Rich, filterable security reports with executive dashboard- **Customizable Rules**: Define and customize security rules based on your organization's requirements

- **Single Account Mode**: Fallback scanning for individual AWS accounts

- **Parallel Processing**: Efficient concurrent scanning across accounts and regions## Architecture



## 🏗️ Architecture```

├── src/

```│   ├── scanners/          # AWS resource scanners

┌─────────────────────────────────────────────────────────────────┐│   ├── rules/             # Security rules and policies

│                    Master Account (Management)                  ││   ├── reports/           # Report generation

│  ┌─────────────────┐    ┌──────────────────────────────────┐   ││   └── utils/             # Utility functions

│  │  CSPM Scanner   │    │     Organization Scanner         │   │├── .github/

│  │                 │    │  - Account Discovery             │   ││   └── workflows/         # GitHub Actions workflows

│  │ - IAM Scanner   │    │  - Cross-Account Orchestration  │   │├── config/                # Configuration files

│  │ - EC2 Scanner   │    │  - Parallel Processing          │   │├── tests/                 # Unit and integration tests

│  │ - S3 Scanner    │    │  - Report Generation            │   │└── docs/                  # Documentation

│  │ - VPC Scanner   │    │                                  │   │```

│  └─────────────────┘    └──────────────────────────────────┘   │

└─────────────────────────────────────────────────────────────────┘## Prerequisites

                                    │

                        ┌───────────┴───────────┐- Python 3.9+

                        │                       │- AWS CLI configured with appropriate permissions

┌─────────────────────────────┐    ┌─────────────────────────────┐- AWS Organizations access

│     Member Account 1        │    │     Member Account N        │- Cross-account IAM roles configured

│  ┌─────────────────────┐    │    │  ┌─────────────────────┐    │

│  │   CSPMScanRole      │    │    │  │   CSPMScanRole      │    │## Quick Start

│  │ - SecurityAudit     │    │    │  │ - SecurityAudit     │    │

│  │ - ViewOnlyAccess    │    │    │  │ - ViewOnlyAccess    │    │1. **Clone the repository**

│  │ - Additional Perms  │    │    │  │ - Additional Perms  │    │   ```bash

│  └─────────────────────┘    │    │  └─────────────────────┘    │   git clone <repository-url>

└─────────────────────────────┘    └─────────────────────────────┘   cd aws-cspm

```   ```



## 🚀 Quick Start2. **Install dependencies**

   ```bash

### Prerequisites   pip install -r requirements.txt

   ```

- Python 3.8+ with pip

- AWS CLI configured with appropriate permissions3. **Configure AWS credentials**

- AWS Organizations enabled (for multi-account scanning)   ```bash

   aws configure

### Installation   # or set environment variables

   export AWS_ACCESS_KEY_ID=your-access-key

1. **Clone the repository**   export AWS_SECRET_ACCESS_KEY=your-secret-key

   ```bash   export AWS_DEFAULT_REGION=us-east-1

   git clone <repository-url>   ```

   cd aws-cspm-scanner

   ```4. **Run a scan**

   ```bash

2. **Install dependencies**   python -m src.main --scan-organization

   ```bash   ```

   pip install -r requirements.txt

   ```## Configuration



3. **Configure AWS credentials**### AWS IAM Setup

   ```bash

   aws configureThe following IAM permissions are required:

   # OR set environment variables

   export AWS_ACCESS_KEY_ID=your_access_key- `organizations:ListAccounts`

   export AWS_SECRET_ACCESS_KEY=your_secret_key- `organizations:DescribeOrganization`

   export AWS_DEFAULT_REGION=us-east-1- `sts:AssumeRole` (for cross-account access)

   ```- Service-specific read permissions (EC2, S3, IAM, etc.)



### For Organization-Wide Scanning### Environment Variables



1. **Deploy cross-account roles**- `AWS_ORGANIZATION_ROLE_NAME`: Name of the cross-account role (default: `CSPMScanRole`)

   ```bash- `AWS_REGIONS`: Comma-separated list of regions to scan (default: all regions)

   python scripts/deploy_via_organization_role.py --accounts all- `SCAN_INTERVAL`: Scan interval in hours (default: 24)

   ```

## GitHub Actions Setup

2. **Run organization scan**

   ```bash1. **Configure repository secrets**:

   python scripts/run_organization_scan.py   - `AWS_ACCESS_KEY_ID`

   ```   - `AWS_SECRET_ACCESS_KEY`

   - `AWS_REGION`

### For Single Account Scanning

2. **Enable GitHub Actions** in your repository settings

1. **Run single account scan**

   ```bash3. **Customize the workflow** in `.github/workflows/cspm-scan.yml`

   python scripts/run_cspm_scan.py

   ```## Security Rules



## 📁 Project StructureThe scanner includes pre-built rules for:



```- EC2 instances (security groups, public IPs, encryption)

aws-cspm-scanner/- S3 buckets (public access, encryption, versioning)

├── scripts/                          # Main execution scripts- IAM (overly permissive policies, unused credentials)

│   ├── run_organization_scan.py       # Multi-account scanning- VPC (security groups, NACLs, flow logs)

│   ├── run_cspm_scan.py              # Single account scanning- CloudTrail (logging enabled, encryption)

│   ├── deploy_via_organization_role.py # Cross-account role deployment- And many more...

│   ├── deploy_member_account_roles.py  # Role deployment verification

│   ├── manual_deploy_guide.py        # Manual deployment assistance## Reports

│   └── run_tests.py                  # Test execution

├── src/                              # Core scanner modulesReports are generated in multiple formats:

│   ├── scanners/                     # Service-specific scanners- JSON (machine-readable)

│   │   ├── iam_scanner.py           # IAM security analysis- HTML (human-readable dashboard)

│   │   ├── ec2_scanner.py           # EC2 security analysis- CSV (spreadsheet import)

│   │   ├── s3_scanner.py            # S3 security analysis- PDF (executive summary)

│   │   ├── vpc_scanner.py           # VPC security analysis

│   │   └── organization_scanner.py  # Multi-account orchestration## Contributing

│   ├── reports/                     # Report generation

│   │   └── report_generator.py      # HTML/JSON/CSV report generation1. Fork the repository

│   ├── rules/                       # Security rules engine2. Create a feature branch

│   │   └── rules_engine.py          # Compliance and security rules3. Make your changes

│   └── utils/                       # Utility modules4. Add tests

│       ├── aws_client.py            # AWS client management5. Submit a pull request

│       ├── config.py                # Configuration handling

│       └── logger.py                # Logging setup## License

├── config/                          # Configuration files

│   ├── config.yaml                  # Main configurationThis project is licensed under the MIT License - see the LICENSE file for details.

│   └── config_detailed.yaml         # Detailed configuration options

├── templates/                       # CloudFormation templates## Support

│   └── cspm-cross-account-role.yaml # Cross-account IAM role

├── tests/                           # Test suitesFor support and questions, please open an issue in the GitHub repository.
│   └── test_comprehensive.py        # Comprehensive tests
├── reports/                         # Generated reports
│   └── *.html                       # HTML security reports
├── docs/                           # Documentation
│   ├── single-account-scan.md      # Single account scanning guide
│   ├── organization-scan.md        # Organization scanning guide
│   └── setup-for-different-org.md  # Setup for different organizations
└── requirements.txt                # Python dependencies
```

## 🔐 Security & Permissions

The scanner requires specific AWS permissions to function properly:

### For Single Account Scanning
- `SecurityAudit` managed policy
- `ViewOnlyAccess` managed policy
- Additional specific permissions (see CloudFormation template)

### For Organization Scanning
- All single account permissions
- `organizations:ListAccounts`
- `organizations:DescribeOrganization`
- `sts:AssumeRole` for cross-account access

## 📊 Reports

The scanner generates comprehensive reports in multiple formats:

- **HTML Reports**: Interactive dashboards with filtering and charts
- **JSON Reports**: Machine-readable structured data
- **CSV Reports**: Spreadsheet-compatible findings export

### Sample Report Metrics
- Total security findings by severity
- Compliance framework mapping
- Account-by-account breakdown
- Service-specific analysis
- Remediation recommendations

## 🛠️ Configuration

Key configuration options in `config/config.yaml`:

```yaml
aws:
  regions:                    # AWS regions to scan
    - us-east-1
  organization_role_name: CSPMScanRole
  external_id: cspm-security-scan

scanning:
  services:                   # Services to scan
    iam: true
    ec2: true
    s3: true
    vpc: true

rules:
  severity_threshold: LOW     # Minimum severity to report
```

## 🧪 Testing

Run the comprehensive test suite:

```bash
python scripts/run_tests.py
```

## 📚 Documentation

- [Single Account Scanning Guide](docs/single-account-scan.md)
- [Organization-Wide Scanning Guide](docs/organization-scan.md)
- [Setup for Different Organizations](docs/setup-for-different-org.md)

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🔗 References

- [AWS Security Best Practices](https://aws.amazon.com/security/security-learning/)
- [CIS AWS Benchmarks](https://www.cisecurity.org/benchmark/amazon_web_services)
- [AWS Multi-Account Security](https://docs.aws.amazon.com/prescriptive-guidance/latest/patterns/create-a-consolidated-report-of-prowler-security-findings-from-multiple-aws-accounts.html)

---

Built with ❤️ for AWS security practitioners