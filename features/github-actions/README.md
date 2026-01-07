# IAMCloud GitHub Actions Feature

This feature branch contains all GitHub Actions workflows and automation scripts for IAMCloud.

## Structure

```
features/github-actions/
├── .github/                    # GitHub workflows and actions
├── scripts/                    # Automation scripts for workflows
├── workflows/                  # Additional workflow templates
└── README.md                   # This file
```

## Components

### Workflows
- **Scanning Workflows**: Automated security scans triggered by events
- **Deployment Workflows**: Automated deployment of CloudFormation templates
- **OIDC Integration**: GitHub Actions OIDC authentication with AWS

### Scripts
- **run_workflow_scan.py**: Main scanning script for GitHub Actions
- **run_organization_scan.py**: Organization-wide scanning automation

### Configuration
- Uses `features/shared/config/.github-config.yaml` for role ARNs and settings
- Integrates with IAMCloud core scanner from `feature/core-scanner`
- Deploys infrastructure from `feature/infrastructure`

## Development

This feature branch focuses on:
1. GitHub Actions workflow definitions
2. OIDC authentication setup
3. Automated scanning triggers
4. CI/CD pipeline automation

## Integration

- **Core Scanner**: Calls scanning logic from `feature/core-scanner`
- **Infrastructure**: Deploys resources from `feature/infrastructure`
- **CLI Tool**: Can trigger same scans as `feature/cli-tool`
- **Shared Utils**: Uses utilities from `features/shared/`