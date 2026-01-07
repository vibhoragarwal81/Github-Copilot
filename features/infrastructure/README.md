# Infrastructure Feature - IAMCloud

This feature contains all CloudFormation templates and infrastructure-as-code components for IAMCloud deployment.

## 📁 Structure

```
features/infrastructure/
├── cloudformation/          # CloudFormation templates
│   ├── *.yaml              # AWS infrastructure templates
└── README.md               # This file
```

## 🚀 Templates Included

- **IAM Roles and Policies**: Cross-account access roles for scanning
- **OIDC Configuration**: GitHub Actions integration
- **Member Account Setup**: Templates for acquired entities
- **Single Account Testing**: Development and testing templates

## 📋 Usage

Deploy templates through AWS Console, AWS CLI, or GitHub Actions workflows.

See the main project README for detailed deployment instructions.