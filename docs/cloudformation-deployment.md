# CloudFormation Deployment Guide for GitHub OIDC

This guide explains how to deploy the GitHub OIDC infrastructure using CloudFormation templates for your CSPM scanner.

## 📁 Templates Overview

| Template | Purpose | Target Account |
|----------|---------|----------------|
| `github-oidc-cloudformation.yaml` | GitHub OIDC Identity Provider & IAM Role | Master/Organization Account |
| `cspm-member-account-role.yaml` | Cross-account CSPM scan role | Member Accounts |

## 🚀 Quick Deployment

### Option 1: Using the Deployment Script (Recommended)

```bash
# Deploy OIDC infrastructure to master account
python scripts/deploy_cloudformation.py \
  --github-org vibhoragarwal81 \
  --github-repo Github-Copilot \
  --role-name GitHubActionsCSPMRole
```

### Option 2: Manual AWS CLI Deployment

```bash
# Deploy to master account
aws cloudformation create-stack \
  --stack-name github-oidc-cspm \
  --template-body file://templates/github-oidc-cloudformation.yaml \
  --parameters \
    ParameterKey=GitHubOrg,ParameterValue=vibhoragarwal81 \
    ParameterKey=GitHubRepo,ParameterValue=Github-Copilot \
    ParameterKey=RoleName,ParameterValue=GitHubActionsCSPMRole \
  --capabilities CAPABILITY_NAMED_IAM
```

### Option 3: AWS Console Deployment

1. Go to **CloudFormation** in AWS Console
2. Click **Create Stack** → **With new resources**
3. Upload `github-oidc-cloudformation.yaml`
4. Fill in parameters:
   - **GitHubOrg**: `vibhoragarwal81`
   - **GitHubRepo**: `Github-Copilot`
   - **RoleName**: `GitHubActionsCSPMRole`
   - **AllowAllBranches**: `false` (recommend main branch only)

## 📋 Detailed Steps

### Step 1: Deploy Master Account Infrastructure

Deploy the OIDC provider and GitHub Actions role to your master/organization account (871007551509):

**Parameters:**
- `GitHubOrg`: Your GitHub username or organization
- `GitHubRepo`: Your repository name
- `RoleName`: Name for the IAM role (default: `GitHubActionsCSPMRole`)
- `AllowAllBranches`: Whether to allow access from all branches (`true`/`false`)
- `SessionDuration`: Maximum session duration in seconds (default: 3600)

**What gets created:**
- ✅ GitHub OIDC Identity Provider
- ✅ IAM Role with SecurityAudit and ViewOnlyAccess policies
- ✅ Custom policies for Organizations and cross-account access
- ✅ Local CSPMScanRole for master account

### Step 2: Deploy Member Account Roles

For each member account (872515281040, 968382677077), deploy the cross-account role:

```bash
# Deploy to member account (run with member account credentials)
aws cloudformation create-stack \
  --stack-name csmp-member-role \
  --template-body file://templates/cspm-member-account-role.yaml \
  --parameters \
    ParameterKey=MasterAccountId,ParameterValue=871007551509 \
    ParameterKey=GitHubActionsRoleName,ParameterValue=GitHubActionsCSPMRole \
  --capabilities CAPABILITY_NAMED_IAM
```

**Parameters:**
- `MasterAccountId`: Account ID of your master/organization account
- `GitHubActionsRoleName`: Name of the role created in master account
- `CSPMScanRoleName`: Name for the cross-account role (default: `CSPMScanRole`)
- `ExternalId`: Additional security external ID

### Step 3: Configure GitHub Repository

After deployment, configure your GitHub repository:

1. **Get the Role ARN** from CloudFormation outputs:
   ```bash
   aws cloudformation describe-stacks \
     --stack-name github-oidc-cspm \
     --query 'Stacks[0].Outputs[?OutputKey==`GitHubActionsRoleArn`].OutputValue' \
     --output text
   ```

2. **Set Repository Variable** in GitHub:
   - Go to: Repository → Settings → Secrets and variables → Actions
   - Click "Variables" tab → "New repository variable"
   - Name: `AWS_ROLE_ARN`
   - Value: The Role ARN from step 1

## 🧪 Testing Your Deployment

### Test Authentication
```bash
# Test locally (if you have AWS CLI configured)
aws sts get-caller-identity

# Test with the authentication script
python scripts/test_aws_auth.py
```

### Test GitHub Actions
1. Go to **Actions** tab in your repository
2. Run the "Test AWS OIDC Authentication" workflow
3. Check the logs for successful authentication

## 🔧 CloudFormation Template Details

### OIDC Provider Configuration
- **URL**: `https://token.actions.githubusercontent.com`
- **Audience**: `sts.amazonaws.com`
- **Thumbprints**: Latest GitHub Actions certificate thumbprints

### Trust Policy Configuration
The role trust policy includes:
- Repository-specific access (`repo:owner/repo:ref:refs/heads/main`)
- Subject claim validation
- Optional branch restrictions

### Permissions Included
- **AWS Managed Policies**:
  - `SecurityAudit` - Read-only access to security-related resources
  - `ViewOnlyAccess` - Read-only access to most AWS resources

- **Custom Policies**:
  - Organizations management access
  - Cross-account role assumption
  - Enhanced security service access (GuardDuty, SecurityHub, etc.)

## 🛠️ Customization Options

### Modify Branch Access
To allow access from all branches instead of just main:
```yaml
# In github-oidc-cloudformation.yaml
Parameters:
  AllowAllBranches:
    Default: 'true'  # Change to true
```

### Add Additional Repositories
To allow multiple repositories to use the same role:
```yaml
# Modify the trust policy condition
StringLike:
  token.actions.githubusercontent.com:sub:
    - "repo:owner/repo1:ref:refs/heads/main"
    - "repo:owner/repo2:ref:refs/heads/main"
```

### Extend Permissions
Add additional permissions to the custom policy:
```yaml
- Effect: Allow
  Action:
    - "service:DescribeResource"
    - "service:ListResources"
  Resource: '*'
```

## 🔍 Troubleshooting

### Common Issues

**1. Stack creation fails with "CAPABILITY_NAMED_IAM required"**
```bash
# Add the capability flag
--capabilities CAPABILITY_NAMED_IAM
```

**2. "User is not authorized to perform iam:CreateRole"**
```bash
# Ensure your user has IAM permissions:
- iam:CreateRole
- iam:AttachRolePolicy  
- iam:PutRolePolicy
- iam:CreateOpenIDConnectProvider
```

**3. GitHub Actions can't assume role**
- Check repository variable `AWS_ROLE_ARN` is set correctly
- Verify repository name matches trust policy exactly
- Ensure workflow has `permissions: id-token: write`

### Validation Commands

```bash
# Check OIDC provider exists
aws iam list-open-id-connect-providers

# Check role configuration
aws iam get-role --role-name GitHubActionsCSPMRole

# View trust policy
aws iam get-role --role-name GitHubActionsCSPMRole \
  --query 'Role.AssumeRolePolicyDocument'
```

## 🗑️ Cleanup

To remove the infrastructure:

```bash
# Delete member account stacks
aws cloudformation delete-stack --stack-name csmp-member-role

# Delete master account stack  
aws cloudformation delete-stack --stack-name github-oidc-cspm
```

## 📊 Cost Considerations

These templates create IAM resources which are **free** in AWS. The only potential costs are:
- CloudTrail data events (if enabled)
- AWS Config (if used for compliance checking)
- Support API calls (if using premium support)

The OIDC setup itself has no direct costs and provides enhanced security over access keys.

---

## 🎯 Next Steps

1. **Deploy the templates** using your preferred method
2. **Configure GitHub variables** with the role ARN
3. **Test authentication** using the provided scripts
4. **Run your first workflow** to validate end-to-end functionality
5. **Schedule regular scans** for ongoing security monitoring

Your CloudFormation-deployed infrastructure will provide secure, scalable, and maintainable GitHub Actions integration with AWS! 🚀