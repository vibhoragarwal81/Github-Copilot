# CSMP OIDC Setup for New AWS Organizations

**Welcome! This guide helps you quickly set up secure GitHub OIDC authentication for CSPM scanning in your AWS organization.**

## 📋 What This Does

This CloudFormation template sets up:
- ✅ GitHub OIDC Identity Provider in your AWS account
- ✅ IAM Role with read-only permissions for security scanning
- ✅ Secure, keyless authentication (no AWS credentials shared)
- ✅ Access restricted to specific GitHub repository only

## 🚀 Quick Setup (5 minutes)

### Option 1: AWS Console (Recommended for new entities)

1. **Download the template**
   - Save `acquired-entity-oidc-setup.yaml` to your computer

2. **Open AWS CloudFormation Console**
   - Go to [AWS CloudFormation Console](https://console.aws.amazon.com/cloudformation/)
   - Click **Create Stack** → **With new resources (standard)**

3. **Upload the template**
   - Choose **Upload a template file**
   - Click **Choose file** and select `acquired-entity-oidc-setup.yaml`
   - Click **Next**

4. **Configure parameters**
   ```
   Stack name: csmp-oidc-setup
   
   GitHub Organization/Username: vibhoragarwal81
   CSMP Scanner Repository Name: Github-Copilot
   IAM Role Name for CSMP Scanning: CSPMScannerRole
   Branch Access Control: main
   Your Organization Name: [Your Company Name]
   ```

5. **Review and create**
   - Click **Next** through remaining pages
   - ✅ Check "I acknowledge that AWS CloudFormation might create IAM resources"
   - Click **Create stack**

6. **Wait for completion**
   - Stack creation takes 2-3 minutes
   - Status will show **CREATE_COMPLETE** when finished

### Option 2: AWS CLI

```bash
aws cloudformation create-stack \
  --stack-name csmp-oidc-setup \
  --template-body file://acquired-entity-oidc-setup.yaml \
  --parameters \
    ParameterKey=GitHubOrganization,ParameterValue=vibhoragarwal81 \
    ParameterKey=GitHubRepository,ParameterValue=Github-Copilot \
    ParameterKey=OrganizationName,ParameterValue="YourCompanyName" \
  --capabilities CAPABILITY_NAMED_IAM
```

## 📤 Share Information with CSPM Team

After successful deployment:

1. **Go to CloudFormation Outputs**
   - Navigate to your stack in CloudFormation console
   - Click the **Outputs** tab

2. **Copy the Role ARN**
   - Find **RoleARNForGitHub** output
   - Copy the full ARN (looks like: `arn:aws:iam::123456789012:role/CSPMScannerRole`)

3. **Provide to CSPM team**
   - **Share**: Role ARN, Organization Name, AWS Account ID
   - **Never share**: AWS access keys, passwords, or other credentials

## 🔒 Security Features

- ✅ **Read-only access** - Cannot modify any AWS resources
- ✅ **Repository restrictions** - Only specified GitHub repository can access
- ✅ **Branch controls** - Access limited to main branch by default
- ✅ **Time limits** - Sessions automatically expire after 1 hour
- ✅ **Audit logging** - All actions logged in CloudTrail
- ✅ **No permanent credentials** - Uses temporary tokens only

## 📊 What Gets Scanned

The CSPM scanner will assess:

| Service Category | Examples |
|------------------|----------|
| **Identity & Access** | IAM users, roles, policies, MFA settings |
| **Network Security** | VPC configurations, security groups, NACLs |
| **Data Protection** | S3 bucket policies, encryption settings |
| **Monitoring** | CloudTrail, GuardDuty, SecurityHub status |
| **Compliance** | CIS benchmarks, security best practices |

## 🧪 Testing the Setup

The CSMP team can validate the setup by:
1. Running their authentication test workflow
2. Performing a sample security scan
3. Generating a test report

You should see activity in:
- **CloudTrail logs** - CSPM access events
- **AWS Organizations** - Account discovery activities

## ❓ FAQ

**Q: Will this affect our AWS costs?**
A: No direct costs. IAM roles and OIDC providers are free. Only CloudTrail logs may incur minimal storage costs.

**Q: Can the CSMP team modify our AWS resources?**
A: No. The role provides read-only access only for security assessment.

**Q: How often will scans occur?**
A: This depends on the schedule configured by the CSMP team (typically daily or weekly).

**Q: Can we revoke access later?**
A: Yes. Delete the CloudFormation stack to remove all access immediately.

**Q: What if we have multiple AWS accounts?**
A: Deploy this template in your organization's management/master account. The CSMP scanner will discover and assess all accounts automatically.

## 🆘 Support

If you need assistance:

1. **Check CloudFormation events** for any deployment errors
2. **Verify your AWS permissions** include IAM and CloudFormation access
3. **Contact the CSMP team** with your stack outputs for configuration help

## 🗑️ Cleanup

To remove CSMP access completely:
```bash
aws cloudformation delete-stack --stack-name csmp-oidc-setup
```

Or delete the stack from AWS Console.

---

## 📋 Template Information

- **Template Name**: `acquired-entity-oidc-setup.yaml`
- **Version**: 1.0.0
- **Purpose**: Quick OIDC setup for new AWS organizations
- **Maintenance**: Maintained by CSMP team

🎯 **Ready!** Your AWS organization is now configured for secure CSMP scanning!