# CSPM Single Account Testing Guide

## 🎯 Testing Overview

This guide helps you test the acquired entity CSPM setup on your current AWS account without affecting the organization-wide setup.

## 🧹 Step 1: Clean Up Current Setup

### 1.1 GitHub Repository
- Remove secrets: `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`  
- Remove variables: `AWS_ROLE_ARN`

### 1.2 Local Environment  
```powershell
# Clear AWS credentials and config
Remove-Item -Force "$env:USERPROFILE\.aws\credentials" -ErrorAction SilentlyContinue
Remove-Item -Force "$env:USERPROFILE\.aws\config" -ErrorAction SilentlyContinue

# Clear environment variables
$env:AWS_PROFILE = ""
$env:AWS_ACCESS_KEY_ID = ""  
$env:AWS_SECRET_ACCESS_KEY = ""
$env:AWS_DEFAULT_REGION = ""
```

### 1.3 AWS Resources (Manual - with temp admin access)
```bash
# List and remove OIDC providers
aws iam list-open-id-connect-providers
aws iam delete-open-id-connect-provider --open-id-connect-provider-arn ARN

# List and remove CSPM roles  
aws iam list-roles --query 'Roles[?contains(RoleName, `CSPM`)].RoleName'
# For each role: detach policies, delete inline policies, then delete role

# Delete CloudFormation stacks
aws cloudformation list-stacks --stack-status-filter CREATE_COMPLETE
aws cloudformation delete-stack --stack-name STACK_NAME
```

## 🧪 Step 2: Deploy Test Template

### Option A: AWS Console (Recommended)
1. **Go to CloudFormation Console**
2. **Create Stack** → Upload `cspm-single-account-test.yaml`
3. **Configure Parameters:**
   ```
   Stack name: cspm-test-setup
   GitHub Organization: vibhoragarwal81
   GitHub Repository: Github-Copilot
   CSMP Role Name: CSPMScannerRole
   Scan Scope: single-account
   Test Mode: true
   ```
4. **Deploy** (takes 2-3 minutes)

### Option B: AWS CLI
```bash
aws cloudformation create-stack \
  --stack-name csmp-test-setup \
  --template-body file://templates/cspm-single-account-test.yaml \
  --parameters \
    ParameterKey=ScanScope,ParameterValue=single-account \
    ParameterKey=TestMode,ParameterValue=true \
  --capabilities CAPABILITY_NAMED_IAM
```

## ⚙️ Step 3: Configure GitHub

### 3.1 Get Role ARN
```bash
# From CloudFormation outputs
aws cloudformation describe-stacks \
  --stack-name csmp-test-setup \
  --query 'Stacks[0].Outputs[?OutputKey==`RoleARNForGitHub`].OutputValue' \
  --output text
```

### 3.2 Set GitHub Repository Variable
1. Go to: https://github.com/vibhoragarwal81/Github-Copilot/settings/variables/actions
2. **New repository variable:**
   - Name: `AWS_ROLE_ARN`
   - Value: `arn:aws:iam::871007551509:role/CSPMScannerRole` (from step 3.1)

## 🔍 Step 4: Test Authentication

### 4.1 Local Testing (Should Fail - Expected!)
```bash
# This should fail since we removed credentials
python scripts/test_aws_auth.py
# Expected: "No AWS credentials detected" - this is good!
```

### 4.2 GitHub Actions Testing
1. **Go to Actions tab** in your repository
2. **Run "Test AWS OIDC Authentication" workflow**
3. **Expected output:**
   ```
   ✅ Authentication Method: OIDC with IAM Role
   🏷️  Role ARN: arn:aws:iam::871007551509:role/CSPMScannerRole
   ✅ AWS STS Response: (successful caller identity)
   ```

## 🎯 Step 5: Test Single Account Scanning

### 5.1 Manual Workflow Run
1. **Go to GitHub Actions** → "CSPM Scan" workflow
2. **Run workflow** with parameters:
   ```
   Scan Type: single
   AWS Account ID: current
   Services: iam,s3,ec2
   Output Format: html
   ```

### 5.2 Expected Results
- ✅ Workflow completes successfully
- ✅ OIDC authentication works
- ✅ Single account scan generates findings
- ✅ HTML report created in reports/
- ✅ No organization-wide scanning

## 📊 Step 6: Verify Single Account Mode

The scan should:
- ✅ **Only scan current account** (871007551509)
- ✅ **Not attempt organization discovery** 
- ✅ **Not try cross-account role assumption**
- ✅ **Generate report for single account only**

## 🔧 Step 7: Test Different Scenarios

### 7.1 Test Different Services
```bash
# Via workflow parameters or manual execution:
python scripts/run_workflow_scan.py \
  --scan-type single \
  --account-id current \
  --services iam \
  --output-format html,json \
  --verbose
```

### 7.2 Test Error Handling
```bash
# Test with invalid account (should fail gracefully)
python scripts/run_workflow_scan.py \
  --scan-type single \
  --account-id 999999999999
```

## ✅ Step 8: Validation Checklist

**Authentication:**
- [ ] Local AWS CLI has no credentials
- [ ] GitHub repository has only `AWS_ROLE_ARN` variable (no secrets)
- [ ] GitHub Actions can assume OIDC role successfully
- [ ] STS calls work from GitHub Actions

**Scanning:**
- [ ] Single account scan completes
- [ ] Reports generated successfully  
- [ ] No cross-account attempts
- [ ] No organization discovery attempts

**Security:**
- [ ] No permanent credentials stored anywhere
- [ ] Role has appropriate permissions (read-only)
- [ ] Session duration limited to 1 hour
- [ ] Repository-specific access only

## 🧹 Step 9: Cleanup After Testing

```bash
# Remove the test CloudFormation stack
aws cloudformation delete-stack --stack-name csmp-test-setup

# Remove GitHub repository variable
# (Go to repository settings and delete AWS_ROLE_ARN)
```

## 🚀 Step 10: Production Deployment

Once testing is successful:
1. **Create production package** for real acquired entities
2. **Use organization-scope template** for multi-account setups
3. **Deploy member account roles** for cross-account scanning
4. **Set up regular scanning schedules**

## 🆘 Troubleshooting

### Issue: OIDC authentication fails
- **Check:** Repository variable `AWS_ROLE_ARN` is set correctly
- **Check:** Role trust policy allows your exact repository
- **Check:** Workflow has `permissions: id-token: write`

### Issue: Permission denied during scan
- **Check:** Role has SecurityAudit policy attached
- **Check:** Custom policy includes necessary permissions
- **Check:** Not trying to access organization APIs in single-account mode

### Issue: No scan results
- **Check:** Account actually has resources to scan
- **Check:** Services parameter includes services that exist
- **Check:** Scan didn't fail silently (check workflow logs)

---

## 🎯 Success Criteria

Your test is successful when:
- ✅ **No local AWS credentials** needed
- ✅ **GitHub Actions authentication** works via OIDC
- ✅ **Single account scan** completes successfully  
- ✅ **Security report** generated with findings
- ✅ **No cross-account** or organization-wide attempts

🎉 **Ready to package for acquired entities!**