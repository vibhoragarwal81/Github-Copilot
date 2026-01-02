# 🔧 AWS Credentials Troubleshooting Guide

## ❌ **Error: InvalidClientTokenId - The security token included in the request is invalid**

This error typically occurs when AWS CLI cannot authenticate with your provided credentials. Let's systematically resolve this issue.

---

## 🔍 **Step-by-Step Diagnosis**

### **Step 1: Verify AWS CLI Configuration**
```powershell
# Check which AWS CLI version you're using
aws --version

# Check current AWS configuration
aws configure list

# Check configured profiles  
aws configure list-profiles

# Check what AWS thinks about your current identity
aws sts get-caller-identity --debug
```

### **Step 2: Check Credential File Locations**
```powershell
# Check if credential files exist and have correct content
Get-Content "$env:USERPROFILE\.aws\credentials"
Get-Content "$env:USERPROFILE\.aws\config"

# Check environment variables that might override
Get-ChildItem env: | Where-Object Name -like "*AWS*"
```

### **Step 3: Verify Credential Format**
Your `~/.aws/credentials` file should look like this:
```ini
[default]
aws_access_key_id = AKIAIOSFODNN7EXAMPLE
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY

[profile-name]
aws_access_key_id = AKIAI44QH8DHBEXAMPLE  
aws_secret_access_key = je7MtGbClwBF/2Zp9Utk/h3yCo8nvbEXAMPLEKEY
```

Your `~/.aws/config` file should look like this:
```ini
[default]
region = us-east-1
output = json

[profile profile-name]
region = us-west-2
output = json
```

---

## 🛠️ **Common Fixes**

### **Fix 1: Reconfigure AWS CLI**
```powershell
# Reconfigure default profile
aws configure

# When prompted, enter:
# AWS Access Key ID: [Your actual access key]
# AWS Secret Access Key: [Your actual secret key]  
# Default region name: us-east-1
# Default output format: json

# Test immediately after configuration
aws sts get-caller-identity
```

### **Fix 2: Use Specific Profile**
```powershell
# If you have multiple profiles, specify one explicitly
aws configure --profile my-profile

# Test with specific profile
aws sts get-caller-identity --profile my-profile

# Set a specific profile as default for current session
$env:AWS_PROFILE = "my-profile"
aws sts get-caller-identity
```

### **Fix 3: Use Environment Variables**
```powershell
# Set environment variables (replace with your actual values)
$env:AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
$env:AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
$env:AWS_DEFAULT_REGION = "us-east-1"

# Clear any conflicting profile setting
$env:AWS_PROFILE = $null

# Test
aws sts get-caller-identity
```

### **Fix 4: Clear Cached Credentials**
```powershell
# Remove existing credential files to start fresh
Remove-Item "$env:USERPROFILE\.aws\credentials" -ErrorAction SilentlyContinue
Remove-Item "$env:USERPROFILE\.aws\config" -ErrorAction SilentlyContinue

# Clear environment variables
$env:AWS_ACCESS_KEY_ID = $null
$env:AWS_SECRET_ACCESS_KEY = $null  
$env:AWS_SESSION_TOKEN = $null
$env:AWS_PROFILE = $null

# Reconfigure from scratch
aws configure
```

---

## 🔐 **Advanced Troubleshooting**

### **Issue 1: Using Temporary Credentials**
If you're using AWS SSO or temporary credentials:
```powershell
# For AWS SSO
aws configure sso
aws sso login
aws sts get-caller-identity

# For assumed role credentials (they include session token)
$env:AWS_ACCESS_KEY_ID = "ASIAIOSFODNN7EXAMPLE"       # Note: ASIA prefix
$env:AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
$env:AWS_SESSION_TOKEN = "FQoDYXdzEJr...long-session-token...EXAMPLEKEy"
```

### **Issue 2: Clock Synchronization**
AWS requires accurate system time:
```powershell
# Sync your system clock
w32tm /resync

# Verify current time
Get-Date

# Check if time is significantly off from UTC
```

### **Issue 3: Corporate Network/Proxy**
If you're behind a corporate firewall:
```powershell
# Set proxy for AWS CLI (if needed)
$env:HTTP_PROXY = "http://proxy.company.com:8080"
$env:HTTPS_PROXY = "http://proxy.company.com:8080"

# Or configure in AWS CLI
aws configure set http_proxy http://proxy.company.com:8080
aws configure set https_proxy http://proxy.company.com:8080
```

### **Issue 4: Region-Specific Issues**
```powershell
# Try with explicit region
aws sts get-caller-identity --region us-east-1

# Or set region explicitly
aws configure set region us-east-1
```

---

## 🎯 **Specific Solutions by Error Pattern**

### **"The security token included in the request is invalid"**
- ✅ **Most Common**: Incorrect access key or secret key
- ✅ **Solution**: Double-check credentials in AWS Console → IAM → Users → Your User → Security credentials

### **"Invalid AWS Access Key ID"**
- ✅ **Cause**: Access key doesn't exist or was deleted
- ✅ **Solution**: Create new access key in AWS Console

### **"SignatureDoesNotMatch"**
- ✅ **Cause**: Incorrect secret access key or clock skew
- ✅ **Solution**: Verify secret key and sync system time

### **"Token has expired"**
- ✅ **Cause**: Using temporary credentials that expired
- ✅ **Solution**: Refresh credentials or use long-term keys

---

## 🧪 **Validation Steps for CSPM**

Once AWS CLI is working, validate for CSPM usage:

### **Step 1: Test Basic AWS Access**
```powershell
# These commands should all work for CSPM scanning:
aws sts get-caller-identity
aws iam get-account-summary
aws ec2 describe-regions
aws s3 ls
```

### **Step 2: Test Required Permissions**
```powershell
# Test IAM permissions (for IAM scanner)
aws iam list-users
aws iam list-roles  
aws iam list-policies --scope Local

# Test EC2 permissions (for EC2 scanner)
aws ec2 describe-instances
aws ec2 describe-security-groups
aws ec2 describe-volumes

# Test VPC permissions (for VPC scanner) 
aws ec2 describe-vpcs
aws ec2 describe-subnets
aws ec2 describe-route-tables

# Test S3 permissions (for S3 scanner)
aws s3api list-buckets
```

### **Step 3: Test CSPM Scanner**
```powershell
# Navigate to your CSPM directory
Set-Location "C:\Users\vagarw35\Documents\Technical documents\Technologies\Github\Github Copilot"

# Activate virtual environment
.\.venv\Scripts\Activate.ps1

# Test the scanner with minimal configuration
python -c "
from src.utils.aws_client import AWSClientManager
from src.utils.config import Config

config = Config({'aws': {'regions': ['us-east-1']}})
client_manager = AWSClientManager(config)
client = client_manager.get_client('sts', 'us-east-1')
identity = client.get_caller_identity()
print('✅ CSPM AWS connection successful!')
print(f'Account: {identity.get(\"Account\")}')
print(f'User: {identity.get(\"Arn\")}')
"
```

---

## 🚨 **Quick Fix Commands**

### **If you need to start completely fresh:**
```powershell
# 1. Clear everything
Remove-Item "$env:USERPROFILE\.aws" -Recurse -Force -ErrorAction SilentlyContinue
Get-ChildItem env: | Where-Object Name -like "*AWS*" | Remove-Item

# 2. Reconfigure with your actual credentials
aws configure
# Enter your actual Access Key ID
# Enter your actual Secret Access Key  
# Enter us-east-1 for region
# Enter json for output format

# 3. Test immediately
aws sts get-caller-identity
```

### **If you're using multiple AWS accounts:**
```powershell
# Configure named profiles for each account
aws configure --profile account1
aws configure --profile account2

# Test specific profiles
aws sts get-caller-identity --profile account1
aws sts get-caller-identity --profile account2

# Use specific profile for CSPM
$env:AWS_PROFILE = "account1"
```

---

## 📋 **Checklist Before Running CSPM**

Before running the CSMP scanner, ensure:

- [ ] ✅ `aws sts get-caller-identity` returns valid account info
- [ ] ✅ `aws iam get-account-summary` works (tests IAM permissions)  
- [ ] ✅ `aws ec2 describe-regions` works (tests EC2 permissions)
- [ ] ✅ `aws s3 ls` works (tests S3 permissions)
- [ ] ✅ System clock is accurate (within 5 minutes of UTC)
- [ ] ✅ No conflicting environment variables set
- [ ] ✅ Network connectivity to AWS APIs (no proxy issues)

---

## 🆘 **Still Having Issues?**

### **Get Detailed Debug Information:**
```powershell
# Run with full debug logging
aws sts get-caller-identity --debug > aws-debug.log 2>&1
Get-Content aws-debug.log

# Check exact credential source being used
aws configure list
aws configure list-profiles
```

### **Create Fresh Test User:**
If you suspect the current user has issues:

1. **In AWS Console:**
   - Go to IAM → Users → Create User
   - Attach policy: `PowerUserAccess` or `ReadOnlyAccess`
   - Generate new access key

2. **Test with new credentials:**
   ```powershell
   aws configure --profile test-user
   aws sts get-caller-identity --profile test-user
   ```

### **Verify Account Status:**
- Check if your AWS account is active (not suspended)
- Verify billing information is up to date
- Ensure you're not hitting service limits

---

## 🎉 **Success Validation**

When everything is working, you should see:
```powershell
PS> aws sts get-caller-identity
{
    "UserId": "AIDACKCEVSQ6C2EXAMPLE", 
    "Account": "123456789012",
    "Arn": "arn:aws:iam::123456789012:user/username"
}
```

**Once this works, your CSMP scanner will be able to authenticate and scan your AWS environment successfully!** 🚀