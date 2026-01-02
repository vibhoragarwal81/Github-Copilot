# Setting Up AWS CSPM Scanner for Different Organizations

This guide helps you adapt the AWS CSPM security scanner to work with different AWS Organizations, account structures, and organizational requirements.

## 🏢 Organization Types and Configurations

### 1. Single Organization (Standard Setup)

**Characteristics**:
- One AWS Organization with centralized management
- Consistent role naming across accounts
- Standard AWS Organizations features enabled

**Configuration**:
```yaml
# config/config.yaml
aws:
  default_region: us-east-1
  organization_role_name: CSPMScanRole
  external_id: csmp-security-scan
  assume_role_method: organization_access

organization:
  type: single
  management_account: auto-detect
  member_account_discovery: organizations_api
```

**Setup Steps**:
1. Deploy from the management account
2. Use automated cross-account role deployment
3. Run organization-wide scans directly

### 2. Multi-Organization (Holding Company)

**Characteristics**:
- Multiple independent AWS Organizations
- Different management accounts per organization
- Requires cross-organization coordination

**Configuration**:
```yaml
# config/config_multi_org.yaml
aws:
  organizations:
    - name: prod_org
      management_account: "111111111111"
      role_name: CSPMScanRole
      external_id: prod-cspm-scan
      regions: [us-east-1, us-west-2]
    
    - name: dev_org
      management_account: "222222222222"
      role_name: CSPMScanRole
      external_id: dev-cspm-scan
      regions: [us-east-1]
    
    - name: international_org
      management_account: "333333333333"
      role_name: CSPMScanRole
      external_id: intl-csmp-scan
      regions: [eu-west-1, ap-southeast-1]

scanning:
  mode: multi_organization
  max_concurrent_orgs: 3
```

**Setup Steps**:
```bash
# Deploy to each organization separately
python scripts/deploy_multi_organization.py --config config/config_multi_org.yaml

# Run cross-organization scan
python scripts/run_multi_organization_scan.py --config config/config_multi_org.yaml
```

### 3. Federated Organizations

**Characteristics**:
- Different role naming conventions
- Varying security policies per organization
- Custom trust relationships

**Configuration**:
```yaml
# config/config_federated.yaml
aws:
  federated_setup:
    central_security_account: "123456789012"
    
  organizations:
    - name: business_unit_a
      management_account: "111111111111"
      role_name: SecurityAuditRole
      trust_policy: custom
      external_id: bu-a-security-scan
      
    - name: business_unit_b
      management_account: "222222222222"
      role_name: ComplianceRole
      trust_policy: saml_federated
      external_id: bu-b-compliance-scan
```

## 🎯 Account Structure Adaptations

### Standard AWS Organizations Structure

```
Management Account (Org Root)
├── Security OU
│   ├── Security Account
│   └── Audit Account
├── Production OU
│   ├── Prod Account 1
│   └── Prod Account 2
└── Non-Production OU
    ├── Dev Account
    └── Test Account
```

**Configuration**:
```yaml
scanning:
  organizational_units:
    - name: Security
      priority: high
      scan_frequency: daily
      
    - name: Production
      priority: high
      scan_frequency: daily
      compliance_frameworks: [SOC2, PCI-DSS]
      
    - name: Non-Production
      priority: medium
      scan_frequency: weekly
```

### Enterprise Landing Zone Structure

```
Management Account
├── Core OU
│   ├── Shared Services
│   ├── Network
│   └── Identity
├── Workloads OU
│   ├── Production
│   └── Non-Production
└── Sandbox OU
    └── Individual Sandboxes
```

**Configuration**:
```yaml
scanning:
  landing_zone_config:
    core_ou:
      scan_priority: critical
      additional_checks:
        - network_security_deep_scan
        - identity_compliance_audit
        
    workloads_ou:
      scan_priority: high
      service_focus: [ec2, s3, rds, lambda]
      
    sandbox_ou:
      scan_priority: low
      scan_frequency: monthly
      lightweight_checks: true
```

### Custom Account Groupings

For organizations with non-standard structures:

```yaml
scanning:
  custom_account_groups:
    critical_accounts:
      account_ids:
        - "111111111111"  # Production
        - "222222222222"  # Shared Services
      scan_frequency: daily
      extended_checks: true
      
    development_accounts:
      account_pattern: "*-dev-*"
      scan_frequency: weekly
      basic_checks_only: true
      
    compliance_scope:
      account_tags:
        compliance_scope: pci
      frameworks: [PCI-DSS]
      scan_frequency: daily
```

## 🛡️ Different Role and Permission Models

### Option 1: Standard AWS Managed Policies

**Template**: `templates/cspm-cross-account-role.yaml`
```yaml
ManagedPolicyArns:
  - "arn:aws:iam::aws:policy/SecurityAudit"
  - "arn:aws:iam::aws:policy/job-function/ViewOnlyAccess"
```

**Use Case**: Standard security scanning with minimal custom permissions

### Option 2: Custom Minimal Permissions

**Template**: `templates/cspm-minimal-permissions-role.yaml`
```yaml
Policies:
  - PolicyName: CSPMMinimalAccess
    PolicyDocument:
      Version: '2012-10-17'
      Statement:
        - Effect: Allow
          Action:
            - iam:List*
            - iam:Get*
            - ec2:Describe*
            - s3:GetBucket*
            - s3:ListBucket*
          Resource: "*"
```

**Use Case**: Organizations requiring minimal necessary permissions

### Option 3: Enhanced Security Scanning

**Template**: `templates/csmp-enhanced-role.yaml`
```yaml
Policies:
  - PolicyName: CSPMEnhancedAccess
    PolicyDocument:
      Version: '2012-10-17'
      Statement:
        - Effect: Allow
          Action:
            - "*:List*"
            - "*:Describe*"
            - "*:Get*"
            - "config:SelectResourceConfig"
            - "cloudtrail:LookupEvents"
          Resource: "*"
```

**Use Case**: Comprehensive security and compliance scanning

### Option 4: Compliance-Specific Permissions

**PCI-DSS Template**: `templates/cspm-pci-role.yaml`
```yaml
Policies:
  - PolicyName: PCIComplianceAccess
    PolicyDocument:
      Statement:
        - Effect: Allow
          Action:
            - "ec2:Describe*"
            - "s3:GetEncryption*"
            - "kms:Describe*"
            - "cloudtrail:Describe*"
            - "vpc:Describe*"
          Resource: "*"
```

## 🌍 Regional Deployment Strategies

### Single Region (Cost-Optimized)

```yaml
aws:
  regions:
    - us-east-1
    
scanning:
  regional_strategy: single_region
  primary_region: us-east-1
```

### Multi-Region (Global Organizations)

```yaml
aws:
  regions:
    - us-east-1      # US East
    - us-west-2      # US West
    - eu-west-1      # Europe
    - ap-southeast-1 # Asia Pacific

scanning:
  regional_strategy: multi_region
  region_priority:
    - us-east-1      # Primary business region
    - eu-west-1      # Secondary business region
    - us-west-2
    - ap-southeast-1
```

### Compliance-Driven Regional Selection

```yaml
aws:
  compliance_regions:
    gdpr:
      - eu-west-1
      - eu-central-1
    ccpa:
      - us-west-1
      - us-west-2
    apac_privacy:
      - ap-southeast-1
      - ap-northeast-1

scanning:
  regional_strategy: compliance_based
  map_accounts_to_regions: true
```

## 🔧 Custom Deployment Scripts

### For Non-Standard Role Names

Create `scripts/deploy_custom_roles.py`:

```python
import boto3
from botocore.exceptions import ClientError

def deploy_custom_role(account_id, role_name, template_path):
    """Deploy custom role to specific account."""
    
    # Assume organization access role
    sts_client = boto3.client('sts')
    
    assumed_role = sts_client.assume_role(
        RoleArn=f"arn:aws:iam::{account_id}:role/OrganizationAccountAccessRole",
        RoleSessionName="CSPMDeployment"
    )
    
    # Create CloudFormation client with assumed credentials
    cf_client = boto3.client(
        'cloudformation',
        aws_access_key_id=assumed_role['Credentials']['AccessKeyId'],
        aws_secret_access_key=assumed_role['Credentials']['SecretAccessKey'],
        aws_session_token=assumed_role['Credentials']['SessionToken']
    )
    
    # Read and customize template
    with open(template_path, 'r') as f:
        template_body = f.read()
    
    # Deploy stack
    try:
        cf_client.create_stack(
            StackName=f'CSPM-{role_name}',
            TemplateBody=template_body,
            Parameters=[
                {
                    'ParameterKey': 'RoleName',
                    'ParameterValue': role_name
                },
                {
                    'ParameterKey': 'ExternalId',
                    'ParameterValue': f'cspm-{account_id}'
                }
            ],
            Capabilities=['CAPABILITY_NAMED_IAM']
        )
        print(f"✅ Successfully deployed {role_name} to account {account_id}")
        
    except ClientError as e:
        print(f"❌ Failed to deploy to account {account_id}: {e}")
```

### For Organizations Without OrganizationAccountAccessRole

Create `scripts/deploy_via_assumed_roles.py`:

```python
def deploy_via_custom_roles(accounts_config):
    """Deploy when each account has different assume role setup."""
    
    for account in accounts_config:
        try:
            # Each account may have different role name
            role_arn = account.get('assume_role_arn')
            external_id = account.get('external_id')
            
            assumed_role = sts_client.assume_role(
                RoleArn=role_arn,
                RoleSessionName="CSPMDeployment",
                ExternalId=external_id
            )
            
            # Deploy CSMP role with custom parameters
            deploy_csmp_role(account, assumed_role['Credentials'])
            
        except Exception as e:
            print(f"Failed to deploy to {account['id']}: {e}")
```

## 📊 Organization-Specific Reporting

### Executive Dashboard Customization

```yaml
reporting:
  executive_dashboard:
    organization_name: "Acme Corporation"
    logo_url: "https://company.com/logo.png"
    
    key_metrics:
      - total_accounts
      - critical_findings_trend
      - compliance_score
      - remediation_velocity
    
    stakeholder_views:
      ciso:
        focus: [critical_findings, compliance_posture]
        frequency: weekly
        
      security_team:
        focus: [all_findings, remediation_tracking]
        frequency: daily
        
      account_owners:
        focus: [account_specific_findings]
        frequency: daily
        delivery: account_filtered_reports
```

### Custom Compliance Frameworks

```yaml
# config/custom_compliance.yaml
compliance_frameworks:
  company_security_policy:
    name: "Acme Security Standards"
    version: "2.0"
    controls:
      - control_id: "ACME-001"
        name: "MFA Enforcement"
        mapping:
          - rule_id: "iam_mfa_enabled_for_console_access"
          - rule_id: "iam_mfa_enabled_for_root"
        
      - control_id: "ACME-002"
        name: "Data Encryption"
        mapping:
          - rule_id: "s3_bucket_encryption_enabled"
          - rule_id: "ebs_encryption_enabled"
```

### Multi-Tenant Reporting

For managed service providers scanning multiple client organizations:

```yaml
reporting:
  multi_tenant:
    enabled: true
    
    client_organizations:
      - name: "Client A"
        organization_ids: ["o-123456789a"]
        branding:
          primary_color: "#FF6B35"
          logo: "client-a-logo.png"
        
      - name: "Client B"
        organization_ids: ["o-123456789b"]
        branding:
          primary_color: "#004225"
          logo: "client-b-logo.png"
    
    report_isolation: true
    cross_client_analytics: false
```

## 🔄 Migration Between Configurations

### From Single Account to Organization

1. **Backup existing configuration**:
   ```bash
   cp config/config.yaml config/config_single_account_backup.yaml
   ```

2. **Update configuration for organization**:
   ```yaml
   # Update config/config.yaml
   scanning:
     mode: organization
     single_account_mode: false
   ```

3. **Deploy cross-account roles**:
   ```bash
   python scripts/deploy_via_organization_role.py --accounts all
   ```

4. **Test organization scan**:
   ```bash
   python scripts/run_organization_scan.py --test-mode
   ```

### From Basic to Enhanced Permissions

1. **Update CloudFormation template**:
   ```bash
   cp templates/cspm-cross-account-role.yaml templates/cspm-enhanced-role.yaml
   ```

2. **Update role permissions in template**

3. **Redeploy roles**:
   ```bash
   python scripts/deploy_via_organization_role.py --update-existing --accounts all
   ```

### From Standard to Compliance-Specific Setup

1. **Configure compliance frameworks**:
   ```yaml
   # Add to config/config.yaml
   compliance:
     frameworks:
       - PCI-DSS
       - SOC-2
     
   scanning:
     compliance_focused: true
   ```

2. **Deploy compliance-specific roles**:
   ```bash
   python scripts/deploy_compliance_roles.py --framework PCI-DSS
   ```

## 🐛 Organization-Specific Troubleshooting

### Issue: Different AWS Partition (GovCloud/China)

**Problem**: Standard ARNs don't work in AWS GovCloud or China regions

**Solution**:
```yaml
aws:
  partition: aws-us-gov  # or aws-cn
  managed_policies:
    security_audit: "arn:aws-us-gov:iam::aws:policy/SecurityAudit"
    view_only: "arn:aws-us-gov:iam::aws:policy/job-function/ViewOnlyAccess"
```

### Issue: Organization with Suspended Accounts

**Problem**: Scan failures on suspended accounts

**Solution**:
```yaml
scanning:
  account_filters:
    include_suspended: false
    status_check_before_scan: true
    skip_inaccessible: true
```

### Issue: Rate Limiting in Large Organizations

**Problem**: API rate limiting with 100+ accounts

**Solution**:
```yaml
scanning:
  rate_limiting:
    max_concurrent_accounts: 5
    inter_account_delay: 2  # seconds
    retry_backoff: exponential
    max_retries: 5
```

### Issue: Custom SCP Restrictions

**Problem**: Service Control Policies block scanning actions

**Solution**:
```yaml
# Identify restricted actions
troubleshooting:
  scp_analysis:
    enabled: true
    alternative_actions:
      iam_list_users: "organizations:DescribeAccount"  # Use alternative APIs
```

## 📚 Configuration Examples

### Large Enterprise (1000+ accounts)
- [View configuration example](examples/large_enterprise_config.yaml)

### Government Organization (GovCloud)
- [View configuration example](examples/govcloud_config.yaml)

### Financial Services (PCI/SOX)
- [View configuration example](examples/financial_services_config.yaml)

### Healthcare Organization (HIPAA)
- [View configuration example](examples/healthcare_config.yaml)

### Managed Service Provider (Multi-Tenant)
- [View configuration example](examples/msp_config.yaml)

---

## 📞 Support and Professional Services

For assistance setting up the CSMP scanner for your specific organization:

- **Community Support**: GitHub Issues
- **Professional Implementation**: Contact implementation services
- **Custom Development**: Dedicated development team for unique requirements

**Common Professional Services Requests**:
- Large-scale organization deployment (500+ accounts)
- Custom compliance framework integration
- SIEM integration and alerting setup
- Advanced multi-organization management
- Custom security rules development

---

Need help with your specific organization setup? Create a GitHub issue with your organization structure and requirements.