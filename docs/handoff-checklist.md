# CSPM OIDC Setup Package for New Organizations

## 📦 Package Contents

This package contains everything needed for new AWS organizations to set up secure CSPM scanning:

```
csmp-setup-package/
├── acquired-entity-oidc-setup.yaml     # CloudFormation template
├── SETUP-GUIDE.md                      # Step-by-step setup instructions  
└── HANDOFF-CHECKLIST.md               # This checklist
```

## ✅ Handoff Checklist

### For CSMP Team (You)

**Before providing to new entity:**
- [ ] Verify template parameters are correct
- [ ] Update GitHub org/repo names if needed
- [ ] Customize organization name parameter
- [ ] Test template in sandbox environment
- [ ] Prepare any specific scanning requirements

**Information to collect from new entity:**
- [ ] AWS Account ID (management/organization account)
- [ ] Organization name for tagging
- [ ] Preferred IAM role name (default: CSPMScannerRole)
- [ ] Technical contact information
- [ ] Preferred scanning schedule/frequency

### For New AWS Organization

**Prerequisites:**
- [ ] AWS Organizations enabled in management account
- [ ] Administrator access to AWS Console or AWS CLI
- [ ] Technical contact familiar with CloudFormation

**Setup steps:**
- [ ] Download CloudFormation template
- [ ] Deploy template via AWS Console or CLI
- [ ] Verify stack deployment successful
- [ ] Copy Role ARN from stack outputs
- [ ] Provide Role ARN and account details to CSMP team
- [ ] Confirm first scan completed successfully

**Information to provide back:**
- [ ] Role ARN: `arn:aws:iam::ACCOUNT:role/ROLENAME`
- [ ] AWS Account ID: `123456789012`
- [ ] Organization name: `Company Name`
- [ ] Technical contact: `name@company.com`
- [ ] Preferred scan schedule: `Daily/Weekly/Monthly`

## 📋 Template Parameters

| Parameter | Description | Default | Notes |
|-----------|-------------|---------|-------|
| `GitHubOrganization` | GitHub org with CSMP scanner | `vibhoragarwal81` | Don't change |
| `GitHubRepository` | CSMP scanner repository | `Github-Copilot` | Don't change |
| `CSPMRoleName` | Name for IAM role | `CSPMScannerRole` | Can customize |
| `AllowedBranches` | Branch access control | `main` | Recommend main only |
| `OrganizationName` | Entity name for tagging | `AcquiredEntity` | Customize per entity |

## 🔒 Security Assurance

**For new organizations to understand:**

- ✅ **Read-only access** - Cannot modify any AWS resources
- ✅ **Temporary credentials** - No permanent keys, tokens expire in 1 hour
- ✅ **Repository-specific** - Only specified GitHub repo can access
- ✅ **Auditable** - All access logged in CloudTrail
- ✅ **Revocable** - Can be disabled by deleting CloudFormation stack
- ✅ **Standard permissions** - Uses AWS SecurityAudit managed policy

## 🎯 Expected Outcomes

**After successful setup:**
- CSMP team can discover all AWS accounts in the organization
- Automated security scans begin according to agreed schedule
- HTML security reports generated and accessible
- Security posture tracked over time
- Compliance gaps identified and reported

## 📞 Support Contacts

**For setup assistance:**
- Technical support: [Your technical contact]
- Template issues: [Your GitHub repository issues]

**For ongoing scanning:**
- Report access: [Your reporting system]
- Finding remediation: [Your security team contact]

## ⏱️ Timeline

| Phase | Duration | Responsibility |
|-------|----------|----------------|
| Template deployment | 5 minutes | New organization |
| Role ARN handoff | 1 day | New organization |
| GitHub configuration | 30 minutes | CSMP team |
| First scan validation | 1 day | Both teams |
| Regular scanning starts | Immediate | Automated |

## 🔄 Ongoing Relationship

**Monthly:**
- [ ] Review security reports
- [ ] Address critical findings
- [ ] Update scanning scope if needed

**Quarterly:**
- [ ] Review access permissions
- [ ] Validate compliance status
- [ ] Assess new requirements

**As needed:**
- [ ] Update IAM roles for new accounts
- [ ] Modify scanning frequency
- [ ] Add custom compliance checks

---

## 📋 Success Criteria

Setup is complete when:
- ✅ CloudFormation stack deployed successfully
- ✅ Role ARN provided to CSMP team  
- ✅ GitHub Actions can assume the role
- ✅ Organization accounts discovered
- ✅ First security scan completes
- ✅ HTML report generated
- ✅ Technical contacts established

🎉 **Ready for ongoing security monitoring!**