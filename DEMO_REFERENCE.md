# 🎬 AWS CSPM Demo - Quick Reference Card

## ⚡ Quick Demo Commands (Copy-Paste Ready)

### 1. Pre-Demo Check (30 seconds)
```powershell
# Verify demo readiness
python prepare_demo.py
```

### 2. AWS Connection Test (30 seconds)
```powershell
# Show AWS connectivity  
python test_aws_connection.py
```

### 3. Live Security Scan (3 minutes)
```powershell
# Run complete CSPM scan
python run_cspm_scan.py
```

### 4. Open Interactive Dashboard (Instant)
```powershell
# Open latest report
Get-ChildItem "reports\*.html" | Sort-Object LastWriteTime -Descending | Select-Object -First 1 | ForEach-Object { Start-Process $_.FullName }
```

---

## 📊 Expected Demo Results

| Metric | Expected Value | Demo Talking Point |
|--------|---------------|--------------------|
| **Total Findings** | ~67 | "Comprehensive security assessment" |
| **Critical** | ~8 | "Immediate action required" |
| **High** | ~20 | "High-priority vulnerabilities" |
| **Medium** | ~24 | "Configuration improvements" |
| **Services Scanned** | 4 (IAM/EC2/S3/VPC) | "Multi-service coverage" |
| **Compliance Frameworks** | 16+ | "CIS, NIST, PCI-DSS mapping" |
| **Scan Time** | 2-3 minutes | "Fast automated assessment" |

---

## 🎯 Key Demo Messages

### **Opening Hook** (30 seconds)
*"I'll demonstrate how we can scan an entire AWS environment for security vulnerabilities in under 3 minutes and generate an interactive compliance dashboard."*

### **Value Propositions** (Throughout demo)
- ✅ **"Zero manual work"** - Fully automated security assessment
- ✅ **"Multi-framework compliance"** - CIS, NIST, PCI-DSS in one scan  
- ✅ **"Actionable intelligence"** - Specific resources and remediation
- ✅ **"Executive dashboards"** - Interactive charts for stakeholders
- ✅ **"Production ready"** - Scales to enterprise organizations

### **Technical Highlights** (For technical audience)
- ⚡ **Async processing** - Parallel scanning across services
- 🔧 **11+ security rules** - Production-grade compliance engine
- 📊 **Modern web UI** - Responsive HTML5 with filtering
- 🔗 **CI/CD ready** - GitHub Actions integration

### **Closing Statement** (30 seconds)
*"This solution transforms security auditing from a manual, weeks-long process into automated, continuous monitoring with enterprise-grade reporting."*

---

## 🎬 Demo Flow Cheat Sheet

| Phase | Duration | Key Actions | Talking Points |
|-------|----------|-------------|----------------|
| **Setup** | 30s | `python test_aws_connection.py` | "Let's verify connectivity..." |
| **Scan** | 3min | `python run_cspm_scan.py` | "Now scanning for vulnerabilities..." |
| **Results** | 5min | Open HTML report | "Here's our interactive dashboard..." |
| **Features** | 5min | Demo filtering/charts | "Notice the compliance mapping..." |
| **Q&A** | 5min | Address questions | "How could this fit your workflow?" |

---

## 🚨 Demo Troubleshooting

### If AWS connection fails:
```powershell
aws configure list
aws sts get-caller-identity
$env:AWS_PROFILE = "default"
```

### If scan shows 0 findings:
- Check the latest report file timestamp
- Verify account has resources to scan
- Re-run with: `python run_cspm_scan.py`

### If report doesn't open:
```powershell
# Manually open latest report
cd reports
Get-ChildItem "*.html" | Sort-Object LastWriteTime -Descending | Select-Object -First 1 | Invoke-Item
```

---

## 📱 Audience-Specific Adaptations

### **For Security Teams:**
- Emphasize compliance frameworks (CIS, NIST, PCI-DSS)
- Show filtering by Critical/High severity
- Discuss remediation workflows

### **For DevOps Teams:**
- Highlight GitHub Actions integration
- Show command-line automation
- Discuss CI/CD pipeline integration

### **For Management:**
- Focus on executive dashboard
- Emphasize cost savings vs manual audits
- Show compliance scoring

### **For Architects:**
- Discuss scalability (multi-account, multi-region)
- Show extensibility (custom rules)
- Highlight AWS service coverage

---

## ⏰ Time Management

- **5-minute demo**: Test connection → Run scan → Show dashboard summary
- **10-minute demo**: Add compliance overview and filtering demo
- **15-minute demo**: Include architecture explanation and Q&A
- **20-minute demo**: Deep dive into findings and remediation workflow

---

*Keep this reference card open during your demo for quick command lookup!*