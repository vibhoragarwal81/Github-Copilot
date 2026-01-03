#!/usr/bin/env python3
"""
CSPM Setup Package Generator

Creates a distribution package for new AWS organizations/acquired entities.
This package contains everything needed for quick OIDC setup.
"""

import os
import shutil
import zipfile
import sys
from datetime import datetime
from pathlib import Path


def create_setup_package(output_dir: str = "cspm-setup-package"):
    """Create a setup package for new organizations."""
    
    print("📦 Creating CSPM Setup Package for New Organizations...")
    
    # Get the project root directory
    script_dir = Path(__file__).parent
    project_root = script_dir.parent
    
    # Create package directory
    package_dir = project_root / output_dir
    if package_dir.exists():
        shutil.rmtree(package_dir)
    package_dir.mkdir()
    
    print(f"   📁 Package directory: {package_dir}")
    
    # Files to include in the package
    files_to_copy = [
        {
            'source': project_root / 'templates' / 'acquired-entity-oidc-setup.yaml',
            'dest': package_dir / 'acquired-entity-oidc-setup.yaml',
            'required': True
        },
        {
            'source': project_root / 'docs' / 'acquired-entity-setup-guide.md',
            'dest': package_dir / 'SETUP-GUIDE.md',
            'required': True
        },
        {
            'source': project_root / 'docs' / 'handoff-checklist.md',
            'dest': package_dir / 'HANDOFF-CHECKLIST.md',
            'required': True
        }
    ]
    
    # Copy files to package
    for file_info in files_to_copy:
        source = file_info['source']
        dest = file_info['dest']
        
        if source.exists():
            shutil.copy2(source, dest)
            print(f"   ✅ Copied: {source.name}")
        elif file_info['required']:
            print(f"   ❌ Required file missing: {source}")
            return False
        else:
            print(f"   ⚠️  Optional file missing: {source}")
    
    # Create a README for the package
    readme_content = f"""# CSMP OIDC Setup Package

**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

## 🎯 Purpose

This package enables new AWS organizations to quickly set up secure OIDC authentication for CSMP scanning.

## 📁 Contents

- `acquired-entity-oidc-setup.yaml` - CloudFormation template for OIDC setup
- `SETUP-GUIDE.md` - Complete step-by-step deployment instructions
- `HANDOFF-CHECKLIST.md` - Checklist for smooth handoff process

## 🚀 Quick Start

1. **AWS Organization Admin:** Deploy the CloudFormation template
2. **Copy Role ARN:** From CloudFormation outputs
3. **Provide to CSMP Team:** Role ARN and organization details
4. **Verify:** First scan completes successfully

## 📞 Support

For assistance with setup or scanning:
- GitHub Repository: https://github.com/vibhoragarwal81/Github-Copilot
- Technical Issues: Create issue in the repository

---

**Ready to secure your AWS organization!** 🔐
"""
    
    readme_file = package_dir / 'README.md'
    with open(readme_file, 'w', encoding='utf-8') as f:
        f.write(readme_content)
    
    print(f"   ✅ Created: README.md")
    
    # Create a simple validation script
    validation_script = f"""#!/bin/bash
# CSMP Setup Validation Script

echo "🔍 CSMP Setup Package Validation"
echo "================================"

# Check required files
echo "📋 Checking package contents..."

files=("acquired-entity-oidc-setup.yaml" "SETUP-GUIDE.md" "HANDOFF-CHECKLIST.md")
all_present=true

for file in "${{files[@]}}"; do
    if [ -f "$file" ]; then
        echo "  ✅ $file"
    else
        echo "  ❌ $file - MISSING"
        all_present=false
    fi
done

if [ "$all_present" = true ]; then
    echo "🎉 Package validation successful!"
    echo "📦 Ready for deployment to new AWS organization"
else
    echo "❌ Package validation failed - missing required files"
    exit 1
fi

echo ""
echo "📋 Next Steps:"
echo "1. Provide this package to the new AWS organization"
echo "2. They deploy the CloudFormation template"
echo "3. They provide the Role ARN back to you"
echo "4. Configure GitHub repository variable with the Role ARN"
echo "5. Start CSMP scanning!"
"""
    
    validation_file = package_dir / 'validate-package.sh'
    with open(validation_file, 'w', encoding='utf-8') as f:
        f.write(validation_script)
    
    # Make validation script executable (on Unix systems)
    if os.name != 'nt':
        validation_file.chmod(0o755)
    
    print(f"   ✅ Created: validate-package.sh")
    
    # Create deployment examples
    examples_content = f"""# Deployment Examples

## AWS Console Deployment

1. Download `acquired-entity-oidc-setup.yaml`
2. Go to CloudFormation Console
3. Create Stack → Upload Template
4. Configure parameters:
   - Stack name: `csmp-oidc-setup`
   - GitHub Organization: `vibhoragarwal81`
   - GitHub Repository: `Github-Copilot`
   - Organization Name: `[Your Company]`

## AWS CLI Deployment

```bash
aws cloudformation create-stack \\
  --stack-name csmp-oidc-setup \\
  --template-body file://acquired-entity-oidc-setup.yaml \\
  --parameters \\
    ParameterKey=GitHubOrganization,ParameterValue=vibhoragarwal81 \\
    ParameterKey=GitHubRepository,ParameterValue=Github-Copilot \\
    ParameterKey=OrganizationName,ParameterValue="YourCompanyName" \\
  --capabilities CAPABILITY_NAMED_IAM
```

## Get Role ARN

```bash
aws cloudformation describe-stacks \\
  --stack-name csmp-oidc-setup \\
  --query 'Stacks[0].Outputs[?OutputKey==`RoleARNForGitHub`].OutputValue' \\
  --output text
```

## Cleanup

```bash
aws cloudformation delete-stack --stack-name csmp-oidc-setup
```
"""
    
    examples_file = package_dir / 'DEPLOYMENT-EXAMPLES.md'
    with open(examples_file, 'w', encoding='utf-8') as f:
        f.write(examples_content)
    
    print(f"   ✅ Created: DEPLOYMENT-EXAMPLES.md")
    
    # Create ZIP file for easy distribution
    zip_filename = f"{output_dir}-{datetime.now().strftime('%Y%m%d')}.zip"
    zip_path = project_root / zip_filename
    
    with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
        for root, dirs, files in os.walk(package_dir):
            for file in files:
                file_path = Path(root) / file
                arc_name = file_path.relative_to(package_dir)
                zipf.write(file_path, arc_name)
    
    print(f"   ✅ Created ZIP: {zip_filename}")
    
    # Summary
    print(f"\n🎉 Package created successfully!")
    print(f"   📁 Directory: {package_dir}")
    print(f"   📦 ZIP file: {zip_path}")
    print(f"   📋 Files included:")
    
    for file in package_dir.iterdir():
        if file.is_file():
            print(f"      • {file.name}")
    
    print(f"\n📤 Distribution options:")
    print(f"   • Share the directory: {package_dir}")
    print(f"   • Share the ZIP file: {zip_filename}")
    print(f"   • Email/upload to secure file sharing platform")
    
    print(f"\n🎯 Ready to distribute to new AWS organizations!")
    
    return True


def main():
    """Main function."""
    import argparse
    
    parser = argparse.ArgumentParser(description='Create CSMP setup package for new organizations')
    parser.add_argument('--output-dir', default='cspm-setup-package',
                        help='Output directory name (default: cspm-setup-package)')
    
    args = parser.parse_args()
    
    success = create_setup_package(args.output_dir)
    
    if success:
        print("\n✨ Package generation completed successfully!")
        sys.exit(0)
    else:
        print("\n💥 Package generation failed!")
        sys.exit(1)


if __name__ == '__main__':
    main()