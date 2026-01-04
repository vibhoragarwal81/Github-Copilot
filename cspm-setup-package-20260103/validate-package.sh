#!/bin/bash
# CSMP Setup Validation Script

echo "🔍 CSMP Setup Package Validation"
echo "================================"

# Check required files
echo "📋 Checking package contents..."

files=("acquired-entity-oidc-setup.yaml" "SETUP-GUIDE.md" "HANDOFF-CHECKLIST.md")
all_present=true

for file in "${files[@]}"; do
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
