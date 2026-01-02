#!/usr/bin/env python3
"""
CSPM Findings Explorer

This script shows sample findings from your security scan to help interpret the results.
"""

import asyncio
import json
import sys
from src.scanners.iam_scanner import IAMScanner
from src.utils.aws_client import AWSClientManager
from src.utils.config import Config
import boto3

async def show_sample_findings():
    """Show sample findings to help interpret the security report."""
    print("🔍 CSPM Security Findings - Sample Analysis")
    print("=" * 60)
    
    try:
        # Get a few sample findings
        config = Config({'aws': {'regions': ['us-east-1']}})
        aws_client_manager = AWSClientManager(config)
        iam_scanner = IAMScanner(config, aws_client_manager)
        
        session = boto3.Session()
        findings = await iam_scanner.scan(session, 'us-east-1')
        
        print(f"📊 Found {len(findings)} total IAM findings")
        print("\n🔍 Sample Findings Analysis:")
        
        # Group findings by type for better understanding
        finding_types = {}
        for finding in findings:
            finding_type = finding.get('type', 'Unknown')
            if finding_type not in finding_types:
                finding_types[finding_type] = []
            finding_types[finding_type].append(finding)
        
        print(f"\n📋 Finding Categories:")
        for category, items in finding_types.items():
            print(f"  • {category}: {len(items)} findings")
        
        # Show detailed examples from each category
        print("\n" + "="*60)
        print("📝 DETAILED FINDING EXAMPLES")
        print("="*60)
        
        for category, items in list(finding_types.items())[:3]:  # Show first 3 categories
            print(f"\n🏷️  CATEGORY: {category}")
            print("-" * 40)
            
            example = items[0]  # Take first example from each category
            
            print(f"📍 Resource ID: {example.get('resource_id', 'N/A')}")
            print(f"🔍 Resource Type: {example.get('resource_type', 'N/A')}")
            print(f"⚠️  Issue Description:")
            print(f"   {example.get('finding', 'No description available')}")
            
            if 'details' in example:
                print(f"📋 Additional Details:")
                details = example['details']
                if isinstance(details, dict):
                    for key, value in list(details.items())[:3]:  # Show first 3 details
                        print(f"   • {key}: {value}")
                else:
                    print(f"   {details}")
            
            if 'compliance' in example:
                print(f"📜 Compliance Framework:")
                compliance = example['compliance']
                if isinstance(compliance, list):
                    for comp in compliance:
                        print(f"   • {comp}")
                else:
                    print(f"   {compliance}")
            
            print()
        
        # Show severity distribution
        severity_counts = {}
        for finding in findings:
            severity = finding.get('severity', 'Unknown')
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        print("📊 SEVERITY DISTRIBUTION")
        print("-" * 30)
        for severity, count in severity_counts.items():
            print(f"  {severity}: {count} findings")
        
        print("\n" + "="*60)
        print("🎯 HOW TO INTERPRET THESE FINDINGS")
        print("="*60)
        
        print("""
🔴 HIGH PRIORITY ACTIONS:
  1. Focus on CRITICAL and HIGH severity findings first
  2. Look for patterns across multiple resources
  3. Prioritize findings affecting public-facing resources

📋 UNDERSTANDING THE STRUCTURE:
  • Resource ID: The specific AWS resource (user, role, bucket, etc.)
  • Resource Type: The AWS service type (IAM User, EC2 Instance, etc.)
  • Issue Description: What security concern was found
  • Details: Additional context and specific configuration issues
  • Compliance: Which security frameworks this relates to

🛠️  REMEDIATION WORKFLOW:
  1. Review each finding in the HTML report
  2. Check the 'details' section for specific issues
  3. Use AWS Console to implement fixes
  4. Re-run scan to verify fixes

📈 REPORT FEATURES:
  • Interactive charts showing security posture
  • Filter by severity, service, or compliance framework
  • Drill down into specific resource details
  • Export findings for remediation tracking
        """)
        
        print(f"\n🌐 To view the full interactive report:")
        print(f"   1. Open File Explorer")
        print(f"   2. Navigate to: reports/")
        print(f"   3. Double-click: cspm_report_20260102_113106.html")
        print(f"   4. It will open in your default web browser")
        
    except Exception as e:
        print(f"❌ Error analyzing findings: {e}")

if __name__ == "__main__":
    asyncio.run(show_sample_findings())