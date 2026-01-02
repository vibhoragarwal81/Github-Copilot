#!/usr/bin/env python3
"""
AWS Organization-Wide CSPM Security Scan

This script scans all AWS accounts within an organization for security vulnerabilities,
applies compliance rules across multiple frameworks, and generates comprehensive reports.
"""

import asyncio
import logging
import os
import sys
from datetime import datetime
from typing import Dict, List

# Add the src directory to the path
sys.path.append('src')

from src.utils.aws_client import AWSClientManager
from src.utils.config import Config
from src.utils.logger import setup_logger
from src.scanners.organization_scanner import OrganizationScanner
from src.reports.report_generator import ReportGenerator
from src.rules.rules_engine import RulesEngine

async def run_organization_scan():
    """Run comprehensive organization-wide CSPM security scan."""
    
    print("🏢 Starting AWS Organization-Wide CSPM Security Scan")
    print("=" * 70)
    
    try:
        # Setup logging
        setup_logger(logging.INFO)
        logger = logging.getLogger(__name__)
        
        # Create configuration for organization scanning
        config_data = {
            'aws': {
                'regions': ['us-east-1', 'us-west-2', 'eu-west-1'],  # Multiple regions
                'default_region': 'us-east-1',
                'organization_role_name': 'CSPMScanRole',  # Cross-account role
                'session_duration': 3600,
                'external_id': None
            },
            'scanning': {
                'services': {
                    'iam': True,
                    'ec2': True,
                    's3': True,
                    'vpc': True
                },
                'behavior': {
                    'max_concurrent_accounts': 5,
                    'max_concurrent_regions': 3,
                    'timeout': 3600,
                    'retry_attempts': 3,
                    'retry_delay': 5
                }
            }
        }
        
        config = Config(config_data)
        
        # Initialize AWS client manager
        aws_client_manager = AWSClientManager(config)
        
        # Test organization access
        print("🔍 Testing AWS Organizations access...")
        try:
            org_client = aws_client_manager.get_client('organizations', 'us-east-1')
            
            # Get organization information
            try:
                org_info = org_client.describe_organization()['Organization']
                master_account = org_info['MasterAccountId']
                print(f"✅ Organization ID: {org_info['Id']}")
                print(f"✅ Master Account: {master_account}")
                print(f"✅ Organization ARN: {org_info['Arn']}")
            except Exception as e:
                print(f"⚠️  Organization details: Limited access - {str(e)[:50]}...")
            
        except Exception as e:
            print(f"❌ Organization access failed: {e}")
            print("🔄 Falling back to single account scan...")
            
            # Fall back to current account scan
            return await run_single_account_scan(config, aws_client_manager)
        
        # Initialize organization scanner
        org_scanner = OrganizationScanner(config, aws_client_manager)
        
        # Discover accounts
        print("\n🏢 Discovering AWS accounts in organization...")
        try:
            accounts = await org_scanner.discover_accounts()
            print(f"✅ Discovered {len(accounts)} accounts in organization")
            
            # Show account list
            for i, account in enumerate(accounts[:5], 1):  # Show first 5
                status = account.get('Status', 'UNKNOWN')
                name = account.get('Name', 'Unknown')
                account_id = account.get('Id', 'Unknown')
                print(f"   {i}. {name} ({account_id}) - {status}")
            
            if len(accounts) > 5:
                print(f"   ... and {len(accounts) - 5} more accounts")
                
        except Exception as e:
            print(f"❌ Account discovery failed: {e}")
            print("🔄 Falling back to single account scan...")
            return await run_single_account_scan(config, aws_client_manager)
        
        # Run organization-wide scan
        print(f"\n🔍 Starting security scan across {len(accounts)} accounts...")
        print("⏱️  This may take several minutes depending on organization size...")
        
        scan_results = {}
        rules_engine = RulesEngine()
        
        # Scan each account
        for i, account in enumerate(accounts, 1):
            account_id = account['Id']
            account_name = account.get('Name', 'Unknown')
            
            print(f"\n📊 [{i}/{len(accounts)}] Scanning {account_name} ({account_id})...")
            
            try:
                # Scan the account
                account_results = await org_scanner.scan_account(account)
                
                # Count findings
                total_findings = sum(
                    len(findings) 
                    for service_data in account_results.get('services', {}).values()
                    for findings in service_data.values()
                )
                
                print(f"   ✅ Found {total_findings} findings")
                scan_results[account_id] = account_results
                
            except Exception as e:
                print(f"   ❌ Scan failed: {str(e)[:50]}...")
                scan_results[account_id] = {
                    'account_id': account_id,
                    'account_name': account_name,
                    'error': str(e),
                    'scan_timestamp': datetime.now().isoformat()
                }
        
        # Generate summary statistics
        total_accounts = len(scan_results)
        successful_scans = len([r for r in scan_results.values() if 'error' not in r])
        failed_scans = total_accounts - successful_scans
        
        total_findings = 0
        severity_summary = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        
        for account_data in scan_results.values():
            if 'error' in account_data:
                continue
                
            for service_data in account_data.get('services', {}).values():
                for findings in service_data.values():
                    total_findings += len(findings)
                    for finding in findings:
                        severity = finding.get('severity', 'info').lower()
                        if severity in severity_summary:
                            severity_summary[severity] += 1
        
        # Display organization-wide summary
        print(f"\n{'='*70}")
        print("🏢 ORGANIZATION-WIDE SECURITY ASSESSMENT COMPLETE")
        print(f"{'='*70}")
        
        print(f"\n📊 Scan Summary:")
        print(f"   Total Accounts: {total_accounts}")
        print(f"   Successful Scans: {successful_scans}")
        print(f"   Failed Scans: {failed_scans}")
        print(f"   Total Security Findings: {total_findings}")
        
        print(f"\n🚨 Severity Breakdown:")
        for severity, count in severity_summary.items():
            if count > 0:
                icon = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢", "info": "🔵"}.get(severity, "⚪")
                print(f"   {icon} {severity.upper()}: {count}")
        
        # Generate organization-wide report
        print(f"\n📝 Generating organization-wide HTML report...")
        try:
            report_generator = ReportGenerator(config)
            await report_generator.generate_html_report(scan_results)
            
            # Find the latest report
            reports_dir = "reports"
            if os.path.exists(reports_dir):
                report_files = [f for f in os.listdir(reports_dir) if f.endswith('.html')]
                if report_files:
                    latest_report = sorted(report_files)[-1]
                    report_path = os.path.join(reports_dir, latest_report)
                    print(f"📄 Organization Report: {report_path}")
                    print(f"🌐 Open: file:///{os.path.abspath(report_path).replace(chr(92), '/')}")
        except Exception as e:
            print(f"❌ Report generation failed: {e}")
        
        print(f"\n✅ Organization-wide CSPM scan completed successfully!")
        print(f"🎯 Ready for executive review and remediation planning!")
        
        return scan_results
        
    except Exception as e:
        print(f"❌ Organization scan failed: {e}")
        import traceback
        traceback.print_exc()
        return None

async def run_single_account_scan(config, aws_client_manager):
    """Fallback to single account scan if organization access is limited."""
    print("\n🏠 Running Single Account CSPM Scan (Fallback Mode)")
    print("-" * 50)
    
    try:
        # Get current account info
        sts_client = aws_client_manager.get_client('sts', 'us-east-1')
        identity = sts_client.get_caller_identity()
        account_id = identity['Account']
        
        print(f"📋 Account: {account_id}")
        print(f"👤 User: {identity.get('Arn')}")
        
        # Run single account scan (using our existing script logic)
        from src.scanners.iam_scanner import IAMScanner
        from src.scanners.ec2_scanner import EC2Scanner
        from src.scanners.s3_scanner import S3Scanner
        from src.scanners.vpc_scanner import VPCScanner
        import boto3
        
        # Initialize scanners
        iam_scanner = IAMScanner(config, aws_client_manager)
        ec2_scanner = EC2Scanner(config, aws_client_manager)
        s3_scanner = S3Scanner(config, aws_client_manager)
        vpc_scanner = VPCScanner(config, aws_client_manager)
        
        session = boto3.Session()
        
        print("\n🔍 Running security scans...")
        
        # Run scans
        all_findings = {}
        
        print("  📊 Scanning IAM...")
        iam_findings = await iam_scanner.scan(session, 'us-east-1')
        all_findings['iam'] = {'us-east-1': iam_findings}
        print(f"     Found {len(iam_findings)} IAM findings")
        
        print("  📊 Scanning EC2...")
        ec2_findings = await ec2_scanner.scan(session, 'us-east-1')
        all_findings['ec2'] = {'us-east-1': ec2_findings}
        print(f"     Found {len(ec2_findings)} EC2 findings")
        
        print("  📊 Scanning S3...")
        s3_findings = await s3_scanner.scan(session, 'us-east-1')
        all_findings['s3'] = {'us-east-1': s3_findings}
        print(f"     Found {len(s3_findings)} S3 findings")
        
        print("  📊 Scanning VPC...")
        vpc_findings = await vpc_scanner.scan(session, 'us-east-1')
        all_findings['vpc'] = {'us-east-1': vpc_findings}
        print(f"     Found {len(vpc_findings)} VPC findings")
        
        # Create scan results in organization format
        scan_results = {
            account_id: {
                'account_id': account_id,
                'account_name': f'Account-{account_id}',
                'scan_timestamp': datetime.now().isoformat(),
                'account_info': identity,
                'services': all_findings,
                'status': 'completed'
            }
        }
        
        # Generate report
        print(f"\n📝 Generating HTML report...")
        report_generator = ReportGenerator(config)
        await report_generator.generate_html_report(scan_results)
        
        print(f"✅ Single account scan completed!")
        return scan_results
        
    except Exception as e:
        print(f"❌ Single account scan failed: {e}")
        return None

if __name__ == "__main__":
    print("🏢 AWS Organization CSPM Scanner")
    print(f"🕒 {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    results = asyncio.run(run_organization_scan())
    
    if results:
        print(f"\n🎉 Scan completed successfully!")
        sys.exit(0)
    else:
        print(f"\n❌ Scan failed!")
        sys.exit(1)