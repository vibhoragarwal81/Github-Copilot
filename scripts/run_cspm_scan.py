#!/usr/bin/env python3
"""
Simple CSPM Test Scan

This script runs a basic CSPM scan to test the system functionality.
"""

import asyncio
import os
import sys
import logging
from datetime import datetime

# Add the src directory to the path
sys.path.append('src')

from src.utils.aws_client import AWSClientManager
from src.utils.config import Config
from src.utils.logger import setup_logger
from src.scanners.iam_scanner import IAMScanner
from src.scanners.ec2_scanner import EC2Scanner
from src.scanners.s3_scanner import S3Scanner
from src.scanners.vpc_scanner import VPCScanner
from src.rules.rules_engine import RulesEngine
from src.reports.report_generator import ReportGenerator

async def run_simple_scan():
    """Run a simple CSPM scan of the current AWS account."""
    try:
        print("🚀 Starting CSPM Security Scan...")
        
        # Setup logging
        setup_logger(logging.INFO)
        logger = logging.getLogger(__name__)
        
        # Create simple configuration
        config_data = {
            'aws': {
                'regions': ['us-east-1'],
                'default_region': 'us-east-1'
            },
            'scanning': {
                'services': {
                    'iam': True,
                    'ec2': True,
                    's3': True,
                    'vpc': True
                }
            }
        }
        
        config = Config(config_data)
        
        # Initialize AWS client manager
        aws_client_manager = AWSClientManager(config)
        
        # Get account info
        sts_client = aws_client_manager.get_client('sts', 'us-east-1')
        identity = sts_client.get_caller_identity()
        account_id = identity['Account']
        
        print(f"📋 Scanning Account: {account_id}")
        print(f"👤 User: {identity.get('Arn')}")
        
        # Initialize scanners
        iam_scanner = IAMScanner(config, aws_client_manager)
        ec2_scanner = EC2Scanner(config, aws_client_manager)
        s3_scanner = S3Scanner(config, aws_client_manager)
        vpc_scanner = VPCScanner(config, aws_client_manager)
        
        # Initialize rules engine
        rules_engine = RulesEngine()
        
        print("\n🔍 Running security scans...")
        
        # Create boto3 session for the current account
        import boto3
        session = boto3.Session()
        
        # Run scans
        all_findings = {}
        
        # IAM Scan
        print("  📊 Scanning IAM...")
        iam_findings = await iam_scanner.scan(session, 'us-east-1')
        all_findings['iam'] = iam_findings
        print(f"     Found {len(iam_findings)} IAM findings")
        
        # EC2 Scan
        print("  📊 Scanning EC2...")
        ec2_findings = await ec2_scanner.scan(session, 'us-east-1')
        all_findings['ec2'] = ec2_findings
        print(f"     Found {len(ec2_findings)} EC2 findings")
        
        # S3 Scan
        print("  📊 Scanning S3...")
        s3_findings = await s3_scanner.scan(session, 'us-east-1')
        all_findings['s3'] = s3_findings
        print(f"     Found {len(s3_findings)} S3 findings")
        
        # VPC Scan
        print("  📊 Scanning VPC...")
        vpc_findings = await vpc_scanner.scan(session, 'us-east-1')
        all_findings['vpc'] = vpc_findings
        print(f"     Found {len(vpc_findings)} VPC findings")
        
        # Combine all findings
        combined_findings = []
        for service_findings in all_findings.values():
            combined_findings.extend(service_findings)
        
        print(f"\n📈 Total findings: {len(combined_findings)}")
        
        # Apply security rules
        print("🔧 Applying security rules...")
        evaluation_results = rules_engine.evaluate_resources(combined_findings)
        evaluated_findings = evaluation_results.get('findings', combined_findings)
        
        # Count findings by severity
        severity_counts = {}
        for finding in evaluated_findings:
            severity = finding.get('severity', 'UNKNOWN')
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        print("\n📊 Security Findings Summary:")
        for severity, count in severity_counts.items():
            print(f"  {severity}: {count}")
        
        # Generate HTML report
        print("\n📝 Generating HTML report...")
        report_generator = ReportGenerator(config)
        
        scan_results = {
            account_id: {
                'account_id': account_id,
                'account_name': f'Account-{account_id}',
                'scan_timestamp': datetime.now().isoformat(),
                'account_info': identity,
                'findings': {
                    'services': {
                        'iam': {
                            'us-east-1': all_findings['iam']
                        },
                        'ec2': {
                            'us-east-1': all_findings['ec2']
                        },
                        's3': {
                            'us-east-1': all_findings['s3']
                        },
                        'vpc': {
                            'us-east-1': all_findings['vpc']
                        }
                    }
                },
                'summary': {
                    'total_findings': len(evaluated_findings),
                    'critical': severity_counts.get('CRITICAL', 0),
                    'high': severity_counts.get('HIGH', 0),
                    'medium': severity_counts.get('MEDIUM', 0),
                    'low': severity_counts.get('LOW', 0)
                }
            }
        }
        
        await report_generator.generate_html_report(scan_results)
        
        # Check if reports directory exists and show report location
        reports_dir = "reports"
        if os.path.exists(reports_dir):
            report_files = [f for f in os.listdir(reports_dir) if f.endswith('.html')]
            if report_files:
                latest_report = sorted(report_files)[-1]
                report_path = os.path.join(reports_dir, latest_report)
                print(f"📄 HTML Report generated: {report_path}")
                print(f"🌐 Open in browser: file:///{os.path.abspath(report_path).replace(chr(92), '/')}")
        
        print("\n✅ CSPM scan completed successfully!")
        print("🎉 Your AWS environment security assessment is ready!")
        
    except Exception as e:
        print(f"❌ Scan failed: {e}")
        import traceback
        traceback.print_exc()
        return False
    
    return True

if __name__ == "__main__":
    success = asyncio.run(run_simple_scan())
    sys.exit(0 if success else 1)