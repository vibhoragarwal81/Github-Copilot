#!/usr/bin/env python3
"""
GitHub Workflow Compatible CSMP Scanner

This script serves as a bridge between GitHub workflows and the existing
CSPM scanning scripts, handling parameter conversion and execution routing.
"""

import argparse
import asyncio
import json
import logging
import os
import sys
import tempfile
import yaml
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

# Add the project root to the path
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, project_root)

from src.utils.logger import setup_logger


class WorkflowCSMPRunner:
    """Workflow-compatible CSPM scanner that bridges to existing scripts."""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.project_root = project_root
        
    def parse_accounts(self, accounts_str: str) -> List[str]:
        """Parse comma-separated account IDs."""
        if not accounts_str or accounts_str.lower() == 'organization':
            return []  # Will trigger organization scan
        elif accounts_str.lower() == 'current':
            # Get current account ID
            try:
                import boto3
                sts = boto3.client('sts')
                identity = sts.get_caller_identity()
                current_account = identity['Account']
                self.logger.info(f"🏠 Using current account: {current_account}")
                return [current_account]
            except Exception as e:
                self.logger.error(f"Failed to get current account: {e}")
                # Fallback - let the scan determine the account
                return ['current']
        return [acc.strip() for acc in accounts_str.split(',') if acc.strip()]
    
    def parse_services(self, services_str: str) -> Dict[str, bool]:
        """Parse comma-separated services into config format."""
        if services_str.lower() == 'all':
            return {
                'iam': True,
                'ec2': True,
                's3': True,
                'vpc': True
            }
        
        services = [svc.strip().lower() for svc in services_str.split(',')]
        return {
            'iam': 'iam' in services,
            'ec2': 'ec2' in services,
            's3': 's3' in services,
            'vpc': 'vpc' in services
        }
    
    def parse_regions(self, regions_str: str) -> List[str]:
        """Parse comma-separated regions."""
        return [region.strip() for region in regions_str.split(',') if region.strip()]
    
    def create_dynamic_config(self, regions: List[str], services: Dict[str, bool]) -> str:
        """Create a temporary config file with workflow parameters."""
        config_data = {
            'aws': {
                'default_region': regions[0] if regions else 'us-east-1',
                'regions': regions
            },
            'scanning': {
                'services': services,
                'behavior': {
                    'max_concurrent_regions': 3,
                    'timeout': 3600,
                    'retry_attempts': 3
                }
            },
            'reporting': {
                'formats': ['html', 'json'],
                'include_compliance': True
            }
        }
        
        # Create temporary config file
        temp_dir = os.path.join(self.project_root, 'temp')
        os.makedirs(temp_dir, exist_ok=True)
        
        config_path = os.path.join(temp_dir, f'workflow_config_{datetime.now().strftime("%Y%m%d_%H%M%S")}.yaml')
        
        with open(config_path, 'w') as f:
            yaml.dump(config_data, f, default_flow_style=False)
        
        self.logger.info(f"Created dynamic config: {config_path}")
        return config_path
    
    def determine_scan_type(self, accounts: List[str]) -> str:
        """Determine whether to run single account or organization scan."""
        if not accounts:
            return 'organization'
        elif len(accounts) == 1:
            return 'single'
        else:
            return 'multi-account'  # Not implemented yet
    
    async def run_organization_scan(self, config_path: str, output_dir: str) -> Dict:
        """Run organization-wide scan using existing script."""
        self.logger.info("🏢 Running organization-wide scan...")
        
        # Import and run the organization scanner
        scripts_path = os.path.join(self.project_root, 'scripts')
        if scripts_path not in sys.path:
            sys.path.insert(0, scripts_path)
        
        # Set environment for the scan
        original_argv = sys.argv
        
        try:
            # Import and run the organization scan function
            import run_organization_scan
            
            result = await run_organization_scan.run_organization_scan()
            return {'status': 'success', 'type': 'organization', 'result': result}
            
        except Exception as e:
            self.logger.error(f"Organization scan failed: {e}")
            return {'status': 'failed', 'error': str(e), 'type': 'organization'}
        finally:
            sys.argv = original_argv
    
    async def run_single_account_scan(self, account_id: str, config_path: str, output_dir: str) -> Dict:
        """Run single account scan using existing script."""
        # Handle "current" account ID
        if account_id.lower() == 'current':
            try:
                import boto3
                sts = boto3.client('sts')
                identity = sts.get_caller_identity()
                account_id = identity['Account']
                self.logger.info(f"🏠 Resolved current account: {account_id}")
            except Exception as e:
                self.logger.error(f"Failed to resolve current account: {e}")
                return {'status': 'failed', 'type': 'single', 'account_id': 'unknown', 'error': str(e)}
        
        self.logger.info(f"🏠 Running single account scan for {account_id}...")
        
        # For single account, we'll use the existing scan script
        # Set environment for the scan
        original_argv = sys.argv

        try:
            # Import and run the single account scan function
            scripts_path = os.path.join(self.project_root, 'scripts')
            if scripts_path not in sys.path:
                sys.path.insert(0, scripts_path)
            
            # Import the run_simple_scan function from run_cspm_scan
            import run_cspm_scan
            
            result = await run_cspm_scan.run_simple_scan()
            return {'status': 'success' if result else 'failed', 'type': 'single', 'account_id': account_id}
            
        except Exception as e:
            self.logger.error(f"Single account scan failed: {e}")
            return {'status': 'failed', 'error': str(e), 'type': 'single', 'account_id': account_id}
        finally:
            sys.argv = original_argv

    def collect_report_metrics(self, output_dir: str) -> Dict:
        """Collect metrics from generated reports for GitHub outputs."""
        metrics = {
            'total_findings': 0,
            'critical_count': 0,
            'high_count': 0,
            'medium_count': 0,
            'low_count': 0,
            'info_count': 0,
            'reports_generated': []
        }
        
        try:
            reports_dir = os.path.join(self.project_root, 'reports')
            if os.path.exists(reports_dir):
                # Find the latest JSON report
                json_files = [f for f in os.listdir(reports_dir) if f.endswith('.json')]
                html_files = [f for f in os.listdir(reports_dir) if f.endswith('.html')]
                
                if json_files:
                    # Try to parse the latest JSON report for metrics
                    latest_json = sorted(json_files)[-1]
                    json_path = os.path.join(reports_dir, latest_json)
                    
                    try:
                        with open(json_path, 'r') as f:
                            data = json.load(f)
                            
                        # Extract metrics based on report structure
                        if isinstance(data, dict):
                            # Handle different report structures
                            for account_id, account_data in data.items():
                                if isinstance(account_data, dict) and 'summary' in account_data:
                                    summary = account_data['summary']
                                    metrics['total_findings'] += summary.get('total_findings', 0)
                                    metrics['critical_count'] += summary.get('critical', 0)
                                    metrics['high_count'] += summary.get('high', 0)
                                    metrics['medium_count'] += summary.get('medium', 0)
                                    metrics['low_count'] += summary.get('low', 0)
                    except Exception as e:
                        self.logger.warning(f"Could not parse JSON report for metrics: {e}")
                
                metrics['reports_generated'] = html_files + json_files
                
        except Exception as e:
            self.logger.warning(f"Could not collect report metrics: {e}")
        
        return metrics
    
    async def execute_scan(self, args) -> Dict:
        """Main execution logic for workflow scans."""
        try:
            # Clear any problematic AWS profile environment variables
            if 'AWS_PROFILE' in os.environ:
                self.logger.info(f"Clearing AWS_PROFILE environment variable: {os.environ.get('AWS_PROFILE')}")
                os.environ.pop('AWS_PROFILE', None)
            
            # Enhanced AWS authentication validation for workflow environments
            self.logger.info("🔐 Validating AWS authentication method...")
            
            # Check if we're using OIDC (indicated by AWS_WEB_IDENTITY_TOKEN_FILE)
            if 'AWS_WEB_IDENTITY_TOKEN_FILE' in os.environ:
                self.logger.info("✅ Using OIDC authentication with IAM roles")
                self.logger.info(f"   Role ARN: {os.environ.get('AWS_ROLE_ARN', 'Not specified')}")
                self.logger.info(f"   Session Name: {os.environ.get('AWS_ROLE_SESSION_NAME', 'Default')}")
            elif 'AWS_ACCESS_KEY_ID' in os.environ:
                self.logger.info("✅ Using AWS access key authentication")
                self.logger.info(f"   Access Key: {os.environ.get('AWS_ACCESS_KEY_ID', '')[:8]}...")
            else:
                self.logger.warning("⚠️ No AWS credentials detected in environment")
            
            # Parse parameters
            accounts = self.parse_accounts(args.accounts)
            regions = self.parse_regions(args.regions)
            services = self.parse_services(args.services)
            
            self.logger.info("🚀 Starting workflow CSPM scan...")
            self.logger.info(f"📋 Configuration:")
            self.logger.info(f"  Accounts: {accounts if accounts else 'Organization-wide'}")
            self.logger.info(f"  Regions: {regions}")
            self.logger.info(f"  Services: {[k for k, v in services.items() if v]}")
            self.logger.info(f"  Output: {args.output_dir}")
            
            # Create dynamic configuration
            config_path = self.create_dynamic_config(regions, services)
            
            # Determine scan type and execute
            scan_type = self.determine_scan_type(accounts)
            
            if scan_type == 'organization':
                result = await self.run_organization_scan(config_path, args.output_dir)
            elif scan_type == 'single':
                result = await self.run_single_account_scan(accounts[0], config_path, args.output_dir)
            else:
                raise NotImplementedError(f"Multi-account scanning not implemented yet")
            
            # Collect metrics for GitHub outputs
            metrics = self.collect_report_metrics(args.output_dir)
            result.update(metrics)
            
            # Cleanup temp config
            if os.path.exists(config_path):
                os.remove(config_path)
            
            return result
            
        except Exception as e:
            self.logger.error(f"Workflow scan failed: {e}")
            return {
                'status': 'failed',
                'error': str(e),
                'total_findings': 0,
                'critical_count': 0,
                'high_count': 0
            }


async def main():
    """Main entry point for workflow-compatible CSPM scanner."""
    parser = argparse.ArgumentParser(description='GitHub Workflow Compatible CSPM Scanner')
    
    # Workflow-compatible parameters
    parser.add_argument('--regions', type=str, required=True,
                       help='Comma-separated AWS regions to scan')
    parser.add_argument('--accounts', type=str, required=True,
                       help='Comma-separated account IDs, or "organization" for org-wide scan')
    parser.add_argument('--services', type=str, required=True,
                       help='Comma-separated services to scan (iam,ec2,s3,vpc) or "all"')
    parser.add_argument('--output-format', type=str, default='json,html',
                       help='Output formats (json,html,csv)')
    parser.add_argument('--compliance-frameworks', type=str, default='CIS-AWS,NIST-CSF',
                       help='Compliance frameworks to include')
    parser.add_argument('--min-severity', type=str, default='info',
                       help='Minimum severity level to report')
    parser.add_argument('--output-dir', type=str, default='reports',
                       help='Output directory for reports')
    parser.add_argument('--verbose', action='store_true',
                       help='Enable verbose logging')
    
    args = parser.parse_args()
    
    # Setup logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    setup_logger(log_level)
    logger = logging.getLogger(__name__)
    
    # Create output directory
    os.makedirs(args.output_dir, exist_ok=True)
    
    # Initialize and run scanner
    scanner = WorkflowCSMPRunner()
    result = await scanner.execute_scan(args)
    
    # Output results for GitHub Actions
    print("\n" + "="*70)
    print("🎯 WORKFLOW SCAN RESULTS")
    print("="*70)
    print(f"Status: {result['status']}")
    print(f"Total Findings: {result.get('total_findings', 0)}")
    print(f"Critical: {result.get('critical_count', 0)}")
    print(f"High: {result.get('high_count', 0)}")
    print(f"Medium: {result.get('medium_count', 0)}")
    print(f"Low: {result.get('low_count', 0)}")
    
    if result.get('reports_generated'):
        print(f"Reports Generated: {len(result['reports_generated'])}")
        for report in result['reports_generated']:
            print(f"  📄 {report}")
    
    # Set GitHub Action outputs
    if 'GITHUB_OUTPUT' in os.environ:
        with open(os.environ['GITHUB_OUTPUT'], 'a') as f:
            f.write(f"status={result['status']}\n")
            f.write(f"total_count={result.get('total_findings', 0)}\n")
            f.write(f"critical_count={result.get('critical_count', 0)}\n")
            f.write(f"high_count={result.get('high_count', 0)}\n")
            f.write(f"medium_count={result.get('medium_count', 0)}\n")
            f.write(f"low_count={result.get('low_count', 0)}\n")
            f.write(f"report_path={args.output_dir}\n")
    
    # Exit with appropriate code
    if result['status'] == 'failed':
        logger.error("❌ Workflow scan failed")
        sys.exit(1)
    else:
        logger.info("✅ Workflow scan completed successfully")
        sys.exit(0)


if __name__ == "__main__":
    asyncio.run(main())