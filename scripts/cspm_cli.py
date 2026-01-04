#!/usr/bin/env python3
"""
CSPM CLI Scanner - Command Line Interface

This script provides a CLI interface for running CSPM scans locally.
It can assume IAM roles using repository variables (similar to GitHub Actions)
or use local AWS credentials.

Usage:
    python scripts/cspm_cli.py --regions us-east-1 --accounts current --services iam,s3,ec2
    python scripts/cspm_cli.py --regions us-east-1,us-west-2 --accounts 123456789012 --services all
    python scripts/cspm_cli.py --regions us-east-1 --accounts organization --services iam,s3,ec2,vpc
"""

import argparse
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

try:
    import boto3
    from botocore.exceptions import ClientError, NoCredentialsError
except ImportError:
    print("Error: boto3 not installed. Please install it using: pip install boto3")
    sys.exit(1)

from src.utils.logger import setup_logger


class CSPMCLIRunner:
    """CLI-based CSPM scanner that can assume IAM roles and run scans locally."""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.project_root = project_root
        self.repo_config_file = os.path.join(project_root, '.github-config.yaml')
        
    def load_repo_variables(self) -> Dict[str, str]:
        """Load repository variables from config file or environment variables."""
        variables = {}
        
        # Try to load from config file first
        if os.path.exists(self.repo_config_file):
            try:
                with open(self.repo_config_file, 'r') as f:
                    config = yaml.safe_load(f)
                    variables = config.get('variables', {})
                    self.logger.info(f"Loaded {len(variables)} variables from {self.repo_config_file}")
            except Exception as e:
                self.logger.warning(f"Failed to load config file {self.repo_config_file}: {e}")
        
        # Override with environment variables if present
        aws_role_arn = os.environ.get('AWS_ROLE_ARN') or variables.get('AWS_ROLE_ARN')
        if aws_role_arn:
            variables['AWS_ROLE_ARN'] = aws_role_arn
            
        return variables
    
    def assume_role_with_arn(self, role_arn: str, session_name: str = None) -> boto3.Session:
        """Assume an IAM role and return a session with the assumed credentials."""
        if not session_name:
            session_name = f"CSPMCLISession-{datetime.now().strftime('%Y%m%d%H%M%S')}"
        
        self.logger.info(f"Attempting to assume role: {role_arn}")
        
        # Create STS client with current credentials
        sts_client = boto3.client('sts')
        
        try:
            # Assume the role
            response = sts_client.assume_role(
                RoleArn=role_arn,
                RoleSessionName=session_name,
                DurationSeconds=3600  # 1 hour
            )
            
            credentials = response['Credentials']
            self.logger.info(f"Successfully assumed role: {response['AssumedRoleUser']['Arn']}")
            
            # Create a new session with the assumed role credentials
            session = boto3.Session(
                aws_access_key_id=credentials['AccessKeyId'],
                aws_secret_access_key=credentials['SecretAccessKey'],
                aws_session_token=credentials['SessionToken']
            )
            
            return session
            
        except ClientError as e:
            self.logger.error(f"Failed to assume role {role_arn}: {e}")
            raise
        except NoCredentialsError as e:
            self.logger.error(f"No AWS credentials available to assume role: {e}")
            raise
    
    def get_current_account_id(self, session: boto3.Session = None) -> str:
        """Get the current AWS account ID."""
        if session:
            sts = session.client('sts')
        else:
            sts = boto3.client('sts')
        
        try:
            response = sts.get_caller_identity()
            return response['Account']
        except Exception as e:
            self.logger.error(f"Failed to get current account ID: {e}")
            raise
    
    def parse_accounts(self, accounts_str: str, session: boto3.Session = None) -> List[str]:
        """Parse account string into a list of account IDs."""
        if accounts_str.lower() == 'current':
            current_account = self.get_current_account_id(session)
            self.logger.info(f"Using current account: {current_account}")
            return [current_account]
        elif accounts_str.lower() == 'organization':
            # For organization scanning, we'll delegate to the existing organization scanner
            self.logger.info("Organization mode selected - will delegate to organization scanner")
            return ['organization']
        else:
            # Parse comma-separated account IDs
            accounts = [acc.strip() for acc in accounts_str.split(',')]
            # Validate account IDs (should be 12 digits)
            for acc in accounts:
                if not acc.isdigit() or len(acc) != 12:
                    raise ValueError(f"Invalid AWS account ID: {acc}")
            return accounts
    
    def parse_regions(self, regions_str: str) -> List[str]:
        """Parse regions string into a list of region names."""
        regions = [region.strip() for region in regions_str.split(',')]
        # Basic validation - AWS regions follow pattern like us-east-1
        for region in regions:
            if not region or len(region) < 8:
                raise ValueError(f"Invalid AWS region: {region}")
        return regions
    
    def parse_services(self, services_str: str) -> List[str]:
        """Parse services string into a list of service names."""
        if services_str.lower() == 'all':
            return ['all']
        
        services = [service.strip().lower() for service in services_str.split(',')]
        # Common AWS services
        valid_services = {
            'iam', 's3', 'ec2', 'vpc', 'rds', 'lambda', 'cloudformation',
            'cloudtrail', 'config', 'cloudwatch', 'sns', 'sqs', 'kms',
            'elasticloadbalancing', 'autoscaling', 'ecs', 'eks', 'all'
        }
        
        for service in services:
            if service not in valid_services:
                self.logger.warning(f"Unknown service: {service} (will attempt to scan anyway)")
        
        return services
    
    def run_scan(self, regions: List[str], accounts: List[str], services: List[str],
                 output_format: str = 'html', output_dir: str = None, verbose: bool = False) -> bool:
        """Run the CSPM scan with the specified parameters."""
        if output_dir is None:
            output_dir = os.path.join(self.project_root, 'reports', 'cli-scan')
        
        # Ensure output directory exists
        os.makedirs(output_dir, exist_ok=True)
        
        self.logger.info("Starting CSPM CLI scan...")
        self.logger.info(f"Regions: {regions}")
        self.logger.info(f"Accounts: {accounts}")
        self.logger.info(f"Services: {services}")
        self.logger.info(f"Output format: {output_format}")
        self.logger.info(f"Output directory: {output_dir}")
        
        try:
            # For organization scanning, use the existing organization scanner
            if accounts == ['organization']:
                self.logger.info("Running organization-wide scan...")
                return self._run_organization_scan(regions, services, output_format, output_dir, verbose)
            else:
                # For single account or multiple specific accounts
                return self._run_account_scan(regions, accounts, services, output_format, output_dir, verbose)
        
        except Exception as e:
            self.logger.error(f"Scan failed: {e}")
            return False
    
    def _run_organization_scan(self, regions: List[str], services: List[str],
                             output_format: str, output_dir: str, verbose: bool) -> bool:
        """Run organization-wide scan using existing organization scanner."""
        try:
            # Import and use the existing organization scanner
            org_scanner_path = os.path.join(self.project_root, 'run_organization_scan.py')
            if os.path.exists(org_scanner_path):
                self.logger.info("Using existing organization scanner...")
                # This is a simplified approach - in practice, you'd integrate more directly
                import subprocess
                
                cmd = [
                    sys.executable, org_scanner_path,
                    '--regions', ','.join(regions),
                    '--services', ','.join(services),
                    '--output-format', output_format,
                    '--output-dir', output_dir
                ]
                
                if verbose:
                    cmd.append('--verbose')
                
                result = subprocess.run(cmd, capture_output=True, text=True)
                
                if result.returncode == 0:
                    self.logger.info("Organization scan completed successfully")
                    return True
                else:
                    self.logger.error(f"Organization scan failed: {result.stderr}")
                    return False
            else:
                self.logger.error(f"Organization scanner not found: {org_scanner_path}")
                return False
                
        except Exception as e:
            self.logger.error(f"Organization scan error: {e}")
            return False
    
    def _run_account_scan(self, regions: List[str], accounts: List[str], services: List[str],
                         output_format: str, output_dir: str, verbose: bool) -> bool:
        """Run single account or multi-account scan."""
        try:
            # Use the existing run_workflow_scan.py for account scanning
            workflow_scanner_path = os.path.join(self.project_root, 'scripts', 'run_workflow_scan.py')
            if os.path.exists(workflow_scanner_path):
                self.logger.info("Using workflow scanner for account scanning...")
                import subprocess
                
                cmd = [
                    sys.executable, workflow_scanner_path,
                    '--regions', ','.join(regions),
                    '--accounts', ','.join(accounts),
                    '--services', ','.join(services),
                    '--output-format', output_format,
                    '--output-dir', output_dir
                ]
                
                if verbose:
                    cmd.append('--verbose')
                
                result = subprocess.run(cmd, capture_output=True, text=True)
                
                if result.returncode == 0:
                    self.logger.info("Account scan completed successfully")
                    print(result.stdout)
                    return True
                else:
                    self.logger.error(f"Account scan failed: {result.stderr}")
                    print(result.stderr)
                    return False
            else:
                self.logger.error(f"Workflow scanner not found: {workflow_scanner_path}")
                return False
                
        except Exception as e:
            self.logger.error(f"Account scan error: {e}")
            return False


def create_sample_config():
    """Create a sample .github-config.yaml file."""
    config = {
        'variables': {
            'AWS_ROLE_ARN': 'arn:aws:iam::ACCOUNT_ID:role/CSPMScannerRole',
            'AWS_DEFAULT_REGION': 'us-east-1'
        }
    }
    
    config_file = '.github-config.yaml'
    with open(config_file, 'w') as f:
        yaml.dump(config, f, default_flow_style=False)
    
    print(f"Created sample config file: {config_file}")
    print("Please update it with your actual AWS Role ARN from the CloudFormation deployment.")


def main():
    parser = argparse.ArgumentParser(
        description='CSPM CLI Scanner - Run AWS security scans locally',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --regions us-east-1 --accounts current --services iam,s3,ec2
  %(prog)s --regions us-east-1,us-west-2 --accounts 123456789012 --services all
  %(prog)s --regions us-east-1 --accounts organization --services iam,s3,ec2,vpc
  %(prog)s --create-config  # Create sample configuration file

Note:
  This CLI tool requires either:
  1. AWS credentials configured locally (via aws configure, IAM role, etc.)
  2. AWS_ROLE_ARN environment variable or .github-config.yaml file
  
  For acquired entity setup, use the CloudFormation template to deploy the IAM role,
  then configure the role ARN in .github-config.yaml or set AWS_ROLE_ARN environment variable.
        """
    )
    
    parser.add_argument('--regions', type=str, required=False,
                        help='AWS regions to scan (comma-separated), e.g., us-east-1,us-west-2')
    
    parser.add_argument('--accounts', type=str, required=False,
                        help='Target accounts: "current" for current account, "organization" for org-wide scan, or specific account ID(s)')
    
    parser.add_argument('--services', type=str, required=False,
                        help='AWS services to scan (comma-separated), e.g., iam,s3,ec2 or "all"')
    
    parser.add_argument('--output-format', type=str, default='html', choices=['html', 'json', 'csv'],
                        help='Output format (default: html)')
    
    parser.add_argument('--output-dir', type=str,
                        help='Output directory for scan results (default: reports/cli-scan)')
    
    parser.add_argument('--use-role-arn', type=str,
                        help='Specific IAM role ARN to assume for scanning')
    
    parser.add_argument('--verbose', action='store_true',
                        help='Enable verbose logging')
    
    parser.add_argument('--create-config', action='store_true',
                        help='Create a sample .github-config.yaml file')
    
    args = parser.parse_args()
    
    # Handle config file creation
    if args.create_config:
        create_sample_config()
        return
    
    # Validate required arguments
    if not args.regions or not args.accounts or not args.services:
        parser.error("--regions, --accounts, and --services are required (unless using --create-config)")
    
    # Set up logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    setup_logger(level=log_level)
    
    # Create CLI runner
    cli_runner = CSPMCLIRunner()
    
    try:
        # Load repository variables
        repo_vars = cli_runner.load_repo_variables()
        
        # Determine which AWS session to use
        session = None
        if args.use_role_arn:
            # Use explicitly provided role ARN
            session = cli_runner.assume_role_with_arn(args.use_role_arn)
        elif repo_vars.get('AWS_ROLE_ARN'):
            # Use role ARN from config/environment
            session = cli_runner.assume_role_with_arn(repo_vars['AWS_ROLE_ARN'])
        else:
            # Use default AWS credentials
            cli_runner.logger.info("No role ARN specified, using default AWS credentials")
        
        # Parse parameters
        regions = cli_runner.parse_regions(args.regions)
        accounts = cli_runner.parse_accounts(args.accounts, session)
        services = cli_runner.parse_services(args.services)
        
        # Run the scan
        success = cli_runner.run_scan(
            regions=regions,
            accounts=accounts,
            services=services,
            output_format=args.output_format,
            output_dir=args.output_dir,
            verbose=args.verbose
        )
        
        if success:
            print("\n✅ CSPM scan completed successfully!")
            print(f"📁 Results saved to: {args.output_dir or 'reports/cli-scan'}")
        else:
            print("\n❌ CSMP scan failed!")
            sys.exit(1)
    
    except Exception as e:
        logging.error(f"CLI scan failed: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()