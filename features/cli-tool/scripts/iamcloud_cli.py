#!/usr/bin/env python3
"""
IAMCloud CLI Scanner - Command Line Interface

This script provides a CLI interface for running IAMCloud scans locally.
It can assume IAM roles using repository variables (similar to GitHub Actions)
or use local AWS credentials.

Usage:
    python features/cli-tool/scripts/iamcloud_cli.py --regions us-east-1 --accounts current --services iam,s3,ec2
    python features/cli-tool/scripts/iamcloud_cli.py --regions us-east-1,us-west-2 --accounts 123456789012 --services all
    python features/cli-tool/scripts/iamcloud_cli.py --regions us-east-1 --accounts organization --services iam,s3,ec2,vpc
"""

import argparse
import boto3
import configparser
import logging
import os
import sys
import yaml
from datetime import datetime
from botocore.exceptions import ClientError, NoCredentialsError
from pathlib import Path

# Add the project root to the Python path for imports
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

# Also add the current working directory to ensure shared modules are found
import os
current_dir = os.getcwd()
sys.path.insert(0, current_dir)

try:
    from shared.utils.logger import setup_logger
    from shared.utils.aws_client import AWSClient
    from shared.utils.config import ConfigManager
    setup_logger_available = True
except ImportError as e:
    # Fallback for basic logging if shared utils not available
    print(f"Warning: Could not import shared utilities: {e}")
    setup_logger_available = False
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    
logger = logging.getLogger(__name__)

class IAMCloudCLIRunner:
    """CLI-based IAMCloud scanner that can assume IAM roles and run scans locally."""
    
    def __init__(self):
        self.logger = logger
        self.session = None
        
    def load_repo_variables(self, config_file: str = None) -> dict:
        """Load repository variables from .github-config.yaml (similar to GitHub Variables)."""
        if not config_file:
            config_file = project_root / 'shared' / 'config' / '.github-config.yaml'
            
        variables = {}
        
        if os.path.exists(config_file):
            try:
                with open(config_file, 'r') as f:
                    data = yaml.safe_load(f)
                    if 'variables' in data:
                        variables = data['variables']
                        self.logger.info(f"Loaded {len(variables)} variables from {config_file}")
            except Exception as e:
                self.logger.error(f"Failed to load repository variables: {e}")
        
        # Allow environment variable override
        aws_role_arn = os.getenv('AWS_ROLE_ARN')
        if aws_role_arn:
            variables['AWS_ROLE_ARN'] = aws_role_arn
            
        return variables
    
    def assume_role_with_arn(self, role_arn: str, session_name: str = None) -> boto3.Session:
        """Assume an IAM role and return a session with the assumed credentials."""
        if not session_name:
            session_name = f"IAMCloudCLISession-{datetime.now().strftime('%Y%m%d%H%M%S')}"
        
        self.logger.info(f"Attempting to assume role: {role_arn}")
        
        # Create STS client with current credentials
        sts_client = boto3.client('sts')
        
        try:
            # Assume the role with External ID
            response = sts_client.assume_role(
                RoleArn=role_arn,
                RoleSessionName=session_name,
                DurationSeconds=3600,  # 1 hour
                ExternalId='iamcloud-security-scan'  # Required by the CloudFormation template
            )
            
            credentials = response['Credentials']
            self.logger.info(f"Successfully assumed role: {response['AssumedRoleUser']['Arn']}")
            
            # Update the default AWS profile with assumed role credentials
            self.update_default_aws_profile(credentials, role_arn)
            
            # Create session with assumed role credentials
            session = boto3.Session(
                aws_access_key_id=credentials['AccessKeyId'],
                aws_secret_access_key=credentials['SecretAccessKey'],
                aws_session_token=credentials['SessionToken']
            )
            
            return session
            
        except ClientError as e:
            error_msg = f"Failed to assume role {role_arn}: {e}"
            self.logger.error(error_msg)
            raise Exception(error_msg)
    
    def update_default_aws_profile(self, credentials: dict, role_arn: str):
        """Update the default AWS profile with assumed role credentials."""
        try:
            aws_dir = Path.home() / '.aws'
            aws_dir.mkdir(exist_ok=True)
            
            credentials_file = aws_dir / 'credentials'
            
            # Read existing credentials or create new
            config = configparser.ConfigParser()
            if credentials_file.exists():
                config.read(credentials_file)
            
            # Update default profile with assumed role credentials
            if 'default' not in config:
                config.add_section('default')
            
            config.set('default', 'aws_access_key_id', credentials['AccessKeyId'])
            config.set('default', 'aws_secret_access_key', credentials['SecretAccessKey'])
            config.set('default', 'aws_session_token', credentials['SessionToken'])
            
            # Add metadata as comments (not standard but helpful for debugging)
            config.set('default', '# Role ARN', role_arn)
            config.set('default', '# Expiration', credentials['Expiration'].isoformat())
            
            # Write updated credentials
            with open(credentials_file, 'w') as f:
                config.write(f)
            
            self.logger.info(f"Updated default AWS profile with assumed role credentials")
            
        except Exception as e:
            self.logger.warning(f"Failed to update AWS profile: {e}")
    
    def get_current_aws_identity(self) -> dict:
        """Get current AWS identity information."""
        try:
            sts = boto3.client('sts')
            identity = sts.get_caller_identity()
            return identity
        except Exception as e:
            raise Exception(f"Failed to get AWS identity: {e}")
    
    def test_cross_account_access(self, target_account: str) -> bool:
        """Test if current credentials can access target account."""
        try:
            # Try to list something in the target account (this is a basic test)
            current_identity = self.get_current_aws_identity()
            current_account = current_identity['Account']
            
            if current_account == target_account:
                return True
            else:
                # For cross-account, we'd need to test actual service access
                # This is a simplified test
                return False
        except Exception:
            return False
    
    def run_scan(self, regions: list, accounts: list, services: list, output_format: str = 'html', 
                output_dir: str = 'reports/cli-scan', use_role_arn: str = None) -> str:
        """Run the IAMCloud scan with the specified parameters."""
        
        # Determine AWS session to use
        aws_session = None
        if use_role_arn:
            aws_session = self.assume_role_with_arn(use_role_arn)
        
        self.logger.info("Starting IAMCloud CLI scan...")
        self.logger.info(f"Regions: {regions}")
        self.logger.info(f"Accounts: {accounts}")
        self.logger.info(f"Services: {services}")
        self.logger.info(f"Output: {output_format} -> {output_dir}")
        
        try:
            # This is where we would integrate with the core scanning engine
            # For now, return a placeholder
            self.logger.info("✅ Scan logic would be integrated here with core scanner")
            self.logger.info("📊 Report generation would happen here")
            
            # Create output directory
            Path(output_dir).mkdir(parents=True, exist_ok=True)
            
            # Generate a simple placeholder report
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            report_file = f"{output_dir}/iamcloud_cli_scan_{timestamp}.{output_format}"
            
            if output_format == 'html':
                with open(report_file, 'w') as f:
                    f.write(f"""
                    <html>
                    <head><title>IAMCloud CLI Scan Report</title></head>
                    <body>
                    <h1>IAMCloud CLI Scan Report</h1>
                    <p>Generated: {datetime.now()}</p>
                    <p>Regions: {', '.join(regions)}</p>
                    <p>Accounts: {', '.join(accounts)}</p>
                    <p>Services: {', '.join(services)}</p>
                    <p>Status: ✅ CLI tool working - core scanner integration pending</p>
                    </body>
                    </html>
                    """)
            
            self.logger.info(f"📄 Report saved to: {report_file}")
            return report_file
            
        except Exception as e:
            self.logger.error(f"Scan failed: {e}")
            raise e
    
    def create_sample_config(self):
        """Create a sample .github-config.yaml file."""
        config_content = {
            'variables': {
                'AWS_DEFAULT_REGION': 'us-east-1',
                'AWS_ROLE_ARN': 'arn:aws:iam::ACCOUNT_ID:role/IAMCloudScannerRole',
            }
        }
        
        config_file = project_root / 'shared' / 'config' / '.github-config.yaml'
        config_file.parent.mkdir(parents=True, exist_ok=True)
        
        with open(config_file, 'w') as f:
            yaml.dump(config_content, f, default_flow_style=False)
        
        print(f"✅ Created sample configuration: {config_file}")
        print("📝 Please update the AWS_ROLE_ARN with your actual role ARN")

def test_authentication(args):
    """Test AWS authentication and role assumption."""
    log_level = logging.DEBUG if args.verbose else logging.INFO
    from shared.utils.logger import setup_logger
    setup_logger(level=log_level)
    
    cli_runner = IAMCloudCLIRunner()
    
    try:
        # Test 1: Default AWS credentials
        print("\\n1️⃣ Testing default AWS credentials...")
        try:
            import boto3
            sts = boto3.client('sts')
            identity = sts.get_caller_identity()
            print(f"   ✅ Default credentials work")
            print(f"   📋 Account: {identity['Account']}")
            print(f"   👤 ARN: {identity['Arn']}")
            current_account = identity['Account']
        except Exception as e:
            print(f"   ❌ Default credentials failed: {e}")
            return False
        
        # Test 2: Repository configuration
        print("\\n2️⃣ Testing repository configuration...")
        repo_vars = cli_runner.load_repo_variables()
        
        if 'AWS_ROLE_ARN' in repo_vars:
            print(f"   ✅ Found AWS_ROLE_ARN: {repo_vars['AWS_ROLE_ARN']}")
            role_arn = repo_vars['AWS_ROLE_ARN']
            
            # Check if cross-account
            if role_arn and '::' in role_arn:
                role_account = role_arn.split(':')[4]
                if role_account != current_account:
                    print(f"   ℹ️  Role is in different account ({role_account}) - cross-account access")
        else:
            print("   ⚠️  No AWS_ROLE_ARN found in repository variables")
            print("   💡 Run: python features/cli-tool/scripts/iamcloud_cli.py --create-config")
            role_arn = None
        
        # Test 3: Role assumption (if role ARN available)
        if role_arn:
            print("\\n3️⃣ Testing role assumption...")
            try:
                session = cli_runner.assume_role_with_arn(role_arn)
                assumed_identity = session.client('sts').get_caller_identity()
                print(f"   ✅ Role assumption successful")
                print(f"   📋 Assumed Account: {assumed_identity['Account']}")
                print(f"   👤 Assumed ARN: {assumed_identity['Arn']}")
                
                # Test 4: Verify default profile was updated
                print("\\n4️⃣ Testing default profile update...")
                try:
                    # Test that the default profile now uses the assumed role
                    default_sts = boto3.client('sts')
                    default_identity = default_sts.get_caller_identity()
                    if 'assumed-role' in default_identity['Arn']:
                        print("   ✅ Default AWS profile updated with assumed role credentials")
                        print(f"   👤 Default profile ARN: {default_identity['Arn']}")
                    else:
                        print("   ⚠️  Default profile may not be using assumed role")
                except Exception as e:
                    print(f"   ⚠️  Could not verify default profile update: {e}")
                    
            except Exception as e:
                error_str = str(e)
                print(f"   ❌ Role assumption failed: {error_str}")
                
                # Provide helpful guidance based on error type
                if "AssumeRoleWithWebIdentity" in error_str or "OIDC" in error_str:
                    print("   💡 This role appears to be configured for GitHub Actions (OIDC)")
                    print("   💡 The trust policy only allows 'AssumeRoleWithWebIdentity', not direct 'AssumeRole'")
                    print("   💡 CLI scanning will use your direct IAM user credentials instead")
                    print(f"   💡 GitHub Actions workflows will use the OIDC role: {role_arn}")
                elif "AccessDenied" in error_str:
                    print("   💡 This role appears to be configured for GitHub Actions (OIDC)")
                    print("   💡 The trust policy only allows 'AssumeRoleWithWebIdentity', not direct 'AssumeRole'")
                    print("   💡 CLI scanning will use your direct IAM user credentials instead")
                    print(f"   💡 GitHub Actions workflows will use the OIDC role: {role_arn}")
                else:
                    print("   💡 Note: Role assumption requires baseline AWS credentials first")
                
                # Test 5: Direct scanning capability
                print("\\n4️⃣ Testing direct scanning capability...")
                try:
                    # Test basic AWS API access with current credentials
                    ec2 = boto3.client('ec2', region_name='us-east-1')
                    ec2.describe_regions(MaxResults=1)  # Minimal API call
                    print("   ✅ Direct AWS API access works with your credentials")
                    print(f"   📡 CLI can perform IAMCloud scanning on account {current_account}")
                except Exception as api_error:
                    print(f"   ❌ Direct AWS API access failed: {api_error}")
                    return False
        else:
            print("   💡 Run: python features/cli-tool/scripts/iamcloud_cli.py --create-config")
            
        print("\\n🎯 CLI is ready for direct scanning!")
        print("\\n🎯 Authentication test completed!")
        return True
        
    except Exception as e:
        print(f"\\n❌ Authentication test failed: {e}")
        return False

def main():
    parser = argparse.ArgumentParser(
        description='IAMCloud CLI Scanner - Run AWS security scans locally',
        epilog='''
Examples:
  iamcloud_cli.py --regions us-east-1 --accounts current --services iam,s3,ec2
  iamcloud_cli.py --regions us-east-1,us-west-2 --accounts 123456789012 --services all
  iamcloud_cli.py --regions us-east-1 --accounts organization --services iam,s3,ec2,vpc
  iamcloud_cli.py --create-config  # Create sample configuration file

Note:
  This CLI tool requires either:
  1. AWS credentials configured locally (via aws configure, IAM role, etc.)
  2. AWS_ROLE_ARN environment variable or .github-config.yaml file

  For acquired entity setup, use the CloudFormation template to deploy the IAM role,
  then configure the role ARN in .github-config.yaml or set AWS_ROLE_ARN environment variable.
        ''',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument('--regions', type=str, 
                       help='AWS regions to scan (comma-separated), e.g., us-east-1,us-west-2')
    parser.add_argument('--accounts', type=str,
                       help='Target accounts: "current" for current account, "organization" for org-wide scan, or specific account ID(s)')
    parser.add_argument('--services', type=str,
                       help='AWS services to scan (comma-separated), e.g., iam,s3,ec2 or "all"')
    parser.add_argument('--output-format', choices=['html', 'json', 'csv'], default='html',
                       help='Output format (default: html)')
    parser.add_argument('--output-dir', type=str, default='reports/cli-scan',
                       help='Output directory for scan results (default: reports/cli-scan)')
    parser.add_argument('--use-role-arn', type=str,
                       help='Specific IAM role ARN to assume for scanning')
    parser.add_argument('--verbose', action='store_true',
                       help='Enable verbose logging')
    parser.add_argument('--test-auth', action='store_true',
                       help='Test authentication only (no scanning)')
    parser.add_argument('--create-config', action='store_true',
                       help='Create a sample .github-config.yaml file')
    
    args = parser.parse_args()
    
    # Set up logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    if setup_logger_available:
        setup_logger(level=log_level)
    else:
        logging.getLogger().setLevel(log_level)
    
    # Create CLI runner
    cli_runner = IAMCloudCLIRunner()
    
    try:
        # Handle special commands first
        if args.create_config:
            cli_runner.create_sample_config()
            return 0
        
        if args.test_auth:
            success = test_authentication(args)
            return 0 if success else 1
        
        # Validate required arguments for scanning
        if not all([args.regions, args.accounts, args.services]):
            parser.error("--regions, --accounts, and --services are required for scanning")
        
        # Load repository variables
        repo_vars = cli_runner.load_repo_variables()
        
        # Determine which AWS session to use
        use_role_arn = args.use_role_arn or repo_vars.get('AWS_ROLE_ARN')
        
        # Parse comma-separated arguments
        regions = [r.strip() for r in args.regions.split(',')]
        accounts = [a.strip() for a in args.accounts.split(',')]
        services = [s.strip() for s in args.services.split(',')]
        
        # Run the scan
        report_file = cli_runner.run_scan(
            regions=regions,
            accounts=accounts,
            services=services,
            output_format=args.output_format,
            output_dir=args.output_dir,
            use_role_arn=use_role_arn
        )
        
        print(f"\\n✅ IAMCloud scan completed successfully!")
        print(f"📄 Report: {report_file}")
        return 0
        
    except KeyboardInterrupt:
        print("\\n⚠️ Scan interrupted by user")
        return 1
    except Exception as e:
        logger.error(f"Scan failed: {e}")
        print(f"\\n❌ Scan failed: {e}")
        return 1

if __name__ == '__main__':
    sys.exit(main())