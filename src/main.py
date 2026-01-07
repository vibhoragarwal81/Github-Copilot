"""
AWS Cloud Security Posture Management (CSMP) Main Module

This module serves as the entry point for the AWS CSMP scanner.
It orchestrates the scanning process across multiple AWS accounts within an organization.
"""

import argparse
import asyncio
import json
import logging
import os
import sys
from datetime import datetime
from typing import Dict, List, Optional

# Add the project root and src directory to Python path for imports
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
src_root = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, project_root)
sys.path.insert(0, src_root)

try:
    from src.scanners.organization_scanner import OrganizationScanner
    from src.reports.report_generator import ReportGenerator
    from src.utils.aws_client import AWSClientManager
    from src.utils.config import Config
    from src.utils.logger import setup_logger
except ImportError:
    # Fallback for relative imports
    from scanners.organization_scanner import OrganizationScanner
    from reports.report_generator import ReportGenerator
    from utils.aws_client import AWSClientManager
    from utils.config import Config
    from utils.logger import setup_logger


class CSPMScanner:
    """Main CSPM Scanner class that coordinates the scanning process."""
    
    def __init__(self, config: Config):
        """Initialize the CSPM Scanner with configuration."""
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.aws_client_manager = AWSClientManager(config)
        self.organization_scanner = OrganizationScanner(config, self.aws_client_manager)
        self.report_generator = ReportGenerator(config)
        
    async def scan_organization(self) -> Dict:
        """
        Scan all accounts in the AWS organization.
        
        Returns:
            Dict: Scan results containing findings from all accounts
        """
        self.logger.info("Starting organization-wide security scan")
        
        try:
            # Discover all accounts in the organization
            accounts = await self.organization_scanner.discover_accounts()
            self.logger.info(f"Discovered {len(accounts)} accounts in organization")
            
            # Scan each account
            all_findings = {}
            for account in accounts:
                self.logger.info(f"Scanning account: {account['Id']} ({account['Name']})")
                
                try:
                    account_findings = await self.organization_scanner.scan_account(account)
                    all_findings[account['Id']] = {
                        'account_info': account,
                        'findings': account_findings,
                        'scan_timestamp': datetime.utcnow().isoformat()
                    }
                    self.logger.info(f"Completed scan for account {account['Id']}")
                    
                except Exception as e:
                    self.logger.error(f"Failed to scan account {account['Id']}: {str(e)}")
                    all_findings[account['Id']] = {
                        'account_info': account,
                        'error': str(e),
                        'scan_timestamp': datetime.utcnow().isoformat()
                    }
            
            return all_findings
            
        except Exception as e:
            self.logger.error(f"Organization scan failed: {str(e)}")
            raise
    
    async def generate_reports(self, scan_results: Dict) -> None:
        """
        Generate reports from scan results.
        
        Args:
            scan_results: Results from the organization scan
        """
        self.logger.info("Generating security reports")
        
        try:
            # Generate different report formats
            await self.report_generator.generate_json_report(scan_results)
            await self.report_generator.generate_html_report(scan_results)
            await self.report_generator.generate_csv_report(scan_results)
            
            if self.config.get('generate_pdf_report', False):
                await self.report_generator.generate_pdf_report(scan_results)
                
            self.logger.info("Reports generated successfully")
            
        except Exception as e:
            self.logger.error(f"Report generation failed: {str(e)}")
            raise


async def main():
    """Main entry point for the CSPM scanner."""
    parser = argparse.ArgumentParser(description='AWS Cloud Security Posture Management Scanner')
    parser.add_argument('--scan-organization', action='store_true', help='Scan entire organization')
    parser.add_argument('--account-id', type=str, help='Scan specific account ID')
    parser.add_argument('--config', type=str, default='config/config.yaml', help='Configuration file path')
    parser.add_argument('--output-dir', type=str, default='reports', help='Output directory for reports')
    parser.add_argument('--verbose', '-v', action='store_true', help='Enable verbose logging')
    parser.add_argument('--regions', type=str, help='AWS regions to scan (comma-separated)')
    parser.add_argument('--services', type=str, help='AWS services to scan (comma-separated)')
    
    args = parser.parse_args()
    
    # Setup logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    setup_logger(log_level)
    logger = logging.getLogger(__name__)
    
    try:
        # Load configuration
        config = Config(args.config)
        config.set('output_directory', args.output_dir)
        
        # Handle regions filter
        if args.regions:
            region_list = [region.strip() for region in args.regions.split(',')]
            config.set('aws_regions', region_list)
            logger.info(f"Scanning regions: {region_list}")
        
        # Handle services filter  
        if args.services:
            if args.services == 'only iam':
                service_list = ['iam']
            else:
                service_list = [service.strip() for service in args.services.split(',')]
            config.set('enabled_services', service_list)
            logger.info(f"Scanning services: {service_list}")
        
        # Initialize scanner
        scanner = CSPMScanner(config)
        
        if args.scan_organization:
            # Scan entire organization
            logger.info("Starting organization-wide security scan")
            scan_results = await scanner.scan_organization()
            
            # Generate reports
            await scanner.generate_reports(scan_results)
            
            # Print summary
            total_accounts = len(scan_results)
            successful_scans = sum(1 for result in scan_results.values() if 'findings' in result)
            failed_scans = total_accounts - successful_scans
            
            print(f"\n=== Scan Summary ===")
            print(f"Total accounts: {total_accounts}")
            print(f"Successful scans: {successful_scans}")
            print(f"Failed scans: {failed_scans}")
            print(f"Reports saved to: {args.output_dir}")
            
        elif args.account_id:
            # Scan specific account
            logger.info(f"Scanning account: {args.account_id}")
            # Implementation for single account scan
            print(f"Single account scan not implemented yet for account: {args.account_id}")
            
        else:
            parser.print_help()
            sys.exit(1)
            
    except Exception as e:
        logger.error(f"CSMP scan failed: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())