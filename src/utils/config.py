"""
Configuration Manager for AWS CSPM

This module handles loading and managing configuration for the CSMP scanner.
"""

import logging
import os
from typing import Any, Dict, List, Optional

import yaml


class Config:
    """Configuration management class for CSPM scanner."""
    
    def __init__(self, config_data=None, config_file=None):
        """
        Initialize configuration.
        
        Args:
            config_data: Configuration dictionary (optional)
            config_file: Path to configuration file (optional)
        """
        self.logger = logging.getLogger(__name__)
        self._config = {}
        self._load_defaults()
        
        if config_file and os.path.exists(config_file):
            self._load_config_file(config_file)
        elif config_data:
            self._config.update(config_data)
        
        self._load_environment_variables()
    def __init__(self, config_data=None, config_file=None):
        """
        Initialize configuration.
        
        Args:
            config_data: Configuration dictionary (optional)
            config_file: Path to configuration file (optional)
        """
        self.logger = logging.getLogger(__name__)
        self._config = {}
        self._load_defaults()
        
        if config_file and os.path.exists(config_file):
            self._load_config_file(config_file)
        elif config_data:
            self._config.update(config_data)
        
        self._load_environment_variables()
    
    @property
    def config_data(self):
        """Get configuration data."""
        return self._config
    
    @config_data.setter  
    def config_data(self, data):
        """Set configuration data."""
        self._config = data
    
    def _load_defaults(self):
        """Load default configuration values."""
        self._config = {
            # AWS Configuration
            'aws_default_region': 'us-east-1',
            'aws_regions': ['us-east-1', 'us-west-2', 'eu-west-1', 'ap-southeast-1'],
            'aws_organization_role_name': 'CSPMScanRole',
            'aws_session_duration': 3600,
            'aws_external_id': None,
            
            # Service Scanning Configuration
            'scan_ec2': True,
            'scan_s3': True,
            'scan_iam': True,
            'scan_vpc': True,
            'scan_cloudtrail': True,
            'scan_cloudwatch': True,
            'scan_config': True,
            'scan_security_hub': True,
            
            # Scanning Behavior
            'max_concurrent_accounts': 5,
            'max_concurrent_regions': 3,
            'scan_timeout': 3600,  # 1 hour
            'retry_attempts': 3,
            'retry_delay': 5,
            
            # Reporting Configuration
            'output_directory': 'reports',
            'generate_json_report': True,
            'generate_html_report': True,
            'generate_csv_report': True,
            'generate_pdf_report': False,
            'report_template_dir': 'templates',
            
            # Logging Configuration
            'log_level': 'INFO',
            'log_format': '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            'log_file': None,
            
            # Security Rules Configuration
            'rules_directory': 'src/rules',
            'custom_rules_directory': 'config/custom_rules',
            'rule_severity_threshold': 'LOW',
            
            # Notification Configuration
            'slack_webhook_url': None,
            'email_notifications': False,
            'email_smtp_server': None,
            'email_smtp_port': 587,
            'email_username': None,
            'email_password': None,
            'email_recipients': [],
            
            # GitHub Integration
            'github_token': None,
            'github_repository': None,
            'create_github_issues': False,
            
            # Performance Configuration
            'enable_caching': True,
            'cache_ttl': 300,  # 5 minutes
            'parallel_processing': True,
            
            # Compliance Frameworks
            'compliance_frameworks': ['CIS', 'NIST', 'PCI-DSS', 'SOC2'],
            'custom_compliance_checks': []
        }
    
    def _load_config_file(self, config_file: str):
        """
        Load configuration from YAML file.
        
        Args:
            config_file: Path to YAML configuration file
        """
        try:
            with open(config_file, 'r') as f:
                file_config = yaml.safe_load(f)
            
            if file_config:
                self._config.update(file_config)
                self.logger.info(f"Loaded configuration from {config_file}")
        
        except Exception as e:
            self.logger.warning(f"Failed to load config file {config_file}: {str(e)}")
    
    def _load_environment_variables(self):
        """Load configuration from environment variables."""
        env_mappings = {
            'AWS_DEFAULT_REGION': 'aws_default_region',
            'AWS_ORGANIZATION_ROLE_NAME': 'aws_organization_role_name',
            'AWS_EXTERNAL_ID': 'aws_external_id',
            'AWS_REGIONS': 'aws_regions',
            'CSPM_OUTPUT_DIR': 'output_directory',
            'CSPM_LOG_LEVEL': 'log_level',
            'CSPM_LOG_FILE': 'log_file',
            'SLACK_WEBHOOK_URL': 'slack_webhook_url',
            'GITHUB_TOKEN': 'github_token',
            'GITHUB_REPOSITORY': 'github_repository',
            'GENERATE_PDF_REPORT': 'generate_pdf_report',
            'MAX_CONCURRENT_ACCOUNTS': 'max_concurrent_accounts',
            'SCAN_TIMEOUT': 'scan_timeout',
            'RULE_SEVERITY_THRESHOLD': 'rule_severity_threshold'
        }
        
        for env_var, config_key in env_mappings.items():
            value = os.getenv(env_var)
            if value is not None:
                # Handle special cases
                if config_key == 'aws_regions' and isinstance(value, str):
                    self._config[config_key] = [region.strip() for region in value.split(',')]
                elif config_key in ['generate_pdf_report', 'enable_caching', 'parallel_processing']:
                    self._config[config_key] = value.lower() in ('true', '1', 'yes', 'on')
                elif config_key in ['max_concurrent_accounts', 'scan_timeout', 'aws_session_duration']:
                    try:
                        self._config[config_key] = int(value)
                    except ValueError:
                        self.logger.warning(f"Invalid integer value for {env_var}: {value}")
                else:
                    self._config[config_key] = value
    
    def get(self, key: str, default: Any = None) -> Any:
        """
        Get configuration value.
        
        Args:
            key: Configuration key
            default: Default value if key not found
            
        Returns:
            Configuration value or default
        """
        return self._config.get(key, default)
    
    def set(self, key: str, value: Any):
        """
        Set configuration value.
        
        Args:
            key: Configuration key
            value: Configuration value
        """
        self._config[key] = value
    
    def get_aws_config(self) -> Dict:
        """
        Get AWS-specific configuration.
        
        Returns:
            Dict: AWS configuration parameters
        """
        return {
            'default_region': self.get('aws_default_region'),
            'regions': self.get('aws_regions'),
            'organization_role_name': self.get('aws_organization_role_name'),
            'session_duration': self.get('aws_session_duration'),
            'external_id': self.get('aws_external_id')
        }
    
    def get_scanning_config(self) -> Dict:
        """
        Get scanning-specific configuration.
        
        Returns:
            Dict: Scanning configuration parameters
        """
        return {
            'services': {
                'ec2': self.get('scan_ec2'),
                's3': self.get('scan_s3'),
                'iam': self.get('scan_iam'),
                'vpc': self.get('scan_vpc'),
                'cloudtrail': self.get('scan_cloudtrail'),
                'cloudwatch': self.get('scan_cloudwatch'),
                'config': self.get('scan_config'),
                'security_hub': self.get('scan_security_hub')
            },
            'behavior': {
                'max_concurrent_accounts': self.get('max_concurrent_accounts'),
                'max_concurrent_regions': self.get('max_concurrent_regions'),
                'timeout': self.get('scan_timeout'),
                'retry_attempts': self.get('retry_attempts'),
                'retry_delay': self.get('retry_delay')
            }
        }
    
    def get_reporting_config(self) -> Dict:
        """
        Get reporting-specific configuration.
        
        Returns:
            Dict: Reporting configuration parameters
        """
        return {
            'output_directory': self.get('output_directory'),
            'formats': {
                'json': self.get('generate_json_report'),
                'html': self.get('generate_html_report'),
                'csv': self.get('generate_csv_report'),
                'pdf': self.get('generate_pdf_report')
            },
            'template_directory': self.get('report_template_dir')
        }
    
    def validate(self) -> List[str]:
        """
        Validate configuration and return list of issues.
        
        Returns:
            List[str]: List of configuration validation issues
        """
        issues = []
        
        # Validate AWS regions
        if not self.get('aws_regions'):
            issues.append("No AWS regions specified")
        
        # Validate concurrent limits
        max_accounts = self.get('max_concurrent_accounts')
        if max_accounts <= 0:
            issues.append("max_concurrent_accounts must be greater than 0")
        
        # Validate timeout
        timeout = self.get('scan_timeout')
        if timeout <= 0:
            issues.append("scan_timeout must be greater than 0")
        
        # Validate output directory
        output_dir = self.get('output_directory')
        if not output_dir:
            issues.append("output_directory must be specified")
        
        return issues
    
    def to_dict(self) -> Dict:
        """
        Get all configuration as dictionary.
        
        Returns:
            Dict: Complete configuration
        """
        return self._config.copy()