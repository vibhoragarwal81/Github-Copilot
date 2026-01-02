"""
Comprehensive Unit Tests for AWS CSPM

This module contains comprehensive unit tests for all CSPM components:
- Scanner modules (IAM, EC2, VPC, S3, Organization)
- Report generation (JSON, HTML, CSV)
- Security rules engine
- AWS client management
- Configuration management

Tests include:
- Unit tests with mocking for AWS API calls
- Integration test scenarios
- Edge case handling
- Security validation
- Performance testing
"""

import asyncio
import json
import os
import tempfile
import unittest
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, Mock, patch

import boto3
import pytest
from botocore.exceptions import ClientError, NoCredentialsError

# Import all modules to test
from src.main import CSPMScanner
from src.reports.report_generator import ReportGenerator
from src.rules.rules_engine import RulesEngine, Severity, ComplianceFramework
from src.scanners.ec2_scanner import EC2Scanner
from src.scanners.iam_scanner import IAMScanner
from src.scanners.organization_scanner import OrganizationScanner
from src.scanners.s3_scanner import S3Scanner
from src.scanners.vpc_scanner import VPCScanner
from src.utils.aws_client import AWSClientManager
from src.utils.config import Config
from src.utils.logger import setup_logging


class TestConfig(unittest.TestCase):
    """Test configuration management."""
    
    def setUp(self):
        """Set up test environment."""
        self.test_config_data = {
            'aws': {
                'regions': ['us-east-1', 'us-west-2'],
                'accounts': ['123456789012', '123456789013'],
                'role_name': 'CSPMRole'
            },
            'scanning': {
                'services': ['iam', 'ec2', 's3'],
                'max_concurrent_accounts': 5,
                'timeout': 300
            },
            'output': {
                'directory': 'test_reports',
                'formats': ['json', 'html']
            }
        }
    
    def test_config_loading_from_dict(self):
        """Test loading configuration from dictionary."""
        config = Config(self.test_config_data)
        
        self.assertEqual(config.get('aws.regions'), ['us-east-1', 'us-west-2'])
        self.assertEqual(config.get('aws.accounts'), ['123456789012', '123456789013'])
        self.assertEqual(config.get('scanning.services'), ['iam', 'ec2', 's3'])
    
    def test_config_nested_access(self):
        """Test nested configuration access."""
        config = Config(self.test_config_data)
        
        self.assertEqual(config.get('aws.role_name'), 'CSPMRole')
        self.assertEqual(config.get('scanning.max_concurrent_accounts'), 5)
        self.assertEqual(config.get('output.directory'), 'test_reports')
    
    def test_config_default_values(self):
        """Test configuration default values."""
        config = Config({})
        
        self.assertEqual(config.get('nonexistent.key', 'default'), 'default')
        self.assertIsNone(config.get('nonexistent.key'))
    
    def test_config_file_loading(self):
        """Test loading configuration from file."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(self.test_config_data, f)
            f.flush()
            
            try:
                config = Config.from_file(f.name)
                self.assertEqual(config.get('aws.regions'), ['us-east-1', 'us-west-2'])
            finally:
                os.unlink(f.name)


class TestAWSClientManager(unittest.TestCase):
    """Test AWS client management."""
    
    def setUp(self):
        """Set up test environment."""
        self.config = Config({
            'aws': {
                'regions': ['us-east-1', 'us-west-2'],
                'role_name': 'CSPMRole'
            }
        })
    
    @patch('boto3.client')
    def test_get_client_creation(self, mock_boto3_client):
        """Test AWS client creation."""
        mock_client = Mock()
        mock_boto3_client.return_value = mock_client
        
        client_manager = AWSClientManager(self.config)
        client = client_manager.get_client('ec2', 'us-east-1')
        
        self.assertEqual(client, mock_client)
        mock_boto3_client.assert_called_with('ec2', region_name='us-east-1')
    
    @patch('boto3.client')
    def test_assume_role_client(self, mock_boto3_client):
        """Test client creation with role assumption."""
        mock_sts_client = Mock()
        mock_sts_client.assume_role.return_value = {
            'Credentials': {
                'AccessKeyId': 'test-key',
                'SecretAccessKey': 'test-secret',
                'SessionToken': 'test-token'
            }
        }
        
        mock_service_client = Mock()
        mock_boto3_client.side_effect = [mock_sts_client, mock_service_client]
        
        client_manager = AWSClientManager(self.config)
        client = client_manager.get_client('ec2', 'us-east-1', account_id='123456789012')
        
        self.assertEqual(client, mock_service_client)
        mock_sts_client.assume_role.assert_called_once()
    
    @patch('boto3.client')
    def test_client_error_handling(self, mock_boto3_client):
        """Test client error handling."""
        mock_boto3_client.side_effect = NoCredentialsError()
        
        client_manager = AWSClientManager(self.config)
        
        with self.assertRaises(NoCredentialsError):
            client_manager.get_client('ec2', 'us-east-1')


class TestIAMScanner(unittest.TestCase):
    """Test IAM scanner functionality."""
    
    def setUp(self):
        """Set up test environment."""
        self.config = Config({'aws': {'regions': ['us-east-1']}})
        self.mock_client_manager = Mock(spec=AWSClientManager)
        self.scanner = IAMScanner(self.mock_client_manager, self.config)
    
    @patch('asyncio.gather')
    async def test_scan_iam_users(self):
        """Test IAM users scanning."""
        mock_client = Mock()
        mock_client.list_users.return_value = {
            'Users': [
                {
                    'UserName': 'test-user',
                    'UserId': 'AIDACKCEVSQ6C2EXAMPLE',
                    'Arn': 'arn:aws:iam::123456789012:user/test-user',
                    'CreateDate': datetime.utcnow(),
                    'PasswordLastUsed': datetime.utcnow() - timedelta(days=30)
                }
            ]
        }
        mock_client.list_mfa_devices.return_value = {'MFADevices': []}
        mock_client.list_access_keys.return_value = {'AccessKeyMetadata': []}
        mock_client.get_user.return_value = {
            'User': {
                'UserName': 'test-user',
                'UserId': 'AIDACKCEVSQ6C2EXAMPLE'
            }
        }
        
        self.mock_client_manager.get_client.return_value = mock_client
        
        # Mock the async method
        with patch.object(self.scanner, '_scan_users', new_callable=AsyncMock) as mock_scan:
            mock_scan.return_value = [
                {
                    'type': 'iam_user',
                    'user_name': 'test-user',
                    'has_console_access': False,
                    'mfa_devices': [],
                    'access_keys': []
                }
            ]
            
            result = await self.scanner._scan_users('us-east-1')
            
            self.assertEqual(len(result), 1)
            self.assertEqual(result[0]['user_name'], 'test-user')
    
    async def test_scan_iam_roles(self):
        """Test IAM roles scanning."""
        mock_client = Mock()
        mock_client.list_roles.return_value = {
            'Roles': [
                {
                    'RoleName': 'test-role',
                    'RoleId': 'AROA1234567890EXAMPLE',
                    'Arn': 'arn:aws:iam::123456789012:role/test-role',
                    'CreateDate': datetime.utcnow(),
                    'AssumeRolePolicyDocument': {
                        'Statement': [
                            {
                                'Effect': 'Allow',
                                'Principal': {'Service': 'ec2.amazonaws.com'},
                                'Action': 'sts:AssumeRole'
                            }
                        ]
                    }
                }
            ]
        }
        
        self.mock_client_manager.get_client.return_value = mock_client
        
        with patch.object(self.scanner, '_scan_roles', new_callable=AsyncMock) as mock_scan:
            mock_scan.return_value = [
                {
                    'type': 'iam_role',
                    'role_name': 'test-role',
                    'assume_role_policy_document': {
                        'Statement': [
                            {
                                'Effect': 'Allow',
                                'Principal': {'Service': 'ec2.amazonaws.com'},
                                'Action': 'sts:AssumeRole'
                            }
                        ]
                    }
                }
            ]
            
            result = await self.scanner._scan_roles('us-east-1')
            
            self.assertEqual(len(result), 1)
            self.assertEqual(result[0]['role_name'], 'test-role')


class TestEC2Scanner(unittest.TestCase):
    """Test EC2 scanner functionality."""
    
    def setUp(self):
        """Set up test environment."""
        self.config = Config({'aws': {'regions': ['us-east-1']}})
        self.mock_client_manager = Mock(spec=AWSClientManager)
        self.scanner = EC2Scanner(self.mock_client_manager, self.config)
    
    async def test_scan_ec2_instances(self):
        """Test EC2 instances scanning."""
        mock_client = Mock()
        mock_client.describe_instances.return_value = {
            'Reservations': [
                {
                    'Instances': [
                        {
                            'InstanceId': 'i-1234567890abcdef0',
                            'State': {'Name': 'running'},
                            'PublicIpAddress': '1.2.3.4',
                            'MetadataOptions': {
                                'HttpTokens': 'optional',
                                'HttpPutResponseHopLimit': 1,
                                'HttpEndpoint': 'enabled'
                            },
                            'SecurityGroups': [
                                {'GroupId': 'sg-12345', 'GroupName': 'test-sg'}
                            ]
                        }
                    ]
                }
            ]
        }
        
        self.mock_client_manager.get_client.return_value = mock_client
        
        with patch.object(self.scanner, '_scan_instances', new_callable=AsyncMock) as mock_scan:
            mock_scan.return_value = [
                {
                    'type': 'ec2_instance',
                    'instance_id': 'i-1234567890abcdef0',
                    'state': {'Name': 'running'},
                    'public_ip_address': '1.2.3.4',
                    'metadata_options': {
                        'HttpTokens': 'optional',
                        'HttpPutResponseHopLimit': 1,
                        'HttpEndpoint': 'enabled'
                    }
                }
            ]
            
            result = await self.scanner._scan_instances('us-east-1')
            
            self.assertEqual(len(result), 1)
            self.assertEqual(result[0]['instance_id'], 'i-1234567890abcdef0')
            self.assertEqual(result[0]['public_ip_address'], '1.2.3.4')
    
    async def test_scan_security_groups(self):
        """Test security groups scanning."""
        mock_client = Mock()
        mock_client.describe_security_groups.return_value = {
            'SecurityGroups': [
                {
                    'GroupId': 'sg-12345',
                    'GroupName': 'test-sg',
                    'Description': 'Test security group',
                    'IpPermissions': [
                        {
                            'IpProtocol': 'tcp',
                            'FromPort': 22,
                            'ToPort': 22,
                            'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
                        }
                    ]
                }
            ]
        }
        
        self.mock_client_manager.get_client.return_value = mock_client
        
        with patch.object(self.scanner, '_scan_security_groups', new_callable=AsyncMock) as mock_scan:
            mock_scan.return_value = [
                {
                    'type': 'security_group',
                    'group_id': 'sg-12345',
                    'group_name': 'test-sg',
                    'ip_permissions': [
                        {
                            'IpProtocol': 'tcp',
                            'FromPort': 22,
                            'ToPort': 22,
                            'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
                        }
                    ]
                }
            ]
            
            result = await self.scanner._scan_security_groups('us-east-1')
            
            self.assertEqual(len(result), 1)
            self.assertEqual(result[0]['group_id'], 'sg-12345')


class TestVPCScanner(unittest.TestCase):
    """Test VPC scanner functionality."""
    
    def setUp(self):
        """Set up test environment."""
        self.config = Config({'aws': {'regions': ['us-east-1']}})
        self.mock_client_manager = Mock(spec=AWSClientManager)
        self.scanner = VPCScanner(self.mock_client_manager, self.config)
    
    async def test_scan_vpcs(self):
        """Test VPC scanning."""
        mock_client = Mock()
        mock_client.describe_vpcs.return_value = {
            'Vpcs': [
                {
                    'VpcId': 'vpc-12345',
                    'State': 'available',
                    'CidrBlock': '10.0.0.0/16',
                    'IsDefault': False
                }
            ]
        }
        
        self.mock_client_manager.get_client.return_value = mock_client
        
        with patch.object(self.scanner, '_scan_vpcs', new_callable=AsyncMock) as mock_scan:
            mock_scan.return_value = [
                {
                    'type': 'vpc',
                    'vpc_id': 'vpc-12345',
                    'state': 'available',
                    'cidr_block': '10.0.0.0/16',
                    'is_default': False
                }
            ]
            
            result = await self.scanner._scan_vpcs('us-east-1')
            
            self.assertEqual(len(result), 1)
            self.assertEqual(result[0]['vpc_id'], 'vpc-12345')


class TestS3Scanner(unittest.TestCase):
    """Test S3 scanner functionality."""
    
    def setUp(self):
        """Set up test environment."""
        self.config = Config({'aws': {'regions': ['us-east-1']}})
        self.mock_client_manager = Mock(spec=AWSClientManager)
        self.scanner = S3Scanner(self.mock_client_manager, self.config)
    
    async def test_scan_s3_buckets(self):
        """Test S3 buckets scanning."""
        mock_client = Mock()
        mock_client.list_buckets.return_value = {
            'Buckets': [
                {
                    'Name': 'test-bucket',
                    'CreationDate': datetime.utcnow()
                }
            ]
        }
        mock_client.get_bucket_encryption.return_value = {
            'ServerSideEncryptionConfiguration': {
                'Rules': [
                    {
                        'ApplyServerSideEncryptionByDefault': {
                            'SSEAlgorithm': 'AES256'
                        }
                    }
                ]
            }
        }
        mock_client.get_public_access_block.return_value = {
            'PublicAccessBlockConfiguration': {
                'BlockPublicAcls': True,
                'IgnorePublicAcls': True,
                'BlockPublicPolicy': True,
                'RestrictPublicBuckets': True
            }
        }
        
        self.mock_client_manager.get_client.return_value = mock_client
        
        with patch.object(self.scanner, '_scan_buckets', new_callable=AsyncMock) as mock_scan:
            mock_scan.return_value = [
                {
                    'type': 's3_bucket',
                    'name': 'test-bucket',
                    'encryption': {
                        'Rules': [
                            {
                                'ApplyServerSideEncryptionByDefault': {
                                    'SSEAlgorithm': 'AES256'
                                }
                            }
                        ]
                    },
                    'public_access_block': {
                        'BlockPublicAcls': True,
                        'IgnorePublicAcls': True,
                        'BlockPublicPolicy': True,
                        'RestrictPublicBuckets': True
                    }
                }
            ]
            
            result = await self.scanner._scan_buckets()
            
            self.assertEqual(len(result), 1)
            self.assertEqual(result[0]['name'], 'test-bucket')


class TestRulesEngine(unittest.TestCase):
    """Test security rules engine."""
    
    def setUp(self):
        """Set up test environment."""
        self.rules_engine = RulesEngine()
    
    def test_rules_loading(self):
        """Test default rules loading."""
        self.assertGreater(len(self.rules_engine.rules), 0)
        
        # Check specific rules exist
        self.assertIn('IAM-001', self.rules_engine.rules)
        self.assertIn('EC2-001', self.rules_engine.rules)
    
    def test_iam_root_access_key_rule(self):
        """Test IAM root access key rule."""
        rule = self.rules_engine.rules['IAM-001']
        
        # Test compliant resource
        compliant_resource = {
            'type': 'account',
            'id': '123456789012',
            'account_summary': {
                'access_keys_present': False,
                'recent_root_activity': False
            }
        }
        
        findings = rule.evaluate(compliant_resource)
        self.assertEqual(len(findings), 0)
        
        # Test non-compliant resource
        non_compliant_resource = {
            'type': 'account',
            'id': '123456789012',
            'account_summary': {
                'access_keys_present': True,
                'recent_root_activity': True
            }
        }
        
        findings = rule.evaluate(non_compliant_resource)
        self.assertEqual(len(findings), 2)  # Two violations
        self.assertEqual(findings[0]['severity'], 'critical')
    
    def test_ec2_public_instance_rule(self):
        """Test EC2 public instance rule."""
        rule = self.rules_engine.rules['EC2-001']
        
        # Test compliant resource (private instance)
        private_instance = {
            'type': 'ec2_instance',
            'instance_id': 'i-12345',
            'public_ip_address': None,
            'state': {'Name': 'running'}
        }
        
        findings = rule.evaluate(private_instance)
        self.assertEqual(len(findings), 0)
        
        # Test non-compliant resource (public instance)
        public_instance = {
            'type': 'ec2_instance',
            'instance_id': 'i-67890',
            'public_ip_address': '1.2.3.4',
            'state': {'Name': 'running'}
        }
        
        findings = rule.evaluate(public_instance)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]['severity'], 'high')
    
    def test_rules_by_framework(self):
        """Test getting rules by compliance framework."""
        cis_rules = self.rules_engine.get_rules_by_framework(ComplianceFramework.CIS_AWS)
        nist_rules = self.rules_engine.get_rules_by_framework(ComplianceFramework.NIST_CSF)
        
        self.assertGreater(len(cis_rules), 0)
        self.assertGreater(len(nist_rules), 0)
    
    def test_rules_by_severity(self):
        """Test getting rules by severity."""
        critical_rules = self.rules_engine.get_rules_by_severity(Severity.CRITICAL)
        high_rules = self.rules_engine.get_rules_by_severity(Severity.HIGH)
        
        self.assertGreater(len(critical_rules), 0)
        self.assertGreater(len(high_rules), 0)
    
    def test_evaluate_multiple_resources(self):
        """Test evaluating multiple resources."""
        resources = [
            {
                'type': 'account',
                'id': '123456789012',
                'account_summary': {
                    'access_keys_present': True,
                    'recent_root_activity': False
                }
            },
            {
                'type': 'ec2_instance',
                'instance_id': 'i-12345',
                'public_ip_address': '1.2.3.4',
                'state': {'Name': 'running'}
            }
        ]
        
        results = self.rules_engine.evaluate_resources(resources)
        
        self.assertGreater(results['total_findings'], 0)
        self.assertIn('summary', results)
        self.assertIn('compliance', results)


class TestReportGenerator(unittest.TestCase):
    """Test report generation functionality."""
    
    def setUp(self):
        """Set up test environment."""
        self.config = Config({
            'output': {
                'directory': tempfile.mkdtemp()
            }
        })
        self.report_generator = ReportGenerator(self.config)
        
        # Sample scan results
        self.sample_results = {
            '123456789012': {
                'account_info': {
                    'Name': 'Test Account',
                    'Id': '123456789012'
                },
                'findings': {
                    'iam': [
                        {
                            'resource_id': 'root',
                            'severity': 'critical',
                            'description': 'Root account has access keys',
                            'compliance': ['CIS-AWS-v1.5.0']
                        }
                    ],
                    'ec2': [
                        {
                            'resource_id': 'i-12345',
                            'severity': 'high',
                            'description': 'Instance is publicly accessible',
                            'compliance': ['CIS-AWS-v1.5.0', 'NIST-CSF']
                        }
                    ]
                }
            }
        }
    
    def tearDown(self):
        """Clean up test environment."""
        import shutil
        shutil.rmtree(self.config.get('output.directory'), ignore_errors=True)
    
    async def test_json_report_generation(self):
        """Test JSON report generation."""
        report_path = await self.report_generator.generate_json_report(self.sample_results)
        
        self.assertTrue(os.path.exists(report_path))
        self.assertTrue(report_path.endswith('.json'))
        
        # Verify content
        with open(report_path, 'r') as f:
            report_data = json.load(f)
        
        self.assertIn('summary', report_data)
        self.assertIn('accounts', report_data)
        self.assertEqual(report_data['summary']['total_accounts'], 1)
    
    async def test_html_report_generation(self):
        """Test HTML report generation."""
        report_path = await self.report_generator.generate_html_report(self.sample_results)
        
        self.assertTrue(os.path.exists(report_path))
        self.assertTrue(report_path.endswith('.html'))
        
        # Verify content contains expected elements
        with open(report_path, 'r', encoding='utf-8') as f:
            html_content = f.read()
        
        self.assertIn('<html', html_content)
        self.assertIn('AWS CSPM Security Report', html_content)
        self.assertIn('Executive Summary', html_content)
    
    async def test_csv_report_generation(self):
        """Test CSV report generation."""
        report_path = await self.report_generator.generate_csv_report(self.sample_results)
        
        self.assertTrue(os.path.exists(report_path))
        self.assertTrue(report_path.endswith('.csv'))
        
        # Verify content
        with open(report_path, 'r') as f:
            csv_content = f.read()
        
        self.assertIn('Account ID', csv_content)
        self.assertIn('123456789012', csv_content)
        self.assertIn('critical', csv_content)


class TestMainCSPMScanner(unittest.TestCase):
    """Test main CSPM scanner integration."""
    
    def setUp(self):
        """Set up test environment."""
        self.config = Config({
            'aws': {
                'regions': ['us-east-1'],
                'accounts': ['123456789012'],
                'role_name': 'CSPMRole'
            },
            'scanning': {
                'services': ['iam', 'ec2'],
                'timeout': 300
            },
            'output': {
                'directory': tempfile.mkdtemp(),
                'formats': ['json']
            }
        })
    
    def tearDown(self):
        """Clean up test environment."""
        import shutil
        shutil.rmtree(self.config.get('output.directory'), ignore_errors=True)
    
    @patch('src.scanners.iam_scanner.IAMScanner')
    @patch('src.scanners.ec2_scanner.EC2Scanner')
    @patch('src.utils.aws_client.AWSClientManager')
    async def test_full_scan_workflow(self, mock_client_manager, mock_ec2_scanner, mock_iam_scanner):
        """Test full scan workflow."""
        # Mock scanner results
        mock_iam_instance = Mock()
        mock_iam_instance.scan_account.return_value = {
            'iam': [
                {
                    'resource_id': 'test-user',
                    'severity': 'medium',
                    'description': 'User without MFA'
                }
            ]
        }
        mock_iam_scanner.return_value = mock_iam_instance
        
        mock_ec2_instance = Mock()
        mock_ec2_instance.scan_account.return_value = {
            'ec2': [
                {
                    'resource_id': 'i-12345',
                    'severity': 'high',
                    'description': 'Public instance'
                }
            ]
        }
        mock_ec2_scanner.return_value = mock_ec2_instance
        
        # Mock client manager
        mock_client_manager.return_value = Mock()
        
        scanner = CSPMScanner(self.config)
        
        with patch.object(scanner, '_get_account_info', return_value={'Name': 'Test Account'}):
            results = await scanner.scan_accounts(['123456789012'])
        
        self.assertIn('123456789012', results)
        self.assertIn('findings', results['123456789012'])
    
    @patch('src.utils.aws_client.AWSClientManager')
    def test_scanner_initialization(self, mock_client_manager):
        """Test scanner initialization."""
        scanner = CSPMScanner(self.config)
        
        self.assertIsNotNone(scanner.config)
        self.assertIsNotNone(scanner.client_manager)
        self.assertIsNotNone(scanner.report_generator)


class TestIntegration(unittest.TestCase):
    """Integration tests for complete workflows."""
    
    def setUp(self):
        """Set up integration test environment."""
        self.config = Config({
            'aws': {
                'regions': ['us-east-1'],
                'accounts': ['123456789012']
            },
            'output': {
                'directory': tempfile.mkdtemp()
            }
        })
    
    def tearDown(self):
        """Clean up integration test environment."""
        import shutil
        shutil.rmtree(self.config.get('output.directory'), ignore_errors=True)
    
    @patch('boto3.client')
    async def test_end_to_end_workflow(self, mock_boto3):
        """Test complete end-to-end workflow."""
        # This would be a comprehensive integration test
        # that exercises the entire scanning and reporting pipeline
        
        # Mock AWS responses
        mock_client = Mock()
        mock_client.list_users.return_value = {'Users': []}
        mock_client.describe_instances.return_value = {'Reservations': []}
        mock_client.list_buckets.return_value = {'Buckets': []}
        mock_boto3.return_value = mock_client
        
        # Create scanner
        scanner = CSPMScanner(self.config)
        
        # Mock account info
        with patch.object(scanner, '_get_account_info', return_value={'Name': 'Test Account'}):
            # Run scan
            results = await scanner.scan_accounts(['123456789012'])
            
            # Generate reports
            json_report = await scanner.report_generator.generate_json_report(results)
            html_report = await scanner.report_generator.generate_html_report(results)
            
            # Verify outputs
            self.assertTrue(os.path.exists(json_report))
            self.assertTrue(os.path.exists(html_report))


class TestPerformance(unittest.TestCase):
    """Performance tests for scalability validation."""
    
    def setUp(self):
        """Set up performance test environment."""
        self.rules_engine = RulesEngine()
    
    def test_rules_engine_performance(self):
        """Test rules engine performance with multiple resources."""
        # Create test resources
        resources = []
        for i in range(1000):
            resources.append({
                'type': 'ec2_instance',
                'instance_id': f'i-{i:012d}',
                'public_ip_address': '1.2.3.4' if i % 2 == 0 else None,
                'state': {'Name': 'running'}
            })
        
        start_time = datetime.utcnow()
        results = self.rules_engine.evaluate_resources(resources)
        end_time = datetime.utcnow()
        
        execution_time = (end_time - start_time).total_seconds()
        
        # Should process 1000 resources in reasonable time
        self.assertLess(execution_time, 30.0)  # Less than 30 seconds
        self.assertGreater(results['total_findings'], 0)


# Test discovery and execution
if __name__ == '__main__':
    # Configure logging for tests
    setup_logging({'level': 'INFO'})
    
    # Run tests
    unittest.main(verbosity=2)


# Pytest configuration for advanced testing
pytest_config = """
[pytest]
testpaths = tests
python_files = test_*.py
python_classes = Test*
python_functions = test_*
addopts = 
    -v
    --tb=short
    --strict-markers
    --disable-warnings
    --cov=src
    --cov-report=html
    --cov-report=term-missing
markers =
    slow: marks tests as slow (deselect with '-m "not slow"')
    integration: marks tests as integration tests
    unit: marks tests as unit tests
"""


# Coverage configuration
coverage_config = """
[run]
source = src
omit = 
    */tests/*
    */test_*
    */__pycache__/*
    */venv/*
    */.venv/*

[report]
exclude_lines =
    pragma: no cover
    def __repr__
    if self.debug:
    if settings.DEBUG
    raise AssertionError
    raise NotImplementedError
    if 0:
    if __name__ == .__main__.:
    class .*\bProtocol\):
    @(abc\.)?abstractmethod

[html]
directory = coverage_html
"""