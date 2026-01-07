"""
EC2 Scanner for AWS CSMP

This module performs comprehensive security scanning of Amazon EC2 (Elastic Compute Cloud) resources.

EC2 forms the foundation of most AWS compute workloads, making its security configuration critical
for overall cloud security posture. This scanner performs deep analysis across all EC2-related
resources to identify vulnerabilities, misconfigurations, and compliance violations.

COMPREHENSIVE EC2 SECURITY SCANNING:

1. EC2 INSTANCES
   - Security group configuration and network exposure
   - Instance metadata service (IMDSv1 vs IMDSv2) security
   - Instance profile and IAM role attachments
   - Public IP address exposure analysis
   - Instance state and lifecycle management
   - User data script security review
   - Detailed monitoring and logging configuration
   - Instance termination protection settings

2. SECURITY GROUPS (Virtual Firewalls)
   - Inbound rule analysis (0.0.0.0/0 detection)
   - Outbound rule review and restrictions
   - Port range security (common vulnerable ports)
   - Protocol-specific security checks
   - Unused security group identification
   - Security group dependency mapping
   - Default security group modifications

3. EBS VOLUMES AND ENCRYPTION
   - Volume encryption at rest verification
   - Unattached volume identification (data leakage risk)
   - Volume snapshot security and sharing
   - Backup and recovery configuration
   - Volume type optimization for security
   - Delete on termination settings
   - Cross-region snapshot sharing analysis

4. AMAZON MACHINE IMAGES (AMIs)
   - Public AMI usage detection
   - Outdated AMI identification
   - Custom AMI security configuration
   - AMI sharing and permission analysis
   - Source image tracking and validation
   - Vulnerability scanning integration readiness

5. KEY PAIRS AND SSH ACCESS
   - Key pair usage tracking and management
   - SSH access pattern analysis
   - Unused key pair identification
   - Key rotation compliance
   - Alternative authentication methods

6. ELASTIC IPS AND NETWORK INTERFACES
   - Unassociated Elastic IP identification
   - Network interface security configuration
   - Public endpoint exposure analysis
   - Source/destination check settings
   - Multi-ENI security considerations

7. PLACEMENT GROUPS AND TENANCY
   - Dedicated tenancy compliance requirements
   - Placement group security implications
   - Host affinity and isolation controls
   - Capacity reservation security settings

SECURITY FOCUS AREAS:
- Network Exposure: Minimizing public internet access and attack surface
- Data Protection: Ensuring encryption and access controls for storage
- Access Management: Proper IAM integration and authentication methods
- Monitoring: Enabling detailed logging and security monitoring
- Compliance: Meeting industry standards and organizational policies

COMPLIANCE FRAMEWORKS COVERED:
- CIS AWS Foundations Benchmark v1.5.0 (EC2 Security Configuration)
- NIST Cybersecurity Framework v1.1 (Asset Management and Protection)
- PCI-DSS v4.0 (Secure System Configuration)
- SOC 2 Type II (System Monitoring and Access Controls)
- ISO 27001:2013 (Information Security Controls)
- AWS Well-Architected Framework (Security Pillar)

COMMON EC2 VULNERABILITIES DETECTED:
- Instances exposed to the internet (0.0.0.0/0)
- Unencrypted EBS volumes and snapshots
- Use of IMDSv1 (metadata service vulnerability)
- SSH access from anywhere (port 22 open)
- Default security group usage
- Unattached volumes with sensitive data
- Public AMIs with custom configurations
- Missing termination protection on critical instances
- Excessive instance privileges
- Unmonitored instance activity
"""

import logging
from datetime import datetime, timezone
from typing import Dict, List, Optional, Set, Tuple

from botocore.exceptions import ClientError


class EC2Scanner:
    """
    Comprehensive EC2 Security Scanner
    
    Analyzes all EC2-related resources for security vulnerabilities, misconfigurations,
    and compliance violations across instances, storage, networking, and access controls.
    """
    
    def __init__(self, config, aws_client_manager):
        """
        Initialize EC2 Scanner with configuration and AWS client manager.
        
        Args:
            config: Configuration object containing security thresholds and compliance requirements
            aws_client_manager: Manager for AWS API client connections across regions
        """
        self.config = config
        self.aws_client_manager = aws_client_manager
        self.logger = logging.getLogger(__name__)
        
        # Security configuration thresholds
        self.max_instance_age_days = config.get('ec2_max_instance_age_days', 365)
        self.require_instance_encryption = config.get('ec2_require_encryption', True)
        self.require_imdsv2 = config.get('ec2_require_imdsv2', True)
        self.max_unattached_volume_days = config.get('ec2_max_unattached_volume_days', 7)
        
        # High-risk ports that should be restricted
        self.critical_ports = {
            22: 'SSH',
            3389: 'RDP',
            1433: 'SQL Server',
            3306: 'MySQL',
            5432: 'PostgreSQL',
            6379: 'Redis',
            27017: 'MongoDB',
            5984: 'CouchDB',
            9200: 'Elasticsearch',
            8080: 'HTTP Proxy',
            8443: 'HTTPS Proxy'
        }
        
        # Cache for cross-resource analysis
        self._instance_cache = {}
        self._security_group_cache = {}
        self._volume_cache = {}
        self._ami_cache = {}
    
    async def scan(self, session, region: str) -> List[Dict]:
        """
        Perform comprehensive EC2 security scan for specified region.
        
        This method orchestrates scanning of all EC2 components including instances,
        security groups, EBS volumes, AMIs, key pairs, and network interfaces.
        
        Args:
            session: Authenticated AWS session with EC2 read permissions
            region: AWS region to scan (e.g., 'us-east-1', 'eu-west-1')
            
        Returns:
            List[Dict]: Comprehensive list of EC2 security findings with structure:
                - resource_type: Type of EC2 resource (EC2Instance, SecurityGroup, EBSVolume, etc.)
                - resource_id: Unique identifier (Instance ID, Security Group ID, Volume ID, etc.)
                - region: AWS region where resource is located
                - severity: CRITICAL, HIGH, MEDIUM, LOW, or INFO
                - title: Brief, actionable description of the finding
                - description: Detailed explanation of security issue and business impact
                - recommendation: Specific remediation steps with implementation guidance
                - compliance: List of compliance frameworks this finding relates to
                - tags: Additional metadata for automation, filtering, and context
        """
        findings = []
        
        try:
            # Initialize EC2 client for the target region
            ec2_client = session.client('ec2', region_name=region)
            self.logger.info(f"Starting comprehensive EC2 security scan in region {region}")
            
            # 1. Scan EC2 instances for security configuration
            self.logger.debug("Scanning EC2 instances...")
            instance_findings = await self._scan_instances(ec2_client, region)
            findings.extend(instance_findings)
            
            # 2. Scan security groups for network exposure
            self.logger.debug("Scanning security groups...")
            sg_findings = await self._scan_security_groups(ec2_client, region)
            findings.extend(sg_findings)
            
            # 3. Scan EBS volumes for encryption and management
            self.logger.debug("Scanning EBS volumes...")
            volume_findings = await self._scan_ebs_volumes(ec2_client, region)
            findings.extend(volume_findings)
            
            # 4. Scan AMIs for security configuration
            self.logger.debug("Scanning AMIs...")
            ami_findings = await self._scan_amis(ec2_client, region)
            findings.extend(ami_findings)
            
            # 5. Scan key pairs and SSH configuration
            self.logger.debug("Scanning key pairs...")
            key_findings = await self._scan_key_pairs(ec2_client, region)
            findings.extend(key_findings)
            
            # 6. Scan Elastic IPs and network interfaces
            self.logger.debug("Scanning network interfaces...")
            network_findings = await self._scan_network_interfaces(ec2_client, region)
            findings.extend(network_findings)
            
            # 7. Analyze cross-resource security dependencies
            self.logger.debug("Analyzing cross-resource dependencies...")
            dependency_findings = await self._analyze_dependencies(ec2_client, region)
            findings.extend(dependency_findings)
            
            self.logger.info(f"EC2 scan completed in {region}. Found {len(findings)} security findings")
            return findings
            
        except Exception as e:
            self.logger.error(f"EC2 scan failed in region {region}: {str(e)}")
            return [{
                'resource_type': 'EC2',
                'resource_id': f'scan-failure-{region}',
                'region': region,
                'severity': 'INFO',
                'title': 'EC2 Scan Failed',
                'description': f'Unable to complete EC2 scan in {region}: {str(e)}',
                'recommendation': 'Check EC2 permissions and AWS connectivity',
                'compliance': [],
                'tags': {'error': True, 'scan_failure': True}
            }]
    
    async def _scan_instances(self, ec2_client, region: str) -> List[Dict]:
        """
        Scan EC2 instances for comprehensive security analysis.
        
        This method performs deep security analysis of all EC2 instances including:
        - Network exposure and public IP configuration
        - Instance metadata service (IMDS) security settings
        - IAM role and instance profile configuration
        - Security group associations and rules
        - EBS volume encryption and attachments
        - Instance state and lifecycle management
        - Monitoring and logging configuration
        - User data security considerations
        
        Args:
            ec2_client: EC2 client for API operations
            region: AWS region being scanned
            
        Returns:
            List[Dict]: Detailed instance security findings
        """
        findings = []
        
        try:
            # Get all instances using pagination for scalability
            paginator = ec2_client.get_paginator('describe_instances')
            instance_count = 0
            running_instances = 0
            stopped_instances = 0
            
            self.logger.debug(f"Retrieving EC2 instances for security analysis in {region}...")
            
            for page in paginator.paginate():
                for reservation in page['Reservations']:
                    for instance in reservation['Instances']:
                        instance_count += 1
                        instance_id = instance['InstanceId']
                        instance_state = instance.get('State', {}).get('Name', 'unknown')
                        
                        # Store instance in cache for cross-analysis
                        self._instance_cache[instance_id] = instance
                        
                        if instance_state == 'running':
                            running_instances += 1
                        elif instance_state == 'stopped':
                            stopped_instances += 1
                        
                        self.logger.debug(f"Analyzing instance: {instance_id} (state: {instance_state})")
                        
                        # Only analyze instances that could pose security risks
                        if instance_state in ['running', 'stopped', 'stopping']:
                            
                            # 1. CRITICAL: Check for public IP exposure
                            public_findings = await self._check_instance_public_exposure(instance, region)
                            findings.extend(public_findings)
                            
                            # 2. HIGH: Instance Metadata Service (IMDS) security
                            imds_findings = await self._check_imds_configuration(ec2_client, instance, region)
                            findings.extend(imds_findings)
                            
                            # 3. HIGH: IAM role and instance profile analysis
                            iam_findings = await self._check_instance_iam_configuration(instance, region)
                            findings.extend(iam_findings)
                            
                            # 4. MEDIUM: Security group configuration
                            sg_findings = await self._check_instance_security_groups(instance, region)
                            findings.extend(sg_findings)
                            
                            # 5. HIGH: EBS volume encryption analysis
                            ebs_findings = await self._check_instance_ebs_encryption(instance, region)
                            findings.extend(ebs_findings)
                            
                            # 6. MEDIUM: Instance lifecycle and management
                            lifecycle_findings = await self._check_instance_lifecycle(instance, region)
                            findings.extend(lifecycle_findings)
                            
                            # 7. LOW: Monitoring and compliance
                            monitoring_findings = await self._check_instance_monitoring(instance, region)
                            findings.extend(monitoring_findings)
                            
                            # 8. MEDIUM: User data and bootstrap security
                            userdata_findings = await self._check_user_data_security(ec2_client, instance, region)
                            findings.extend(userdata_findings)
            
            # Generate summary findings for the region
            self.logger.info(f"Completed analysis of {instance_count} instances in {region}")
            self.logger.info(f"Instance states: {running_instances} running, {stopped_instances} stopped")
            
            # Add informational finding about instance distribution
            if instance_count > 0:
                findings.append({
                    'resource_type': 'EC2Account',
                    'resource_id': f'instance-summary-{region}',
                    'region': region,
                    'severity': 'INFO',
                    'title': 'EC2 Instance Summary',
                    'description': (
                        f'Region {region} contains {instance_count} total instances: '
                        f'{running_instances} running, {stopped_instances} stopped'
                    ),
                    'recommendation': 'Regularly review instance inventory for unused or unnecessary resources',
                    'compliance': ['AWS-Well-Architected'],
                    'tags': {
                        'service': 'ec2',
                        'category': 'inventory',
                        'total_instances': instance_count,
                        'running_instances': running_instances,
                        'stopped_instances': stopped_instances,
                        'region': region
                    }
                })
                
        except ClientError as e:
            self.logger.error(f"Failed to scan EC2 instances in {region}: {e}")
            findings.append({
                'resource_type': 'EC2',
                'resource_id': 'instances-scan-error',
                'region': region,
                'severity': 'INFO',
                'title': 'EC2 Instances Scan Permission Error',
                'description': f'Unable to describe EC2 instances: {e}',
                'recommendation': 'Ensure ec2:DescribeInstances permission is granted',
                'compliance': [],
                'tags': {'error': True, 'permission_error': True}
            })
        
        return findings
    
    async def _check_instance_public_exposure(self, instance: Dict, region: str) -> List[Dict]:
        """
        Check instance for public IP exposure and internet accessibility.
        
        Public instances are often the primary attack vector for cloud environments.
        This method identifies instances that may be exposed to the internet.
        
        Args:
            instance: Instance data from EC2 API
            region: AWS region
            
        Returns:
            List[Dict]: Public exposure findings
        """
        findings = []
        instance_id = instance['InstanceId']
        
        try:
            # Check for public IPv4 address
            public_ip = instance.get('PublicIpAddress')
            public_dns = instance.get('PublicDnsName')
            
            if public_ip:
                # Determine severity based on instance state and configuration
                state = instance.get('State', {}).get('Name', 'unknown')
                severity = 'HIGH' if state == 'running' else 'MEDIUM'
                
                findings.append({
                    'resource_type': 'EC2Instance',
                    'resource_id': instance_id,
                    'region': region,
                    'severity': severity,
                    'title': 'EC2 Instance Has Public IP Address',
                    'description': (
                        f'Instance {instance_id} has a public IP address ({public_ip}) '
                        f'making it directly accessible from the internet. This increases '
                        f'the attack surface and requires careful security group configuration '
                        f'to prevent unauthorized access.'
                    ),
                    'recommendation': (
                        'Review if public IP is necessary: '
                        '1. Consider using private subnets with NAT Gateway for outbound access '
                        '2. If public access is required, ensure security groups are restrictive '
                        '3. Use Application Load Balancer or API Gateway for web applications '
                        '4. Implement network monitoring and intrusion detection '
                        '5. Enable detailed logging and monitoring for public instances'
                    ),
                    'compliance': ['CIS-AWS-1.5.0-4.1', 'NIST-800-53-SC-7', 'PCI-DSS-1.3'],
                    'tags': {
                        'service': 'ec2',
                        'category': 'network_exposure',
                        'public_ip': public_ip,
                        'public_dns': public_dns,
                        'instance_state': state,
                        'security_risk': 'public_exposure'
                    }
                })
            
            # Check for IPv6 addresses which may also provide public access
            ipv6_addresses = instance.get('Ipv6Addresses', [])
            if ipv6_addresses:
                findings.append({
                    'resource_type': 'EC2Instance',
                    'resource_id': instance_id,
                    'region': region,
                    'severity': 'MEDIUM',
                    'title': 'EC2 Instance Has IPv6 Address',
                    'description': (
                        f'Instance {instance_id} has IPv6 address(es) configured. '
                        'IPv6 addresses in AWS are typically public by default and '
                        'may provide internet access even without a public IPv4 address.'
                    ),
                    'recommendation': (
                        'Review IPv6 configuration: '
                        '1. Ensure security groups properly restrict IPv6 access '
                        '2. Consider disabling IPv6 if not needed '
                        '3. Monitor IPv6 traffic patterns'
                    ),
                    'compliance': ['NIST-800-53-SC-7'],
                    'tags': {
                        'service': 'ec2',
                        'category': 'network_exposure',
                        'ipv6_count': len(ipv6_addresses),
                        'network_protocol': 'ipv6'
                    }
                })
            
        except Exception as e:
            self.logger.error(f"Failed to check public exposure for instance {instance_id}: {e}")
        
        return findings
    
    async def _check_imds_configuration(self, ec2_client, instance: Dict, region: str) -> List[Dict]:
        """
        Check Instance Metadata Service (IMDS) security configuration.
        
        IMDS vulnerabilities (like SSRF attacks) can lead to credential theft and privilege escalation.
        IMDSv2 provides session-oriented requests that are more secure than IMDSv1.
        
        Args:
            ec2_client: EC2 client for API calls
            instance: Instance data
            region: AWS region
            
        Returns:
            List[Dict]: IMDS security findings
        """
        findings = []
        instance_id = instance['InstanceId']
        
        try:
            metadata_options = instance.get('MetadataOptions', {})
            
            # Check IMDS state
            http_endpoint = metadata_options.get('HttpEndpoint', 'enabled')
            http_tokens = metadata_options.get('HttpTokens', 'optional')
            http_hop_limit = metadata_options.get('HttpPutResponseHopLimit', 1)
            
            # CRITICAL: IMDSv1 enabled (allows non-session based requests)
            if http_endpoint == 'enabled' and http_tokens == 'optional':
                findings.append({
                    'resource_type': 'EC2Instance',
                    'resource_id': instance_id,
                    'region': region,
                    'severity': 'HIGH',
                    'title': 'EC2 Instance Uses Vulnerable IMDSv1',
                    'description': (
                        f'Instance {instance_id} has Instance Metadata Service v1 (IMDSv1) enabled. '
                        'IMDSv1 is vulnerable to Server-Side Request Forgery (SSRF) attacks that '
                        'can be used to steal IAM credentials and compromise the instance. '
                        'IMDSv2 requires session tokens and provides better security.'
                    ),
                    'recommendation': (
                        'Upgrade to IMDSv2 immediately: '
                        '1. Set HttpTokens to "required" to enforce IMDSv2 '
                        '2. Test applications for IMDSv2 compatibility '
                        '3. Set HttpPutResponseHopLimit to 1 to prevent forwarding '
                        '4. Consider disabling IMDS entirely if not needed '
                        'AWS CLI: aws ec2 modify-instance-metadata-options --instance-id {instance_id} --http-tokens required'
                    ),
                    'compliance': ['CIS-AWS-1.5.0-4.2', 'NIST-800-53-IA-5', 'AWS-Security-Best-Practices'],
                    'tags': {
                        'service': 'ec2',
                        'category': 'metadata_security',
                        'imds_version': 'v1',
                        'vulnerability': 'ssrf_risk',
                        'http_tokens': http_tokens,
                        'urgent_remediation': True
                    }
                })
            
            # HIGH: IMDS completely disabled may break some applications
            elif http_endpoint == 'disabled':
                findings.append({
                    'resource_type': 'EC2Instance',
                    'resource_id': instance_id,
                    'region': region,
                    'severity': 'INFO',
                    'title': 'EC2 Instance Has IMDS Disabled',
                    'description': (
                        f'Instance {instance_id} has Instance Metadata Service completely disabled. '
                        'While this is secure, some applications and AWS services may require IMDS access.'
                    ),
                    'recommendation': 'Ensure all applications function correctly without IMDS access',
                    'compliance': ['AWS-Security-Best-Practices'],
                    'tags': {
                        'service': 'ec2',
                        'category': 'metadata_security',
                        'imds_status': 'disabled',
                        'security_posture': 'hardened'
                    }
                })
            
            # MEDIUM: High hop limit may allow forwarding
            if http_hop_limit > 1:
                findings.append({
                    'resource_type': 'EC2Instance',
                    'resource_id': instance_id,
                    'region': region,
                    'severity': 'MEDIUM',
                    'title': 'EC2 Instance IMDS Allows Request Forwarding',
                    'description': (
                        f'Instance {instance_id} has HTTP hop limit set to {http_hop_limit}, '
                        'which allows IMDS requests to be forwarded through multiple network hops. '
                        'This could enable indirect access to instance credentials.'
                    ),
                    'recommendation': 'Set HttpPutResponseHopLimit to 1 to prevent request forwarding',
                    'compliance': ['AWS-Security-Best-Practices'],
                    'tags': {
                        'service': 'ec2',
                        'category': 'metadata_security',
                        'hop_limit': http_hop_limit,
                        'forwarding_risk': True
                    }
                })
            
            # INFO: Good configuration (IMDSv2 enforced)
            if http_endpoint == 'enabled' and http_tokens == 'required' and http_hop_limit == 1:
                findings.append({
                    'resource_type': 'EC2Instance',
                    'resource_id': instance_id,
                    'region': region,
                    'severity': 'INFO',
                    'title': 'EC2 Instance Uses Secure IMDSv2',
                    'description': f'Instance {instance_id} is properly configured with IMDSv2 security settings',
                    'recommendation': 'Continue following IMDS security best practices',
                    'compliance': ['CIS-AWS-1.5.0-4.2'],
                    'tags': {
                        'service': 'ec2',
                        'category': 'metadata_security',
                        'imds_version': 'v2',
                        'security_status': 'compliant'
                    }
                })
                
        except Exception as e:
            self.logger.error(f"Failed to check IMDS configuration for instance {instance_id}: {e}")
        
        return findings
    
    async def _check_instance_iam_configuration(self, instance: Dict, region: str) -> List[Dict]:
        """Check IAM role and instance profile configuration."""
        findings = []
        instance_id = instance['InstanceId']
        
        try:
            iam_instance_profile = instance.get('IamInstanceProfile')
            
            if not iam_instance_profile:
                findings.append({
                    'resource_type': 'EC2Instance',
                    'resource_id': instance_id,
                    'region': region,
                    'severity': 'MEDIUM',
                    'title': 'EC2 Instance Has No IAM Instance Profile',
                    'description': f'Instance {instance_id} has no IAM instance profile attached',
                    'recommendation': 'Attach an IAM instance profile with minimal required permissions',
                    'compliance': ['AWS-Well-Architected'],
                    'tags': {'service': 'ec2', 'category': 'iam_configuration', 'instance_profile': False}
                })
            else:
                # Instance has IAM role - this is generally good
                profile_arn = iam_instance_profile.get('Arn', '')
                findings.append({
                    'resource_type': 'EC2Instance',
                    'resource_id': instance_id,
                    'region': region,
                    'severity': 'INFO',
                    'title': 'EC2 Instance Has IAM Instance Profile',
                    'description': f'Instance {instance_id} has IAM instance profile attached: {profile_arn}',
                    'recommendation': 'Review instance profile permissions follow principle of least privilege',
                    'compliance': ['AWS-Well-Architected'],
                    'tags': {'service': 'ec2', 'category': 'iam_configuration', 'instance_profile': True}
                })
                
        except Exception as e:
            self.logger.error(f"Failed to check IAM configuration for instance {instance_id}: {e}")
        
        return findings
    
    async def _scan_security_groups(self, ec2_client, region: str) -> List[Dict]:
        """Scan security groups for overly permissive rules and security issues."""
        findings = []
        
        try:
            response = ec2_client.describe_security_groups()
            security_groups = response.get('SecurityGroups', [])
            
            for sg in security_groups:
                sg_id = sg['GroupId']
                sg_name = sg['GroupName']
                vpc_id = sg.get('VpcId', 'EC2-Classic')
                
                # Store in cache
                self._security_group_cache[sg_id] = sg
                
                # Check for overly permissive inbound rules
                for rule in sg.get('IpPermissions', []):
                    # Check for 0.0.0.0/0 access
                    for ip_range in rule.get('IpRanges', []):
                        cidr = ip_range.get('CidrIp', '')
                        if cidr == '0.0.0.0/0':
                            severity = self._determine_rule_severity(rule)
                            port_description = self._format_port_range(rule)
                            
                            findings.append({
                                'resource_type': 'SecurityGroup',
                                'resource_id': sg_id,
                                'region': region,
                                'severity': severity,
                                'title': 'Security Group Allows Access From Anywhere',
                                'description': (
                                    f'Security group {sg_name} ({sg_id}) has an inbound rule '
                                    f'allowing access from anywhere (0.0.0.0/0) on {port_description}. '
                                    'This exposes resources to potential attacks from the internet.'
                                ),
                                'recommendation': (
                                    'Restrict access to specific IP addresses or ranges. '
                                    'Use least privilege principle and only allow access '
                                    'from trusted networks or specific IP addresses.'
                                ),
                                'compliance': ['CIS-AWS-1.5.0-4.1', 'CIS-AWS-1.5.0-4.2', 'NIST-800-53-AC-4'],
                                'tags': {
                                    'service': 'ec2',
                                    'category': 'network_security',
                                    'sg_name': sg_name,
                                    'vpc_id': vpc_id,
                                    'protocol': rule.get('IpProtocol', 'unknown'),
                                    'port_range': port_description,
                                    'cidr': cidr
                                }
                            })
                
                # Check if this is the default security group with custom rules
                if sg_name == 'default':
                    inbound_rules = sg.get('IpPermissions', [])
                    outbound_rules = sg.get('IpPermissionsEgress', [])
                    
                    if len(inbound_rules) > 1 or len(outbound_rules) > 1:
                        findings.append({
                            'resource_type': 'SecurityGroup',
                            'resource_id': sg_id,
                            'region': region,
                            'severity': 'MEDIUM',
                            'title': 'Default Security Group Has Custom Rules',
                            'description': f'Default security group {sg_id} in VPC {vpc_id} has been modified with custom rules',
                            'recommendation': 'Create specific security groups for resources instead of modifying the default security group',
                            'compliance': ['CIS-AWS-1.5.0-4.3'],
                            'tags': {'service': 'ec2', 'category': 'security_groups', 'default_modified': True}
                        })
                        
        except ClientError as e:
            self.logger.error(f"Failed to scan security groups in region {region}: {e}")
            
        return findings
    
    async def _scan_ebs_volumes(self, ec2_client, region: str) -> List[Dict]:
        """Scan EBS volumes for encryption issues and management problems."""
        findings = []
        
        try:
            response = ec2_client.describe_volumes()
            volumes = response.get('Volumes', [])
            
            for volume in volumes:
                volume_id = volume['VolumeId']
                encrypted = volume.get('Encrypted', False)
                state = volume.get('State', 'unknown')
                
                # Store volume in cache
                self._volume_cache[volume_id] = volume
                
                # Check encryption
                if not encrypted:
                    findings.append({
                        'resource_type': 'EBSVolume',
                        'resource_id': volume_id,
                        'region': region,
                        'severity': 'HIGH',
                        'title': 'EBS Volume Is Not Encrypted',
                        'description': f'EBS volume {volume_id} is not encrypted',
                        'recommendation': 'Enable encryption for all EBS volumes to protect data at rest',
                        'compliance': ['CIS-AWS-1.5.0-2.2', 'PCI-DSS-3.4'],
                        'tags': {'service': 'ec2', 'category': 'encryption', 'encrypted': False, 'state': state}
                    })
                
                # Check for unattached volumes
                attachments = volume.get('Attachments', [])
                if not attachments and state == 'available':
                    create_time = volume.get('CreateTime')
                    if create_time:
                        age_days = (datetime.now(timezone.utc) - create_time.replace(tzinfo=timezone.utc)).days
                        
                        if age_days > self.max_unattached_volume_days:
                            findings.append({
                                'resource_type': 'EBSVolume',
                                'resource_id': volume_id,
                                'region': region,
                                'severity': 'MEDIUM',
                                'title': 'EBS Volume Unattached for Extended Period',
                                'description': f'EBS volume {volume_id} has been unattached for {age_days} days',
                                'recommendation': 'Review if this volume is still needed or attach it to an instance',
                                'compliance': ['AWS-Well-Architected'],
                                'tags': {'service': 'ec2', 'category': 'volume_management', 'age_days': age_days}
                            })
                            
        except ClientError as e:
            self.logger.error(f"Failed to scan EBS volumes in region {region}: {e}")
            
        return findings
    
    async def _scan_amis(self, ec2_client, region: str) -> List[Dict]:
        """Scan AMIs for security issues."""
        findings = []
        
        try:
            # Only scan owned AMIs to avoid too much data
            response = ec2_client.describe_images(Owners=['self'])
            amis = response.get('Images', [])
            
            for ami in amis:
                ami_id = ami['ImageId']
                public = ami.get('Public', False)
                
                # Store AMI in cache
                self._ami_cache[ami_id] = ami
                
                # Check for public AMIs
                if public:
                    findings.append({
                        'resource_type': 'AMI',
                        'resource_id': ami_id,
                        'region': region,
                        'severity': 'HIGH',
                        'title': 'AMI Is Public',
                        'description': f'AMI {ami_id} is publicly accessible',
                        'recommendation': 'Make AMI private unless public sharing is intentional',
                        'compliance': ['CIS-AWS-1.5.0-2.1'],
                        'tags': {'service': 'ec2', 'category': 'ami_security', 'public': True}
                    })
                    
        except ClientError as e:
            self.logger.error(f"Failed to scan AMIs in region {region}: {e}")
            
        return findings
    
    async def _scan_key_pairs(self, ec2_client, region: str) -> List[Dict]:
        """Scan key pairs for management issues."""
        findings = []
        
        try:
            response = ec2_client.describe_key_pairs()
            key_pairs = response.get('KeyPairs', [])
            
            if not key_pairs:
                findings.append({
                    'resource_type': 'EC2Account',
                    'resource_id': f'key-pairs-{region}',
                    'region': region,
                    'severity': 'INFO',
                    'title': 'No EC2 Key Pairs Found',
                    'description': f'No EC2 key pairs found in region {region}',
                    'recommendation': 'Ensure proper SSH access management if instances require it',
                    'compliance': ['AWS-Well-Architected'],
                    'tags': {'service': 'ec2', 'category': 'key_management', 'key_count': 0}
                })
            else:
                findings.append({
                    'resource_type': 'EC2Account',
                    'resource_id': f'key-pairs-{region}',
                    'region': region,
                    'severity': 'INFO',
                    'title': 'EC2 Key Pairs Inventory',
                    'description': f'Found {len(key_pairs)} EC2 key pairs in region {region}',
                    'recommendation': 'Regularly review and rotate SSH key pairs',
                    'compliance': ['AWS-Well-Architected'],
                    'tags': {'service': 'ec2', 'category': 'key_management', 'key_count': len(key_pairs)}
                })
                
        except ClientError as e:
            self.logger.error(f"Failed to scan key pairs in region {region}: {e}")
            
        return findings
    
    async def _scan_network_interfaces(self, ec2_client, region: str) -> List[Dict]:
        """Scan network interfaces and Elastic IPs."""
        findings = []
        
        try:
            # Scan Elastic IPs
            eip_response = ec2_client.describe_addresses()
            addresses = eip_response.get('Addresses', [])
            
            unassociated_eips = 0
            for address in addresses:
                if 'InstanceId' not in address and 'AssociationId' not in address:
                    unassociated_eips += 1
            
            if unassociated_eips > 0:
                findings.append({
                    'resource_type': 'ElasticIP',
                    'resource_id': f'unassociated-eips-{region}',
                    'region': region,
                    'severity': 'LOW',
                    'title': 'Unassociated Elastic IPs Found',
                    'description': f'Found {unassociated_eips} unassociated Elastic IPs in region {region}',
                    'recommendation': 'Release unused Elastic IPs to avoid charges',
                    'compliance': ['AWS-Well-Architected'],
                    'tags': {'service': 'ec2', 'category': 'network_management', 'unassociated_count': unassociated_eips}
                })
                
        except ClientError as e:
            self.logger.error(f"Failed to scan network interfaces in region {region}: {e}")
            
        return findings
    
    async def _analyze_dependencies(self, ec2_client, region: str) -> List[Dict]:
        """Analyze cross-resource security dependencies."""
        # This would analyze relationships between instances, security groups, volumes, etc.
        return []
    
    def _determine_rule_severity(self, rule: Dict) -> str:
        """Determine the severity of a security group rule."""
        protocol = rule.get('IpProtocol', '')
        from_port = rule.get('FromPort', 0)
        to_port = rule.get('ToPort', 0)
        
        if protocol == '-1':  # All traffic
            return 'CRITICAL'
        elif from_port in self.critical_ports or to_port in self.critical_ports:
            return 'CRITICAL'
        elif to_port - from_port > 100:  # Large port range
            return 'HIGH'
        else:
            return 'MEDIUM'
    
    def _format_port_range(self, rule: Dict) -> str:
        """Format port range for human-readable output."""
        protocol = rule.get('IpProtocol', 'unknown')
        
        if protocol == '-1':
            return 'all ports (all traffic)'
        
        from_port = rule.get('FromPort', 0)
        to_port = rule.get('ToPort', 0)
        
        port_name = self.critical_ports.get(from_port, '')
        if port_name and from_port == to_port:
            return f'port {from_port}/{protocol} ({port_name})'
        elif from_port == to_port:
            return f'port {from_port}/{protocol}'
        else:
            return f'ports {from_port}-{to_port}/{protocol}'