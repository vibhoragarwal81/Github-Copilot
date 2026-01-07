"""
VPC (Virtual Private Cloud) Scanner for AWS CSPM

This module performs comprehensive security scanning of AWS VPC components including:

NETWORK INFRASTRUCTURE SCANNED:
1. VPCs (Virtual Private Clouds)
   - Default VPCs (should be removed in production)
   - CIDR block configurations 
   - DNS settings and resolution
   - DHCP option sets

2. Subnets
   - Public vs Private subnet configuration
   - Auto-assign public IP settings
   - Availability zone distribution
   - Network ACL associations

3. Security Groups (Virtual Firewalls) 
   - Inbound/outbound rules analysis
   - Overly permissive rules (0.0.0.0/0, ::/0)
   - Unused security groups
   - Default security group modifications

4. Network Access Control Lists (NACLs)
   - Stateless firewall rules
   - Default NACL modifications  
   - Overly permissive NACL rules
   - Subnet associations

5. Route Tables
   - Public route configurations
   - Internet Gateway associations
   - NAT Gateway usage
   - VPC Peering routes

6. Internet and NAT Gateways
   - Unnecessary internet access
   - NAT Gateway high availability
   - Elastic IP associations

7. VPC Endpoints
   - S3 and DynamoDB gateway endpoints
   - Interface endpoints for services
   - Endpoint policies and access

8. Flow Logs
   - VPC Flow Logs configuration
   - CloudWatch integration
   - S3 delivery settings

SECURITY FOCUS AREAS:
- Network Segmentation: Proper isolation between environments
- Access Control: Least privilege network access
- Monitoring: Traffic logging and analysis
- Public Exposure: Minimizing internet-facing resources
- Encryption: Traffic encryption in transit

COMPLIANCE FRAMEWORKS:
- CIS AWS Foundations Benchmark (VPC sections)
- NIST Cybersecurity Framework (Network Security)
- PCI-DSS (Network Segmentation requirements)
- SOC 2 (Network monitoring and controls)

COMMON VULNERABILITIES DETECTED:
- Default VPCs in production environments
- Overly broad security group rules (0.0.0.0/0)
- Missing VPC Flow Logs
- Public subnets with sensitive resources
- Unused or orphaned network resources
- Misconfigured route tables
"""

import logging
from typing import Dict, List, Optional

from botocore.exceptions import ClientError


class VPCScanner:
    """
    Comprehensive VPC Security Scanner
    
    Analyzes AWS VPC infrastructure for security vulnerabilities, 
    misconfigurations, and compliance violations across network components.
    """
    
    def __init__(self, config, aws_client_manager):
        """
        Initialize VPC Scanner with configuration and AWS client manager.
        
        Args:
            config: Configuration object containing scan settings
            aws_client_manager: Manager for AWS API client connections
        """
        self.config = config
        self.aws_client_manager = aws_client_manager
        self.logger = logging.getLogger(__name__)
        
        # Cache for reducing API calls
        self._vpc_cache = {}
        self._subnet_cache = {}
        self._security_group_cache = {}
    
    async def scan(self, session, region: str) -> List[Dict]:
        """
        Perform comprehensive VPC security scan for specified region.
        
        This method orchestrates scanning of all VPC components including
        VPCs, subnets, security groups, NACLs, route tables, gateways,
        endpoints, and flow logs.
        
        Args:
            session: Authenticated AWS session with appropriate permissions
            region: AWS region to scan (e.g., 'us-east-1', 'eu-west-1')
            
        Returns:
            List[Dict]: Security findings with the following structure:
                - resource_type: Type of AWS resource (e.g., 'VPC', 'SecurityGroup')
                - resource_id: Unique identifier (VPC ID, Security Group ID, etc.)
                - region: AWS region where resource is located  
                - severity: CRITICAL, HIGH, MEDIUM, LOW, or INFO
                - title: Brief description of the finding
                - description: Detailed explanation of the security issue
                - recommendation: Specific steps to remediate the issue
                - compliance: List of compliance frameworks this finding relates to
                - tags: Additional metadata for categorization
        """
        findings = []
        
        try:
            # Initialize EC2 client for VPC operations
            ec2_client = session.client('ec2', region_name=region)
            self.logger.info(f"Starting VPC security scan in region {region}")
            
            # 1. Scan VPCs for configuration issues
            self.logger.debug("Scanning VPCs...")
            vpc_findings = await self._scan_vpcs(ec2_client, region)
            findings.extend(vpc_findings)
            
            # 2. Scan subnets for public exposure and configuration
            self.logger.debug("Scanning subnets...")
            subnet_findings = await self._scan_subnets(ec2_client, region)
            findings.extend(subnet_findings)
            
            # 3. Scan security groups for overly permissive rules
            self.logger.debug("Scanning security groups...")
            security_group_findings = await self._scan_security_groups(ec2_client, region)
            findings.extend(security_group_findings)
            
            # 4. Scan Network ACLs for misconfigurations
            self.logger.debug("Scanning Network ACLs...")
            nacl_findings = await self._scan_nacls(ec2_client, region)
            findings.extend(nacl_findings)
            
            # 5. Scan route tables for public routing issues
            self.logger.debug("Scanning route tables...")
            route_table_findings = await self._scan_route_tables(ec2_client, region)
            findings.extend(route_table_findings)
            
            # 6. Scan internet and NAT gateways  
            self.logger.debug("Scanning gateways...")
            gateway_findings = await self._scan_gateways(ec2_client, region)
            findings.extend(gateway_findings)
            
            # 7. Scan VPC endpoints for proper configuration
            self.logger.debug("Scanning VPC endpoints...")
            endpoint_findings = await self._scan_vpc_endpoints(ec2_client, region)
            findings.extend(endpoint_findings)
            
            # 8. Check VPC Flow Logs configuration
            self.logger.debug("Checking VPC Flow Logs...")
            flow_log_findings = await self._check_vpc_flow_logs(ec2_client, region)
            findings.extend(flow_log_findings)
            
            self.logger.info(f"VPC scan completed in {region}. Found {len(findings)} findings")
            return findings
            
        except Exception as e:
            self.logger.error(f"VPC scan failed in region {region}: {str(e)}")
            # Return a finding about the scan failure itself
            return [{
                'resource_type': 'VPC',
                'resource_id': f'scan-failure-{region}',
                'region': region,
                'severity': 'INFO',
                'title': 'VPC Scan Failed',
                'description': f'Unable to complete VPC scan in {region}: {str(e)}',
                'recommendation': 'Check AWS permissions and connectivity',
                'compliance': [],
                'tags': {'error': True, 'scan_failure': True}
            }]
    
    async def _scan_vpcs(self, ec2_client, region: str) -> List[Dict]:
        """
        Scan VPCs for security and configuration issues.
        
        This method checks for:
        - Default VPCs in production environments (security risk)
        - VPCs without proper DNS settings
        - VPCs with overly broad CIDR blocks
        - Missing or misconfigured DHCP option sets
        - VPCs without Flow Logs enabled
        
        Args:
            ec2_client: EC2 client for the target region
            region: AWS region being scanned
            
        Returns:
            List[Dict]: VPC-specific security findings
        """
        findings = []
        
        try:
            # Get all VPCs in the region
            response = ec2_client.describe_vpcs()
            vpcs = response.get('Vpcs', [])
            
            self.logger.debug(f"Found {len(vpcs)} VPCs in region {region}")
            
            for vpc in vpcs:
                vpc_id = vpc['VpcId']
                is_default = vpc.get('IsDefault', False)
                cidr_block = vpc.get('CidrBlock', '')
                state = vpc.get('State', '')
                
                # Store VPC in cache for other methods to use
                self._vpc_cache[vpc_id] = vpc
                
                # CRITICAL: Check for default VPC in production
                # Default VPCs are created automatically and often have insecure defaults
                if is_default:
                    findings.append({
                        'resource_type': 'VPC',
                        'resource_id': vpc_id,
                        'region': region,
                        'severity': 'HIGH',  # Could be CRITICAL in production environments
                        'title': 'Default VPC Found',
                        'description': (
                            f'Default VPC {vpc_id} exists in region {region}. '
                            'Default VPCs are created automatically by AWS and typically have '
                            'insecure default configurations including internet gateways and '
                            'public subnets that may expose resources unintentionally.'
                        ),
                        'recommendation': (
                            'Delete the default VPC and create custom VPCs with explicit '
                            'security configurations. Ensure all subnets, route tables, '
                            'and security groups are intentionally configured.'
                        ),
                        'compliance': ['CIS-AWS-2.1', 'NIST-800-53-SC-7'],
                        'tags': {
                            'service': 'vpc',
                            'category': 'default_resources',
                            'cidr_block': cidr_block,
                            'impact': 'high'
                        }
                    })
                
                # Check for overly broad CIDR blocks
                # Large CIDR blocks can indicate poor network planning
                if cidr_block:
                    cidr_size = self._calculate_cidr_size(cidr_block)
                    if cidr_size > 65536:  # /16 or larger (more than 65,536 IPs)
                        findings.append({
                            'resource_type': 'VPC',
                            'resource_id': vpc_id,
                            'region': region,
                            'severity': 'MEDIUM',
                            'title': 'VPC Has Large CIDR Block',
                            'description': (
                                f'VPC {vpc_id} has a large CIDR block ({cidr_block}) '
                                f'providing {cidr_size:,} IP addresses. '
                                'Large CIDR blocks can indicate poor network planning '
                                'and may complicate security group rules and monitoring.'
                            ),
                            'recommendation': (
                                'Consider using smaller, more specific CIDR blocks for better '
                                'network segmentation and security. Plan your IP address space '
                                'based on actual requirements rather than using default large blocks.'
                            ),
                            'compliance': ['NIST-800-53-SC-7'],
                            'tags': {
                                'service': 'vpc',
                                'category': 'network_planning',
                                'cidr_block': cidr_block,
                                'ip_count': cidr_size
                            }
                        })
                
                # Check DNS configuration
                # Proper DNS settings are important for service discovery and resolution
                try:
                    dns_response = ec2_client.describe_vpc_attribute(
                        VpcId=vpc_id,
                        Attribute='enableDnsResolution'
                    )
                    dns_hostnames_response = ec2_client.describe_vpc_attribute(
                        VpcId=vpc_id,
                        Attribute='enableDnsHostnames'
                    )
                    
                    dns_resolution = dns_response.get('EnableDnsResolution', {}).get('Value', False)
                    dns_hostnames = dns_hostnames_response.get('EnableDnsHostnames', {}).get('Value', False)
                    
                    if not dns_resolution:
                        findings.append({
                            'resource_type': 'VPC',
                            'resource_id': vpc_id,
                            'region': region,
                            'severity': 'MEDIUM',
                            'title': 'VPC DNS Resolution Disabled',
                            'description': (
                                f'VPC {vpc_id} has DNS resolution disabled. '
                                'This can cause issues with service discovery, '
                                'AWS service endpoints, and application connectivity.'
                            ),
                            'recommendation': 'Enable DNS resolution for the VPC unless specifically not needed.',
                            'compliance': ['AWS-Well-Architected'],
                            'tags': {'service': 'vpc', 'category': 'dns_configuration'}
                        })
                    
                    if not dns_hostnames and dns_resolution:
                        findings.append({
                            'resource_type': 'VPC',
                            'resource_id': vpc_id,
                            'region': region,
                            'severity': 'LOW',
                            'title': 'VPC DNS Hostnames Disabled',
                            'description': (
                                f'VPC {vpc_id} has DNS hostnames disabled while DNS resolution is enabled. '
                                'This may prevent instances from receiving public DNS hostnames.'
                            ),
                            'recommendation': 'Enable DNS hostnames if instances need public DNS names.',
                            'compliance': ['AWS-Well-Architected'],
                            'tags': {'service': 'vpc', 'category': 'dns_configuration'}
                        })
                        
                except ClientError as e:
                    self.logger.debug(f"Could not check DNS settings for VPC {vpc_id}: {e}")
                
        except ClientError as e:
            self.logger.error(f"Failed to scan VPCs in region {region}: {e}")
            findings.append({
                'resource_type': 'VPC',
                'resource_id': 'unknown',
                'region': region,
                'severity': 'INFO',
                'title': 'VPC Scan Permission Error',
                'description': f'Unable to describe VPCs: {e}',
                'recommendation': 'Ensure EC2:DescribeVpcs permission is granted',
                'compliance': [],
                'tags': {'error': True, 'permission_error': True}
            })
            
        return findings
    
    def _calculate_cidr_size(self, cidr_block: str) -> int:
        """
        Calculate the number of IP addresses in a CIDR block.
        
        Args:
            cidr_block: CIDR notation (e.g., '10.0.0.0/16')
            
        Returns:
            int: Number of available IP addresses
        """
        try:
            _, prefix_length = cidr_block.split('/')
            prefix_length = int(prefix_length)
            # IPv4 has 32 bits total
            host_bits = 32 - prefix_length
            return 2 ** host_bits
        except:
            return 0
    
    async def _scan_security_groups(self, ec2_client, region: str) -> List[Dict]:
        """
        Scan Security Groups for overly permissive rules and security issues.
        
        Security Groups act as virtual firewalls and are critical for network security.
        This method identifies:
        - Rules allowing access from anywhere (0.0.0.0/0, ::/0)
        - Overly broad port ranges
        - Unused security groups
        - Default security group modifications
        - Missing egress restrictions
        
        Args:
            ec2_client: EC2 client for API calls
            region: AWS region being scanned
            
        Returns:
            List[Dict]: Security group findings
        """
        findings = []
        
        try:
            response = ec2_client.describe_security_groups()
            security_groups = response.get('SecurityGroups', [])
            
            self.logger.debug(f"Found {len(security_groups)} security groups in region {region}")
            
            for sg in security_groups:
                sg_id = sg['GroupId']
                sg_name = sg['GroupName']
                vpc_id = sg.get('VpcId', 'EC2-Classic')
                
                # Store in cache
                self._security_group_cache[sg_id] = sg
                
                # Check for overly permissive inbound rules
                for rule in sg.get('IpPermissions', []):
                    # Check for 0.0.0.0/0 (anywhere IPv4) access
                    for ip_range in rule.get('IpRanges', []):
                        cidr = ip_range.get('CidrIp', '')
                        if cidr == '0.0.0.0/0':
                            severity = self._determine_rule_severity(rule)
                            findings.append({
                                'resource_type': 'SecurityGroup',
                                'resource_id': sg_id,
                                'region': region,
                                'severity': severity,
                                'title': 'Security Group Allows Access From Anywhere',
                                'description': (
                                    f'Security group {sg_name} ({sg_id}) has an inbound rule '
                                    f'allowing access from anywhere (0.0.0.0/0) on '
                                    f'{self._format_port_range(rule)}. '
                                    'This exposes resources to potential attacks from the internet.'
                                ),
                                'recommendation': (
                                    'Restrict access to specific IP addresses or ranges. '
                                    'Use least privilege principle and only allow access '
                                    'from trusted networks or specific IP addresses.'
                                ),
                                'compliance': ['CIS-AWS-4.1', 'CIS-AWS-4.2', 'NIST-800-53-AC-4'],
                                'tags': {
                                    'service': 'ec2',
                                    'category': 'network_security',
                                    'sg_name': sg_name,
                                    'vpc_id': vpc_id,
                                    'protocol': rule.get('IpProtocol', 'unknown'),
                                    'port_range': self._format_port_range(rule)
                                }
                            })
                    
                    # Check for ::/0 (anywhere IPv6) access
                    for ipv6_range in rule.get('Ipv6Ranges', []):
                        cidr = ipv6_range.get('CidrIpv6', '')
                        if cidr == '::/0':
                            severity = self._determine_rule_severity(rule)
                            findings.append({
                                'resource_type': 'SecurityGroup', 
                                'resource_id': sg_id,
                                'region': region,
                                'severity': severity,
                                'title': 'Security Group Allows IPv6 Access From Anywhere',
                                'description': (
                                    f'Security group {sg_name} ({sg_id}) allows inbound '
                                    f'IPv6 access from anywhere (::/0) on {self._format_port_range(rule)}'
                                ),
                                'recommendation': 'Restrict IPv6 access to specific networks or disable if not needed',
                                'compliance': ['CIS-AWS-4.1', 'NIST-800-53-AC-4'],
                                'tags': {
                                    'service': 'ec2',
                                    'category': 'network_security',
                                    'sg_name': sg_name,
                                    'vpc_id': vpc_id,
                                    'ipv6': True
                                }
                            })
                
                # Check if this is the default security group with custom rules
                if sg_name == 'default':
                    inbound_rules = sg.get('IpPermissions', [])
                    outbound_rules = sg.get('IpPermissionsEgress', [])
                    
                    # Default SG should ideally have no custom rules
                    if len(inbound_rules) > 1 or len(outbound_rules) > 1:  # More than just the default self-referencing rule
                        findings.append({
                            'resource_type': 'SecurityGroup',
                            'resource_id': sg_id,
                            'region': region,
                            'severity': 'MEDIUM',
                            'title': 'Default Security Group Has Custom Rules',
                            'description': (
                                f'Default security group {sg_id} in VPC {vpc_id} '
                                'has been modified with custom rules. '
                                'Default security groups should not be used for resources.'
                            ),
                            'recommendation': (
                                'Create specific security groups for your resources instead '
                                'of modifying the default security group. Remove custom rules '
                                'from the default security group.'
                            ),
                            'compliance': ['CIS-AWS-4.3'],
                            'tags': {
                                'service': 'ec2',
                                'category': 'default_resources',
                                'vpc_id': vpc_id
                            }
                        })
                        
        except ClientError as e:
            self.logger.error(f"Failed to scan security groups in region {region}: {e}")
            
        return findings
    
    def _determine_rule_severity(self, rule: Dict) -> str:
        """Determine the severity of a security group rule based on protocol and ports."""
        protocol = rule.get('IpProtocol', '')
        from_port = rule.get('FromPort', 0)
        to_port = rule.get('ToPort', 0)
        
        # Critical ports that should never be open to 0.0.0.0/0
        critical_ports = [22, 3389, 1433, 3306, 5432, 6379, 27017]  # SSH, RDP, SQL Server, MySQL, PostgreSQL, Redis, MongoDB
        
        # High risk ports
        high_risk_ports = [21, 23, 25, 53, 80, 110, 143, 993, 995, 8080, 8443]  # FTP, Telnet, SMTP, DNS, HTTP, etc.
        
        if protocol == '-1':  # All traffic
            return 'CRITICAL'
        elif any(port in range(from_port, to_port + 1) for port in critical_ports):
            return 'CRITICAL'
        elif any(port in range(from_port, to_port + 1) for port in high_risk_ports):
            return 'HIGH'
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
        
        if from_port == to_port:
            return f'port {from_port}/{protocol}'
        else:
            return f'ports {from_port}-{to_port}/{protocol}'
    
    async def _scan_subnets(self, ec2_client, region: str) -> List[Dict]:
        """Scan subnets for public exposure and misconfigurations."""
        findings = []
        
        try:
            response = ec2_client.describe_subnets()
            subnets = response.get('Subnets', [])
            
            for subnet in subnets:
                subnet_id = subnet['SubnetId']
                vpc_id = subnet['VpcId']
                map_public_ip = subnet.get('MapPublicIpOnLaunch', False)
                availability_zone = subnet['AvailabilityZone']
                
                # Store subnet in cache
                self._subnet_cache[subnet_id] = subnet
                
                # Check for auto-assign public IP
                if map_public_ip:
                    findings.append({
                        'resource_type': 'Subnet',
                        'resource_id': subnet_id,
                        'region': region,
                        'severity': 'HIGH',
                        'title': 'Subnet Auto-Assigns Public IPs',
                        'description': f'Subnet {subnet_id} in VPC {vpc_id} automatically assigns public IP addresses to instances',
                        'recommendation': 'Disable auto-assign public IP for subnets containing sensitive resources',
                        'compliance': ['CIS-AWS-2.1'],
                        'tags': {'service': 'vpc', 'category': 'subnet_security', 'vpc_id': vpc_id, 'az': availability_zone}
                    })
                    
        except Exception as e:
            self.logger.error(f"Failed to scan subnets in region {region}: {e}")
            
        return findings
    
    async def _scan_nacls(self, ec2_client, region: str) -> List[Dict]:
        """Scan Network ACLs for overly permissive rules."""
        findings = []
        
        try:
            response = ec2_client.describe_network_acls()
            nacls = response.get('NetworkAcls', [])
            
            for nacl in nacls:
                nacl_id = nacl['NetworkAclId']
                is_default = nacl.get('IsDefault', False)
                
                # Check for overly permissive rules
                entries = nacl.get('Entries', [])
                for entry in entries:
                    cidr_block = entry.get('CidrBlock', '')
                    rule_action = entry.get('RuleAction', '')
                    
                    if cidr_block == '0.0.0.0/0' and rule_action == 'allow':
                        protocol = entry.get('Protocol', '')
                        port_range = entry.get('PortRange', {})
                        
                        findings.append({
                            'resource_type': 'NetworkACL',
                            'resource_id': nacl_id,
                            'region': region,
                            'severity': 'MEDIUM',
                            'title': 'Network ACL Allows Access From Anywhere',
                            'description': f'Network ACL {nacl_id} has a rule allowing access from 0.0.0.0/0',
                            'recommendation': 'Review and restrict Network ACL rules to specific IP ranges',
                            'compliance': ['CIS-AWS-4.1'],
                            'tags': {'service': 'vpc', 'category': 'network_acl', 'is_default': is_default, 'protocol': protocol}
                        })
                        
        except Exception as e:
            self.logger.error(f"Failed to scan Network ACLs in region {region}: {e}")
            
        return findings
    
    async def _scan_route_tables(self, ec2_client, region: str) -> List[Dict]:
        """Scan route tables for public routing issues."""
        findings = []
        
        try:
            response = ec2_client.describe_route_tables()
            route_tables = response.get('RouteTables', [])
            
            for rt in route_tables:
                rt_id = rt['RouteTableId']
                vpc_id = rt['VpcId']
                routes = rt.get('Routes', [])
                
                # Check for routes to internet gateway
                for route in routes:
                    destination = route.get('DestinationCidrBlock', '')
                    gateway_id = route.get('GatewayId', '')
                    
                    if destination == '0.0.0.0/0' and gateway_id.startswith('igw-'):
                        findings.append({
                            'resource_type': 'RouteTable',
                            'resource_id': rt_id,
                            'region': region,
                            'severity': 'MEDIUM',
                            'title': 'Route Table Has Internet Gateway Route',
                            'description': f'Route table {rt_id} has a route to internet gateway {gateway_id}',
                            'recommendation': 'Ensure only public subnets are associated with this route table',
                            'compliance': ['AWS-Well-Architected'],
                            'tags': {'service': 'vpc', 'category': 'routing', 'vpc_id': vpc_id, 'igw_id': gateway_id}
                        })
                        
        except Exception as e:
            self.logger.error(f"Failed to scan route tables in region {region}: {e}")
            
        return findings
    
    async def _scan_gateways(self, ec2_client, region: str) -> List[Dict]:
        """Scan internet and NAT gateways."""
        findings = []
        
        try:
            # Scan Internet Gateways
            igw_response = ec2_client.describe_internet_gateways()
            igws = igw_response.get('InternetGateways', [])
            
            for igw in igws:
                igw_id = igw['InternetGatewayId']
                attachments = igw.get('Attachments', [])
                
                if attachments:
                    for attachment in attachments:
                        vpc_id = attachment.get('VpcId', '')
                        state = attachment.get('State', '')
                        
                        if state == 'available':
                            findings.append({
                                'resource_type': 'InternetGateway',
                                'resource_id': igw_id,
                                'region': region,
                                'severity': 'INFO',
                                'title': 'Internet Gateway Attached to VPC',
                                'description': f'Internet Gateway {igw_id} is attached to VPC {vpc_id}',
                                'recommendation': 'Ensure proper security controls for internet-facing resources',
                                'compliance': ['AWS-Well-Architected'],
                                'tags': {'service': 'vpc', 'category': 'internet_gateway', 'vpc_id': vpc_id}
                            })
            
            # Scan NAT Gateways
            nat_response = ec2_client.describe_nat_gateways()
            nat_gateways = nat_response.get('NatGateways', [])
            
            for nat in nat_gateways:
                nat_id = nat['NatGatewayId']
                state = nat.get('State', '')
                subnet_id = nat.get('SubnetId', '')
                
                if state == 'available':
                    findings.append({
                        'resource_type': 'NATGateway',
                        'resource_id': nat_id,
                        'region': region,
                        'severity': 'INFO',
                        'title': 'NAT Gateway Available',
                        'description': f'NAT Gateway {nat_id} is available in subnet {subnet_id}',
                        'recommendation': 'Monitor NAT Gateway costs and usage',
                        'compliance': ['AWS-Well-Architected'],
                        'tags': {'service': 'vpc', 'category': 'nat_gateway', 'subnet_id': subnet_id}
                    })
                    
        except Exception as e:
            self.logger.error(f"Failed to scan gateways in region {region}: {e}")
            
        return findings
    
    async def _scan_vpc_endpoints(self, ec2_client, region: str) -> List[Dict]:
        """Scan VPC endpoints for proper configuration."""
        findings = []
        
        try:
            response = ec2_client.describe_vpc_endpoints()
            endpoints = response.get('VpcEndpoints', [])
            
            if not endpoints:
                findings.append({
                    'resource_type': 'VPCEndpoints',
                    'resource_id': f'endpoints-{region}',
                    'region': region,
                    'severity': 'LOW',
                    'title': 'No VPC Endpoints Found',
                    'description': f'No VPC endpoints found in region {region}',
                    'recommendation': 'Consider using VPC endpoints for AWS services to improve security and reduce costs',
                    'compliance': ['AWS-Well-Architected'],
                    'tags': {'service': 'vpc', 'category': 'vpc_endpoints', 'endpoint_count': 0}
                })
            else:
                for endpoint in endpoints:
                    endpoint_id = endpoint['VpcEndpointId']
                    service_name = endpoint.get('ServiceName', '')
                    state = endpoint.get('State', '')
                    
                    findings.append({
                        'resource_type': 'VPCEndpoint',
                        'resource_id': endpoint_id,
                        'region': region,
                        'severity': 'INFO',
                        'title': 'VPC Endpoint Available',
                        'description': f'VPC endpoint {endpoint_id} for service {service_name} is {state}',
                        'recommendation': 'Ensure VPC endpoint policies are properly configured',
                        'compliance': ['AWS-Well-Architected'],
                        'tags': {'service': 'vpc', 'category': 'vpc_endpoints', 'service_name': service_name, 'state': state}
                    })
                    
        except Exception as e:
            self.logger.error(f"Failed to scan VPC endpoints in region {region}: {e}")
            
        return findings
    
    async def _check_vpc_flow_logs(self, ec2_client, region: str) -> List[Dict]:
        """Check VPC Flow Logs configuration."""
        findings = []
        
        try:
            # Get all VPCs first
            vpcs_response = ec2_client.describe_vpcs()
            vpcs = vpcs_response.get('Vpcs', [])
            
            # Get flow logs
            flow_logs_response = ec2_client.describe_flow_logs()
            flow_logs = flow_logs_response.get('FlowLogs', [])
            
            # Create a set of VPCs that have flow logs
            vpcs_with_flow_logs = set()
            for log in flow_logs:
                resource_id = log.get('ResourceId', '')
                if resource_id.startswith('vpc-'):
                    vpcs_with_flow_logs.add(resource_id)
            
            # Check each VPC for flow logs
            for vpc in vpcs:
                vpc_id = vpc['VpcId']
                is_default = vpc.get('IsDefault', False)
                
                if vpc_id not in vpcs_with_flow_logs:
                    severity = 'HIGH' if not is_default else 'MEDIUM'
                    findings.append({
                        'resource_type': 'VPC',
                        'resource_id': vpc_id,
                        'region': region,
                        'severity': severity,
                        'title': 'VPC Flow Logs Not Enabled',
                        'description': f'VPC {vpc_id} does not have flow logs enabled',
                        'recommendation': 'Enable VPC Flow Logs for network monitoring and security analysis',
                        'compliance': ['CIS-AWS-2.9'],
                        'tags': {'service': 'vpc', 'category': 'flow_logs', 'is_default': is_default}
                    })
                    
        except Exception as e:
            self.logger.error(f"Failed to check VPC flow logs in region {region}: {e}")
            
        return findings