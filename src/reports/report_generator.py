"""
Report Generator for AWS CSPM

This module generates various types of reports from scan results.
"""

import json
import logging
import os
from datetime import datetime
from typing import Dict

from src.utils.config import Config


class ReportGenerator:
    """Generates security reports from scan results."""
    
    def __init__(self, config: Config):
        """
        Initialize the Report Generator.
        
        Args:
            config: Configuration object
        """
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.output_dir = config.get('output_directory', 'reports')
        
        # Create output directory if it doesn't exist
        os.makedirs(self.output_dir, exist_ok=True)
    
    async def generate_json_report(self, scan_results: Dict) -> str:
        """
        Generate JSON report from scan results.
        
        Args:
            scan_results: Scan results dictionary
            
        Returns:
            str: Path to generated JSON report
        """
        timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
        filename = f"cspm_report_{timestamp}.json"
        filepath = os.path.join(self.output_dir, filename)
        
        try:
            # Process scan results into a structured format
            processed_results = self._process_scan_results(scan_results)
            
            # Create comprehensive report structure
            report = {
                'metadata': {
                    'scan_timestamp': datetime.utcnow().isoformat(),
                    'report_version': '1.0',
                    'scanner_version': self.config.get('version', '1.0.0'),
                    'total_accounts_scanned': len(scan_results),
                },
                'summary': processed_results['summary'],
                'accounts': processed_results['accounts'],
                'findings_by_service': processed_results['findings_by_service'],
                'findings_by_severity': processed_results['findings_by_severity'],
                'compliance_summary': processed_results['compliance_summary']
            }
            
            # Write to file
            with open(filepath, 'w') as f:
                json.dump(report, f, indent=2, default=str)
            
            # Generate summary file for GitHub Actions
            summary_filepath = os.path.join(self.output_dir, 'scan_summary.json')
            with open(summary_filepath, 'w') as f:
                json.dump({
                    'total_accounts': processed_results['summary']['total_accounts'],
                    'total_findings': processed_results['summary']['total_findings'],
                    'critical_findings': processed_results['summary']['critical_findings'],
                    'high_findings': processed_results['summary']['high_findings'],
                    'medium_findings': processed_results['summary']['medium_findings'],
                    'low_findings': processed_results['summary']['low_findings'],
                    'scan_duration': processed_results['summary'].get('scan_duration', 'N/A'),
                    'timestamp': datetime.utcnow().isoformat()
                }, f, indent=2)
            
            self.logger.info(f"JSON report generated: {filepath}")
            return filepath
            
        except Exception as e:
            self.logger.error(f"Failed to generate JSON report: {str(e)}")
            raise
    
    def _process_scan_results(self, scan_results: Dict) -> Dict:
        """Process raw scan results into structured format for reporting."""
        total_findings = 0
        findings_by_severity = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        findings_by_service = {}
        compliance_summary = {}
        processed_accounts = []
        
        for account_id, account_data in scan_results.items():
            if 'error' in account_data:
                processed_accounts.append({
                    'account_id': account_id,
                    'account_name': account_data.get('account_info', {}).get('Name', 'Unknown'),
                    'scan_status': 'failed',
                    'error': account_data['error'],
                    'findings_count': 0
                })
                continue
            
            account_findings = account_data.get('findings', {})
            account_total_findings = 0
            
            # Process service findings
            for service_name, regions in account_findings.get('services', {}).items():
                if service_name not in findings_by_service:
                    findings_by_service[service_name] = 0
                
                for region, findings in regions.items():
                    for finding in findings:
                        total_findings += 1
                        account_total_findings += 1
                        findings_by_service[service_name] += 1
                        
                        # Count by severity
                        severity = finding.get('severity', 'info').lower()
                        if severity in findings_by_severity:
                            findings_by_severity[severity] += 1
                        
                        # Count compliance frameworks
                        for framework in finding.get('compliance', []):
                            if framework not in compliance_summary:
                                compliance_summary[framework] = 0
                            compliance_summary[framework] += 1
            
            processed_accounts.append({
                'account_id': account_id,
                'account_name': account_data.get('account_info', {}).get('Name', 'Unknown'),
                'scan_status': 'completed',
                'findings_count': account_total_findings,
                'scan_timestamp': account_data.get('scan_timestamp')
            })
        
        return {
            'summary': {
                'total_accounts': len(scan_results),
                'total_findings': total_findings,
                'critical_findings': findings_by_severity['critical'],
                'high_findings': findings_by_severity['high'],
                'medium_findings': findings_by_severity['medium'],
                'low_findings': findings_by_severity['low'],
                'info_findings': findings_by_severity['info']
            },
            'accounts': processed_accounts,
            'findings_by_service': findings_by_service,
            'findings_by_severity': findings_by_severity,
            'compliance_summary': compliance_summary
        }
    
    async def generate_html_report(self, scan_results: Dict) -> str:
        """
        Generate HTML report from scan results.
        
        Args:
            scan_results: Scan results dictionary
            
        Returns:
            str: Path to generated HTML report
        """
        timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
        filename = f"cspm_report_{timestamp}.html"
        filepath = os.path.join(self.output_dir, filename)
        
        try:
            html_content = self._generate_html_content(scan_results)
            
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            self.logger.info(f"Generated HTML report: {filepath}")
            return filepath
            
        except Exception as e:
            self.logger.error(f"Failed to generate HTML report: {str(e)}")
            raise
    
    async def generate_csv_report(self, scan_results: Dict) -> str:
        """
        Generate CSV report from scan results.
        
        Args:
            scan_results: Scan results dictionary
            
        Returns:
            str: Path to generated CSV report
        """
        timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
        filename = f"cspm_report_{timestamp}.csv"
        filepath = os.path.join(self.output_dir, filename)
        
        try:
            csv_content = self._generate_csv_content(scan_results)
            
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(csv_content)
            
            self.logger.info(f"Generated CSV report: {filepath}")
            return filepath
            
        except Exception as e:
            self.logger.error(f"Failed to generate CSV report: {str(e)}")
            raise
    
    async def generate_pdf_report(self, scan_results: Dict) -> str:
        """
        Generate PDF report from scan results.
        
        Args:
            scan_results: Scan results dictionary
            
        Returns:
            str: Path to generated PDF report
        """
        # PDF generation would require additional dependencies like reportlab
        self.logger.warning("PDF report generation not implemented yet")
        return ""
    
    def _generate_html_content(self, scan_results: Dict) -> str:
        """
        Generate comprehensive HTML content for the security report.
        
        Creates an interactive dashboard with executive summary, detailed findings,
        charts, filtering capabilities, and compliance overview.
        
        Args:
            scan_results: Scan results dictionary
            
        Returns:
            str: Complete HTML content with embedded CSS and JavaScript
        """
        processed_results = self._process_scan_results(scan_results)
        timestamp = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
        
        html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AWS CSPM Security Report - {timestamp}</title>
    <style>
        /* Modern CSS Variables for theming */
        :root {{
            --primary-color: #232f3e;
            --secondary-color: #ff9900;
            --background-color: #f8f9fa;
            --card-background: #ffffff;
            --text-color: #333333;
            --border-color: #dee2e6;
            --success-color: #28a745;
            --warning-color: #ffc107;
            --danger-color: #dc3545;
            --info-color: #17a2b8;
            --critical-color: #8b0000;
            --shadow: 0 2px 4px rgba(0,0,0,0.1);
            --border-radius: 8px;
        }}

        /* Base styles */
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}

        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background-color: var(--background-color);
            color: var(--text-color);
            line-height: 1.6;
        }}

        .container {{
            max-width: 1400px;
            margin: 0 auto;
            padding: 20px;
        }}

        /* Header */
        .header {{
            background: linear-gradient(135deg, var(--primary-color), #34495e);
            color: white;
            padding: 30px 20px;
            border-radius: var(--border-radius);
            margin-bottom: 30px;
            box-shadow: var(--shadow);
        }}

        .header h1 {{
            font-size: 2.5em;
            margin-bottom: 10px;
            display: flex;
            align-items: center;
        }}

        .header .icon {{
            font-size: 1.2em;
            margin-right: 15px;
        }}

        .header .subtitle {{
            font-size: 1.1em;
            opacity: 0.9;
            margin-bottom: 10px;
        }}

        .header .timestamp {{
            font-size: 0.9em;
            opacity: 0.7;
        }}

        /* Executive Summary Cards */
        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
            gap: 20px;
            margin-bottom: 40px;
        }}

        .summary-card {{
            background: var(--card-background);
            padding: 25px;
            border-radius: var(--border-radius);
            box-shadow: var(--shadow);
            border-left: 4px solid var(--secondary-color);
            transition: transform 0.2s ease;
        }}

        .summary-card:hover {{
            transform: translateY(-2px);
            box-shadow: 0 4px 8px rgba(0,0,0,0.15);
        }}

        .summary-card h3 {{
            font-size: 1.1em;
            margin-bottom: 10px;
            color: var(--primary-color);
        }}

        .summary-card .metric {{
            font-size: 2.5em;
            font-weight: bold;
            margin-bottom: 5px;
        }}

        .summary-card .label {{
            font-size: 0.9em;
            color: #666;
        }}

        /* Severity-specific colors */
        .critical {{ color: var(--critical-color); }}
        .high {{ color: var(--danger-color); }}
        .medium {{ color: var(--warning-color); }}
        .low {{ color: var(--success-color); }}
        .info {{ color: var(--info-color); }}

        /* Charts Container */
        .charts-container {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 30px;
            margin-bottom: 40px;
        }}

        .chart-card {{
            background: var(--card-background);
            padding: 25px;
            border-radius: var(--border-radius);
            box-shadow: var(--shadow);
        }}

        .chart-card h3 {{
            color: var(--primary-color);
            margin-bottom: 20px;
            text-align: center;
        }}

        /* Filters */
        .filters {{
            background: var(--card-background);
            padding: 20px;
            border-radius: var(--border-radius);
            margin-bottom: 30px;
            box-shadow: var(--shadow);
        }}

        .filters h3 {{
            margin-bottom: 15px;
            color: var(--primary-color);
        }}

        .filter-group {{
            display: flex;
            gap: 15px;
            flex-wrap: wrap;
            align-items: center;
        }}

        .filter-group select,
        .filter-group input {{
            padding: 8px 12px;
            border: 1px solid var(--border-color);
            border-radius: 4px;
            font-size: 0.9em;
        }}

        .filter-group label {{
            font-weight: 500;
            margin-right: 5px;
        }}

        /* Account Details */
        .accounts-section {{
            margin-bottom: 40px;
        }}

        .section-title {{
            font-size: 1.5em;
            color: var(--primary-color);
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 2px solid var(--secondary-color);
        }}

        .accounts-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(350px, 1fr));
            gap: 20px;
        }}

        .account-card {{
            background: var(--card-background);
            border: 1px solid var(--border-color);
            border-radius: var(--border-radius);
            padding: 20px;
            box-shadow: var(--shadow);
        }}

        .account-header {{
            display: flex;
            justify-content: between;
            align-items: center;
            margin-bottom: 15px;
        }}

        .account-id {{
            font-weight: bold;
            color: var(--primary-color);
        }}

        .account-name {{
            color: #666;
            font-size: 0.9em;
        }}

        .account-status {{
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.8em;
            font-weight: bold;
        }}

        .status-success {{
            background: #d4edda;
            color: #155724;
        }}

        .status-error {{
            background: #f8d7da;
            color: #721c24;
        }}

        /* Findings Table */
        .findings-section {{
            background: var(--card-background);
            border-radius: var(--border-radius);
            box-shadow: var(--shadow);
            overflow: hidden;
        }}

        .findings-header {{
            background: var(--primary-color);
            color: white;
            padding: 20px;
        }}

        .findings-header h3 {{
            margin-bottom: 10px;
        }}

        .findings-stats {{
            font-size: 0.9em;
            opacity: 0.9;
        }}

        .findings-table {{
            width: 100%;
            border-collapse: collapse;
        }}

        .findings-table th,
        .findings-table td {{
            padding: 12px 15px;
            text-align: left;
            border-bottom: 1px solid var(--border-color);
        }}

        .findings-table th {{
            background: #f8f9fa;
            font-weight: 600;
            position: sticky;
            top: 0;
        }}

        .findings-table tr:hover {{
            background: #f8f9fa;
        }}

        .severity-badge {{
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.8em;
            font-weight: bold;
            text-transform: uppercase;
        }}

        .badge-critical {{
            background: var(--critical-color);
            color: white;
        }}

        .badge-high {{
            background: var(--danger-color);
            color: white;
        }}

        .badge-medium {{
            background: var(--warning-color);
            color: #333;
        }}

        .badge-low {{
            background: var(--success-color);
            color: white;
        }}

        .badge-info {{
            background: var(--info-color);
            color: white;
        }}

        /* Compliance Section */
        .compliance-section {{
            margin-bottom: 40px;
        }}

        .compliance-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
        }}

        .compliance-card {{
            background: var(--card-background);
            padding: 20px;
            border-radius: var(--border-radius);
            box-shadow: var(--shadow);
            text-align: center;
        }}

        .compliance-score {{
            font-size: 2em;
            font-weight: bold;
            margin-bottom: 10px;
        }}

        .compliance-framework {{
            font-weight: 600;
            color: var(--primary-color);
        }}

        /* Responsive Design */
        @media (max-width: 768px) {{
            .charts-container {{
                grid-template-columns: 1fr;
            }}

            .summary-grid {{
                grid-template-columns: 1fr;
            }}

            .filter-group {{
                flex-direction: column;
                align-items: flex-start;
            }}

            .accounts-grid {{
                grid-template-columns: 1fr;
            }}

            .findings-table {{
                font-size: 0.8em;
            }}

            .findings-table th,
            .findings-table td {{
                padding: 8px 10px;
            }}
        }}

        /* Utility Classes */
        .text-center {{ text-align: center; }}
        .mb-20 {{ margin-bottom: 20px; }}
        .mt-20 {{ margin-top: 20px; }}
        .font-bold {{ font-weight: bold; }}
        .text-muted {{ color: #666; }}

        /* Animation */
        @keyframes fadeIn {{
            from {{ opacity: 0; transform: translateY(20px); }}
            to {{ opacity: 1; transform: translateY(0); }}
        }}

        .fade-in {{
            animation: fadeIn 0.6s ease-out;
        }}
    </style>
</head>
<body>
    <div class="container">
        <!-- Header Section -->
        <div class="header fade-in">
            <h1>
                <span class="icon">🛡️</span>
                AWS Cloud Security Posture Management Report
            </h1>
            <div class="subtitle">Comprehensive Security Assessment Dashboard</div>
            <div class="timestamp">Generated on: {timestamp} UTC</div>
        </div>

        <!-- Executive Summary -->
        <div class="summary-grid fade-in">
            <div class="summary-card">
                <h3>Total Accounts Scanned</h3>
                <div class="metric info">{processed_results['summary']['total_accounts']}</div>
                <div class="label">AWS Accounts</div>
            </div>
            <div class="summary-card">
                <h3>Critical Findings</h3>
                <div class="metric critical">{processed_results['summary']['critical_findings']}</div>
                <div class="label">Immediate Action Required</div>
            </div>
            <div class="summary-card">
                <h3>High Priority Issues</h3>
                <div class="metric high">{processed_results['summary']['high_findings']}</div>
                <div class="label">High Risk Vulnerabilities</div>
            </div>
            <div class="summary-card">
                <h3>Medium Priority Issues</h3>
                <div class="metric medium">{processed_results['summary']['medium_findings']}</div>
                <div class="label">Configuration Issues</div>
            </div>
            <div class="summary-card">
                <h3>Total Findings</h3>
                <div class="metric">{processed_results['summary']['total_findings']}</div>
                <div class="label">Security Issues Detected</div>
            </div>
        </div>

        <!-- Filters -->
        <div class="filters fade-in">
            <h3>🔍 Filter Results</h3>
            <div class="filter-group">
                <label for="severity-filter">Severity:</label>
                <select id="severity-filter" onchange="filterFindings()">
                    <option value="">All Severities</option>
                    <option value="critical">Critical</option>
                    <option value="high">High</option>
                    <option value="medium">Medium</option>
                    <option value="low">Low</option>
                    <option value="info">Info</option>
                </select>

                <label for="service-filter">Service:</label>
                <select id="service-filter" onchange="filterFindings()">
                    <option value="">All Services</option>"""
        
        # Add service options dynamically
        for service in processed_results['findings_by_service'].keys():
            html += f'<option value="{service}">{service.upper()}</option>'
        
        html += """
                </select>

                <label for="account-filter">Account:</label>
                <select id="account-filter" onchange="filterFindings()">
                    <option value="">All Accounts</option>"""
        
        # Add account options dynamically
        for account in processed_results['accounts']:
            account_id = account['account_id']
            account_name = account['account_name']
            html += f'<option value="{account_id}">{account_name} ({account_id})</option>'
        
        html += f"""
                </select>

                <input type="text" id="search-box" placeholder="Search findings..." onkeyup="filterFindings()">
            </div>
        </div>

        <!-- Charts Section -->
        <div class="charts-container fade-in">
            <div class="chart-card">
                <h3>📊 Findings by Severity</h3>
                <canvas id="severityChart" width="400" height="300"></canvas>
            </div>
            <div class="chart-card">
                <h3>🔧 Findings by Service</h3>
                <canvas id="serviceChart" width="400" height="300"></canvas>
            </div>
        </div>

        <!-- Account Details Section -->
        <div class="accounts-section fade-in">
            <h2 class="section-title">📋 Account Summary</h2>
            <div class="accounts-grid">"""

        # Generate account cards
        for account in processed_results['accounts']:
            account_id = account['account_id']
            account_name = account['account_name']
            scan_status = account['scan_status']
            findings_count = account['findings_count']
            
            status_class = 'status-success' if scan_status == 'completed' else 'status-error'
            status_icon = '✅' if scan_status == 'completed' else '❌'
            
            html += f"""
                <div class="account-card">
                    <div class="account-header">
                        <div>
                            <div class="account-id">{account_id}</div>
                            <div class="account-name">{account_name}</div>
                        </div>
                        <span class="account-status {status_class}">{status_icon} {scan_status}</span>
                    </div>
                    <div class="account-metrics">
                        <strong>Findings:</strong> {findings_count}<br>
                        <strong>Status:</strong> {scan_status.title()}
                    </div>
                </div>"""

        html += f"""
            </div>
        </div>

        <!-- Compliance Overview -->
        <div class="compliance-section fade-in">
            <h2 class="section-title">📈 Compliance Overview</h2>
            <div class="compliance-grid">"""

        # Generate compliance cards
        total_findings = processed_results['summary']['total_findings']
        for framework, count in processed_results['compliance_summary'].items():
            # Calculate a simple compliance score (this is a simplified example)
            compliance_score = max(0, 100 - (count * 10))  # Simplified scoring
            score_color = 'success' if compliance_score > 80 else 'warning' if compliance_score > 60 else 'danger'
            
            html += f"""
                <div class="compliance-card">
                    <div class="compliance-score {score_color}">{compliance_score}%</div>
                    <div class="compliance-framework">{framework}</div>
                    <div class="text-muted">{count} issues found</div>
                </div>"""

        html += """
            </div>
        </div>

        <!-- Detailed Findings -->
        <div class="findings-section fade-in">
            <div class="findings-header">
                <h3>🔍 Detailed Security Findings</h3>
                <div class="findings-stats" id="findings-stats">
                    Showing all findings
                </div>
            </div>
            <div style="overflow-x: auto;">
                <table class="findings-table" id="findings-table">
                    <thead>
                        <tr>
                            <th>Severity</th>
                            <th>Service</th>
                            <th>Account</th>
                            <th>Resource</th>
                            <th>Finding</th>
                            <th>Compliance</th>
                        </tr>
                    </thead>
                    <tbody id="findings-tbody">"""

        # Generate findings rows (sample - would need actual findings data structure)
        html += """
                    </tbody>
                </table>
            </div>
        </div>
    </div>

    <script>
        // Chart data
        const severityData = {
            labels: ['Critical', 'High', 'Medium', 'Low', 'Info'],
            values: [""" + str(processed_results['summary']['critical_findings']) + """, 
                    """ + str(processed_results['summary']['high_findings']) + """, 
                    """ + str(processed_results['summary']['medium_findings']) + """, 
                    """ + str(processed_results['summary']['low_findings']) + """, 
                    """ + str(processed_results['summary']['info_findings']) + """]
        };

        const serviceData = {
            labels: [""" + ', '.join([f'"{service}"' for service in processed_results['findings_by_service'].keys()]) + """],
            values: [""" + ', '.join([str(count) for count in processed_results['findings_by_service'].values()]) + """]
        };

        // Simple chart drawing function
        function drawChart(canvasId, data, colors) {
            const canvas = document.getElementById(canvasId);
            const ctx = canvas.getContext('2d');
            const total = data.values.reduce((a, b) => a + b, 0);
            
            if (total === 0) {
                ctx.fillStyle = '#666';
                ctx.font = '16px Arial';
                ctx.textAlign = 'center';
                ctx.fillText('No data available', canvas.width/2, canvas.height/2);
                return;
            }

            let currentAngle = -Math.PI / 2;
            const centerX = canvas.width / 2;
            const centerY = canvas.height / 2;
            const radius = Math.min(centerX, centerY) - 20;

            // Draw pie slices
            data.values.forEach((value, index) => {
                const sliceAngle = (value / total) * 2 * Math.PI;
                
                ctx.beginPath();
                ctx.moveTo(centerX, centerY);
                ctx.arc(centerX, centerY, radius, currentAngle, currentAngle + sliceAngle);
                ctx.closePath();
                ctx.fillStyle = colors[index % colors.length];
                ctx.fill();
                ctx.strokeStyle = '#fff';
                ctx.lineWidth = 2;
                ctx.stroke();

                currentAngle += sliceAngle;
            });

            // Draw legend
            const legendY = canvas.height - 60;
            let legendX = 10;
            data.labels.forEach((label, index) => {
                if (data.values[index] > 0) {
                    ctx.fillStyle = colors[index % colors.length];
                    ctx.fillRect(legendX, legendY, 15, 15);
                    ctx.fillStyle = '#333';
                    ctx.font = '12px Arial';
                    ctx.fillText(`${label} (${data.values[index]})`, legendX + 20, legendY + 12);
                    legendX += 120;
                }
            });
        }

        // Draw charts
        const severityColors = ['#8b0000', '#dc3545', '#ffc107', '#28a745', '#17a2b8'];
        const serviceColors = ['#ff6384', '#36a2eb', '#ffce56', '#4bc0c0', '#9966ff', '#ff9f40'];

        drawChart('severityChart', severityData, severityColors);
        drawChart('serviceChart', serviceData, serviceColors);

        // Filter functionality
        function filterFindings() {
            const severity = document.getElementById('severity-filter').value.toLowerCase();
            const service = document.getElementById('service-filter').value.toLowerCase();
            const account = document.getElementById('account-filter').value;
            const search = document.getElementById('search-box').value.toLowerCase();

            const rows = document.querySelectorAll('#findings-tbody tr');
            let visibleCount = 0;

            rows.forEach(row => {
                const cells = row.cells;
                const rowSeverity = cells[0].textContent.toLowerCase();
                const rowService = cells[1].textContent.toLowerCase();
                const rowAccount = cells[2].textContent;
                const rowText = row.textContent.toLowerCase();

                const severityMatch = !severity || rowSeverity.includes(severity);
                const serviceMatch = !service || rowService.includes(service);
                const accountMatch = !account || rowAccount.includes(account);
                const searchMatch = !search || rowText.includes(search);

                if (severityMatch && serviceMatch && accountMatch && searchMatch) {
                    row.style.display = '';
                    visibleCount++;
                } else {
                    row.style.display = 'none';
                }
            });

            document.getElementById('findings-stats').textContent = 
                `Showing ${visibleCount} of ${rows.length} findings`;
        }

        // Initialize page
        document.addEventListener('DOMContentLoaded', function() {
            // Add fade-in animation
            const elements = document.querySelectorAll('.fade-in');
            elements.forEach((el, index) => {
                setTimeout(() => {
                    el.style.opacity = '1';
                }, index * 100);
            });
        });
    </script>
</body>
</html>"""
        
        return html
    
    def _generate_csv_content(self, scan_results: Dict) -> str:
        """
        Generate CSV content for the report.
        
        Args:
            scan_results: Scan results dictionary
            
        Returns:
            str: CSV content
        """
        csv_lines = ["Account ID,Account Name,Service,Region,Finding,Severity,Description"]
        
        for account_id, result in scan_results.items():
            account_info = result.get('account_info', {})
            account_name = account_info.get('Name', 'Unknown')
            
            if 'findings' in result:
                findings = result['findings']
                services = findings.get('services', {})
                
                for service_name, regions in services.items():
                    for region, region_findings in regions.items():
                        for finding in region_findings:
                            csv_lines.append(
                                f"{account_id},{account_name},{service_name},{region},"
                                f"\"{finding.get('title', 'Unknown')}\","
                                f"{finding.get('severity', 'UNKNOWN')},"
                                f"\"{finding.get('description', '')}\""
                            )
        
        return "\\n".join(csv_lines)