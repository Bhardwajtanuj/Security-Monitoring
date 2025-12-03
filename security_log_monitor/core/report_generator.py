"""
Report Generator Module
Generates comprehensive security reports in HTML and JSON formats.
"""

import json
from datetime import datetime
from typing import List, Dict, Any, Optional
from pathlib import Path
import logging


class ReportGenerator:
    """
    Generate security monitoring reports.
    Supports HTML and JSON output formats with visualizations.
    """
    
    def __init__(self, output_dir: str = 'reports'):
        """
        Initialize ReportGenerator.
        
        Args:
            output_dir: Directory to save reports
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.logger = logging.getLogger('security_monitor.report_generator')
        
    def generate_report(self, 
                       log_stats: Dict[str, Any],
                       anomalies: List[Dict[str, Any]],
                       anomaly_stats: Dict[str, Any],
                       format: str = 'html') -> str:
        """
        Generate comprehensive security report.
        
        Args:
            log_stats: Log parsing statistics
            anomalies: List of detected anomalies
            anomaly_stats: Anomaly statistics
            format: Output format ('html' or 'json')
            
        Returns:
            Path to generated report file
        """
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        if format.lower() == 'html':
            filename = f'security_report_{timestamp}.html'
            filepath = self.output_dir / filename
            self._generate_html_report(filepath, log_stats, anomalies, anomaly_stats)
        else:
            filename = f'security_report_{timestamp}.json'
            filepath = self.output_dir / filename
            self._generate_json_report(filepath, log_stats, anomalies, anomaly_stats)
        
        self.logger.info(f"Report generated: {filepath}")
        return str(filepath)
    
    def _generate_html_report(self,
                             filepath: Path,
                             log_stats: Dict[str, Any],
                             anomalies: List[Dict[str, Any]],
                             anomaly_stats: Dict[str, Any]) -> None:
        """Generate HTML report."""
        
        html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Monitoring Report</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 20px;
            min-height: 100vh;
        }}
        
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 15px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            overflow: hidden;
        }}
        
        .header {{
            background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
            color: white;
            padding: 40px;
            text-align: center;
        }}
        
        .header h1 {{
            font-size: 2.5em;
            margin-bottom: 10px;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
        }}
        
        .header .timestamp {{
            font-size: 1.1em;
            opacity: 0.9;
        }}
        
        .content {{
            padding: 40px;
        }}
        
        .section {{
            margin-bottom: 40px;
        }}
        
        .section h2 {{
            color: #1e3c72;
            font-size: 1.8em;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 3px solid #667eea;
        }}
        
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        
        .stat-card {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 25px;
            border-radius: 10px;
            box-shadow: 0 5px 15px rgba(0,0,0,0.2);
            transition: transform 0.3s ease;
        }}
        
        .stat-card:hover {{
            transform: translateY(-5px);
        }}
        
        .stat-card h3 {{
            font-size: 1em;
            opacity: 0.9;
            margin-bottom: 10px;
        }}
        
        .stat-card .value {{
            font-size: 2.5em;
            font-weight: bold;
        }}
        
        .anomaly-card {{
            background: #f8f9fa;
            border-left: 5px solid #dc3545;
            padding: 20px;
            margin-bottom: 15px;
            border-radius: 5px;
            transition: all 0.3s ease;
        }}
        
        .anomaly-card:hover {{
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
            transform: translateX(5px);
        }}
        
        .anomaly-card.critical {{
            border-left-color: #dc3545;
            background: #fff5f5;
        }}
        
        .anomaly-card.high {{
            border-left-color: #fd7e14;
            background: #fff8f0;
        }}
        
        .anomaly-card.medium {{
            border-left-color: #ffc107;
            background: #fffbf0;
        }}
        
        .anomaly-card.low {{
            border-left-color: #28a745;
            background: #f0fff4;
        }}
        
        .anomaly-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 10px;
        }}
        
        .anomaly-type {{
            font-size: 1.2em;
            font-weight: bold;
            color: #1e3c72;
        }}
        
        .severity-badge {{
            padding: 5px 15px;
            border-radius: 20px;
            font-size: 0.9em;
            font-weight: bold;
            text-transform: uppercase;
        }}
        
        .severity-badge.critical {{
            background: #dc3545;
            color: white;
        }}
        
        .severity-badge.high {{
            background: #fd7e14;
            color: white;
        }}
        
        .severity-badge.medium {{
            background: #ffc107;
            color: #000;
        }}
        
        .severity-badge.low {{
            background: #28a745;
            color: white;
        }}
        
        .anomaly-details {{
            color: #555;
            line-height: 1.6;
        }}
        
        .anomaly-details strong {{
            color: #1e3c72;
        }}
        
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        
        th {{
            background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
            color: white;
            padding: 15px;
            text-align: left;
            font-weight: 600;
        }}
        
        td {{
            padding: 12px 15px;
            border-bottom: 1px solid #ddd;
        }}
        
        tr:hover {{
            background: #f8f9fa;
        }}
        
        .footer {{
            background: #f8f9fa;
            padding: 20px;
            text-align: center;
            color: #666;
            font-size: 0.9em;
        }}
        
        .no-anomalies {{
            background: #d4edda;
            color: #155724;
            padding: 20px;
            border-radius: 5px;
            text-align: center;
            font-size: 1.1em;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ Security Monitoring Report</h1>
            <div class="timestamp">Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</div>
        </div>
        
        <div class="content">
            <!-- Log Statistics Section -->
            <div class="section">
                <h2>📊 Log Statistics</h2>
                <div class="stats-grid">
                    <div class="stat-card">
                        <h3>Total Log Entries</h3>
                        <div class="value">{log_stats.get('total_entries', 0):,}</div>
                    </div>
                    <div class="stat-card">
                        <h3>Unique IP Addresses</h3>
                        <div class="value">{log_stats.get('unique_ips', 0):,}</div>
                    </div>
                    <div class="stat-card">
                        <h3>Total Anomalies</h3>
                        <div class="value">{anomaly_stats.get('total_anomalies', 0):,}</div>
                    </div>
                    <div class="stat-card">
                        <h3>Affected IPs</h3>
                        <div class="value">{anomaly_stats.get('unique_ips', 0):,}</div>
                    </div>
                </div>
                
                {self._generate_log_type_table(log_stats)}
            </div>
            
            <!-- Anomaly Statistics Section -->
            <div class="section">
                <h2>⚠️ Anomaly Statistics</h2>
                <div class="stats-grid">
                    {self._generate_severity_cards(anomaly_stats)}
                </div>
                
                {self._generate_anomaly_type_table(anomaly_stats)}
            </div>
            
            <!-- Detailed Anomalies Section -->
            <div class="section">
                <h2>🔍 Detected Anomalies</h2>
                {self._generate_anomaly_cards(anomalies)}
            </div>
        </div>
        
        <div class="footer">
            <p>Security Log Monitoring & Alert Automation System v1.0</p>
            <p>This report was automatically generated by the security monitoring system.</p>
        </div>
    </div>
</body>
</html>
"""
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(html_content)
    
    def _generate_log_type_table(self, log_stats: Dict[str, Any]) -> str:
        """Generate log type breakdown table."""
        log_types = log_stats.get('log_types', {})
        if not log_types:
            return ""
        
        html = "<table><thead><tr><th>Log Type</th><th>Count</th><th>Percentage</th></tr></thead><tbody>"
        total = log_stats.get('total_entries', 1)
        
        for log_type, count in sorted(log_types.items(), key=lambda x: x[1], reverse=True):
            percentage = (count / total * 100) if total > 0 else 0
            html += f"<tr><td>{log_type.upper()}</td><td>{count:,}</td><td>{percentage:.1f}%</td></tr>"
        
        html += "</tbody></table>"
        return html
    
    def _generate_severity_cards(self, anomaly_stats: Dict[str, Any]) -> str:
        """Generate severity breakdown cards."""
        severities = anomaly_stats.get('by_severity', {})
        severity_order = ['critical', 'high', 'medium', 'low']
        
        html = ""
        for severity in severity_order:
            count = severities.get(severity, 0)
            if count > 0:
                html += f"""
                <div class="stat-card">
                    <h3>{severity.upper()} Severity</h3>
                    <div class="value">{count:,}</div>
                </div>
                """
        
        return html
    
    def _generate_anomaly_type_table(self, anomaly_stats: Dict[str, Any]) -> str:
        """Generate anomaly type breakdown table."""
        anomaly_types = anomaly_stats.get('by_type', {})
        if not anomaly_types:
            return ""
        
        html = "<table><thead><tr><th>Anomaly Type</th><th>Count</th></tr></thead><tbody>"
        
        for atype, count in sorted(anomaly_types.items(), key=lambda x: x[1], reverse=True):
            display_name = atype.replace('_', ' ').title()
            html += f"<tr><td>{display_name}</td><td>{count:,}</td></tr>"
        
        html += "</tbody></table>"
        return html
    
    def _generate_anomaly_cards(self, anomalies: List[Dict[str, Any]]) -> str:
        """Generate anomaly detail cards."""
        if not anomalies:
            return '<div class="no-anomalies">✅ No anomalies detected. System is secure!</div>'
        
        html = ""
        # Sort by severity
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
        sorted_anomalies = sorted(anomalies, 
                                 key=lambda x: severity_order.get(x.get('severity', 'low'), 4))
        
        for anomaly in sorted_anomalies[:50]:  # Limit to 50 for readability
            severity = anomaly.get('severity', 'medium')
            atype = anomaly.get('type', 'unknown').replace('_', ' ').title()
            ip = anomaly.get('ip_address', 'Unknown')
            description = anomaly.get('description', 'No description')
            count = anomaly.get('count', 0)
            
            html += f"""
            <div class="anomaly-card {severity}">
                <div class="anomaly-header">
                    <div class="anomaly-type">{atype}</div>
                    <div class="severity-badge {severity}">{severity}</div>
                </div>
                <div class="anomaly-details">
                    <p><strong>IP Address:</strong> {ip}</p>
                    <p><strong>Occurrences:</strong> {count}</p>
                    <p><strong>Description:</strong> {description}</p>
                </div>
            </div>
            """
        
        if len(anomalies) > 50:
            html += f'<p style="text-align: center; color: #666; margin-top: 20px;">Showing 50 of {len(anomalies)} anomalies</p>'
        
        return html
    
    def _generate_json_report(self,
                             filepath: Path,
                             log_stats: Dict[str, Any],
                             anomalies: List[Dict[str, Any]],
                             anomaly_stats: Dict[str, Any]) -> None:
        """Generate JSON report."""
        
        # Prepare anomalies for JSON (remove non-serializable data)
        clean_anomalies = []
        for anomaly in anomalies:
            clean_anomaly = {
                'type': anomaly.get('type'),
                'severity': anomaly.get('severity'),
                'ip_address': anomaly.get('ip_address'),
                'count': anomaly.get('count'),
                'description': anomaly.get('description'),
                'timestamp': str(anomaly.get('timestamp', ''))
            }
            clean_anomalies.append(clean_anomaly)
        
        report_data = {
            'report_metadata': {
                'generated_at': datetime.now().isoformat(),
                'version': '1.0.0'
            },
            'log_statistics': log_stats,
            'anomaly_statistics': anomaly_stats,
            'anomalies': clean_anomalies
        }
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2, default=str)
    
    def generate_quick_summary(self, 
                              log_stats: Dict[str, Any],
                              anomaly_stats: Dict[str, Any]) -> str:
        """
        Generate quick text summary.
        
        Args:
            log_stats: Log statistics
            anomaly_stats: Anomaly statistics
            
        Returns:
            Summary text
        """
        summary = f"""
Security Monitoring Summary
===========================
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

Log Statistics:
  - Total Entries: {log_stats.get('total_entries', 0):,}
  - Unique IPs: {log_stats.get('unique_ips', 0):,}

Anomaly Statistics:
  - Total Anomalies: {anomaly_stats.get('total_anomalies', 0):,}
  - Affected IPs: {anomaly_stats.get('unique_ips', 0):,}

Severity Breakdown:
"""
        
        for severity, count in anomaly_stats.get('by_severity', {}).items():
            summary += f"  - {severity.upper()}: {count}\n"
        
        return summary
