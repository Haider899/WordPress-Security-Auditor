import json
from pathlib import Path
from datetime import datetime
from typing import Dict, List
from dataclasses import asdict


class ReportGenerator:
    """Generate various report formats"""
    
    def __init__(self, config):
        self.config = config
    
    def generate_html_report(self, results, output_file: Path):
        """Generate HTML security report"""
        html_template = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WP-SEC-AUDIT Security Report</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
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
        .header .subtitle {{
            font-size: 1.2em;
            opacity: 0.9;
        }}
        .risk-score {{
            display: inline-block;
            background: {'#e74c3c' if results.risk_score > 70 else '#f39c12' if results.risk_score > 30 else '#2ecc71'};
            color: white;
            padding: 10px 30px;
            border-radius: 50px;
            font-size: 1.5em;
            font-weight: bold;
            margin-top: 20px;
            box-shadow: 0 4px 15px rgba(0,0,0,0.2);
        }}
        .content {{
            padding: 40px;
        }}
        .section {{
            margin-bottom: 40px;
            padding: 25px;
            background: #f8f9fa;
            border-radius: 10px;
            border-left: 5px solid #3498db;
        }}
        .section.critical {{ border-left-color: #e74c3c; }}
        .section.high {{ border-left-color: #e67e22; }}
        .section.medium {{ border-left-color: #f1c40f; }}
        .section.low {{ border-left-color: #2ecc71; }}
        .section h2 {{
            color: #2c3e50;
            margin-bottom: 20px;
            display: flex;
            align-items: center;
            gap: 10px;
        }}
        .section h2 i {{ font-size: 1.3em; }}
        .vulnerability {{
            background: white;
            padding: 20px;
            margin-bottom: 15px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.08);
            border: 1px solid #e0e0e0;
        }}
        .vulnerability.critical {{ border-left: 4px solid #e74c3c; }}
        .vulnerability.high {{ border-left: 4px solid #e67e22; }}
        .vulnerability.medium {{ border-left: 4px solid #f1c40f; }}
        .vulnerability.low {{ border-left: 4px solid #2ecc71; }}
        .severity {{
            display: inline-block;
            padding: 5px 15px;
            border-radius: 20px;
            font-size: 0.9em;
            font-weight: bold;
            color: white;
            margin-right: 10px;
        }}
        .severity.critical {{ background: #e74c3c; }}
        .severity.high {{ background: #e67e22; }}
        .severity.medium {{ background: #f1c40f; }}
        .severity.low {{ background: #2ecc71; }}
        .info-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-top: 20px;
        }}
        .info-card {{
            background: white;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 4px 15px rgba(0,0,0,0.1);
            text-align: center;
        }}
        .info-card .number {{
            font-size: 2.5em;
            font-weight: bold;
            color: #3498db;
            margin-bottom: 10px;
        }}
        .info-card .label {{
            color: #7f8c8d;
            font-size: 0.9em;
            text-transform: uppercase;
            letter-spacing: 1px;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
        }}
        th, td {{
            padding: 12px 15px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }}
        th {{
            background: #f1f8ff;
            font-weight: bold;
            color: #2c3e50;
        }}
        tr:hover {{
            background: #f5f9ff;
        }}
        .footer {{
            text-align: center;
            padding: 30px;
            background: #f8f9fa;
            color: #7f8c8d;
            border-top: 1px solid #e0e0e0;
        }}
        .timestamp {{
            font-size: 0.9em;
            margin-top: 10px;
        }}
        @media (max-width: 768px) {{
            .container {{ margin: 10px; }}
            .header {{ padding: 20px; }}
            .content {{ padding: 20px; }}
            .section {{ padding: 15px; }}
        }}
    </style>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
</head>
<body>
    <div class="container">
        <div class="header">
            <h1><i class="fas fa-shield-alt"></i> WP-SEC-AUDIT Security Report</h1>
            <div class="subtitle">Professional WordPress Security Assessment</div>
            <div class="risk-score">
                Risk Score: {results.risk_score:.1f}/100
            </div>
        </div>
        
        <div class="content">
            <!-- Summary Section -->
            <div class="section">
                <h2><i class="fas fa-info-circle"></i> Scan Summary</h2>
                <div class="info-grid">
                    <div class="info-card">
                        <div class="number">{len(results.vulnerabilities)}</div>
                        <div class="label">Vulnerabilities</div>
                    </div>
                    <div class="info-card">
                        <div class="number">{len(results.users)}</div>
                        <div class="label">Exposed Users</div>
                    </div>
                    <div class="info-card">
                        <div class="number">{len(results.plugins)}</div>
                        <div class="label">Plugins</div>
                    </div>
                    <div class="info-card">
                        <div class="number">{len(results.configuration_issues)}</div>
                        <div class="label">Config Issues</div>
                    </div>
                </div>
                <div style="margin-top: 20px;">
                    <p><strong>Target:</strong> {results.target}</p>
                    <p><strong>Scan Time:</strong> {results.scan_time}</p>
                </div>
            </div>
            
            <!-- Vulnerabilities Section -->
            {self._generate_vulnerabilities_html(results.vulnerabilities)}
            
            <!-- Exposed Users Section -->
            {self._generate_users_html(results.users)}
            
            <!-- Recommendations Section -->
            {self._generate_recommendations_html(results.recommendations)}
        </div>
        
        <div class="footer">
            <p>Report generated by <strong>WP-SEC-AUDIT v3.0</strong> - Professional Security Tool</p>
            <p class="timestamp">Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p style="margin-top: 20px; font-size: 0.8em;">
                <i class="fas fa-exclamation-triangle"></i> This report is for authorized security testing only.
                Unauthorized use is prohibited.
            </p>
        </div>
    </div>
</body>
</html>
        """
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html_template)
    
    def _generate_vulnerabilities_html(self, vulnerabilities: List[Dict]) -> str:
        """Generate vulnerabilities HTML section"""
        if not vulnerabilities:
            return '''
            <div class="section">
                <h2><i class="fas fa-check-circle" style="color: #2ecc71;"></i> No Vulnerabilities Found</h2>
                <p>No critical vulnerabilities were detected during this scan.</p>
            </div>
            '''
        
        html = '<div class="section critical">\n'
        html += '<h2><i class="fas fa-exclamation-triangle"></i> Vulnerabilities Found</h2>\n'
        
        for vuln in vulnerabilities:
            severity_class = vuln.get('severity', 'medium').lower()
            html += f'''
            <div class="vulnerability {severity_class}">
                <div>
                    <span class="severity {severity_class}">{severity_class.upper()}</span>
                    <strong>{vuln.get('title', 'Unknown')}</strong>
                </div>
                <p style="margin-top: 10px; color: #555;">{vuln.get('description', '')}</p>
                <p style="margin-top: 10px;"><strong>Type:</strong> {vuln.get('type', 'Unknown')}</p>
                <p style="margin-top: 10px;"><strong>Solution:</strong> {vuln.get('solution', 'Not specified')}</p>
            </div>
            '''
        
        html += '</div>'
        return html
    
    def _generate_users_html(self, users: List[Dict]) -> str:
        """Generate exposed users HTML section"""
        if not users:
            return ''
        
        html = '<div class="section medium">\n'
        html += '<h2><i class="fas fa-user-secret"></i> Exposed Users</h2>\n'
        html += '<table>\n'
        html += '<thead><tr><th>ID</th><th>Username</th><th>Slug</th><th>Detection Method</th></tr></thead>\n'
        html += '<tbody>\n'
        
        for user in users:
            html += f'''
            <tr>
                <td>{user.get('id', 'N/A')}</td>
                <td><strong>{user.get('name', 'Unknown')}</strong></td>
                <td>{user.get('slug', 'N/A')}</td>
                <td><code>{user.get('method', 'Unknown')}</code></td>
            </tr>
            '''
        
        html += '</tbody>\n</table>\n'
        html += '<p style="margin-top: 15px; color: #e67e22;"><i class="fas fa-exclamation-circle"></i> '
        html += 'User enumeration exposes usernames that can be used in brute force attacks.</p>\n'
        html += '</div>'
        return html
    
    def _generate_recommendations_html(self, recommendations: List[str]) -> str:
        """Generate recommendations HTML section"""
        if not recommendations:
            return ''
        
        html = '<div class="section low">\n'
        html += '<h2><i class="fas fa-lightbulb"></i> Security Recommendations</h2>\n'
        html += '<ul style="list-style-type: none; padding-left: 0;">\n'
        
        for i, rec in enumerate(recommendations, 1):
            html += f'''
            <li style="margin-bottom: 15px; padding: 15px; background: white; border-radius: 8px; box-shadow: 0 2px 5px rgba(0,0,0,0.05);">
                <strong>{i}.</strong> {rec}
            </li>
            '''
        
        html += '</ul>\n</div>'
        return html
    
    def generate_markdown_report(self, results, output_file: Path):
        """Generate Markdown report"""
        md = f"""# WP-SEC-AUDIT Security Report

## Scan Summary
- **Target**: {results.target}
- **Scan Time**: {results.scan_time}
- **Risk Score**: {results.risk_score:.1f}/100
- **Status**: {'⚠️ High Risk' if results.risk_score > 70 else '⚠️ Medium Risk' if results.risk_score > 30 else '✅ Low Risk'}

## Findings Summary
- **Vulnerabilities Found**: {len(results.vulnerabilities)}
- **Exposed Users**: {len(results.users)}
- **Plugins Detected**: {len(results.plugins)}
- **Configuration Issues**: {len(results.configuration_issues)}

## Vulnerabilities
"""
        
        if results.vulnerabilities:
            for vuln in results.vulnerabilities:
                md += f"""
### {vuln.get('title', 'Unknown')}
- **Type**: {vuln.get('type', 'Unknown')}
- **Severity**: {vuln.get('severity', 'Unknown')}
- **Description**: {vuln.get('description', '')}
- **Solution**: {vuln.get('solution', '')}
"""
        else:
            md += "\n✅ No vulnerabilities found.\n"
        
        md += "\n## Recommendations\n"
        for rec in results.recommendations:
            md += f"- {rec}\n"
        
        md += f"\n---\n*Report generated by WP-SEC-AUDIT v3.0 on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*"
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(md)
    
    def generate_executive_summary(self, results, output_file: Path):
        """Generate executive summary"""
        summary = f"""EXECUTIVE SECURITY SUMMARY
============================

TARGET: {results.target}
SCAN DATE: {results.scan_time}
RISK SCORE: {results.risk_score:.1f}/100

OVERVIEW
--------
This security assessment identified {len(results.vulnerabilities)} vulnerabilities
and {len(results.configuration_issues)} configuration issues.

KEY FINDINGS
------------
"""
        
        if results.vulnerabilities:
            summary += "CRITICAL ISSUES:\n"
            for vuln in results.vulnerabilities[:3]:
                summary += f"  • {vuln['title']} ({vuln['severity']})\n"
        
        if results.users:
            summary += f"\nSECURITY EXPOSURES:\n"
            summary += f"  • {len(results.users)} user accounts exposed\n"
        
        summary += f"\nIMMEDIATE ACTIONS REQUIRED:\n"
        for rec in results.recommendations[:3]:
            summary += f"  • {rec}\n"
        
        summary += f"\n---\nGenerated by WP-SEC-AUDIT Professional Security Tool\n"
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(summary)
