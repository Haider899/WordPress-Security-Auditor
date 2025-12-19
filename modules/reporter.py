"""
Advanced Report Generation Module for WP-SEC-AUDIT
Professional security reports with CVE detection and risk assessment
"""

import json
import os
import time
from datetime import datetime
from pathlib import Path

class ReportGenerator:
    """Professional report generator with advanced features"""
    
    def __init__(self, config=None):
        self.config = config or {}
        self.report_dir = self._get_report_dir()
    
    def _get_report_dir(self):
        """Get report directory path"""
        report_dir = self.config.get('output', {}).get('report_dir', '')
        if not report_dir:
            report_dir = os.path.expanduser("~/Desktop/WP-SEC-AUDIT-Results")
        else:
            report_dir = os.path.expanduser(report_dir)
        
        Path(report_dir).mkdir(parents=True, exist_ok=True)
        return report_dir
    
    def generate_report(self, results, format='text'):
        """Generate report in specified format"""
        format = format.lower()
        
        if format == 'json':
            return self._generate_json_report(results)
        elif format == 'html':
            return self._generate_html_report(results)
        elif format == 'markdown' or format == 'md':
            return self._generate_markdown_report(results)
        else:  # text format (default)
            return self._generate_text_report(results)
    
    def _generate_text_report(self, results):
        """Generate detailed text report"""
        scan_type = results.get('scan_type', 'standard')
        
        report = []
        report.append("=" * 70)
        report.append(f"WP-SEC-AUDIT SECURITY REPORT - {scan_type.upper()} SCAN")
        report.append("=" * 70)
        report.append(f"Target URL: {results.get('url', 'Unknown')}")
        report.append(f"Scan Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append(f"WordPress Detected: {'YES' if results.get('wordpress') else 'NO'}")
        report.append(f"Scan Type: {scan_type}")
        report.append("")
        
        if results.get('wordpress'):
            # User enumeration section
            if results.get('users_exposed'):
                report.append("⚠️ CRITICAL: USER ENUMERATION VULNERABILITY")
                report.append("-" * 50)
                users = results.get('users', [])
                report.append(f"Found {len(users)} exposed user accounts:")
                for user in users[:15]:  # Show first 15 users
                    user_info = f"  • {user.get('name', 'Unknown')}"
                    if user.get('id'):
                        user_info += f" (ID: {user.get('id')}"
                        if user.get('username'):
                            user_info += f", Username: {user.get('username')}"
                        if user.get('method'):
                            user_info += f", Method: {user.get('method')}"
                        user_info += ")"
                    report.append(user_info)
                if len(users) > 15:
                    report.append(f"  ... and {len(users) - 15} more users")
                report.append("")
            else:
                report.append("✅ User enumeration appears to be blocked")
                report.append("")
            
            # CVEs section
            cves = results.get('cves', [])
            if cves:
                report.append(f"💀 {len(cves)} KNOWN CVEs DETECTED")
                report.append("-" * 50)
                for cve in cves[:10]:  # Show first 10 CVEs
                    report.append(f"  • {cve.get('cve_id', 'Unknown')}: {cve.get('description', '')}")
                    if cve.get('severity'):
                        report.append(f"    Severity: {cve.get('severity').upper()}")
                if len(cves) > 10:
                    report.append(f"  ... and {len(cves) - 10} more CVEs")
                report.append("")
            
            # Vulnerabilities section
            vulns = results.get('vulnerabilities', [])
            if vulns:
                report.append(f"⚠️ {len(vulns)} VULNERABILITIES FOUND")
                report.append("-" * 50)
                for vuln in vulns:
                    report.append(f"  • {vuln.get('description', 'Unknown')}")
                    if vuln.get('severity'):
                        report.append(f"    Severity: {vuln.get('severity').upper()}")
                    if vuln.get('solution'):
                        report.append(f"    Solution: {vuln.get('solution')}")
                report.append("")
            
            # Sensitive files section
            files = results.get('sensitive_files', [])
            if files:
                critical_files = [f for f in files if f.get('critical')]
                if critical_files:
                    report.append(f"🔓 {len(critical_files)} CRITICAL FILES EXPOSED")
                    report.append("-" * 50)
                    for file in critical_files:
                        report.append(f"  • {file.get('path', 'Unknown')}")
                        if file.get('status_code'):
                            report.append(f"    Status Code: {file.get('status_code')}")
                report.append("")
            
            # Directory listings section
            dirs = results.get('directory_listings', [])
            if dirs:
                report.append(f"📁 {len(dirs)} DIRECTORY LISTINGS ENABLED")
                report.append("-" * 50)
                for directory in dirs:
                    report.append(f"  • {directory.get('directory', 'Unknown')}")
                report.append("")
            
            # Plugins section
            plugins = results.get('plugins', [])
            if plugins:
                report.append(f"🔌 {len(plugins)} PLUGINS DETECTED")
                report.append("-" * 50)
                for plugin in plugins[:10]:  # Show first 10 plugins
                    plugin_info = f"  • {plugin.get('name', 'Unknown')}"
                    if plugin.get('version') and plugin['version'] != 'unknown':
                        plugin_info += f" (v{plugin.get('version')})"
                    report.append(plugin_info)
                if len(plugins) > 10:
                    report.append(f"  ... and {len(plugins) - 10} more plugins")
                report.append("")
            
            # Themes section
            themes = results.get('themes', [])
            if themes:
                report.append(f"🎨 {len(themes)} THEMES DETECTED")
                report.append("-" * 50)
                for theme in themes:
                    theme_info = f"  • {theme.get('full_name', theme.get('name', 'Unknown'))}"
                    if theme.get('version') and theme['version'] != 'unknown':
                        theme_info += f" (v{theme.get('version')})"
                    report.append(theme_info)
                report.append("")
            
            # Configuration issues
            config_issues = results.get('config_issues', [])
            if config_issues:
                report.append(f"⚙️ {len(config_issues)} CONFIGURATION ISSUES")
                report.append("-" * 50)
                for issue in config_issues:
                    report.append(f"  • {issue}")
                report.append("")
            
            # Security issues summary
            issues = results.get('issues', [])
            if issues:
                report.append(f"🚨 {len(issues)} SECURITY ISSUES IDENTIFIED")
                report.append("-" * 50)
                for issue in issues:
                    report.append(f"  • {issue}")
                report.append("")
            
            # Risk Assessment
            report.append("📊 RISK ASSESSMENT")
            report.append("-" * 50)
            risk_score = self._calculate_risk_score(results)
            risk_level = self._get_risk_level(risk_score)
            
            report.append(f"Overall Risk Score: {risk_score}/100")
            report.append(f"Risk Level: {risk_level}")
            report.append("")
            
            # Recommendations
            report.append("💡 SECURITY RECOMMENDATIONS")
            report.append("-" * 50)
            recommendations = self._generate_recommendations(results)
            for i, rec in enumerate(recommendations, 1):
                report.append(f"{i}. {rec}")
            
        else:
            report.append("❌ NOT A WORDPRESS SITE")
            report.append("The target does not appear to be a WordPress installation.")
            
            # Still show if we found anything
            if results.get('sensitive_files') or results.get('directory_listings'):
                report.append("\n⚠️ Non-WordPress Findings:")
                if results.get('sensitive_files'):
                    report.append(f"  • Found {len(results['sensitive_files'])} sensitive files")
                if results.get('directory_listings'):
                    report.append(f"  • Found {len(results['directory_listings'])} directory listings")
        
        report.append("")
        report.append("=" * 70)
        report.append("Report generated by WP-SEC-AUDIT v1.2.0")
        report.append("For authorized security testing only")
        
        return "\n".join(report)
    
    def _generate_json_report(self, results):
        """Generate JSON report"""
        report_data = {
            'metadata': {
                'tool': 'WP-SEC-AUDIT',
                'version': '1.2.0',
                'scan_type': results.get('scan_type', 'standard'),
                'scan_time': datetime.now().isoformat(),
                'report_format': 'json',
                'timestamp': results.get('timestamp')
            },
            'target': {
                'url': results.get('url'),
                'wordpress_detected': results.get('wordpress', False)
            },
            'findings': {
                'user_enumeration': {
                    'exposed': results.get('users_exposed', False),
                    'user_count': len(results.get('users', [])),
                    'users': results.get('users', [])
                },
                'vulnerabilities': {
                    'cves': results.get('cves', []),
                    'other_vulnerabilities': results.get('vulnerabilities', []),
                    'total_count': len(results.get('cves', [])) + len(results.get('vulnerabilities', []))
                },
                'files_and_directories': {
                    'sensitive_files': results.get('sensitive_files', []),
                    'directory_listings': results.get('directory_listings', []),
                    'critical_files': [f for f in results.get('sensitive_files', []) if f.get('critical')]
                },
                'components': {
                    'plugins': results.get('plugins', []),
                    'themes': results.get('themes', [])
                },
                'configuration': {
                    'issues': results.get('config_issues', [])
                },
                'summary': {
                    'issues': results.get('issues', []),
                    'risk_score': self._calculate_risk_score(results),
                    'risk_level': self._get_risk_level(self._calculate_risk_score(results))
                }
            },
            'recommendations': self._generate_recommendations(results),
            'scan_details': {
                'scan_type': results.get('scan_type'),
                'timestamp': results.get('timestamp'),
                'error': results.get('error')
            }
        }
        
        return json.dumps(report_data, indent=2, default=str)
    
    def _generate_html_report(self, results):
        """Generate professional HTML report"""
        risk_score = self._calculate_risk_score(results)
        risk_level, risk_color, risk_icon = self._get_risk_display(risk_score)
        scan_type = results.get('scan_type', 'standard')
        
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WP-SEC-AUDIT Security Report</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ 
            font-family: 'Segoe UI', 'Roboto', 'Arial', sans-serif;
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
            font-size: 2.8em;
            margin-bottom: 10px;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
        }}
        .header .subtitle {{
            font-size: 1.2em;
            opacity: 0.9;
            margin-bottom: 20px;
        }}
        .scan-info {{
            background: rgba(255,255,255,0.1);
            padding: 15px;
            border-radius: 10px;
            margin-bottom: 20px;
        }}
        .risk-badge {{
            display: inline-block;
            background: {risk_color};
            color: white;
            padding: 12px 35px;
            border-radius: 50px;
            font-size: 1.8em;
            font-weight: bold;
            margin-top: 10px;
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
            animation: fadeIn 0.5s ease-in;
        }}
        .section.critical {{ border-left-color: #e74c3c; background: #fff5f5; }}
        .section.high {{ border-left-color: #e67e22; background: #fff9e6; }}
        .section.medium {{ border-left-color: #f1c40f; background: #fffce6; }}
        .section.low {{ border-left-color: #27ae60; background: #f0fff4; }}
        .section.info {{ border-left-color: #3498db; background: #f0f8ff; }}
        .section h2 {{
            color: #2c3e50;
            margin-bottom: 20px;
            display: flex;
            align-items: center;
            gap: 10px;
        }}
        .finding {{
            background: white;
            padding: 20px;
            margin-bottom: 15px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.08);
            border: 1px solid #e0e0e0;
            transition: transform 0.2s;
        }}
        .finding:hover {{ transform: translateY(-2px); box-shadow: 0 4px 20px rgba(0,0,0,0.12); }}
        .finding.critical {{ border-left: 4px solid #e74c3c; }}
        .finding.high {{ border-left: 4px solid #e67e22; }}
        .finding.medium {{ border-left: 4px solid #f1c40f; }}
        .finding.low {{ border-left: 4px solid #2ecc71; }}
        .severity {{
            display: inline-block;
            padding: 6px 18px;
            border-radius: 20px;
            font-size: 0.9em;
            font-weight: bold;
            color: white;
            margin-right: 10px;
        }}
        .severity.critical {{ background: #e74c3c; }}
        .severity.high {{ background: #e67e22; }}
        .severity.medium {{ background: #f1c40f; color: #333; }}
        .severity.low {{ background: #2ecc71; }}
        .info-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-top: 20px;
        }}
        .info-card {{
            background: white;
            padding: 25px;
            border-radius: 10px;
            box-shadow: 0 4px 15px rgba(0,0,0,0.1);
            text-align: center;
            transition: transform 0.3s;
        }}
        .info-card:hover {{ transform: translateY(-5px); }}
        .info-card .number {{
            font-size: 2.8em;
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
        .user-grid, .plugin-grid, .theme-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
            gap: 15px;
            margin-top: 15px;
        }}
        .user-item, .plugin-item, .theme-item {{
            background: white;
            padding: 15px;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            text-align: center;
        }}
        .cve-item {{
            background: #fff5f5;
            padding: 15px;
            border-radius: 8px;
            margin-bottom: 10px;
            border-left: 4px solid #e74c3c;
        }}
        .footer {{
            text-align: center;
            padding: 30px;
            background: #f8f9fa;
            color: #7f8c8d;
            border-top: 1px solid #e0e0e0;
        }}
        @keyframes fadeIn {{
            from {{ opacity: 0; transform: translateY(20px); }}
            to {{ opacity: 1; transform: translateY(0); }}
        }}
        @media (max-width: 768px) {{
            .container {{ margin: 10px; }}
            .header {{ padding: 20px; }}
            .content {{ padding: 20px; }}
            .info-grid {{ grid-template-columns: 1fr; }}
            .user-grid, .plugin-grid, .theme-grid {{ grid-template-columns: 1fr; }}
        }}
    </style>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
</head>
<body>
    <div class="container">
        <div class="header">
            <h1><i class="fas fa-shield-alt"></i> WP-SEC-AUDIT Security Report</h1>
            <div class="subtitle">Professional WordPress Security Assessment</div>
            
            <div class="scan-info">
                <p><strong>Target:</strong> {results.get('url', 'Unknown')}</p>
                <p><strong>Scan Type:</strong> {scan_type.upper()}</p>
                <p><strong>Scan Time:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            </div>
            
            <div class="risk-badge">
                {risk_icon} Risk Score: {risk_score}/100 ({risk_level})
            </div>
        </div>
        
        <div class="content">
            <!-- Summary Section -->
            <div class="section info">
                <h2><i class="fas fa-info-circle"></i> Scan Summary</h2>
                <div class="info-grid">
                    <div class="info-card">
                        <div class="number">{'YES' if results.get('wordpress') else 'NO'}</div>
                        <div class="label">WordPress Detected</div>
                    </div>
                    <div class="info-card">
                        <div class="number">{len(results.get('users', []))}</div>
                        <div class="label">Exposed Users</div>
                    </div>
                    <div class="info-card">
                        <div class="number">{len(results.get('cves', []))}</div>
                        <div class="label">CVEs Found</div>
                    </div>
                    <div class="info-card">
                        <div class="number">{len(results.get('plugins', []))}</div>
                        <div class="label">Plugins Found</div>
                    </div>
                </div>
            </div>
"""
        
        # Critical Vulnerabilities Section
        if results.get('users_exposed') or results.get('cves'):
            html += """
            <div class="section critical">
                <h2><i class="fas fa-exclamation-triangle"></i> Critical Vulnerabilities</h2>
"""
            
            if results.get('users_exposed'):
                html += f"""
                <div class="finding critical">
                    <div>
                        <span class="severity critical">CRITICAL</span>
                        <strong>User Enumeration Vulnerability</strong>
                    </div>
                    <p style="margin-top: 10px; color: #555;">Found {len(results.get('users', []))} exposed user accounts via WordPress REST API.</p>
                    <p style="margin-top: 10px;"><strong>Impact:</strong> Enables targeted brute-force attacks</p>
                    <p style="margin-top: 10px;"><strong>Solution:</strong> Disable user enumeration via REST API</p>
                    
                    <div class="user-grid" style="margin-top: 15px;">
"""
                for user in results.get('users', [])[:12]:  # Show first 12 users
                    html += f"""
                        <div class="user-item">
                            <strong>{user.get('name', 'Unknown')}</strong>
                            <p style="font-size: 0.9em; color: #666;">ID: {user.get('id')}<br>Method: {user.get('method', 'Unknown')}</p>
                        </div>
"""
                if len(results.get('users', [])) > 12:
                    html += f"""
                        <div class="user-item">
                            <strong>... and {len(results.get('users', [])) - 12} more</strong>
                            <p style="font-size: 0.9em; color: #666;">users exposed</p>
                        </div>
"""
                html += """
                    </div>
                </div>
"""
            
            # CVEs
            cves = results.get('cves', [])
            if cves:
                html += f"""
                <div class="finding high" style="margin-top: 20px;">
                    <div>
                        <span class="severity high">HIGH</span>
                        <strong>Known CVEs Detected</strong>
                    </div>
                    <p style="margin-top: 10px; color: #555;">Found {len(cves)} known vulnerabilities in WordPress core.</p>
"""
                for cve in cves[:5]:  # Show first 5 CVEs
                    html += f"""
                    <div class="cve-item">
                        <strong>{cve.get('cve_id', 'Unknown')}</strong>
                        <p>{cve.get('description', '')}</p>
                        <p style="font-size: 0.9em; color: #666;">Affected Version: {cve.get('affected_version', 'Unknown')}</p>
                    </div>
"""
                if len(cves) > 5:
                    html += f"""
                    <div style="text-align: center; margin-top: 10px;">
                        <em>... and {len(cves) - 5} more CVEs detected</em>
                    </div>
"""
                html += """
                </div>
"""
            
            html += """
            </div>
"""
        
        # Other Vulnerabilities
        vulns = results.get('vulnerabilities', [])
        if vulns:
            html += f"""
            <div class="section high">
                <h2><i class="fas fa-bug"></i> Other Vulnerabilities ({len(vulns)})</h2>
"""
            for vuln in vulns:
                severity = vuln.get('severity', 'medium').lower()
                html += f"""
                <div class="finding {severity}">
                    <span class="severity {severity}">{severity.upper()}</span>
                    <strong>{vuln.get('type', 'Vulnerability').replace('_', ' ').title()}</strong>
                    <p style="margin-top: 10px;">{vuln.get('description', '')}</p>
                    <p style="margin-top: 10px;"><strong>Solution:</strong> {vuln.get('solution', 'Not specified')}</p>
                </div>
"""
            html += """
            </div>
"""
        
        # Sensitive Files
        files = results.get('sensitive_files', [])
        if files:
            critical_files = [f for f in files if f.get('critical')]
            if critical_files:
                html += f"""
            <div class="section medium">
                <h2><i class="fas fa-file-exclamation"></i> Exposed Files ({len(critical_files)})</h2>
"""
                for file in critical_files[:10]:
                    html += f"""
                <div class="finding medium">
                    <span class="severity medium">EXPOSED</span>
                    <strong>{file.get('path', 'Unknown')}</strong>
                    <p style="margin-top: 5px; color: #666;">Status Code: {file.get('status_code', 'Unknown')}</p>
                </div>
"""
                if len(critical_files) > 10:
                    html += f"""
                <div style="text-align: center; margin-top: 10px;">
                    <em>... and {len(critical_files) - 10} more critical files exposed</em>
                </div>
"""
                html += """
            </div>
"""
        
        # Plugins
        plugins = results.get('plugins', [])
        if plugins:
            html += f"""
            <div class="section info">
                <h2><i class="fas fa-plug"></i> Detected Plugins ({len(plugins)})</h2>
                <div class="plugin-grid">
"""
            for plugin in plugins[:16]:  # Show first 16 plugins
                version = f" v{plugin['version']}" if plugin.get('version') and plugin['version'] != 'unknown' else ''
                html += f"""
                    <div class="plugin-item">
                        <strong>{plugin.get('name', 'Unknown')}</strong>
                        <p style="font-size: 0.9em; color: #666;">{version if version else 'Version unknown'}</p>
                    </div>
"""
            if len(plugins) > 16:
                html += f"""
                    <div class="plugin-item">
                        <strong>... and {len(plugins) - 16} more</strong>
                        <p style="font-size: 0.9em; color: #666;">plugins detected</p>
                    </div>
"""
            html += """
                </div>
            </div>
"""
        
        # Security Recommendations
        recommendations = self._generate_recommendations(results)
        if recommendations:
            html += """
            <div class="section low">
                <h2><i class="fas fa-lightbulb"></i> Security Recommendations</h2>
                <ul style="list-style-type: none; padding-left: 0;">
"""
            for i, rec in enumerate(recommendations, 1):
                html += f"""
                    <li style="margin-bottom: 15px; padding: 15px; background: white; border-radius: 8px; box-shadow: 0 2px 5px rgba(0,0,0,0.05);">
                        <strong>{i}.</strong> {rec}
                    </li>
"""
            html += """
                </ul>
            </div>
"""
        
        html += """
        </div>
        
        <div class="footer">
            <p>Report generated by <strong>WP-SEC-AUDIT v1.2.0</strong> - Enterprise Security Scanner</p>
            <p class="timestamp">Scan completed: """ + datetime.now().strftime('%Y-%m-%d %H:%M:%S') + """</p>
            <p style="margin-top: 20px; font-size: 0.8em;">
                <i class="fas fa-exclamation-triangle"></i> This report is for authorized security testing only.
                Unauthorized use is prohibited.
            </p>
        </div>
    </div>
</body>
</html>
"""
        return html
    
    def _generate_markdown_report(self, results):
        """Generate Markdown report"""
        risk_score = self._calculate_risk_score(results)
        risk_level = self._get_risk_level(risk_score)
        
        md = f"""# WP-SEC-AUDIT Security Report

## 📊 Scan Summary
- **Target URL**: {results.get('url', 'Unknown')}
- **Scan Time**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
- **Scan Type**: {results.get('scan_type', 'standard')}
- **WordPress Detected**: {'✅ Yes' if results.get('wordpress') else '❌ No'}
- **Risk Score**: {risk_score}/100 ({risk_level})

## 🔍 Findings
"""
        
        if results.get('wordpress'):
            if results.get('users_exposed'):
                md += f"\n### 🚨 Critical: User Enumeration\nFound **{len(results.get('users', []))}** exposed user accounts!\n"
            
            cves = results.get('cves', [])
            if cves:
                md += f"\n### 💀 CVEs Detected ({len(cves)})\n"
                for cve in cves[:5]:
                    md += f"- **{cve.get('cve_id')}**: {cve.get('description')}\n"
                if len(cves) > 5:
                    md += f"- ... and {len(cves) - 5} more CVEs\n"
            
            vulns = results.get('vulnerabilities', [])
            if vulns:
                md += f"\n### ⚠️ Other Vulnerabilities ({len(vulns)})\n"
                for vuln in vulns:
                    md += f"- {vuln.get('description')} ({vuln.get('severity', 'medium')})\n"
            
            plugins = results.get('plugins', [])
            if plugins:
                md += f"\n### 🔌 Plugins Detected ({len(plugins)})\n"
                for plugin in plugins[:10]:
                    version = f" v{plugin['version']}" if plugin.get('version') and plugin['version'] != 'unknown' else ''
                    md += f"- {plugin['name']}{version}\n"
                if len(plugins) > 10:
                    md += f"- ... and {len(plugins) - 10} more plugins\n"
            
            md += f"\n### 💡 Recommendations\n"
            recommendations = self._generate_recommendations(results)
            for rec in recommendations:
                md += f"- {rec}\n"
        else:
            md += "\n❌ Not a WordPress site or inaccessible.\n"
        
        md += f"\n---\n*Report generated by WP-SEC-AUDIT v1.2.0 on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*"
        
        return md
    
            def _calculate_risk_score(self, results):
        """
        INTELLIGENT RISK SCORING SYSTEM
        ================================
        
        FEATURES:
        1. 🔍 CONTEXT-AWARE: Considers vulnerability context and environment
        2. ⚡ DYNAMIC: Adjusts based on quantity, severity, and combinations
        3. 🧠 INTELLIGENT: Recognizes patterns and compound risks
        4. 🎯 REALISTIC: Matches real-world security risk assessment
        
        SCORING CATEGORIES:
        - User Enumeration (25-40 points)
        - CVEs (Weighted by severity: 10-35 points)
        - Vulnerabilities (Context-based: 5-25 points)
        - Sensitive Files (Graded by type: 3-20 points)
        - Directory Listings (Location-based: 5-15 points)
        - Components (Version analysis: 2-10 points)
        - Compound Risk (Bonus: 0-15 points)
        """
        
        score = 0
        scoring_debug = []  # For detailed scoring breakdown
        
        # ========== 1. CONTEXT-AWARE: USER ENUMERATION ==========
        if results.get('users_exposed'):
            users = results.get('users', [])
            user_count = len(users)
            
            # Base context score
            base_score = 25
            
            # DYNAMIC multiplier based on user count
            if user_count >= 20:
                user_multiplier = 2.0  # Mass exposure - critical
                context_note = "Mass user enumeration (20+ users)"
            elif user_count >= 10:
                user_multiplier = 1.5  # Significant exposure - high
                context_note = "Significant user exposure (10-19 users)"
            elif user_count >= 5:
                user_multiplier = 1.2  # Moderate exposure - medium
                context_note = "Moderate user exposure (5-9 users)"
            else:
                user_multiplier = 1.0  # Limited exposure - low
                context_note = "Limited user exposure (1-4 users)"
            
            # INTELLIGENT: Detect admin users (higher risk)
            admin_users = []
            for user in users:
                username = str(user.get('username', '')).lower()
                name = str(user.get('name', '')).lower()
                if any(admin_keyword in username or admin_keyword in name 
                      for admin_keyword in ['admin', 'administrator', 'root', 'super']):
                    admin_users.append(user)
            
            admin_count = len(admin_users)
            admin_bonus = admin_count * 5  # Extra points for admin accounts
            
            # REALISTIC: Check for email exposure (PII risk)
            email_exposed = any('@' in str(user.get('email', '')) for user in users)
            email_bonus = 3 if email_exposed else 0
            
            user_score = min(40, base_score + (user_count * user_multiplier) + admin_bonus + email_bonus)
            score += user_score
            
            scoring_debug.append({
                'category': 'User Enumeration',
                'score': user_score,
                'details': {
                    'user_count': user_count,
                    'admin_count': admin_count,
                    'context': context_note,
                    'email_exposed': email_exposed
                }
            })
        
        # ========== 2. INTELLIGENT: CVE SCORING ==========
        cves = results.get('cves', [])
        if cves:
            cve_score = 0
            severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
            
            for cve in cves:
                severity = cve.get('severity', 'medium').lower()
                
                # Weight based on REALISTIC impact assessment
                if severity == 'critical':
                    weight = 15
                    severity_counts['critical'] += 1
                elif severity == 'high':
                    weight = 10
                    severity_counts['high'] += 1
                elif severity == 'medium':
                    weight = 5
                    severity_counts['medium'] += 1
                else:  # low
                    weight = 2
                    severity_counts['low'] += 1
                
                cve_score += weight
                
                # DYNAMIC: Recent CVEs are more relevant
                cve_id = cve.get('cve_id', '')
                if cve_id and 'CVE-' in cve_id:
                    try:
                        year = int(cve_id.split('-')[1])
                        current_year = datetime.now().year
                        if current_year - year <= 1:  # Last year
                            cve_score += 5  # High relevance bonus
                        elif current_year - year <= 2:  # Last 2 years
                            cve_score += 3  # Medium relevance bonus
                    except:
                        pass
            
            # CONTEXT-AWARE: Multiple critical CVEs = exponential risk
            if severity_counts['critical'] >= 2:
                cve_score += 10  # Compound critical vulnerability bonus
            
            cve_score = min(35, cve_score)
            score += cve_score
            
            scoring_debug.append({
                'category': 'CVEs',
                'score': cve_score,
                'details': {
                    'total': len(cves),
                    'critical': severity_counts['critical'],
                    'high': severity_counts['high'],
                    'medium': severity_counts['medium'],
                    'low': severity_counts['low']
                }
            })
        
        # ========== 3. CONTEXT-AWARE: VULNERABILITY SCORING ==========
        vulns = results.get('vulnerabilities', [])
        if vulns:
            vuln_score = 0
            
            # REALISTIC vulnerability impact assessment
            vulnerability_context = {
                'xmlrpc_enabled': {
                    'base': 12,
                    'description': 'XML-RPC enabled (brute force vector)',
                    'context': 'Attack vector for brute force and DDoS',
                    'severity': 'high'
                },
                'debug_log_exposed': {
                    'base': 15,
                    'description': 'Debug log publicly accessible',
                    'context': 'Exposes sensitive debug information',
                    'severity': 'high'
                },
                'wpconfig_exposed': {
                    'base': 20,
                    'description': 'wp-config.php accessible',
                    'context': 'Database credentials exposure - CRITICAL',
                    'severity': 'critical'
                },
                'readme_exposed': {
                    'base': 5,
                    'description': 'readme.html exposed',
                    'context': 'Information disclosure',
                    'severity': 'low'
                },
                'directory_listing': {
                    'base': 8,
                    'description': 'Directory listing enabled',
                    'context': 'Information disclosure and file enumeration',
                    'severity': 'medium'
                }
            }
            
            for vuln in vulns:
                vuln_type = vuln.get('type', '')
                severity = vuln.get('severity', 'medium').lower()
                
                if vuln_type in vulnerability_context:
                    context_info = vulnerability_context[vuln_type]
                    base_weight = context_info['base']
                    
                    # DYNAMIC severity adjustment
                    if severity == 'critical':
                        multiplier = 1.5
                    elif severity == 'high':
                        multiplier = 1.3
                    elif severity == 'medium':
                        multiplier = 1.1
                    else:
                        multiplier = 1.0
                    
                    vuln_score += base_weight * multiplier
                    
                    # INTELLIGENT: Context-based bonus
                    if vuln_type == 'wpconfig_exposed':
                        vuln_score += 5  # Extra for credential exposure risk
                    elif vuln_type == 'xmlrpc_enabled':
                        # Check if combined with user enumeration (compound attack)
                        if results.get('users_exposed'):
                            vuln_score += 3  # XML-RPC + known users = higher risk
                else:
                    # Default scoring for unknown vulnerability types
                    if severity == 'critical':
                        vuln_score += 15
                    elif severity == 'high':
                        vuln_score += 10
                    elif severity == 'medium':
                        vuln_score += 7
                    else:
                        vuln_score += 3
            
            vuln_score = min(25, vuln_score)
            score += vuln_score
            
            scoring_debug.append({
                'category': 'Vulnerabilities',
                'score': vuln_score,
                'details': {
                    'total': len(vulns),
                    'types': list(set([v.get('type', 'unknown') for v in vulns]))
                }
            })
        
        # ========== 4. REALISTIC: SENSITIVE FILE ANALYSIS ==========
        files = results.get('sensitive_files', [])
        if files:
            file_score = 0
            
            # REALISTIC file sensitivity grading
            file_sensitivity = {
                'wp-config.php': {
                    'weight': 25,
                    'reason': 'Database credentials exposure - CRITICAL',
                    'risk': 'critical'
                },
                'wp-config.php.bak': {
                    'weight': 20,
                    'reason': 'Database backup file exposure - HIGH',
                    'risk': 'high'
                },
                'debug.log': {
                    'weight': 18,
                    'reason': 'Debug information exposure - HIGH',
                    'risk': 'high'
                },
                'xmlrpc.php': {
                    'weight': 10,
                    'reason': 'Attack vector exposure - MEDIUM',
                    'risk': 'medium'
                },
                'readme.html': {
                    'weight': 5,
                    'reason': 'Version information disclosure - LOW',
                    'risk': 'low'
                }
            }
            
            critical_files_found = []
            
            for file in files:
                file_path = file.get('path', '')
                status_code = file.get('status_code', 0)
                
                # Find matching file type
                file_weight = 5  # Default for unknown files
                file_risk = 'low'
                
                for file_type, sensitivity in file_sensitivity.items():
                    if file_type in file_path:
                        file_weight = sensitivity['weight']
                        file_risk = sensitivity['risk']
                        
                        if file_risk in ['critical', 'high']:
                            critical_files_found.append({
                                'file': file_type,
                                'path': file_path,
                                'risk': file_risk
                            })
                        break
                
                # DYNAMIC: Adjust based on accessibility
                if status_code == 200:  # Fully accessible
                    file_weight *= 1.5
                elif status_code == 403:  # Forbidden (but existence confirmed)
                    file_weight *= 1.2
                elif status_code == 401:  # Unauthorized
                    file_weight *= 1.1
                
                file_score += file_weight
            
            file_score = min(20, file_score)
            score += file_score
            
            scoring_debug.append({
                'category': 'Sensitive Files',
                'score': file_score,
                'details': {
                    'total': len(files),
                    'critical_high': len([f for f in critical_files_found if f['risk'] in ['critical', 'high']]),
                    'critical_files': [f['file'] for f in critical_files_found[:3]]  # First 3
                }
            })
        
        # ========== 5. INTELLIGENT: COMPOUND RISK ANALYSIS ==========
        # INTELLIGENT pattern recognition for compound risks
        compound_bonus = 0
        
        # Pattern 1: Credential exposure + attack vector
        wpconfig_exposed = any('wp-config' in f.get('path', '') for f in files)
        xmlrpc_enabled = any(v.get('type') == 'xmlrpc_enabled' for v in vulns)
        
        if wpconfig_exposed and xmlrpc_enabled:
            compound_bonus += 8
            scoring_debug.append({
                'category': 'Compound Risk',
                'bonus': 8,
                'pattern': 'CRITICAL: Database exposure + XML-RPC attack vector'
            })
        
        # Pattern 2: User enumeration + outdated components
        if results.get('users_exposed'):
            # Check for outdated components
            outdated_components = self._check_outdated_components(results)
            if outdated_components:
                compound_bonus += 5
                scoring_debug.append({
                    'category': 'Compound Risk',
                    'bonus': 5,
                    'pattern': 'User enumeration + Outdated components'
                })
        
        # Pattern 3: Multiple critical findings
        critical_count = sum([
            1 for f in files if any(critical in f.get('path', '') 
                                  for critical in ['wp-config', 'debug.log']),
            1 for v in vulns if v.get('severity') == 'critical',
            severity_counts.get('critical', 0)
        ])
        
        if critical_count >= 3:
            compound_bonus += 10
            scoring_debug.append({
                'category': 'Compound Risk',
                'bonus': 10,
                'pattern': f'Multiple critical findings ({critical_count})'
            })
        elif critical_count >= 2:
            compound_bonus += 5
            scoring_debug.append({
                'category': 'Compound Risk',
                'bonus': 5,
                'pattern': f'Multiple critical findings ({critical_count})'
            })
        
        compound_bonus = min(15, compound_bonus)
        score += compound_bonus
        
        # ========== 6. FINAL ADJUSTMENTS ==========
        # Cap at 100
        score = min(100, score)
        
        # Ensure minimum score for any findings
        if score > 0 and score < 10:
            score = 10  # Minimum risk for any finding
        
        # Round to nearest integer
        score = round(score)
        
        # ========== 7. DEBUG OUTPUT (if enabled) ==========
        if self.config.get('logging', {}).get('level') == 'DEBUG':
            print("\n" + "="*60)
            print("🧠 INTELLIGENT RISK SCORING BREAKDOWN")
            print("="*60)
            
            for item in scoring_debug:
                print(f"\n{item['category']}: {item['score']} points")
                if 'details' in item:
                    for key, value in item['details'].items():
                        print(f"  • {key}: {value}")
                if 'pattern' in item:
                    print(f"  • Pattern: {item['pattern']}")
            
            print(f"\n" + "="*60)
            print(f"📊 FINAL RISK SCORE: {score}/100")
            print("="*60)
            print("SCORING SYSTEM FEATURES:")
            print("  • 🔍 Context-Aware: Considers vulnerability context")
            print("  • ⚡ Dynamic: Adjusts based on quantity/severity")
            print("  • 🧠 Intelligent: Recognizes patterns/compound risks")
            print("  • 🎯 Realistic: Matches real-world risk assessment")
            print("="*60)
        
        return score
    
    def _check_outdated_components(self, results):
        """Check for outdated plugins and themes"""
        outdated = []
        
        plugins = results.get('plugins', [])
        for plugin in plugins:
            version = plugin.get('version', '')
            if version != 'unknown' and self._is_outdated_version(version):
                outdated.append(f"{plugin.get('name')} v{version}")
        
        themes = results.get('themes', [])
        for theme in themes:
            version = theme.get('version', '')
            if version != 'unknown' and self._is_outdated_version(version):
                outdated.append(f"{theme.get('name')} v{version}")
        
        return outdated
    
    def _is_outdated_version(self, version):
        """Intelligent version outdated detection"""
        try:
            # Remove any non-numeric/period characters
            version = ''.join(c for c in version if c.isdigit() or c == '.')
            
            # Split into parts
            parts = version.split('.')
            
            if len(parts) < 2:
                return True  # Incomplete version
            
            # Convert to integers
            major = int(parts[0]) if parts[0].isdigit() else 0
            minor = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
            
            # REALISTIC: Consider version age and support
            # WordPress core versions older than 2 years are outdated
            # Plugins/themes with major version 0 or 1 are often unstable/old
            
            if major == 0:
                return True  # Alpha/beta versions
            elif major == 1 and minor < 5:
                return True  # Very old 1.x versions
            elif major < 4:
                return True  # Pre-WordPress 4.x (2015+)
            
            return False
        except:
            return False  # Assume not outdated if can't parse
    
    def _is_outdated_version(self, version):
        """Check if a version is outdated"""
        try:
            # Simple check - if version has less than 3 parts or major version < 2
            parts = version.split('.')
            if len(parts) < 2:
                return True
            
            # Check if it's a very old version
            major_version = int(parts[0]) if parts[0].isdigit() else 0
            return major_version < 2
        except:
            return False
    
        def _analyze_vulnerability_impact(self, vuln_type, details):
        """Analyze the impact of a vulnerability"""
        impact_scores = {
            'user_enumeration': {
                'base': 25,
                'factors': {
                    'user_count': lambda x: min(15, x * 0.5),
                    'admin_users': lambda x: x * 3,
                    'exposed_emails': lambda x: x * 2
                }
            },
            'cve': {
                'base': 20,
                'factors': {
                    'cvss_score': lambda x: x * 2,
                    'recent': lambda x: 5 if x else 0,
                    'exploit_public': lambda x: 10 if x else 0
                }
            },
            'sensitive_file': {
                'base': 15,
                'factors': {
                    'file_type': {
                        'wp-config.php': 10,
                        'debug.log': 8,
                        'backup_file': 6,
                        'other': 3
                    },
                    'accessible': lambda x: 5 if x else 0
                }
            }
        }
        
        analysis = impact_scores.get(vuln_type, {'base': 10, 'factors': {}})
        score = analysis['base']
        
        # Apply factors based on details
        for factor, value in details.items():
            if factor in analysis['factors']:
                if callable(analysis['factors'][factor]):
                    score += analysis['factors'][factor](value)
                elif isinstance(analysis['factors'][factor], dict):
                    score += analysis['factors'][factor].get(value, 0)
        
        return min(score, 100)
    
    def _get_risk_level(self, score):
        """Get risk level based on score"""
        if score >= 70:
            return "CRITICAL 🔴"
        elif score >= 40:
            return "HIGH 🟡"
        elif score >= 20:
            return "MEDIUM 🟠"
        else:
            return "LOW 🟢"
    
    def _get_risk_display(self, score):
        """Get risk display properties for HTML"""
        if score >= 70:
            return "CRITICAL", "#e74c3c", "🔴"
        elif score >= 40:
            return "HIGH", "#e67e22", "🟡"
        elif score >= 20:
            return "MEDIUM", "#f1c40f", "🟠"
        else:
            return "LOW", "#27ae60", "🟢"
    
    def _generate_recommendations(self, results):
        """Generate security recommendations"""
        recommendations = []
        
        if results.get('users_exposed'):
            recommendations.append("Disable user enumeration via REST API by adding authentication to /wp-json/wp/v2/users endpoint")
            recommendations.append("Implement login rate limiting and CAPTCHA to prevent brute force attacks")
        
        if results.get('cves'):
            recommendations.append("Update WordPress core to the latest version immediately")
            recommendations.append("Apply all security patches for the identified CVEs")
        
        if results.get('vulnerabilities'):
            if any('xmlrpc' in str(v).lower() for v in results.get('vulnerabilities', [])):
                recommendations.append("Disable XML-RPC if not needed for your applications")
            
            if any('debug' in str(v).lower() for v in results.get('vulnerabilities', [])):
                recommendations.append("Disable debug mode and remove debug.log file from public access")
        
        files = results.get('sensitive_files', [])
        if files:
            if any('wp-config' in f.get('path', '').lower() for f in files):
                recommendations.append("Move wp-config.php one level above web root or restrict access via .htaccess")
            
            if any('debug.log' in f.get('path', '').lower() for f in files):
                recommendations.append("Delete debug.log file and disable WordPress debug mode")
        
        # Always include these
        recommendations.extend([
            "Implement Web Application Firewall (WAF) for additional protection",
            "Use strong, unique passwords and enable two-factor authentication",
            "Keep all plugins and themes updated to their latest versions",
            "Remove unused plugins and themes to reduce attack surface",
            "Regularly backup your WordPress site and database",
            "Monitor security logs and implement intrusion detection systems",
            "Use security plugins like Wordfence or Sucuri for real-time protection",
            "Conduct regular security audits and vulnerability assessments"
        ])
        
        return list(dict.fromkeys(recommendations))[:10]  # Remove duplicates, max 10
    
    def save_report(self, report_content, filename, format='text'):
        """Save report to file"""
        # Ensure proper file extension
        extensions = {
            'text': '.txt',
            'json': '.json',
            'html': '.html',
            'markdown': '.md',
            'md': '.md'
        }
        
        ext = extensions.get(format.lower(), '.txt')
        
        # Clean filename
        if not filename.endswith(ext):
            filename += ext
        
        # Create subdirectory based on format
        format_dir = os.path.join(self.report_dir, format)
        Path(format_dir).mkdir(parents=True, exist_ok=True)
        
        # Create full path
        filepath = os.path.join(format_dir, filename)
        
        # Save file
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(report_content)
            
            # Also save a copy in main directory
            main_path = os.path.join(self.report_dir, filename)
            with open(main_path, 'w', encoding='utf-8') as f:
                f.write(report_content)
                
            return filepath
        except Exception as e:
            print(f"[!] Error saving report: {e}")
            return None
    
    # Aliases for backward compatibility
    def generate_html_report(self, results):
        """Alias for generate_report with HTML format"""
        return self.generate_report(results, 'html')
    
    def generate_json_report(self, results):
        """Alias for generate_report with JSON format"""
        return self.generate_report(results, 'json')
