"""
Advanced Report Generation Module
Generate professional security reports in multiple formats
"""

import json
import os
from datetime import datetime
from pathlib import Path

class ReportGenerator:
    """Professional report generator for WP-SEC-AUDIT"""
    
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
        else:  # text format
            return self._generate_text_report(results)
    
    def _generate_text_report(self, results):
        """Generate detailed text report"""
        report = []
        report.append("=" * 70)
        report.append("WP-SEC-AUDIT SECURITY REPORT")
        report.append("=" * 70)
        report.append(f"Target URL: {results.get('url', 'Unknown')}")
        report.append(f"Scan Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append(f"WordPress Detected: {'YES' if results.get('wordpress') else 'NO'}")
        report.append("")
        
        if results.get('wordpress'):
            # User enumeration section
            if results.get('users_exposed'):
                report.append("⚠️ CRITICAL: USER ENUMERATION VULNERABILITY")
                report.append("-" * 50)
                users = results.get('users', [])
                report.append(f"Found {len(users)} exposed user accounts:")
                for user in users:
                    report.append(f"  • {user.get('name', 'Unknown')} (ID: {user.get('id')}, Username: {user.get('username')})")
                report.append("")
            else:
                report.append("✅ User enumeration appears to be blocked")
                report.append("")
            
            # Plugins section
            plugins = results.get('plugins', [])
            if plugins:
                report.append(f"🔌 PLUGINS DETECTED ({len(plugins)})")
                report.append("-" * 50)
                for plugin in plugins:
                    report.append(f"  • {plugin.get('name', 'Unknown')}")
                report.append("")
            
            # Themes section
            themes = results.get('themes', [])
            if themes:
                report.append(f"🎨 THEMES DETECTED ({len(themes)})")
                report.append("-" * 50)
                for theme in themes:
                    report.append(f"  • {theme.get('name', 'Unknown')}")
                report.append("")
            
            # Security issues
            issues = results.get('issues', [])
            if issues:
                report.append("🚨 SECURITY ISSUES FOUND")
                report.append("-" * 50)
                for issue in issues:
                    report.append(f"  • {issue}")
                report.append("")
            
            # Vulnerabilities
            vulns = results.get('vulnerabilities', [])
            if vulns:
                report.append("💀 VULNERABILITIES IDENTIFIED")
                report.append("-" * 50)
                for vuln in vulns:
                    report.append(f"  • {vuln}")
                report.append("")
            
            # Configuration issues
            config_issues = results.get('config_issues', [])
            if config_issues:
                report.append("⚙️ CONFIGURATION ISSUES")
                report.append("-" * 50)
                for issue in config_issues:
                    report.append(f"  • {issue}")
                report.append("")
            
            # Risk Assessment
            report.append("📊 RISK ASSESSMENT")
            report.append("-" * 50)
            risk_score = self._calculate_risk_score(results)
            report.append(f"Overall Risk Score: {risk_score}/100")
            
            if risk_score >= 70:
                report.append("Risk Level: 🔴 HIGH - Immediate action required")
            elif risk_score >= 40:
                report.append("Risk Level: 🟡 MEDIUM - Address soon")
            else:
                report.append("Risk Level: 🟢 LOW - Monitor regularly")
            report.append("")
            
            # Recommendations
            report.append("💡 RECOMMENDATIONS")
            report.append("-" * 50)
            recommendations = self._generate_recommendations(results)
            for i, rec in enumerate(recommendations, 1):
                report.append(f"{i}. {rec}")
            
        else:
            report.append("❌ NOT A WORDPRESS SITE")
            report.append("The target does not appear to be a WordPress installation.")
        
        report.append("")
        report.append("=" * 70)
        report.append("Report generated by WP-SEC-AUDIT v1.0.0")
        report.append("For authorized security testing only")
        
        return "\n".join(report)
    
    def _generate_json_report(self, results):
        """Generate JSON report"""
        report_data = {
            'metadata': {
                'tool': 'WP-SEC-AUDIT',
                'version': '1.0.0',
                'scan_time': datetime.now().isoformat(),
                'report_format': 'json'
            },
            'target': results.get('url'),
            'findings': {
                'wordpress_detected': results.get('wordpress', False),
                'users_exposed': results.get('users_exposed', False),
                'exposed_users': results.get('users', []),
                'plugins_detected': results.get('plugins', []),
                'themes_detected': results.get('themes', []),
                'security_issues': results.get('issues', []),
                'vulnerabilities': results.get('vulnerabilities', []),
                'configuration_issues': results.get('config_issues', []),
                'risk_score': self._calculate_risk_score(results)
            },
            'recommendations': self._generate_recommendations(results),
            'timestamp': results.get('timestamp')
        }
        
        return json.dumps(report_data, indent=2, default=str)
    
    def _generate_html_report(self, results):
        """Generate professional HTML report"""
        risk_score = self._calculate_risk_score(results)
        
        if risk_score >= 70:
            risk_color = "#e74c3c"
            risk_level = "HIGH"
            risk_icon = "🔴"
        elif risk_score >= 40:
            risk_color = "#f39c12"
            risk_level = "MEDIUM"
            risk_icon = "🟡"
        else:
            risk_color = "#27ae60"
            risk_level = "LOW"
            risk_icon = "🟢"
        
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
        .section.warning {{ border-left-color: #f39c12; background: #fff9e6; }}
        .section.info {{ border-left-color: #3498db; background: #f0f8ff; }}
        .section.success {{ border-left-color: #27ae60; background: #f0fff4; }}
        .section h2 {{
            color: #2c3e50;
            margin-bottom: 20px;
            display: flex;
            align-items: center;
            gap: 10px;
        }}
        .vulnerability {{
            background: white;
            padding: 20px;
            margin-bottom: 15px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.08);
            border: 1px solid #e0e0e0;
            transition: transform 0.2s;
        }}
        .vulnerability:hover {{ transform: translateY(-2px); box-shadow: 0 4px 20px rgba(0,0,0,0.12); }}
        .vulnerability.critical {{ border-left: 4px solid #e74c3c; }}
        .vulnerability.high {{ border-left: 4px solid #e67e22; }}
        .vulnerability.medium {{ border-left: 4px solid #f1c40f; }}
        .vulnerability.low {{ border-left: 4px solid #2ecc71; }}
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
        .user-list, .plugin-list, .theme-list {{
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
        }}
    </style>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
</head>
<body>
    <div class="container">
        <div class="header">
            <h1><i class="fas fa-shield-alt"></i> WP-SEC-AUDIT Security Report</h1>
            <div class="subtitle">Professional WordPress Security Assessment</div>
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
                        <div class="number">{len(results.get('plugins', []))}</div>
                        <div class="label">Plugins Found</div>
                    </div>
                    <div class="info-card">
                        <div class="number">{len(results.get('issues', []))}</div>
                        <div class="label">Security Issues</div>
                    </div>
                </div>
                <div style="margin-top: 20px;">
                    <p><strong>Target URL:</strong> {results.get('url', 'Unknown')}</p>
                    <p><strong>Scan Time:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                </div>
            </div>
"""
        
        # Vulnerabilities Section
        if results.get('users_exposed'):
            html += """
            <div class="section critical">
                <h2><i class="fas fa-exclamation-triangle"></i> Critical Vulnerability Found</h2>
                <div class="vulnerability critical">
                    <div>
                        <span class="severity critical">CRITICAL</span>
                        <strong>User Enumeration Vulnerability</strong>
                    </div>
                    <p style="margin-top: 10px; color: #555;">Attackers can enumerate user accounts via WordPress REST API.</p>
                    <p style="margin-top: 10px;"><strong>Impact:</strong> Enables targeted brute-force attacks</p>
                    <p style="margin-top: 10px;"><strong>Solution:</strong> Disable user enumeration via REST API</p>
                </div>
                <div class="user-list">
"""
            for user in results.get('users', []):
                html += f"""
                    <div class="user-item">
                        <strong>{user.get('name', 'Unknown')}</strong>
                        <p style="font-size: 0.9em; color: #666;">ID: {user.get('id')}<br>Username: {user.get('username', 'N/A')}</p>
                    </div>
"""
            html += """
                </div>
            </div>
"""
        
        # Plugins Section
        plugins = results.get('plugins', [])
        if plugins:
            html += f"""
            <div class="section info">
                <h2><i class="fas fa-plug"></i> Detected Plugins ({len(plugins)})</h2>
                <div class="plugin-list">
"""
            for plugin in plugins:
                html += f"""
                    <div class="plugin-item">
                        <strong>{plugin.get('name', 'Unknown')}</strong>
                        <p style="font-size: 0.9em; color: #666;">Status: {plugin.get('status', 'detected')}</p>
                    </div>
"""
            html += """
                </div>
            </div>
"""
        
        # Security Issues
        issues = results.get('issues', [])
        if issues:
            html += """
            <div class="section warning">
                <h2><i class="fas fa-exclamation-circle"></i> Security Issues</h2>
"""
            for issue in issues:
                html += f"""
                <div class="vulnerability medium">
                    <span class="severity medium">ISSUE</span>
                    {issue}
                </div>
"""
            html += """
            </div>
"""
        
        # Recommendations
        recommendations = self._generate_recommendations(results)
        if recommendations:
            html += """
            <div class="section success">
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
            <p>Report generated by <strong>WP-SEC-AUDIT v1.0.0</strong> - Professional Security Tool</p>
            <p class="timestamp">Generated on: """ + datetime.now().strftime('%Y-%m-%d %H:%M:%S') + """</p>
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
        md = f"""# WP-SEC-AUDIT Security Report

## 📊 Scan Summary
- **Target URL**: {results.get('url', 'Unknown')}
- **Scan Time**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
- **WordPress Detected**: {'✅ Yes' if results.get('wordpress') else '❌ No'}
- **Risk Score**: {self._calculate_risk_score(results)}/100

## 🔍 Findings
"""
        
        if results.get('wordpress'):
            if results.get('users_exposed'):
                md += f"\n### 🚨 Critical Vulnerability\nUser enumeration possible! Found {len(results.get('users', []))} exposed users.\n"
            
            plugins = results.get('plugins', [])
            if plugins:
                md += f"\n### 🔌 Detected Plugins ({len(plugins)})\n"
                for plugin in plugins:
                    md += f"- {plugin.get('name', 'Unknown')}\n"
            
            issues = results.get('issues', [])
            if issues:
                md += f"\n### ⚠️ Security Issues ({len(issues)})\n"
                for issue in issues:
                    md += f"- {issue}\n"
            
            md += f"\n### 💡 Recommendations\n"
            recommendations = self._generate_recommendations(results)
            for rec in recommendations:
                md += f"- {rec}\n"
        else:
            md += "\n❌ Not a WordPress site or inaccessible.\n"
        
        md += f"\n---\n*Report generated by WP-SEC-AUDIT v1.0.0 on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*"
        
        return md
    
    def _calculate_risk_score(self, results):
        """Calculate risk score (0-100)"""
        score = 0
        
        # Critical: User enumeration (40 points)
        if results.get('users_exposed'):
            score += 40
        
        # High: Multiple plugins (20 points)
        plugins = len(results.get('plugins', []))
        score += min(plugins * 5, 20)
        
        # Medium: Security issues (15 points)
        issues = len(results.get('issues', []))
        score += min(issues * 5, 15)
        
        # Low: Configuration issues (10 points)
        config_issues = len(results.get('config_issues', []))
        score += min(config_issues * 5, 10)
        
        # Base WordPress detection (15 points)
        if results.get('wordpress'):
            score += 15
        
        return min(score, 100)
    
    def _generate_recommendations(self, results):
        """Generate security recommendations"""
        recommendations = []
        
        if results.get('users_exposed'):
            recommendations.append("Disable user enumeration via REST API (add authentication to /wp-json/wp/v2/users)")
            recommendations.append("Implement login rate limiting to prevent brute force attacks")
        
        if results.get('plugins'):
            recommendations.append("Keep all plugins updated to their latest versions")
            recommendations.append("Remove unused plugins to reduce attack surface")
        
        if results.get('issues'):
            if any('wp-config' in issue.lower() for issue in results.get('issues', [])):
                recommendations.append("Protect wp-config.php file from public access")
            
            if any('xmlrpc' in issue.lower() for issue in results.get('issues', [])):
                recommendations.append("Disable XML-RPC if not needed for your applications")
        
        # Always include these
        recommendations.extend([
            "Implement Web Application Firewall (WAF)",
            "Use strong passwords and enable two-factor authentication",
            "Regularly backup your WordPress site",
            "Monitor security logs and implement intrusion detection"
        ])
        
        return list(set(recommendations))[:8]  # Return unique recommendations, max 8
    
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
        
        # Create full path
        filepath = os.path.join(self.report_dir, filename)
        
        # Save file
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(report_content)
            return filepath
        except Exception as e:
            print(f"[!] Error saving report: {e}")
            return None
    
    def generate_html_report(self, results):
        """Alias for generate_report with HTML format"""
        return self.generate_report(results, 'html')
    
    def generate_json_report(self, results):
        """Alias for generate_report with JSON format"""
        return self.generate_report(results, 'json')
