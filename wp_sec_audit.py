#!/usr/bin/env python3
"""
WP-SEC-AUDIT: Professional WordPress Security Auditor
Author: Security Researcher
Version: 3.0
"""

import os
import sys
import json
import yaml
import argparse
import threading
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, asdict
from pathlib import Path
import concurrent.futures

# Third-party imports
import requests
from colorama import init, Fore, Style
from bs4 import BeautifulSoup
import urllib3

# Local imports
from modules.scanner import WordPressScanner
from modules.reporter import ReportGenerator
from modules.utils import ConfigManager, Logger, ProgressBar

# Suppress SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Initialize colorama
init(autoreset=True)

@dataclass
class ScanResult:
    """Data class for scan results"""
    target: str
    scan_time: str
    vulnerabilities: List[Dict]
    plugins: List[Dict]
    themes: List[Dict]
    users: List[Dict]
    configuration_issues: List[Dict]
    recommendations: List[str]
    risk_score: float


class WPSecAudit:
    """Main WordPress Security Auditor Class"""
    
    def __init__(self, config_path: str = "config/settings.yaml"):
        self.config = ConfigManager(config_path).config
        self.logger = Logger(self.config['logging']['level'])
        self.scanner = WordPressScanner(self.config, self.logger)
        self.reporter = ReportGenerator(self.config)
        self.results_dir = Path.home() / "Desktop" / "WP-SEC-AUDIT-Results"
        self.results_dir.mkdir(exist_ok=True)
        
        # Session for requests
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': self.config['scanning']['user_agent'],
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
        })
        
        self.current_target = None
        self.scan_id = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    def print_banner(self) -> None:
        """Display tool banner"""
        banner = f"""
{Fore.CYAN}{Style.BRIGHT}
╔════════════════════════════════════════════════════════════════╗
║                    WP-SEC-AUDIT v3.0                           ║
║             Professional WordPress Security Scanner            ║
╚════════════════════════════════════════════════════════════════╝
{Style.RESET_ALL}
"""
        print(banner)
    
    def test_connection(self, url: str) -> bool:
        """Test connection to target"""
        try:
            response = self.session.get(
                url, 
                timeout=self.config['scanning']['timeout'],
                verify=False,
                allow_redirects=True
            )
            return response.status_code in [200, 301, 302, 403, 401]
        except Exception as e:
            self.logger.error(f"Connection failed: {e}")
            return False
    
    def set_target(self, url: str) -> bool:
        """Set and validate target URL"""
        if not url.startswith(('http://', 'https://')):
            url = f"https://{url}"
        
        url = url.rstrip('/')
        self.current_target = url
        
        print(f"\n{Fore.YELLOW}[*] Testing connection to: {url}{Style.RESET_ALL}")
        
        if self.test_connection(url):
            print(f"{Fore.GREEN}[+] Connection successful{Style.RESET_ALL}")
            return True
        else:
            print(f"{Fore.RED}[!] Connection failed{Style.RESET_ALL}")
            choice = input(f"{Fore.YELLOW}[?] Continue anyway? (y/n): {Style.RESET_ALL}").lower()
            return choice == 'y'
    
    def run_quick_scan(self) -> ScanResult:
        """Run quick security scan"""
        if not self.current_target:
            raise ValueError("No target set. Use set_target() first.")
        
        print(f"\n{Fore.CYAN}[*] Starting quick scan on {self.current_target}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Scan ID: {self.scan_id}{Style.RESET_ALL}")
        
        results = ScanResult(
            target=self.current_target,
            scan_time=datetime.now().isoformat(),
            vulnerabilities=[],
            plugins=[],
            themes=[],
            users=[],
            configuration_issues=[],
            recommendations=[],
            risk_score=0.0
        )
        
        # Run scans in parallel for speed
        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
            futures = {
                executor.submit(self.scanner.enumerate_users, self.current_target): 'users',
                executor.submit(self.scanner.detect_plugins, self.current_target): 'plugins',
                executor.submit(self.scanner.check_wp_config, self.current_target): 'config'
            }
            
            for future in concurrent.futures.as_completed(futures):
                scan_type = futures[future]
                try:
                    data = future.result()
                    if scan_type == 'users':
                        results.users = data
                    elif scan_type == 'plugins':
                        results.plugins = data
                    elif scan_type == 'config':
                        results.configuration_issues = data
                except Exception as e:
                    self.logger.error(f"Scan {scan_type} failed: {e}")
        
        # Calculate risk score
        results.risk_score = self._calculate_risk_score(results)
        
        return results
    
    def run_full_scan(self) -> ScanResult:
        """Run comprehensive security scan"""
        if not self.current_target:
            raise ValueError("No target set. Use set_target() first.")
        
        print(f"\n{Fore.MAGENTA}[*] Starting FULL security scan{Style.RESET_ALL}")
        print(f"{Fore.MAGENTA}[*] This may take several minutes...{Style.RESET_ALL}")
        
        with ProgressBar() as progress:
            # Update progress
            progress.update(0, "Initializing scan...")
            
            # Run all scans
            results = ScanResult(
                target=self.current_target,
                scan_time=datetime.now().isoformat(),
                vulnerabilities=self.scanner.scan_vulnerabilities(self.current_target),
                plugins=self.scanner.detect_plugins(self.current_target),
                themes=self.scanner.detect_themes(self.current_target),
                users=self.scanner.enumerate_users(self.current_target),
                configuration_issues=self.scanner.check_configuration(self.current_target),
                recommendations=[],
                risk_score=0.0
            )
            
            progress.update(100, "Scan complete!")
        
        # Generate recommendations
        results.recommendations = self._generate_recommendations(results)
        results.risk_score = self._calculate_risk_score(results)
        
        return results
    
    def _calculate_risk_score(self, results: ScanResult) -> float:
        """Calculate overall risk score (0-100)"""
        score = 0.0
        
        # Vulnerabilities weight: 40%
        if results.vulnerabilities:
            score += min(len(results.vulnerabilities) * 10, 40)
        
        # Exposed users weight: 20%
        if results.users:
            score += min(len(results.users) * 5, 20)
        
        # Configuration issues weight: 25%
        if results.configuration_issues:
            score += min(len(results.configuration_issues) * 5, 25)
        
        # Old plugins/themes weight: 15%
        old_components = sum(1 for p in results.plugins if p.get('outdated', False))
        score += min(old_components * 3, 15)
        
        return min(score, 100.0)
    
    def _generate_recommendations(self, results: ScanResult) -> List[str]:
        """Generate security recommendations based on findings"""
        recommendations = []
        
        if results.vulnerabilities:
            recommendations.append("Update WordPress core to latest version")
            recommendations.append("Apply security patches immediately")
        
        if results.users:
            recommendations.append("Disable user enumeration via REST API")
            recommendations.append("Implement login rate limiting")
        
        if any(p.get('outdated', False) for p in results.plugins):
            recommendations.append("Update all outdated plugins")
            recommendations.append("Remove unused plugins")
        
        if results.configuration_issues:
            if any('debug' in issue['issue'].lower() for issue in results.configuration_issues):
                recommendations.append("Disable WordPress debug mode")
            if any('xmlrpc' in issue['issue'].lower() for issue in results.configuration_issues):
                recommendations.append("Disable XML-RPC if not needed")
        
        # Always recommend basic security measures
        recommendations.extend([
            "Implement Web Application Firewall (WAF)",
            "Use strong passwords and two-factor authentication",
            "Regular security audits and backups"
        ])
        
        return list(set(recommendations))  # Remove duplicates
    
    def save_results(self, results: ScanResult, format: str = 'all') -> Dict[str, str]:
        """Save scan results in multiple formats"""
        saved_files = {}
        
        # Create scan directory
        target_name = self.current_target.replace('https://', '').replace('http://', '').replace('/', '_')
        scan_dir = self.results_dir / f"{target_name}_{self.scan_id}"
        scan_dir.mkdir(exist_ok=True)
        
        # Save JSON
        if format in ['json', 'all']:
            json_file = scan_dir / "scan_results.json"
            with open(json_file, 'w') as f:
                json.dump(asdict(results), f, indent=2, default=str)
            saved_files['json'] = str(json_file)
        
        # Save HTML report
        if format in ['html', 'all']:
            html_file = scan_dir / "security_report.html"
            self.reporter.generate_html_report(results, html_file)
            saved_files['html'] = str(html_file)
        
        # Save Markdown
        if format in ['md', 'all']:
            md_file = scan_dir / "README.md"
            self.reporter.generate_markdown_report(results, md_file)
            saved_files['markdown'] = str(md_file)
        
        # Save executive summary
        if format in ['summary', 'all']:
            summary_file = scan_dir / "executive_summary.txt"
            self.reporter.generate_executive_summary(results, summary_file)
            saved_files['summary'] = str(summary_file)
        
        return saved_files
    
    def batch_scan(self, targets_file: str) -> List[ScanResult]:
        """Scan multiple targets from a file"""
        all_results = []
        
        try:
            with open(targets_file, 'r') as f:
                targets = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        except FileNotFoundError:
            self.logger.error(f"Targets file not found: {targets_file}")
            return []
        
        print(f"\n{Fore.CYAN}[*] Starting batch scan of {len(targets)} targets{Style.RESET_ALL}")
        
        for i, target in enumerate(targets, 1):
            print(f"\n{Fore.YELLOW}[{i}/{len(targets)}] Scanning: {target}{Style.RESET_ALL}")
            
            try:
                if self.set_target(target):
                    results = self.run_quick_scan()
                    all_results.append(results)
                    
                    # Save individual results
                    self.save_results(results, 'json')
                    
                    # Print quick summary
                    print(f"{Fore.GREEN}[+] Found: {len(results.vulnerabilities)} vulns, "
                          f"{len(results.users)} users, Risk: {results.risk_score:.1f}/100{Style.RESET_ALL}")
            except Exception as e:
                self.logger.error(f"Failed to scan {target}: {e}")
                continue
        
        return all_results
    
    def interactive_menu(self):
        """Interactive menu system"""
        while True:
            self.print_banner()
            
            if self.current_target:
                print(f"{Fore.GREEN}[+] Current Target: {self.current_target}{Style.RESET_ALL}\n")
            
            print(f"{Fore.CYAN}Main Menu:{Style.RESET_ALL}")
            print(f"{Fore.GREEN} 1.{Style.RESET_ALL} Set Target URL")
            print(f"{Fore.GREEN} 2.{Style.RESET_ALL} Quick Security Scan")
            print(f"{Fore.GREEN} 3.{Style.RESET_ALL} Full Security Audit")
            print(f"{Fore.GREEN} 4.{Style.RESET_ALL} Batch Scan from File")
            print(f"{Fore.GREEN} 5.{Style.RESET_ALL} View Previous Reports")
            print(f"{Fore.GREEN} 6.{Style.RESET_ALL} Tool Settings")
            print(f"{Fore.GREEN} 7.{Style.RESET_ALL} Generate Wordlists")
            print(f"{Fore.GREEN} 8.{Style.RESET_ALL} Export Results")
            print(f"{Fore.GREEN} 0.{Style.RESET_ALL} Exit")
            
            try:
                choice = input(f"\n{Fore.YELLOW}[?] Select option (0-8): {Style.RESET_ALL}").strip()
                
                if choice == '1':
                    url = input(f"{Fore.YELLOW}[?] Enter target URL: {Style.RESET_ALL}").strip()
                    self.set_target(url)
                
                elif choice == '2':
                    if not self.current_target:
                        print(f"{Fore.RED}[!] Please set a target first{Style.RESET_ALL}")
                        input("Press Enter to continue...")
                        continue
                    
                    results = self.run_quick_scan()
                    self.display_results_summary(results)
                    
                    save = input(f"{Fore.YELLOW}[?] Save results? (y/n): {Style.RESET_ALL}").lower()
                    if save == 'y':
                        saved = self.save_results(results)
                        print(f"{Fore.GREEN}[+] Results saved to: {saved['json']}{Style.RESET_ALL}")
                    
                    input("\nPress Enter to continue...")
                
                elif choice == '3':
                    if not self.current_target:
                        print(f"{Fore.RED}[!] Please set a target first{Style.RESET_ALL}")
                        input("Press Enter to continue...")
                        continue
                    
                    results = self.run_full_scan()
                    self.display_detailed_results(results)
                    
                    saved = self.save_results(results, 'all')
                    print(f"\n{Fore.GREEN}[+] Reports saved to Desktop/WP-SEC-AUDIT-Results/{Style.RESET_ALL}")
                    
                    input("\nPress Enter to continue...")
                
                elif choice == '4':
                    file_path = input(f"{Fore.YELLOW}[?] Path to targets file: {Style.RESET_ALL}").strip()
                    self.batch_scan(file_path)
                    input("\nPress Enter to continue...")
                
                elif choice == '5':
                    self.view_reports()
                
                elif choice == '6':
                    self.settings_menu()
                
                elif choice == '7':
                    self.generate_wordlists()
                
                elif choice == '8':
                    if not self.current_target:
                        print(f"{Fore.RED}[!] No scan results to export{Style.RESET_ALL}")
                    else:
                        self.export_results_menu()
                
                elif choice == '0':
                    print(f"\n{Fore.GREEN}[+] Thank you for using WP-SEC-AUDIT!{Style.RESET_ALL}")
                    print(f"{Fore.CYAN}[*] Results saved on Desktop: {self.results_dir}{Style.RESET_ALL}")
                    sys.exit(0)
                
                else:
                    print(f"{Fore.RED}[!] Invalid choice{Style.RESET_ALL}")
            
            except KeyboardInterrupt:
                print(f"\n{Fore.YELLOW}[!] Interrupted by user{Style.RESET_ALL}")
                continue
            except Exception as e:
                self.logger.error(f"Menu error: {e}")
                input("Press Enter to continue...")
    
    def display_results_summary(self, results: ScanResult):
        """Display scan results summary"""
        print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}SCAN RESULTS SUMMARY{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        
        print(f"Target: {results.target}")
        print(f"Scan Time: {results.scan_time}")
        print(f"Risk Score: {Fore.RED if results.risk_score > 70 else Fore.YELLOW if results.risk_score > 30 else Fore.GREEN}"
              f"{results.risk_score:.1f}/100{Style.RESET_ALL}")
        
        print(f"\n{Fore.YELLOW}Findings:{Style.RESET_ALL}")
        print(f"  • Vulnerabilities: {len(results.vulnerabilities)}")
        print(f"  • Exposed Users: {len(results.users)}")
        print(f"  • Plugins Detected: {len(results.plugins)}")
        print(f"  • Configuration Issues: {len(results.configuration_issues)}")
        
        if results.recommendations:
            print(f"\n{Fore.GREEN}Top Recommendations:{Style.RESET_ALL}")
            for i, rec in enumerate(results.recommendations[:3], 1):
                print(f"  {i}. {rec}")
    
    def display_detailed_results(self, results: ScanResult):
        """Display detailed scan results"""
        self.display_results_summary(results)
        
        # Display vulnerabilities
        if results.vulnerabilities:
            print(f"\n{Fore.RED}{'='*60}{Style.RESET_ALL}")
            print(f"{Fore.RED}VULNERABILITIES FOUND:{Style.RESET_ALL}")
            print(f"{Fore.RED}{'='*60}{Style.RESET_ALL}")
            for vuln in results.vulnerabilities:
                print(f"\n{Fore.RED}[!] {vuln['title']}{Style.RESET_ALL}")
                print(f"    Type: {vuln['type']}")
                print(f"    Severity: {vuln['severity']}")
                print(f"    Description: {vuln['description']}")
                if 'solution' in vuln:
                    print(f"    Solution: {vuln['solution']}")
        
        # Display exposed users
        if results.users:
            print(f"\n{Fore.YELLOW}{'='*60}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}EXPOSED USERS:{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}{'='*60}{Style.RESET_ALL}")
            for user in results.users:
                print(f"  • {user['name']} (ID: {user['id']}, Slug: {user['slug']})")
    
    def view_reports(self):
        """View previously generated reports"""
        if not self.results_dir.exists():
            print(f"{Fore.YELLOW}[!] No reports found{Style.RESET_ALL}")
            return
        
        reports = list(self.results_dir.glob("*/*.html"))
        
        if not reports:
            print(f"{Fore.YELLOW}[!] No HTML reports found{Style.RESET_ALL}")
            return
        
        print(f"\n{Fore.CYAN}Available Reports:{Style.RESET_ALL}")
        for i, report in enumerate(reports, 1):
            print(f"  {i}. {report.parent.name} - {report.stat().st_mtime:%Y-%m-%d %H:%M}")
        
        try:
            choice = input(f"\n{Fore.YELLOW}[?] Select report to open (0 to cancel): {Style.RESET_ALL}").strip()
            if choice == '0':
                return
            
            idx = int(choice) - 1
            if 0 <= idx < len(reports):
                # Try to open report in default browser
                import webbrowser
                webbrowser.open(f"file://{reports[idx].absolute()}")
                print(f"{Fore.GREEN}[+] Opening report in browser...{Style.RESET_ALL}")
        except (ValueError, IndexError):
            print(f"{Fore.RED}[!] Invalid selection{Style.RESET_ALL}")
    
    def settings_menu(self):
        """Tool settings menu"""
        while True:
            print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
            print(f"{Fore.CYAN}TOOL SETTINGS{Style.RESET_ALL}")
            print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
            
            print(f"1. Change User Agent (Current: {self.config['scanning']['user_agent']})")
            print(f"2. Change Timeout (Current: {self.config['scanning']['timeout']}s)")
            print(f"3. Toggle Verbose Mode")
            print(f"4. View Current Configuration")
            print(f"5. Reset to Defaults")
            print(f"0. Back to Main Menu")
            
            choice = input(f"\n{Fore.YELLOW}[?] Select option: {Style.RESET_ALL}").strip()
            
            if choice == '0':
                break
            elif choice == '1':
                new_ua = input("Enter new User Agent: ").strip()
                if new_ua:
                    self.config['scanning']['user_agent'] = new_ua
                    self.session.headers.update({'User-Agent': new_ua})
                    print(f"{Fore.GREEN}[+] User Agent updated{Style.RESET_ALL}")
            elif choice == '2':
                try:
                    new_timeout = int(input("Enter new timeout (seconds): "))
                    self.config['scanning']['timeout'] = new_timeout
                    print(f"{Fore.GREEN}[+] Timeout updated{Style.RESET_ALL}")
                except ValueError:
                    print(f"{Fore.RED}[!] Invalid timeout value{Style.RESET_ALL}")
    
    def generate_wordlists(self):
        """Generate wordlists for scanning"""
        print(f"\n{Fore.CYAN}[*] Generating wordlists...{Style.RESET_ALL}")
        
        wordlists_dir = Path("wordlists")
        wordlists_dir.mkdir(exist_ok=True)
        
        # Generate user wordlist
        users = [
            "admin", "administrator", "wpadmin", "user", "test",
            "demo", "author", "editor", "contributor", "subscriber",
            "manager", "superadmin", "root", "system", "webadmin"
        ]
        
        with open(wordlists_dir / "users.txt", "w") as f:
            f.write("\n".join(users))
        
        print(f"{Fore.GREEN}[+] Generated wordlists in 'wordlists/' directory{Style.RESET_ALL}")
    
    def export_results_menu(self):
        """Export results in different formats"""
        print(f"\n{Fore.CYAN}Export Options:{Style.RESET_ALL}")
        print("1. JSON (Machine readable)")
        print("2. HTML (Web report)")
        print("3. PDF (Printable)")
        print("4. CSV (Spreadsheet)")
        print("5. All formats")
        
        choice = input(f"\n{Fore.YELLOW}[?] Select format: {Style.RESET_ALL}").strip()
        
        formats = {
            '1': 'json',
            '2': 'html',
            '3': 'pdf',
            '4': 'csv',
            '5': 'all'
        }
        
        if choice in formats:
            # This would need actual scan results
            print(f"{Fore.YELLOW}[*] Export functionality would be implemented here{Style.RESET_ALL}")
            print(f"{Fore.GREEN}[+] Results are automatically saved to Desktop{Style.RESET_ALL}")


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="WP-SEC-AUDIT: Professional WordPress Security Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                          # Interactive mode
  %(prog)s -t https://example.com   # Quick scan
  %(prog)s -t example.com -f full   # Full scan
  %(prog)s -b targets.txt           # Batch scan
  %(prog)s -o json                  # Output as JSON
        """
    )
    
    parser.add_argument('-t', '--target', help='Target URL to scan')
    parser.add_argument('-f', '--scan-type', choices=['quick', 'full'], default='quick',
                       help='Type of scan to perform (default: quick)')
    parser.add_argument('-b', '--batch', help='File containing list of targets')
    parser.add_argument('-o', '--output', choices=['json', 'html', 'all'],
                       help='Output format')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Verbose output')
    parser.add_argument('--version', action='version', version='WP-SEC-AUDIT v3.0')
    
    args = parser.parse_args()
    
    try:
        # Initialize tool
        tool = WPSecAudit()
        
        # Handle command line arguments
        if args.batch:
            tool.batch_scan(args.batch)
        elif args.target:
            if tool.set_target(args.target):
                if args.scan_type == 'full':
                    results = tool.run_full_scan()
                else:
                    results = tool.run_quick_scan()
                
                tool.display_results_summary(results)
                
                if args.output:
                    saved = tool.save_results(results, args.output)
                    print(f"\n{Fore.GREEN}[+] Results saved:{Style.RESET_ALL}")
                    for fmt, path in saved.items():
                        print(f"  • {fmt.upper()}: {path}")
        else:
            # Interactive mode
            tool.interactive_menu()
    
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Scan interrupted by user{Style.RESET_ALL}")
        sys.exit(1)
    except Exception as e:
        print(f"{Fore.RED}[!] Error: {e}{Style.RESET_ALL}")
        sys.exit(1)


if __name__ == "__main__":
    main()
