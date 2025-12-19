#!/usr/bin/env python3
"""
WP-SEC-AUDIT: WordPress Security Auditor
Main entry point
"""

import sys
import argparse
from colorama import init

# Import our modules
from modules.scanner import WordPressScanner
from modules.reporter import ReportGenerator
from modules.utils import (
    load_config, validate_url, print_banner,
    print_result, create_directories, check_dependencies
)

init(autoreset=True)

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="WP-SEC-AUDIT: Professional WordPress Security Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument('-t', '--target', help='Target URL to scan')
    parser.add_argument('-o', '--output', choices=['text', 'json', 'html'],
                       default='text', help='Output format (default: text)')
    parser.add_argument('-q', '--quick', action='store_true',
                       help='Perform quick scan')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Verbose output')
    parser.add_argument('--version', action='version',
                       version='WP-SEC-AUDIT v1.0.0')
    
    args = parser.parse_args()
    
    # Print banner
    print_banner()
    
    # Check dependencies
    if not check_dependencies():
        return 1
    
    # Create directories
    report_dir = create_directories()
    if report_dir:
        print_result(f"Reports will be saved to: {report_dir}", "info")
    
    # Load configuration
    config = load_config('config/settings.yaml')
    
    if args.target:
        # Validate URL
        target = validate_url(args.target)
        if not target:
            print_result("Invalid URL format", "error")
            return 1
        
        print_result(f"Starting scan for: {target}", "info")
        
        # Initialize scanner and perform scan
        scanner = WordPressScanner(config)
        results = scanner.quick_scan(target)
        
        # Generate report
        reporter = ReportGenerator(config)
        report = reporter.generate_report(results, args.output)
        
        # Save report
        if config['output'].get('save_reports', True):
            # Create filename from target
            from datetime import datetime
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            target_name = target.replace('https://', '').replace('http://', '')
            target_name = target_name.replace('/', '_').replace('.', '_')
            filename = f"scan_{target_name}_{timestamp}"
            
            filepath = reporter.save_report(report, filename, args.output)
            print_result(f"Report saved to: {filepath}", "success")
        
        # Print report to console if text format
        if args.output == 'text':
            print("\n" + report)
        
    else:
        # Interactive mode
        print_result("Interactive mode selected", "info")
        print_result("Please enter target URL or use -t option", "info")
        print("\nExamples:")
        print("  python wp_sec_audit.py -t https://example.com")
        print("  python wp_sec_audit.py -t example.com -o html")
        print("  python wp_sec_audit.py -t example.com --quick")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
