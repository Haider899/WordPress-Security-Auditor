"""
Utility Functions for WP-SEC-AUDIT
Complete version with all required functions
"""

import yaml
import os
import sys
from colorama import Fore, Style
import importlib.util

def load_config(config_path=None):
    """Load configuration from YAML file"""
    default_config = {
        'scanning': {
            'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 WP-SEC-AUDIT/3.0',
            'timeout': 30,
            'threads': 5,
            'retries': 3,
            'verify_ssl': False
        },
        'output': {
            'save_reports': True,
            'report_dir': '~/Desktop/WP-SEC-AUDIT-Results',
            'formats': ['html', 'json', 'text'],
            'auto_open': False
        },
        'logging': {
            'level': 'INFO',
            'file': 'wp_sec_audit.log',
            'console': True
        }
    }
    
    if config_path and os.path.exists(config_path):
        try:
            with open(config_path, 'r') as f:
                user_config = yaml.safe_load(f) or {}
                # Deep merge configuration
                return _merge_dicts(default_config, user_config)
        except Exception as e:
            print_error(f"Error loading config: {e}")
            return default_config
    
    return default_config

def _merge_dicts(dict1, dict2):
    """Recursively merge two dictionaries"""
    result = dict1.copy()
    for key, value in dict2.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = _merge_dicts(result[key], value)
        else:
            result[key] = value
    return result

def validate_url(url):
    """Validate and format URL"""
    if not url or not isinstance(url, str):
        return None
    
    url = url.strip()
    
    # Remove any quotes
    url = url.strip('"\'')
    
    # Add https:// if no protocol specified
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    # Remove trailing slash
    url = url.rstrip('/')
    
    return url

def print_banner():
    """Print tool banner"""
    banner = f"""
{Fore.CYAN}{Style.BRIGHT}
╔══════════════════════════════════════════════════════╗
║              WP-SEC-AUDIT v1.0.0                     ║
║         Professional WordPress Security Scanner       ║
╚══════════════════════════════════════════════════════╝
{Style.RESET_ALL}
"""
    print(banner)

def print_result(message, level="info"):
    """Print colored result messages"""
    colors = {
        "success": Fore.GREEN + Style.BRIGHT,
        "error": Fore.RED + Style.BRIGHT,
        "warning": Fore.YELLOW + Style.BRIGHT,
        "info": Fore.CYAN,
        "debug": Fore.MAGENTA
    }
    
    prefix = {
        "success": "[+]",
        "error": "[-]",
        "warning": "[!]",
        "info": "[*]",
        "debug": "[DEBUG]"
    }
    
    color = colors.get(level, Fore.WHITE)
    prefix_text = prefix.get(level, "[*]")
    
    print(f"{color}{prefix_text} {message}{Style.RESET_ALL}")

def print_error(message):
    """Print error message"""
    print_result(message, "error")

def print_success(message):
    """Print success message"""
    print_result(message, "success")

def print_info(message):
    """Print info message"""
    print_result(message, "info")

def create_directories():
    """Create necessary directories"""
    try:
        # Create report directory on Desktop
        desktop = os.path.expanduser("~/Desktop")
        report_dir = os.path.join(desktop, "WP-SEC-AUDIT-Results")
        
        os.makedirs(report_dir, exist_ok=True)
        
        # Create logs directory
        log_dir = os.path.join(os.path.dirname(__file__), '..', 'logs')
        os.makedirs(log_dir, exist_ok=True)
        
        return report_dir
        
    except Exception as e:
        print_error(f"Failed to create directories: {e}")
        return None

def check_dependencies():
    """Check if required packages are installed"""
    required = [
        ('requests', 'requests'),
        ('colorama', 'colorama'),
        ('yaml', 'pyyaml'),  # ← FIXED: import 'yaml', package 'pyyaml'
        ('bs4', 'beautifulsoup4'),
        ('urllib3', 'urllib3')
    ]
    
    missing = []
    
    for import_name, package_name in required:
        try:
            importlib.import_module(import_name)
        except ImportError:
            missing.append(package_name)
    
    if missing:
        print_error(f"Missing required packages: {', '.join(missing)}")
        print_info("Install with: pip install " + " ".join(missing))
        return False
    
    return True

def ensure_config_exists():
    """Ensure configuration file exists"""
    config_path = os.path.join(os.path.dirname(__file__), '..', 'config', 'settings.yaml')
    
    if not os.path.exists(config_path):
        print_warning("Configuration file not found. Creating default...")
        
        # Create config directory if it doesn't exist
        config_dir = os.path.dirname(config_path)
        os.makedirs(config_dir, exist_ok=True)
        
        # Create default config
        default_config = """# WP-SEC-AUDIT Configuration

scanning:
  user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 WP-SEC-AUDIT/3.0"
  timeout: 30
  threads: 5
  retries: 3
  verify_ssl: false

output:
  save_reports: true
  report_dir: "~/Desktop/WP-SEC-AUDIT-Results"
  formats: ["html", "json", "text"]
  auto_open: false

logging:
  level: "INFO"
  console: true
"""
        
        try:
            with open(config_path, 'w') as f:
                f.write(default_config)
            print_success(f"Created default configuration at: {config_path}")
        except Exception as e:
            print_error(f"Failed to create config file: {e}")
    
    return config_path

def get_timestamp():
    """Get current timestamp for filenames"""
    from datetime import datetime
    return datetime.now().strftime("%Y%m%d_%H%M%S")

def sanitize_filename(filename):
    """Sanitize string for use as filename"""
    import re
    # Remove invalid characters
    filename = re.sub(r'[<>:"/\\|?*]', '_', filename)
    # Replace spaces and dots
    filename = filename.replace(' ', '_').replace('.', '_')
    # Limit length
    if len(filename) > 100:
        filename = filename[:100]
    return filename

def print_warning(message):
    """Print warning message"""
    print_result(message, "warning")

def print_debug(message):
    """Print debug message"""
    print_result(message, "debug")

def progress_bar(iteration, total, prefix='', suffix='', length=50, fill='█'):
    """Display progress bar"""
    percent = ("{0:.1f}").format(100 * (iteration / float(total)))
    filled_length = int(length * iteration // total)
    bar = fill * filled_length + '-' * (length - filled_length)
    print(f'\r{prefix} |{bar}| {percent}% {suffix}', end='\r')
    # Print New Line on Complete
    if iteration == total: 
        print()
