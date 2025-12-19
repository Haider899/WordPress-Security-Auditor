# 🔍 WP-SEC-AUDIT: WordPress Security Auditor

**Professional WordPress Security Scanner & Vulnerability Auditor**

> ⚡ Automated security assessment for WordPress websites

---

## ✨ Features

- **User Enumeration** - Detect exposed users via REST API
- **Plugin Detection** - Identify installed plugins with versions
- **Theme Analysis** - Detect active themes
- **Vulnerability Scanning** - Check for known vulnerabilities
- **Configuration Auditing** - Review security settings
- **Professional Reports** - HTML, JSON, Markdown formats

---
# Quick Examples
bash
# Interactive mode
python wp_sec_audit.py

# Quick scan
python wp_sec_audit.py -t https://example.com

# Batch scan
python wp_sec_audit.py -b targets.txt


## 🚀 Quick Start

```bash
# Clone repository
git clone https://github.com/yourusername/WordPress-Security-Auditor.git
cd WordPress-Security-Auditor

# Install dependencies
pip install -r requirements.txt

# Run the tool
python wp_sec_audit.py
