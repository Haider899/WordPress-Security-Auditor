from setuptools import setup, find_packages

setup(
    name="wp-sec-audit",
    version="1.0.0",
    author="Security Researcher",
    description="WordPress Security Auditor",
    packages=find_packages(),
    install_requires=[
        'requests>=2.28.0',
        'beautifulsoup4>=4.11.0',
        'colorama>=0.4.6',
        'PyYAML>=6.0',
    ],
    entry_points={
        "console_scripts": [
            "wp-sec-audit=wp_sec_audit:main",
        ]
    },
)
