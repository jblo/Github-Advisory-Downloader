#!/usr/bin/env python3
"""
Setup script for GitHub Security Advisory Downloader
"""

from setuptools import setup, find_packages
from pathlib import Path

# Read the README file
this_directory = Path(__file__).parent
long_description = (this_directory / "README.md").read_text()

# Read requirements
requirements = []
with open("requirements.txt", "r") as f:
    requirements = [line.strip() for line in f if line.strip() and not line.startswith("#")]

setup(
    name="github-advisory-downloader",
    version="1.0.0",
    author="Security Research Team",
    author_email="security@example.com",
    description="Download and analyze GitHub Security Advisories with CISA KEV integration",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/your-org/github-advisory-downloader",
    py_modules=["github_advisory_downloader"],
    install_requires=requirements,
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Topic :: System :: Systems Administration",
    ],
    python_requires=">=3.7",
    entry_points={
        "console_scripts": [
            "github-advisory-downloader=github_advisory_downloader:main",
        ],
    },
    keywords="security, vulnerabilities, github, cisa, kev, advisories, cve",
    project_urls={
        "Bug Reports": "https://github.com/your-org/github-advisory-downloader/issues",
        "Source": "https://github.com/your-org/github-advisory-downloader",
        "Documentation": "https://github.com/your-org/github-advisory-downloader#readme",
    },
    include_package_data=True,
    zip_safe=False,
)
