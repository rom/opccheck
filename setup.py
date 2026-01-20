#!/usr/bin/env python3
"""Setup script for OPCCheck - OPC-DA Security Checker"""

from setuptools import setup, find_packages
import os

# Read version from main module
version = "1.0.0"

# Read long description from README
here = os.path.abspath(os.path.dirname(__file__))
try:
    with open(os.path.join(here, 'README.md'), encoding='utf-8') as f:
        long_description = f.read()
except FileNotFoundError:
    long_description = "OPC-DA Security Checker"

setup(
    name="opccheck",
    version=version,
    author="OPCCheck Team",
    author_email="security@opccheck.local",
    description="A command-line tool for security assessment of OPC-DA servers",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/opccheck/opccheck",
    license="MIT",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: Console",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Operating System :: POSIX :: Linux",
        "Operating System :: MacOS :: MacOS X",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
        "Topic :: System :: Networking",
        "Topic :: System :: Systems Administration",
    ],
    keywords="opc opc-da dcom security scanner industrial",
    python_requires=">=3.8",
    py_modules=["opccheck"],
    entry_points={
        "console_scripts": [
            "opccheck=opccheck:main",
        ],
    },
    data_files=[
        ("share/man/man1", ["opccheck.1"]),
    ],
    project_urls={
        "Bug Reports": "https://github.com/opccheck/opccheck/issues",
        "Source": "https://github.com/opccheck/opccheck",
    },
)
