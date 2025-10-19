#!/usr/bin/env python3
"""
Setup script for DFAS - Digital Forensics Agent System
This script checks and installs required dependencies
"""

import subprocess
import sys
import os

def install_package(package):
    """Install a package using pip"""
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", package])
        return True
    except subprocess.CalledProcessError:
        return False

def check_and_install_dependencies():
    """Check and install required dependencies"""
    required_packages = [
        "PyYAML>=6.0",
        "cryptography>=3.4.8"
    ]
    
    print("DFAS Setup - Installing Dependencies")
    print("="*40)
    
    for package in required_packages:
        print(f"Installing {package}...")
        if install_package(package):
            print(f"✓ {package} installed successfully")
        else:
            print(f"✗ Failed to install {package}")
            return False
    
    # Try to install python-magic for Windows
    print("\nTrying to install python-magic (optional)...")
    if os.name == 'nt':  # Windows
        if install_package("python-magic-bin"):
            print("✓ python-magic-bin installed successfully")
        else:
            print("⚠ python-magic-bin installation failed (optional - will use fallback)")
    else:  # Unix/Linux/Mac
        if install_package("python-magic"):
            print("✓ python-magic installed successfully")
        else:
            print("⚠ python-magic installation failed (optional - will use fallback)")
    
    print("\n" + "="*40)
    print("Setup complete! You can now run: python DFAS.py")
    return True

if __name__ == "__main__":
    check_and_install_dependencies()