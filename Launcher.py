#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# ============================================
# INITIALIZATION SCRIPT FOR CYBER SECURITY BOT
# ============================================

"""
Cyber Security Bot - Network Monitoring and Analysis Tool
Version: 41.0
Author: Ian Carter Kulani
Description: A command-line cyber security tool for network monitoring, scanning, and attack simulation.
"""

import os
import sys
import platform
import json
import threading


# Configuration
CONFIG_FILE = "cyberbot_config.json"
DEFAULT_CONFIG = "DEFAULT_CONFIG.json"
COLORS = "colors.json"
current_theme = "blue"


#unecessary but checks if all the needed packages are installed 
#and then notifies the user if any are missing
def check_import(package, import_name=None):
    import_name = import_name or package
    try:
        __import__(import_name)
    except ImportError:
        print(f"Dependency missing: '{package}'. Please install it manually and rerun.")
        sys.exit(1)

# Your external packages (package_name, import_name)
dependencies = [
    ('requests', 'requests'),
    ('scapy', 'scapy.all'),
    ('dnspython', 'dns.resolver'),
    ('psutil', 'psutil'),
    ('netifaces', 'netifaces'),
]

for pkg, imp in dependencies:
    check_import(pkg, imp)

#launch main script
from cyberbot import CyberBot

if __name__ == "__main__":
    # Check for root privileges on Linux
    if platform.system() != "Windows" and os.geteuid() != 0:
        print(f"{COLORS[current_theme]['error']}This tool requires root privileges for some operations. Please run with sudo.{COLORS[current_theme]['reset']}")
        sys.exit(1)
    
    # Initialize and run the bot
    bot = CyberBot()
    bot.run()

