#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Cyber Security Bot - Network Monitoring and Analysis Tool
Version: 41.0
Author: Ian Carter Kulani
Description: A command-line cyber security tool for network monitoring, scanning, and attack simulation.
"""

import os
import sys
import time
import socket
import threading
import subprocess
import argparse
import json
import platform
import select
import random
import struct
import binascii
from datetime import datetime
from collections import defaultdict
import requests
import scapy.all as scapy
from scapy.layers import http
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.sendrecv import sniff, send, sr1, srp
from scapy.layers.l2 import ARP, Ether
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.packet import Raw
from scapy.arch import get_if_hwaddr
from scapy.route import Route
import dns.resolver
import psutil
import netifaces

# Configuration
CONFIG_FILE = "cyberbot_config.json"
DEFAULT_CONFIG = "DEFAULT_CONFIG.json"

# ANSI Color Codes for Blue Theme
COLORS = {
    "blue": {
        "primary": "\033[94m",
        "secondary": "\033[36m",
        "success": "\033[92m",
        "warning": "\033[93m",
        "error": "\033[91m",
        "info": "\033[96m",
        "reset": "\033[0m"
    }
}

# Global variables
current_theme = "blue"
active_monitoring = False
monitoring_thread = None
packet_sniffer_thread = None
ddos_attack_active = False
ddos_threads = []

from cyberbot import CyberBot

if __name__ == "__main__":
    # Check for root privileges on Linux
    if platform.system() != "Windows" and os.geteuid() != 0:
        print(f"{COLORS[current_theme]['error']}This tool requires root privileges for some operations. Please run with sudo.{COLORS[current_theme]['reset']}")
        sys.exit(1)
    
    # Initialize and run the bot
    bot = CyberBot()
    bot.run()
