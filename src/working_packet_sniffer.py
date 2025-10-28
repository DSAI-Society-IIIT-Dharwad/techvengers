#!/usr/bin/env python3
"""
Working Packet Capture Solution
=============================

This script provides multiple approaches to capture network traffic:
1. Layer 3 capture (may work without admin)
2. Socket-based capture (no admin required)
3. Process monitoring (no admin required)
"""

import csv
import os
import signal
import sys
import socket
import psutil
import time
from datetime import datetime
from typing import Dict, Any, Optional

try:
    from scapy.all import *
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.l2 import Ether
except ImportError:
    print("Error: scapy library not found. Please install it using: pip install scapy")
    sys.exit(1)

try:
    from wifi_auth_handler import WiFiAuthHandler
except ImportError:
    print("Warning: WiFi authentication handler not found. Continuing without auth support.")
    WiFiAuthHandler = None


class WorkingPacketSniffer:
    """
    Working packet sniffer with multiple capture methods.
    """
    
    def __init__(self, output_file: str = "data/packets.csv"):
        """
        Initialize the packet sniffer.
        
        Args:
            output_file: Path to the CSV file where packet data will be stored
        """
        self.output_file = output_file
        self.packet_count = 0
        self.start_time = datetime.now()
        self.running = False
        self.auth_handler = WiFiAuthHandler() if WiFiAuthHandler else None
        
        # Initialize CSV file with headers
        self._initialize_csv()
        
        # Set up signal handler for graceful shutdown
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
    
    def _initialize_csv(self):
        """Initialize the CSV file with column headers."""
        headers = [
            'timestamp',
            'source_ip',
            'destination_ip',
            'protocol',
            'packet_length',
            'source_port',
            'destination_port',
            'src_mac',
            'dst_mac',
            'packet_id',
            'method'
        ]
        
        # Create CSV file with headers if it doesn't exist
        if not os.path.exists(self.output_file):
            with open(self.output_file, 'w', newline='', encoding='utf-8') as file:
                writer = csv.writer(file)
                writer.writerow(headers)
    
    def _write_to_csv(self, packet_info: Dict[str, Any]):
        """Write packet information to CSV file."""
        try:
            with open(self.output_file, 'a', newline='', encoding='utf-8') as file:
                writer = csv.writer(file)
                writer.writerow([
                    packet_info['timestamp'],
                    packet_info['source_ip'],
                    packet_info['destination_ip'],
                    packet_info['protocol'],
                    packet_info['packet_length'],
                    packet_info['source_port'],
                    packet_info['destination_port'],
                    packet_info['src_mac'],
                    packet_info['dst_mac'],
                    packet_info['packet_id'],
                    packet_info['method']
                ])
        except Exception as e:
            print(f"Error writing to CSV: {e}")
    
    def _print_packet_info(self, packet_info: Dict[str, Any]):
        """Print packet information to console."""
        print(f"[{packet_info['packet_id']:06d}] "
              f"{packet_info['timestamp'][:19]} | "
              f"{packet_info['source_ip']:15s} -> {packet_info['destination_ip']:15s} | "
              f"{packet_info['protocol']:4s} | "
              f"Len: {packet_info['packet_length']:4d} | "
              f"Ports: {packet_info['source_port']} -> {packet_info['destination_port']} | "
              f"Method: {packet_info['method']}")
    
    def _signal_handler(self, signum, frame):
        """Handle interrupt signals for graceful shutdown."""
        print(f"\n\nReceived signal {signum}. Stopping packet capture...")
        self.running = False
    
    def check_network_connectivity(self) -> bool:
        """
        Check network connectivity and handle WiFi authentication if needed.
        
        Returns:
            True if network is accessible, False otherwise
        """
        if not self.auth_handler:
            print("WiFi authentication handler not available. Proceeding without auth check.")
            return True
        
        print("Checking network connectivity...")
        
        # Detect captive portal
        if self.auth_handler.detect_captive_portal():
            print("WiFi authentication required!")
            
            # Handle authentication
            success = self.auth_handler.handle_authentication()
            
            if success:
                print("Network authentication successful!")
                return True
            else:
                print("Network authentication failed!")
                return False
        else:
            print("Network connectivity confirmed!")
            return True
    
    def method1_scapy_layer3(self, count: int = 10):
        """Method 1: Try Scapy Layer 3 capture."""
        print("\nMethod 1: Trying Scapy Layer 3 capture...")
        
        try:
            # Force Layer 3 socket
            conf.L3socket = conf.L3socket6
            
            packets = sniff(count=count, timeout=10)
            
            if packets:
                print(f"Successfully captured {len(packets)} packets using Layer 3!")
                for packet in packets:
                    packet_info = self._extract_packet_info_scapy(packet, "Layer3")
                    self.packet_count += 1
                    self._print_packet_info(packet_info)
                    self._write_to_csv(packet_info)
                return True
            else:
                print("No packets captured with Layer 3 method.")
                return False
                
        except Exception as e:
            print(f"Layer 3 capture failed: {e}")
            return False
    
    def method2_socket_capture(self, count: int = 10):
        """Method 2: Socket-based capture."""
        print("\nMethod 2: Trying socket-based capture...")
        
        try:
            # Create raw socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            sock.bind(('0.0.0.0', 0))
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            
            captured = 0
            start_time = time.time()
            
            while captured < count and self.running and (time.time() - start_time) < 30:
                try:
                    data, addr = sock.recvfrom(65535)
                    if data:
                        packet_info = self._extract_packet_info_socket(data, addr)
                        self.packet_count += 1
                        self._print_packet_info(packet_info)
                        self._write_to_csv(packet_info)
                        captured += 1
                except socket.timeout:
                    continue
                except Exception as e:
                    print(f"Socket error: {e}")
                    break
            
            sock.close()
            
            if captured > 0:
                print(f"Successfully captured {captured} packets using socket method!")
                return True
            else:
                print("No packets captured with socket method.")
                return False
                
        except Exception as e:
            print(f"Socket capture failed: {e}")
            return False
    
    def method3_network_monitoring(self, count: int = 10):
        """Method 3: Network connection monitoring."""
        print("\nMethod 3: Monitoring network connections...")
        
        try:
            captured = 0
            start_time = time.time()
            seen_connections = set()
            
            while captured < count and self.running and (time.time() - start_time) < 30:
                connections = psutil.net_connections(kind='inet')
                
                for conn in connections:
                    if conn.laddr and conn.raddr:
                        conn_key = (conn.laddr.ip, conn.laddr.port, conn.raddr.ip, conn.raddr.port, conn.type)
                        
                        if conn_key not in seen_connections:
                            seen_connections.add(conn_key)
                            
                            packet_info = self._extract_packet_info_psutil(conn)
                            self.packet_count += 1
                            self._print_packet_info(packet_info)
                            self._write_to_csv(packet_info)
                            captured += 1
                            
                            if captured >= count:
                                break
                
                time.sleep(0.5)  # Wait before next check
            
            if captured > 0:
                print(f"Successfully captured {captured} network connections!")
                return True
            else:
                print("No network connections captured.")
                return False
                
        except Exception as e:
            print(f"Network monitoring failed: {e}")
            return False
    
    def _extract_packet_info_scapy(self, packet, method: str) -> Dict[str, Any]:
        """Extract packet info from Scapy packet."""
        packet_info = {
            'timestamp': datetime.now().isoformat(),
            'source_ip': 'N/A',
            'destination_ip': 'N/A',
            'protocol': 'Unknown',
            'packet_length': len(packet),
            'source_port': 'N/A',
            'destination_port': 'N/A',
            'src_mac': 'N/A',
            'dst_mac': 'N/A',
            'packet_id': self.packet_count,
            'method': method
        }
        
        if packet.haslayer(Ether):
            packet_info['src_mac'] = packet[Ether].src
            packet_info['dst_mac'] = packet[Ether].dst
        
        if packet.haslayer(IP):
            packet_info['source_ip'] = packet[IP].src
            packet_info['destination_ip'] = packet[IP].dst
            
            if packet.haslayer(TCP):
                packet_info['protocol'] = 'TCP'
                packet_info['source_port'] = packet[TCP].sport
                packet_info['destination_port'] = packet[TCP].dport
            elif packet.haslayer(UDP):
                packet_info['protocol'] = 'UDP'
                packet_info['source_port'] = packet[UDP].sport
                packet_info['destination_port'] = packet[UDP].dport
            elif packet.haslayer(ICMP):
                packet_info['protocol'] = 'ICMP'
            else:
                packet_info['protocol'] = packet[IP].proto
        
        return packet_info
    
    def _extract_packet_info_socket(self, data: bytes, addr) -> Dict[str, Any]:
        """Extract packet info from socket data."""
        packet_info = {
            'timestamp': datetime.now().isoformat(),
            'source_ip': addr[0] if addr else 'Unknown',
            'destination_ip': 'Unknown',
            'protocol': 'Raw',
            'packet_length': len(data),
            'source_port': addr[1] if addr and len(addr) > 1 else 'N/A',
            'destination_port': 'N/A',
            'src_mac': 'N/A',
            'dst_mac': 'N/A',
            'packet_id': self.packet_count,
            'method': 'Socket'
        }
        
        # Try to parse IP header
        if len(data) >= 20:
            try:
                # IP header parsing (simplified)
                protocol = data[9]
                src_ip = '.'.join(map(str, data[12:16]))
                dst_ip = '.'.join(map(str, data[16:20]))
                
                packet_info['source_ip'] = src_ip
                packet_info['destination_ip'] = dst_ip
                packet_info['protocol'] = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}.get(protocol, f'Protocol-{protocol}')
            except:
                pass
        
        return packet_info
    
    def _extract_packet_info_psutil(self, conn) -> Dict[str, Any]:
        """Extract packet info from psutil connection."""
        packet_info = {
            'timestamp': datetime.now().isoformat(),
            'source_ip': conn.laddr.ip if conn.laddr else 'Unknown',
            'destination_ip': conn.raddr.ip if conn.raddr else 'Unknown',
            'protocol': conn.type.name if conn.type else 'Unknown',
            'packet_length': 0,  # Not available from psutil
            'source_port': conn.laddr.port if conn.laddr else 'N/A',
            'destination_port': conn.raddr.port if conn.raddr else 'N/A',
            'src_mac': 'N/A',
            'dst_mac': 'N/A',
            'packet_id': self.packet_count,
            'method': 'Psutil'
        }
        
        return packet_info
    
    def start_capture(self, count: int = 10):
        """
        Start capturing packets using multiple methods.
        
        Args:
            count: Number of packets to capture
        """
        print("=" * 80)
        print("WORKING NETWORK TRAFFIC ANALYZER - PACKET CAPTURE")
        print("=" * 80)
        
        # Check network connectivity first
        if not self.check_network_connectivity():
            print("Cannot proceed without network connectivity.")
            return
        
        print(f"Output file: {self.output_file}")
        print(f"Count: {count}")
        print("=" * 80)
        print("Trying multiple capture methods...")
        print("=" * 80)
        
        self.running = True
        
        # Try different methods
        methods = [
            ("Scapy Layer 3", lambda: self.method1_scapy_layer3(count)),
            ("Socket Capture", lambda: self.method2_socket_capture(count)),
            ("Network Monitoring", lambda: self.method3_network_monitoring(count))
        ]
        
        success = False
        for method_name, method_func in methods:
            print(f"\nTrying {method_name}...")
            try:
                if method_func():
                    success = True
                    break
            except Exception as e:
                print(f"{method_name} failed: {e}")
                continue
        
        if not success:
            print("\nAll capture methods failed. This usually means:")
            print("1. Run as Administrator for full packet capture")
            print("2. Install Npcap/WinPcap for Windows")
            print("3. Check Windows Firewall settings")
        
        self._print_summary()
    
    def _print_summary(self):
        """Print capture summary statistics."""
        duration = datetime.now() - self.start_time
        print("\n" + "=" * 80)
        print("CAPTURE SUMMARY")
        print("=" * 80)
        print(f"Total packets captured: {self.packet_count}")
        print(f"Duration: {duration}")
        if duration.total_seconds() > 0:
            print(f"Average packets per second: {self.packet_count / duration.total_seconds():.2f}")
        print(f"Data saved to: {self.output_file}")
        print("=" * 80)


def main():
    """Main function to run the working packet sniffer."""
    print("Working Network Traffic Analyzer - Packet Capture Tool")
    print("=" * 60)
    print("This version tries multiple methods to capture network traffic.")
    print("=" * 60)
    
    # Get user preferences
    print("\nConfiguration Options:")
    print("1. Capture 10 packets (quick test)")
    print("2. Capture 50 packets")
    print("3. Capture 100 packets")
    print("4. Test WiFi authentication only")
    
    try:
        choice = input("\nEnter your choice (1-4): ").strip()
    except EOFError:
        # Handle non-interactive execution
        print("\nRunning quick test...")
        choice = "1"
    
    if choice == "4":
        # Test WiFi authentication only
        if WiFiAuthHandler:
            handler = WiFiAuthHandler()
            handler.detect_captive_portal()
            if handler.auth_required:
                handler.handle_authentication()
        else:
            print("WiFi authentication handler not available.")
        return
    
    count = 10
    if choice == "1":
        count = 10
    elif choice == "2":
        count = 50
    elif choice == "3":
        count = 100
    
    # Initialize and start sniffer
    sniffer = WorkingPacketSniffer(output_file="data/packets.csv")
    
    try:
        sniffer.start_capture(count=count)
    except Exception as e:
        print(f"Fatal error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
