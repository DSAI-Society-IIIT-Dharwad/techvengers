#!/usr/bin/env python3
"""
Simplified Network Traffic Analyzer with WiFi Authentication Support
==================================================================

This script captures live network traffic packets and handles WiFi captive portal
authentication automatically. Simplified version without pandas dependency.

Author: Network Security Team
Date: 2024
"""

import csv
import os
import signal
import sys
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


class SimplePacketSniffer:
    """
    Simplified packet sniffer with WiFi authentication support.
    """
    
    def __init__(self, output_file: str = "packets.csv", interface: Optional[str] = None):
        """
        Initialize the packet sniffer.
        
        Args:
            output_file: Path to the CSV file where packet data will be stored
            interface: Network interface to capture packets from (None for default)
        """
        self.output_file = output_file
        self.interface = interface
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
            'packet_id'
        ]
        
        # Create CSV file with headers if it doesn't exist
        if not os.path.exists(self.output_file):
            with open(self.output_file, 'w', newline='', encoding='utf-8') as file:
                writer = csv.writer(file)
                writer.writerow(headers)
    
    def _extract_packet_info(self, packet) -> Dict[str, Any]:
        """
        Extract relevant information from a captured packet.
        
        Args:
            packet: Scapy packet object
            
        Returns:
            Dictionary containing packet information
        """
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
            'packet_id': self.packet_count
        }
        
        # Extract MAC addresses from Ethernet layer
        if packet.haslayer(Ether):
            packet_info['src_mac'] = packet[Ether].src
            packet_info['dst_mac'] = packet[Ether].dst
        
        # Extract IP information
        if packet.haslayer(IP):
            packet_info['source_ip'] = packet[IP].src
            packet_info['destination_ip'] = packet[IP].dst
            
            # Determine protocol
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
    
    def _process_packet(self, packet):
        """
        Process a captured packet and log it to CSV.
        
        Args:
            packet: Scapy packet object
        """
        try:
            packet_info = self._extract_packet_info(packet)
            self.packet_count += 1
            
            # Print packet info to console
            self._print_packet_info(packet_info)
            
            # Write to CSV file
            self._write_to_csv(packet_info)
            
        except Exception as e:
            print(f"Error processing packet: {e}")
    
    def _print_packet_info(self, packet_info: Dict[str, Any]):
        """Print packet information to console."""
        print(f"[{packet_info['packet_id']:06d}] "
              f"{packet_info['timestamp'][:19]} | "
              f"{packet_info['source_ip']:15s} -> {packet_info['destination_ip']:15s} | "
              f"{packet_info['protocol']:4s} | "
              f"Len: {packet_info['packet_length']:4d} | "
              f"Ports: {packet_info['source_port']} -> {packet_info['destination_port']}")
    
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
                    packet_info['packet_id']
                ])
        except Exception as e:
            print(f"Error writing to CSV: {e}")
    
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
    
    def start_capture(self, filter_str: str = "", count: int = 0):
        """
        Start capturing packets with network connectivity check.
        
        Args:
            filter_str: BPF filter string (e.g., "tcp", "host 192.168.1.1")
            count: Number of packets to capture (0 for unlimited)
        """
        print("=" * 80)
        print("NETWORK TRAFFIC ANALYZER - PACKET CAPTURE")
        print("=" * 80)
        
        # Check network connectivity first
        if not self.check_network_connectivity():
            print("Cannot proceed without network connectivity.")
            return
        
        print(f"Output file: {self.output_file}")
        print(f"Interface: {self.interface or 'Default'}")
        print(f"Filter: {filter_str or 'None (capture all)'}")
        print(f"Count: {count or 'Unlimited'}")
        print("=" * 80)
        print("Press Ctrl+C to stop capture")
        print("=" * 80)
        
        self.running = True
        
        try:
            # Start packet capture
            sniff(
                iface=self.interface,
                filter=filter_str,
                count=count,
                prn=self._process_packet,
                stop_filter=lambda x: not self.running
            )
        except KeyboardInterrupt:
            print("\nCapture interrupted by user")
        except Exception as e:
            print(f"Error during capture: {e}")
        finally:
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


def get_available_interfaces():
    """Get list of available network interfaces."""
    try:
        interfaces = get_if_list()
        print("Available network interfaces:")
        for i, interface in enumerate(interfaces):
            print(f"  {i}: {interface}")
        return interfaces
    except Exception as e:
        print(f"Error getting interfaces: {e}")
        return []


def main():
    """Main function to run the packet sniffer."""
    print("Network Traffic Analyzer - Packet Capture Tool")
    print("=" * 60)
    
    # Get user preferences
    print("\nConfiguration Options:")
    print("1. Use default settings (capture all traffic)")
    print("2. Customize capture settings")
    print("3. Test WiFi authentication only")
    
    try:
        choice = input("\nEnter your choice (1-3): ").strip()
    except EOFError:
        # Handle non-interactive execution
        print("\nRunning with default settings...")
        choice = "1"
    
    if choice == "3":
        # Test WiFi authentication only
        if WiFiAuthHandler:
            handler = WiFiAuthHandler()
            handler.detect_captive_portal()
            if handler.auth_required:
                handler.handle_authentication()
        else:
            print("WiFi authentication handler not available.")
        return
    
    interface = None
    filter_str = ""
    count = 0
    
    if choice == "2":
        # Show available interfaces
        interfaces = get_available_interfaces()
        if interfaces:
            try:
                interface_choice = input(f"\nSelect interface (0-{len(interfaces)-1}) or press Enter for default: ").strip()
                if interface_choice.isdigit() and 0 <= int(interface_choice) < len(interfaces):
                    interface = interfaces[int(interface_choice)]
            except EOFError:
                pass
        
        # Get filter
        print("\nCommon filters:")
        print("  - tcp (TCP packets only)")
        print("  - udp (UDP packets only)")
        print("  - host 192.168.1.1 (packets to/from specific host)")
        print("  - port 80 (packets on specific port)")
        print("  - Leave empty to capture all traffic")
        try:
            filter_str = input("\nEnter BPF filter (or press Enter for all): ").strip()
        except EOFError:
            filter_str = ""
        
        # Get count
        try:
            count_input = input("\nEnter number of packets to capture (or press Enter for unlimited): ").strip()
            if count_input.isdigit():
                count = int(count_input)
        except EOFError:
            count = 0
    
    # Initialize and start sniffer
    sniffer = SimplePacketSniffer(output_file="packets.csv", interface=interface)
    
    try:
        sniffer.start_capture(filter_str=filter_str, count=count)
    except Exception as e:
        print(f"Fatal error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
