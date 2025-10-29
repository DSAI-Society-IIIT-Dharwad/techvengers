#!/usr/bin/env python3
"""
Real Network Packet Sniffer
Captures actual packets from WiFi network interface
"""

import socket
import struct
import threading
import time
from datetime import datetime
from collections import deque
import psutil
import subprocess
import platform

try:
    from scapy.all import *
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.l2 import Ether, ARP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("Warning: Scapy not available. Install with: pip install scapy")

class RealPacketSniffer:
    """Real-time packet sniffer for actual network traffic"""
    
    def __init__(self):
        self.is_sniffing = False
        self.packet_queue = deque(maxlen=1000)
        self.device_info = {}
        self.bandwidth_usage = {}
        self.packet_count = 0
        self.network_interfaces = self.get_network_interfaces()
        self.selected_interface = None
        
    def get_network_interfaces(self):
        """Get available network interfaces"""
        interfaces = []
        try:
            # Get network interfaces using psutil
            for interface, addrs in psutil.net_if_addrs().items():
                for addr in addrs:
                    if addr.family == socket.AF_INET and not addr.address.startswith('127.'):
                        interfaces.append({
                            'name': interface,
                            'ip': addr.address,
                            'mac': self.get_mac_address(interface)
                        })
                        break
        except Exception as e:
            print(f"Error getting interfaces: {e}")
            
        return interfaces
    
    def get_mac_address(self, interface):
        """Get MAC address for interface"""
        try:
            if platform.system() == "Windows":
                # Windows method
                result = subprocess.run(['getmac', '/fo', 'csv'], 
                                      capture_output=True, text=True)
                for line in result.stdout.split('\n'):
                    if interface in line:
                        return line.split(',')[0].strip('"')
            else:
                # Linux/Unix method
                with open(f'/sys/class/net/{interface}/address', 'r') as f:
                    return f.read().strip()
        except:
            return "Unknown"
    
    def select_interface(self, interface_name=None):
        """Select network interface for sniffing"""
        if interface_name:
            for interface in self.network_interfaces:
                if interface['name'] == interface_name:
                    self.selected_interface = interface
                    return True
        else:
            # Auto-select Wi-Fi interface if available, otherwise first interface
            wifi_interface = None
            for interface in self.network_interfaces:
                if 'Wi-Fi' in interface['name'] or 'wlan' in interface['name'].lower():
                    wifi_interface = interface
                    break
            
            if wifi_interface:
                self.selected_interface = wifi_interface
                print(f"Auto-selected Wi-Fi interface: {wifi_interface['name']}")
            elif self.network_interfaces:
                self.selected_interface = self.network_interfaces[0]
                print(f"Auto-selected first available interface: {self.network_interfaces[0]['name']}")
            
            return self.selected_interface is not None
        return False
    
    def packet_handler(self, packet):
        """Handle captured packets"""
        if not self.is_sniffing:
            return
            
        try:
            # Extract packet information
            packet_info = self.extract_packet_info(packet)
            if packet_info:
                self.packet_count += 1
                self.packet_queue.append(packet_info)
                
                # Update device info
                self.update_device_info(packet_info)
                
                # Update bandwidth usage
                self.update_bandwidth_usage(packet_info)
                
        except Exception as e:
            print(f"Error processing packet: {e}")
    
    def extract_packet_info(self, packet):
        """Extract relevant information from packet"""
        try:
            packet_info = {
                'id': self.packet_count,
                'timestamp': datetime.now(),
                'size': len(packet),
                'raw_packet': packet
            }
            
            # Extract Ethernet layer
            if Ether in packet:
                packet_info['src_mac'] = packet[Ether].src
                packet_info['dst_mac'] = packet[Ether].dst
                packet_info['ether_type'] = packet[Ether].type
            
            # Extract IP layer
            if IP in packet:
                packet_info['source'] = packet[IP].src
                packet_info['destination'] = packet[IP].dst
                packet_info['protocol'] = packet[IP].proto
                packet_info['ttl'] = packet[IP].ttl
                packet_info['tos'] = packet[IP].tos
                
                # Determine protocol name
                protocol_map = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}
                packet_info['protocol_name'] = protocol_map.get(packet[IP].proto, 'Unknown')
            
            # Extract TCP layer
            if TCP in packet:
                packet_info['src_port'] = packet[TCP].sport
                packet_info['dst_port'] = packet[TCP].dport
                packet_info['flags'] = packet[TCP].flags
                packet_info['seq'] = packet[TCP].seq
                packet_info['ack'] = packet[TCP].ack
                packet_info['window'] = packet[TCP].window
                
            # Extract UDP layer
            if UDP in packet:
                packet_info['src_port'] = packet[UDP].sport
                packet_info['dst_port'] = packet[UDP].dport
                packet_info['length'] = packet[UDP].len
                
            # Extract ICMP layer
            if ICMP in packet:
                packet_info['icmp_type'] = packet[ICMP].type
                packet_info['icmp_code'] = packet[ICMP].code
            
            # Extract ARP layer
            if ARP in packet:
                packet_info['arp_op'] = packet[ARP].op
                packet_info['arp_src_ip'] = packet[ARP].psrc
                packet_info['arp_dst_ip'] = packet[ARP].pdst
                packet_info['arp_src_mac'] = packet[ARP].hwsrc
                packet_info['arp_dst_mac'] = packet[ARP].hwdst
            
            # Determine device type based on IP
            if 'source' in packet_info:
                packet_info['device_type'] = self.get_device_type(packet_info['source'])
            
            return packet_info
            
        except Exception as e:
            print(f"Error extracting packet info: {e}")
            return None
    
    def get_device_type(self, ip):
        """Determine device type based on IP address"""
        try:
            # Check if it's a local IP
            if ip.startswith('192.168.') or ip.startswith('10.') or ip.startswith('172.'):
                # Try to determine device type based on common patterns
                if ip.endswith('.1'):
                    return 'Router/Gateway'
                elif ip.endswith('.254'):
                    return 'Router/Gateway'
                elif any(ip.endswith(f'.{i}') for i in range(2, 10)):
                    return 'Server'
                elif any(ip.endswith(f'.{i}') for i in range(10, 50)):
                    return 'Desktop'
                elif any(ip.endswith(f'.{i}') for i in range(50, 100)):
                    return 'Laptop'
                elif any(ip.endswith(f'.{i}') for i in range(100, 200)):
                    return 'Mobile Device'
                else:
                    return 'IoT Device'
            else:
                return 'External Device'
        except:
            return 'Unknown'
    
    def update_device_info(self, packet_info):
        """Update device information"""
        if 'source' in packet_info:
            ip = packet_info['source']
            if ip not in self.device_info:
                self.device_info[ip] = {
                    'first_seen': packet_info['timestamp'],
                    'last_seen': packet_info['timestamp'],
                    'packet_count': 0,
                    'total_bytes': 0,
                    'protocols': set(),
                    'ports': set(),
                    'mac_address': packet_info.get('src_mac', 'Unknown'),
                    'device_type': packet_info.get('device_type', 'Unknown'),
                    'connection_status': 'active'
                }
            
            device = self.device_info[ip]
            device['last_seen'] = packet_info['timestamp']
            device['packet_count'] += 1
            device['total_bytes'] += packet_info['size']
            
            if 'protocol_name' in packet_info:
                device['protocols'].add(packet_info['protocol_name'])
            if 'src_port' in packet_info:
                device['ports'].add(packet_info['src_port'])
    
    def update_bandwidth_usage(self, packet_info):
        """Update bandwidth usage statistics"""
        if 'source' in packet_info and 'destination' in packet_info:
            src_ip = packet_info['source']
            dst_ip = packet_info['destination']
            size = packet_info['size']
            
            # Update source IP bandwidth
            if src_ip not in self.bandwidth_usage:
                self.bandwidth_usage[src_ip] = {
                    'bytes_sent': 0,
                    'bytes_received': 0,
                    'packets_sent': 0,
                    'packets_received': 0
                }
            
            self.bandwidth_usage[src_ip]['bytes_sent'] += size
            self.bandwidth_usage[src_ip]['packets_sent'] += 1
            
            # Update destination IP bandwidth
            if dst_ip not in self.bandwidth_usage:
                self.bandwidth_usage[dst_ip] = {
                    'bytes_sent': 0,
                    'bytes_received': 0,
                    'packets_sent': 0,
                    'packets_received': 0
                }
            
            self.bandwidth_usage[dst_ip]['bytes_received'] += size
            self.bandwidth_usage[dst_ip]['packets_received'] += 1
    
    def start_sniffing(self, interface_name=None):
        """Start packet sniffing"""
        if not SCAPY_AVAILABLE:
            print("Error: Scapy is required for packet sniffing")
            return False
            
        if not self.select_interface(interface_name):
            print("Error: No suitable network interface found")
            return False
            
        self.is_sniffing = True
        self.packet_count = 0
        self.device_info.clear()
        self.bandwidth_usage.clear()
        
        print(f"Starting packet sniffing on interface: {self.selected_interface['name']}")
        print(f"Interface IP: {self.selected_interface['ip']}")
        print(f"Interface MAC: {self.selected_interface['mac']}")
        
        try:
            # Start sniffing in a separate thread
            sniff_thread = threading.Thread(
                target=self._sniff_packets,
                daemon=True
            )
            sniff_thread.start()
            return True
            
        except Exception as e:
            print(f"Error starting packet sniffing: {e}")
            self.is_sniffing = False
            return False
    
    def _sniff_packets(self):
        """Internal method to sniff packets"""
        try:
            # Use scapy to sniff packets
            sniff(
                iface=self.selected_interface['name'],
                prn=self.packet_handler,
                store=0,  # Don't store packets in memory
                stop_filter=lambda x: not self.is_sniffing
            )
        except Exception as e:
            print(f"Error in packet sniffing: {e}")
            self.is_sniffing = False
    
    def stop_sniffing(self):
        """Stop packet sniffing"""
        self.is_sniffing = False
        print("Packet sniffing stopped")
    
    def get_packet_data(self):
        """Get recent packet data"""
        return list(self.packet_queue)
    
    def get_device_data(self):
        """Get device information"""
        return self.device_info
    
    def get_bandwidth_data(self):
        """Get bandwidth usage data"""
        return self.bandwidth_usage
    
    def get_stats(self):
        """Get overall statistics"""
        return {
            'total_packets': self.packet_count,
            'active_devices': len(self.device_info),
            'is_sniffing': self.is_sniffing,
            'interface': self.selected_interface['name'] if self.selected_interface else None,
            'interface_ip': self.selected_interface['ip'] if self.selected_interface else None
        }

# Test the packet sniffer
if __name__ == "__main__":
    sniffer = RealPacketSniffer()
    
    print("Available Network Interfaces:")
    for i, interface in enumerate(sniffer.network_interfaces):
        print(f"{i+1}. {interface['name']} - {interface['ip']} ({interface['mac']})")
    
    if sniffer.network_interfaces:
        print(f"\nStarting packet sniffing on {sniffer.network_interfaces[0]['name']}...")
        sniffer.start_sniffing()
        
        try:
            while True:
                time.sleep(5)
                stats = sniffer.get_stats()
                print(f"Packets captured: {stats['total_packets']}, Devices: {stats['active_devices']}")
        except KeyboardInterrupt:
            sniffer.stop_sniffing()
            print("Packet sniffing stopped by user")
    else:
        print("No network interfaces found!")
