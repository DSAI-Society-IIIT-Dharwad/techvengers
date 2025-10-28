#!/usr/bin/env python3
"""
Real-time Threat Injector
Injects threats into the running desktop application for live demonstration
"""

import time
import random
import threading
from datetime import datetime
import sys
import os

# Add the current directory to Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from network_dashboard_desktop import NetworkMonitor, RealTimeMLManager

class ThreatInjector:
    """Inject threats into the network monitoring system"""
    
    def __init__(self, network_monitor):
        self.network_monitor = network_monitor
        self.injection_active = False
        self.threat_types = [
            "ddos_attack",
            "port_scan", 
            "external_communication",
            "massive_packet",
            "suspicious_protocol"
        ]
    
    def inject_ddos_attack(self):
        """Inject DDoS attack packets"""
        for i in range(10):
            packet = {
                'id': f"ddos_{i}",
                'timestamp': datetime.now(),
                'source': f"192.168.1.{random.randint(200, 254)}",
                'destination': '192.168.1.1',
                'protocol': 'UDP',
                'port': random.randint(49152, 65535),
                'size': random.randint(1500, 2000),
                'protocol_num': 2,
                'flags': 0
            }
            self.network_monitor.packet_queue.put(packet)
            time.sleep(0.1)
    
    def inject_port_scan(self):
        """Inject port scanning packets"""
        for port in [22, 23, 25, 53, 80, 110, 135, 139, 443, 993]:
            packet = {
                'id': f"scan_{port}",
                'timestamp': datetime.now(),
                'source': '192.168.1.250',
                'destination': '192.168.1.1',
                'protocol': 'TCP',
                'port': port,
                'size': random.randint(20, 40),
                'protocol_num': 1,
                'flags': 2
            }
            self.network_monitor.packet_queue.put(packet)
            time.sleep(0.2)
    
    def inject_external_communication(self):
        """Inject external communication packets"""
        external_ips = ['8.8.8.8', '1.1.1.1', '208.67.222.222', '9.9.9.9']
        for i in range(5):
            packet = {
                'id': f"external_{i}",
                'timestamp': datetime.now(),
                'source': random.choice(external_ips),
                'destination': f"192.168.1.{random.randint(100, 150)}",
                'protocol': 'TCP',
                'port': random.choice([80, 443, 22, 25]),
                'size': random.randint(500, 1500),
                'protocol_num': 1,
                'flags': 0
            }
            self.network_monitor.packet_queue.put(packet)
            time.sleep(0.3)
    
    def inject_massive_packet(self):
        """Inject massive packets"""
        for i in range(3):
            packet = {
                'id': f"massive_{i}",
                'timestamp': datetime.now(),
                'source': f"192.168.1.{random.randint(10, 50)}",
                'destination': f"192.168.1.{random.randint(51, 100)}",
                'protocol': 'TCP',
                'port': random.choice([80, 443]),
                'size': random.randint(10000, 50000),
                'protocol_num': 1,
                'flags': 0
            }
            self.network_monitor.packet_queue.put(packet)
            time.sleep(0.5)
    
    def inject_suspicious_protocol(self):
        """Inject suspicious protocol packets"""
        for i in range(5):
            packet = {
                'id': f"suspicious_{i}",
                'timestamp': datetime.now(),
                'source': f"192.168.1.{random.randint(1, 50)}",
                'destination': f"192.168.1.{random.randint(51, 100)}",
                'protocol': 'ICMP',
                'port': 0,
                'size': random.randint(32, 64),
                'protocol_num': 3,
                'flags': 0
            }
            self.network_monitor.packet_queue.put(packet)
            time.sleep(0.2)
    
    def start_threat_injection(self):
        """Start injecting threats periodically"""
        self.injection_active = True
        print("Starting threat injection...")
        
        while self.injection_active:
            threat_type = random.choice(self.threat_types)
            
            print(f"Injecting {threat_type}...")
            
            if threat_type == "ddos_attack":
                self.inject_ddos_attack()
            elif threat_type == "port_scan":
                self.inject_port_scan()
            elif threat_type == "external_communication":
                self.inject_external_communication()
            elif threat_type == "massive_packet":
                self.inject_massive_packet()
            elif threat_type == "suspicious_protocol":
                self.inject_suspicious_protocol()
            
            # Wait before next injection
            time.sleep(random.randint(5, 15))
    
    def stop_threat_injection(self):
        """Stop threat injection"""
        self.injection_active = False
        print("Threat injection stopped.")

def main():
    """Main function for standalone threat injection"""
    print("=" * 50)
    print("REAL-TIME THREAT INJECTOR")
    print("=" * 50)
    print("This script injects threats into the network monitoring system.")
    print("Make sure the desktop application is running first!")
    print("=" * 50)
    
    # Create network monitor
    ml_manager = RealTimeMLManager()
    network_monitor = NetworkMonitor(ml_manager)
    
    # Create threat injector
    injector = ThreatInjector(network_monitor)
    
    try:
        print("Starting threat injection in 3 seconds...")
        time.sleep(3)
        
        # Start threat injection in a separate thread
        injection_thread = threading.Thread(target=injector.start_threat_injection)
        injection_thread.daemon = True
        injection_thread.start()
        
        print("Threat injection started! Press Ctrl+C to stop.")
        
        # Keep the main thread alive
        while True:
            time.sleep(1)
            
    except KeyboardInterrupt:
        print("\nStopping threat injection...")
        injector.stop_threat_injection()
        print("Threat injection stopped.")

if __name__ == "__main__":
    main()
