#!/usr/bin/env python3
"""
Network Interface Checker
========================

This script checks available network interfaces and tests basic packet capture functionality.
"""

try:
    from scapy.all import get_if_list, sniff, conf
    print("Scapy imported successfully")
except ImportError as e:
    print(f"Error importing scapy: {e}")
    exit(1)

def check_interfaces():
    """Check available network interfaces."""
    print("\nChecking available network interfaces...")
    try:
        interfaces = get_if_list()
        if interfaces:
            print("Available interfaces:")
            for i, interface in enumerate(interfaces):
                print(f"  {i}: {interface}")
            return interfaces
        else:
            print("No interfaces found")
            return []
    except Exception as e:
        print(f"Error getting interfaces: {e}")
        return []

def test_packet_capture():
    """Test basic packet capture functionality."""
    print("\nTesting packet capture...")
    
    try:
        # Test if we can create a sniff object
        print("Testing sniff functionality...")
        
        # Try to sniff just 1 packet with a timeout
        packets = sniff(count=1, timeout=3)
        
        if packets:
            print(f"Successfully captured {len(packets)} packet(s)")
            for packet in packets:
                print(f"   Packet: {packet.summary()}")
            return True
        else:
            print("No packets captured (this might be normal)")
            return False
            
    except Exception as e:
        print(f"Packet capture test failed: {e}")
        return False

def check_npcap():
    """Check if Npcap is available."""
    print("\nChecking Npcap availability...")
    
    try:
        # Check if we can access layer 2
        if hasattr(conf, 'L2socket'):
            print("Layer 2 socket available")
            return True
        else:
            print("Layer 2 socket not available")
            return False
    except Exception as e:
        print(f"Error checking Npcap: {e}")
        return False

def main():
    """Main function."""
    print("Network Interface and Packet Capture Checker")
    print("=" * 50)
    
    # Check interfaces
    interfaces = check_interfaces()
    
    # Check Npcap
    npcap_available = check_npcap()
    
    # Test packet capture
    capture_works = test_packet_capture()
    
    # Summary
    print("\n" + "=" * 50)
    print("SUMMARY")
    print("=" * 50)
    print(f"Interfaces found: {len(interfaces) if interfaces else 0}")
    print(f"Npcap available: {'Yes' if npcap_available else 'No'}")
    print(f"Packet capture: {'Working' if capture_works else 'Not working'}")
    
    if not npcap_available:
        print("\nSOLUTION:")
        print("1. Download Npcap from: https://nmap.org/npcap/")
        print("2. Install Npcap (run installer as Administrator)")
        print("3. Restart your computer")
        print("4. Run this script again as Administrator")
    elif not capture_works:
        print("\nSOLUTION:")
        print("1. Run this script as Administrator")
        print("2. Check Windows Firewall settings")
        print("3. Try specifying a specific interface")

if __name__ == "__main__":
    main()
