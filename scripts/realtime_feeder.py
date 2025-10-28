#!/usr/bin/env python3
"""
Real-Time Packet Feeder for Streaming Analysis
==============================================

This module feeds live packet data from the packet sniffer into the streaming analyzer.
"""

import time
import threading
from datetime import datetime
from typing import Dict, Any
from streaming_analyzer import StreamingPacketProcessor
from working_packet_sniffer import WorkingPacketSniffer


class RealTimePacketFeeder:
    """
    Feeds real-time packet data to the streaming analyzer.
    """
    
    def __init__(self, 
                 analyzer: StreamingPacketProcessor,
                 capture_interval: float = 2.0,
                 packets_per_capture: int = 20):
        """
        Initialize the packet feeder.
        
        Args:
            analyzer: Streaming analyzer instance
            capture_interval: Seconds between packet captures
            packets_per_capture: Number of packets to capture each time
        """
        self.analyzer = analyzer
        self.capture_interval = capture_interval
        self.packets_per_capture = packets_per_capture
        self.running = False
        self.capture_thread = None
        
    def start_feeding(self):
        """Start feeding packets to the analyzer."""
        if self.running:
            print("Packet feeder already running!")
            return
        
        self.running = True
        self.capture_thread = threading.Thread(target=self._capture_loop, daemon=True)
        self.capture_thread.start()
        print(f"Started packet feeder (interval: {self.capture_interval}s, packets: {self.packets_per_capture})")
    
    def stop_feeding(self):
        """Stop feeding packets."""
        self.running = False
        if self.capture_thread:
            self.capture_thread.join()
        print("Stopped packet feeder")
    
    def _capture_loop(self):
        """Main capture loop."""
        while self.running:
            try:
                # Capture packets using the working sniffer
                packets = self._capture_packets()
                
                # Feed packets to analyzer
                for packet in packets:
                    self.analyzer.add_packet(packet)
                
                # Wait for next capture
                time.sleep(self.capture_interval)
                
            except Exception as e:
                print(f"Error in capture loop: {e}")
                time.sleep(1)
    
    def _capture_packets(self) -> list:
        """Capture packets using the working sniffer."""
        try:
            # Use the psutil method from working sniffer
            import psutil
            
            packets = []
            connections = psutil.net_connections(kind='inet')
            
            # Take a sample of connections
            sample_size = min(self.packets_per_capture, len(connections))
            sampled_connections = connections[:sample_size]
            
            for conn in sampled_connections:
                if conn.laddr and conn.raddr:
                    packet_data = {
                        'source_ip': conn.laddr.ip,
                        'destination_ip': conn.raddr.ip,
                        'destination_port': conn.raddr.port,
                        'source_port': conn.laddr.port,
                        'protocol': conn.type.name if conn.type else 'TCP',
                        'packet_length': 64,  # Default size
                        'timestamp': datetime.now().isoformat()
                    }
                    packets.append(packet_data)
            
            return packets
            
        except Exception as e:
            print(f"Error capturing packets: {e}")
            return []


def main():
    """Main function to run real-time streaming analysis."""
    print("Real-Time Network Traffic Streaming Analysis")
    print("=" * 60)
    
    # Create streaming analyzer
    analyzer = StreamingPacketProcessor(
        window_size=30,  # Analyze every 30 packets
        update_interval=5.0,  # Check every 5 seconds
        baseline_period=6  # Build baseline from 6 windows
    )
    
    # Create packet feeder
    feeder = RealTimePacketFeeder(
        analyzer=analyzer,
        capture_interval=3.0,  # Capture every 3 seconds
        packets_per_capture=15  # Capture 15 packets each time
    )
    
    # Start the system
    analyzer.start_processing()
    feeder.start_feeding()
    
    try:
        print("\nReal-time streaming analysis started!")
        print("The system will:")
        print("1. Capture live network packets")
        print("2. Build a baseline from normal traffic")
        print("3. Detect anomalies in real-time")
        print("4. Generate alerts for suspicious activity")
        print("\nPress Ctrl+C to stop...")
        
        # Monitor the system
        while True:
            time.sleep(10)
            analyzer.print_statistics()
            
    except KeyboardInterrupt:
        print("\nStopping real-time analysis...")
        feeder.stop_feeding()
        analyzer.stop_processing()
        
        # Final statistics
        analyzer.print_statistics()
        
        print(f"\nStreaming alerts saved to: {analyzer.alert_file}")
        print("Real-time analysis complete!")


if __name__ == "__main__":
    main()
