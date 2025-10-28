#!/usr/bin/env python3
"""
Network Traffic Analyzer - Part 3: Visualization Dashboard
=========================================================

Real-time interactive dashboard for monitoring network traffic and security alerts.
Built with Streamlit for easy deployment and interaction.

Features:
- Live metrics display
- Packet traffic visualization
- Security alerts table
- GeoIP mapping
- Auto-refresh functionality
"""

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import numpy as np
import time
import os
from datetime import datetime, timedelta
import requests
import json
from typing import Dict, List, Tuple, Optional
import warnings
warnings.filterwarnings('ignore')

# Page configuration
st.set_page_config(
    page_title="Network Traffic Analyzer",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for better styling
st.markdown("""
<style>
    .main-header {
        font-size: 3rem;
        font-weight: bold;
        text-align: center;
        color: #1f77b4;
        margin-bottom: 2rem;
    }
    .metric-card {
        background-color: #f0f2f6;
        padding: 1rem;
        border-radius: 0.5rem;
        border-left: 4px solid #1f77b4;
    }
    .alert-high {
        background-color: #ffebee;
        border-left: 4px solid #f44336;
        padding: 0.5rem;
        margin: 0.25rem 0;
    }
    .alert-medium {
        background-color: #fff3e0;
        border-left: 4px solid #ff9800;
        padding: 0.5rem;
        margin: 0.25rem 0;
    }
    .alert-low {
        background-color: #e8f5e8;
        border-left: 4px solid #4caf50;
        padding: 0.5rem;
        margin: 0.25rem 0;
    }
</style>
""", unsafe_allow_html=True)


class NetworkDashboard:
    """Main dashboard class for network traffic visualization."""
    
    def __init__(self):
        self.packets_file = "data/packets_extended.csv"
        self.alerts_file = "data/alerts.csv"
        self.streaming_alerts_file = "data/streaming_alerts.csv"
        self.cache_duration = 5  # seconds
        
    def load_packet_data(self) -> pd.DataFrame:
        """Load packet data from CSV file."""
        try:
            if os.path.exists(self.packets_file):
                df = pd.read_csv(self.packets_file)
                df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
                return df
            else:
                return pd.DataFrame()
        except Exception as e:
            st.error(f"Error loading packet data: {e}")
            return pd.DataFrame()
    
    def load_alerts_data(self) -> pd.DataFrame:
        """Load alerts data from CSV files."""
        alerts_dfs = []
        
        # Load regular alerts
        if os.path.exists(self.alerts_file):
            try:
                alerts_df = pd.read_csv(self.alerts_file)
                alerts_df['timestamp'] = pd.to_datetime(alerts_df['timestamp'], errors='coerce')
                alerts_dfs.append(alerts_df)
            except Exception as e:
                st.warning(f"Error loading alerts: {e}")
        
        # Load streaming alerts
        if os.path.exists(self.streaming_alerts_file):
            try:
                streaming_df = pd.read_csv(self.streaming_alerts_file)
                streaming_df['timestamp'] = pd.to_datetime(streaming_df['timestamp'], errors='coerce')
                alerts_dfs.append(streaming_df)
            except Exception as e:
                st.warning(f"Error loading streaming alerts: {e}")
        
        if alerts_dfs:
            combined_df = pd.concat(alerts_dfs, ignore_index=True)
            combined_df = combined_df.sort_values('timestamp', ascending=False)
            return combined_df
        else:
            return pd.DataFrame()
    
    def get_geoip_info(self, ip_address: str) -> Dict[str, str]:
        """Get geographic information for an IP address."""
        try:
            # Use ipinfo.io free API (rate limited but good for demo)
            response = requests.get(f"https://ipinfo.io/{ip_address}/json", timeout=2)
            if response.status_code == 200:
                data = response.json()
                return {
                    'country': data.get('country', 'Unknown'),
                    'city': data.get('city', 'Unknown'),
                    'region': data.get('region', 'Unknown'),
                    'org': data.get('org', 'Unknown')
                }
        except:
            pass
        
        return {
            'country': 'Unknown',
            'city': 'Unknown', 
            'region': 'Unknown',
            'org': 'Unknown'
        }
    
    def calculate_metrics(self, packets_df: pd.DataFrame, alerts_df: pd.DataFrame) -> Dict[str, any]:
        """Calculate key metrics from the data."""
        if packets_df.empty:
            return {
                'total_packets': 0,
                'unique_devices': 0,
                'active_alerts': 0,
                'packets_per_second': 0,
                'total_bytes': 0,
                'protocol_distribution': {},
                'top_source_ips': [],
                'recent_alerts': []
            }
        
        # Basic metrics
        total_packets = len(packets_df)
        unique_devices = packets_df['source_ip'].nunique()
        
        # Active alerts (last 24 hours)
        if not alerts_df.empty:
            recent_time = datetime.now() - timedelta(hours=24)
            recent_alerts = alerts_df[alerts_df['timestamp'] >= recent_time]
            active_alerts = len(recent_alerts)
        else:
            active_alerts = 0
        
        # Calculate packets per second
        if not packets_df.empty and len(packets_df) > 1:
            time_span = (packets_df['timestamp'].max() - packets_df['timestamp'].min()).total_seconds()
            packets_per_second = total_packets / time_span if time_span > 0 else 0
        else:
            packets_per_second = 0
        
        # Total bytes
        total_bytes = packets_df['packet_length'].sum() if 'packet_length' in packets_df.columns else 0
        
        # Protocol distribution
        protocol_distribution = packets_df['protocol'].value_counts().to_dict()
        
        # Top source IPs by packet count
        top_source_ips = packets_df['source_ip'].value_counts().head(10).to_dict()
        
        # Recent alerts
        recent_alerts = alerts_df.head(10).to_dict('records') if not alerts_df.empty else []
        
        return {
            'total_packets': total_packets,
            'unique_devices': unique_devices,
            'active_alerts': active_alerts,
            'packets_per_second': packets_per_second,
            'total_bytes': total_bytes,
            'protocol_distribution': protocol_distribution,
            'top_source_ips': top_source_ips,
            'recent_alerts': recent_alerts
        }
    
    def create_packet_traffic_chart(self, packets_df: pd.DataFrame) -> go.Figure:
        """Create a line chart showing packet traffic over time."""
        if packets_df.empty:
            fig = go.Figure()
            fig.add_annotation(
                text="No packet data available",
                xref="paper", yref="paper",
                x=0.5, y=0.5, showarrow=False,
                font=dict(size=16)
            )
            return fig
        
        # Group by minute for better visualization
        packets_df['minute'] = packets_df['timestamp'].dt.floor('min')
        traffic_by_minute = packets_df.groupby('minute').size().reset_index(name='packet_count')
        
        fig = go.Figure()
        fig.add_trace(go.Scatter(
            x=traffic_by_minute['minute'],
            y=traffic_by_minute['packet_count'],
            mode='lines+markers',
            name='Packets per Minute',
            line=dict(color='#1f77b4', width=2),
            marker=dict(size=6)
        ))
        
        fig.update_layout(
            title="Packet Traffic Over Time",
            xaxis_title="Time",
            yaxis_title="Packets per Minute",
            hovermode='x unified',
            height=400
        )
        
        return fig
    
    def create_protocol_distribution_chart(self, protocol_data: Dict[str, int]) -> go.Figure:
        """Create a pie chart showing protocol distribution."""
        if not protocol_data:
            fig = go.Figure()
            fig.add_annotation(
                text="No protocol data available",
                xref="paper", yref="paper",
                x=0.5, y=0.5, showarrow=False,
                font=dict(size=16)
            )
            return fig
        
        fig = go.Figure(data=[go.Pie(
            labels=list(protocol_data.keys()),
            values=list(protocol_data.values()),
            hole=0.3
        )])
        
        fig.update_layout(
            title="Traffic Distribution by Protocol",
            height=400
        )
        
        return fig
    
    def create_top_ips_chart(self, ip_data: Dict[str, int]) -> go.Figure:
        """Create a bar chart showing top source IPs."""
        if not ip_data:
            fig = go.Figure()
            fig.add_annotation(
                text="No IP data available",
                xref="paper", yref="paper",
                x=0.5, y=0.5, showarrow=False,
                font=dict(size=16)
            )
            return fig
        
        fig = go.Figure(data=[
            go.Bar(
                x=list(ip_data.keys()),
                y=list(ip_data.values()),
                marker_color='#1f77b4'
            )
        ])
        
        fig.update_layout(
            title="Top Source IPs by Packet Count",
            xaxis_title="Source IP",
            yaxis_title="Packet Count",
            height=400
        )
        
        return fig
    
    def display_alerts_table(self, alerts_data: List[Dict]) -> None:
        """Display alerts in a formatted table."""
        if not alerts_data:
            st.info("No alerts found.")
            return
        
        st.subheader("🚨 Latest Security Alerts")
        
        for alert in alerts_data:
            risk_level = alert.get('risk_level', 'UNKNOWN')
            timestamp = alert.get('timestamp', 'Unknown')
            source_ip = alert.get('source_ip', 'Unknown')
            destination_ip = alert.get('destination_ip', 'Unknown')
            reason = alert.get('reason', 'Unknown')
            score = alert.get('anomaly_score', 0)
            
            # Format timestamp
            if isinstance(timestamp, str):
                try:
                    dt = pd.to_datetime(timestamp)
                    formatted_time = dt.strftime("%H:%M:%S")
                except:
                    formatted_time = timestamp
            else:
                formatted_time = str(timestamp)
            
            # Choose alert style based on risk level
            if risk_level == 'HIGH':
                alert_class = 'alert-high'
                risk_icon = '🔴'
            elif risk_level == 'MEDIUM':
                alert_class = 'alert-medium'
                risk_icon = '🟡'
            else:
                alert_class = 'alert-low'
                risk_icon = '🟢'
            
            # Display alert
            st.markdown(f"""
            <div class="{alert_class}">
                <strong>{risk_icon} {risk_level} RISK</strong> - {formatted_time}<br>
                <strong>Source:</strong> {source_ip} → <strong>Destination:</strong> {destination_ip}<br>
                <strong>Reason:</strong> {reason}<br>
                <strong>Score:</strong> {score:.3f}
            </div>
            """, unsafe_allow_html=True)
    
    def run_dashboard(self):
        """Main dashboard function."""
        # Header
        st.markdown('<h1 class="main-header">🛡️ Home Network Security Dashboard</h1>', unsafe_allow_html=True)
        
        # Sidebar controls
        st.sidebar.header("Dashboard Controls")
        auto_refresh = st.sidebar.checkbox("Auto-refresh (5s)", value=True)
        refresh_interval = st.sidebar.slider("Refresh interval (seconds)", 1, 30, 5)
        
        if auto_refresh:
            time.sleep(refresh_interval)
            st.rerun()
        
        # Load data
        with st.spinner("Loading data..."):
            packets_df = self.load_packet_data()
            alerts_df = self.load_alerts_data()
            metrics = self.calculate_metrics(packets_df, alerts_df)
        
        # Metrics cards
        st.subheader("📊 Network Overview")
        
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric(
                label="Total Packets",
                value=f"{metrics['total_packets']:,}",
                delta=None
            )
        
        with col2:
            st.metric(
                label="Active Devices",
                value=metrics['unique_devices'],
                delta=None
            )
        
        with col3:
            st.metric(
                label="Active Alerts",
                value=metrics['active_alerts'],
                delta=None
            )
        
        with col4:
            st.metric(
                label="Packets/sec",
                value=f"{metrics['packets_per_second']:.1f}",
                delta=None
            )
        
        # Charts section
        st.subheader("📈 Network Traffic Analysis")
        
        col1, col2 = st.columns(2)
        
        with col1:
            traffic_chart = self.create_packet_traffic_chart(packets_df)
            st.plotly_chart(traffic_chart, use_container_width=True)
        
        with col2:
            protocol_chart = self.create_protocol_distribution_chart(metrics['protocol_distribution'])
            st.plotly_chart(protocol_chart, use_container_width=True)
        
        # Top IPs chart
        st.subheader("🌐 Top Source IPs")
        top_ips_chart = self.create_top_ips_chart(metrics['top_source_ips'])
        st.plotly_chart(top_ips_chart, use_container_width=True)
        
        # Alerts section
        st.subheader("🚨 Security Alerts")
        self.display_alerts_table(metrics['recent_alerts'])
        
        # Data summary
        with st.expander("📋 Data Summary"):
            st.write(f"**Last Updated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            st.write(f"**Packet Data:** {len(packets_df)} records")
            st.write(f"**Alert Data:** {len(alerts_df)} records")
            st.write(f"**Total Bytes:** {metrics['total_bytes']:,} bytes")
            
            if not packets_df.empty:
                st.write(f"**Time Range:** {packets_df['timestamp'].min()} to {packets_df['timestamp'].max()}")


def main():
    """Main function to run the dashboard."""
    dashboard = NetworkDashboard()
    dashboard.run_dashboard()


if __name__ == "__main__":
    main()
