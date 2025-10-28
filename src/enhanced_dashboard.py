#!/usr/bin/env python3
"""
Network Traffic Analyzer - Part 3: Enhanced Visualization Dashboard
================================================================

Real-time interactive dashboard with GeoIP mapping and world map visualization.
Built with Streamlit and Plotly for comprehensive network monitoring.

Features:
- Live metrics display
- Packet traffic visualization
- Security alerts table
- GeoIP mapping with world map
- Auto-refresh functionality
- Real-time threat detection
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
        border-radius: 0.25rem;
    }
    .alert-medium {
        background-color: #fff3e0;
        border-left: 4px solid #ff9800;
        padding: 0.5rem;
        margin: 0.25rem 0;
        border-radius: 0.25rem;
    }
    .alert-low {
        background-color: #e8f5e8;
        border-left: 4px solid #4caf50;
        padding: 0.5rem;
        margin: 0.25rem 0;
        border-radius: 0.25rem;
    }
    .threat-indicator {
        background-color: #ffcdd2;
        border: 2px solid #f44336;
        padding: 1rem;
        border-radius: 0.5rem;
        margin: 1rem 0;
        text-align: center;
    }
    .status-good {
        color: #4caf50;
        font-weight: bold;
    }
    .status-warning {
        color: #ff9800;
        font-weight: bold;
    }
    .status-danger {
        color: #f44336;
        font-weight: bold;
    }
</style>
""", unsafe_allow_html=True)


class EnhancedNetworkDashboard:
    """Enhanced dashboard class with GeoIP mapping and advanced visualizations."""
    
    def __init__(self):
        self.packets_file = "data/packets_extended.csv"
        self.alerts_file = "data/alerts.csv"
        self.streaming_alerts_file = "data/streaming_alerts.csv"
        self.cache_duration = 5  # seconds
        self.geoip_cache = {}  # Cache for GeoIP lookups
        
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
        """Get geographic information for an IP address with caching."""
        if ip_address in self.geoip_cache:
            return self.geoip_cache[ip_address]
        
        # Skip local/private IPs
        if ip_address.startswith(('10.', '172.16.', '192.168.', '127.0.0.1')):
            result = {
                'country': 'Local',
                'city': 'Local Network',
                'region': 'Private',
                'org': 'Local Network',
                'lat': 0,
                'lon': 0
            }
            self.geoip_cache[ip_address] = result
            return result
        
        try:
            # Use ipinfo.io free API
            response = requests.get(f"https://ipinfo.io/{ip_address}/json", timeout=3)
            if response.status_code == 200:
                data = response.json()
                
                # Parse coordinates if available
                lat, lon = 0, 0
                if 'loc' in data:
                    try:
                        lat, lon = map(float, data['loc'].split(','))
                    except:
                        pass
                
                result = {
                    'country': data.get('country', 'Unknown'),
                    'city': data.get('city', 'Unknown'),
                    'region': data.get('region', 'Unknown'),
                    'org': data.get('org', 'Unknown'),
                    'lat': lat,
                    'lon': lon
                }
                self.geoip_cache[ip_address] = result
                return result
        except Exception as e:
            st.warning(f"GeoIP lookup failed for {ip_address}: {e}")
        
        # Default result
        result = {
            'country': 'Unknown',
            'city': 'Unknown',
            'region': 'Unknown',
            'org': 'Unknown',
            'lat': 0,
            'lon': 0
        }
        self.geoip_cache[ip_address] = result
        return result
    
    def calculate_enhanced_metrics(self, packets_df: pd.DataFrame, alerts_df: pd.DataFrame) -> Dict[str, any]:
        """Calculate enhanced metrics including GeoIP data."""
        if packets_df.empty:
            return {
                'total_packets': 0,
                'unique_devices': 0,
                'active_alerts': 0,
                'packets_per_second': 0,
                'total_bytes': 0,
                'protocol_distribution': {},
                'top_source_ips': [],
                'recent_alerts': [],
                'geoip_data': [],
                'threat_level': 'LOW',
                'external_connections': 0,
                'suspicious_countries': []
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
        
        # GeoIP analysis
        unique_dest_ips = packets_df['destination_ip'].unique()
        geoip_data = []
        external_connections = 0
        suspicious_countries = []
        
        for ip in unique_dest_ips[:20]:  # Limit to first 20 for performance
            geo_info = self.get_geoip_info(ip)
            if geo_info['country'] != 'Local':
                external_connections += 1
                geoip_data.append({
                    'ip': ip,
                    'country': geo_info['country'],
                    'city': geo_info['city'],
                    'org': geo_info['org'],
                    'lat': geo_info['lat'],
                    'lon': geo_info['lon'],
                    'packet_count': packets_df[packets_df['destination_ip'] == ip].shape[0]
                })
                
                # Check for suspicious countries (simplified heuristic)
                if geo_info['country'] in ['CN', 'RU', 'KP', 'IR']:  # Example suspicious countries
                    suspicious_countries.append(geo_info['country'])
        
        # Determine threat level
        threat_level = 'LOW'
        if active_alerts > 10:
            threat_level = 'HIGH'
        elif active_alerts > 5:
            threat_level = 'MEDIUM'
        elif len(suspicious_countries) > 0:
            threat_level = 'MEDIUM'
        
        return {
            'total_packets': total_packets,
            'unique_devices': unique_devices,
            'active_alerts': active_alerts,
            'packets_per_second': packets_per_second,
            'total_bytes': total_bytes,
            'protocol_distribution': protocol_distribution,
            'top_source_ips': top_source_ips,
            'recent_alerts': recent_alerts,
            'geoip_data': geoip_data,
            'threat_level': threat_level,
            'external_connections': external_connections,
            'suspicious_countries': suspicious_countries
        }
    
    def create_world_map(self, geoip_data: List[Dict]) -> go.Figure:
        """Create a world map showing connection locations."""
        if not geoip_data:
            fig = go.Figure()
            fig.add_annotation(
                text="No external connections found",
                xref="paper", yref="paper",
                x=0.5, y=0.5, showarrow=False,
                font=dict(size=16)
            )
            return fig
        
        # Prepare data for plotting
        countries = [item['country'] for item in geoip_data]
        cities = [item['city'] for item in geoip_data]
        lats = [item['lat'] for item in geoip_data if item['lat'] != 0]
        lons = [item['lon'] for item in geoip_data if item['lon'] != 0]
        packet_counts = [item['packet_count'] for item in geoip_data if item['lat'] != 0]
        
        if not lats:  # No valid coordinates
            fig = go.Figure()
            fig.add_annotation(
                text="No valid geographic coordinates found",
                xref="paper", yref="paper",
                x=0.5, y=0.5, showarrow=False,
                font=dict(size=16)
            )
            return fig
        
        fig = go.Figure(data=go.Scattergeo(
            lon=lons,
            lat=lats,
            text=[f"{countries[i]}: {packet_counts[i]} packets" for i in range(len(lats))],
            mode='markers',
            marker=dict(
                size=[max(5, min(20, count/10)) for count in packet_counts],
                color=packet_counts,
                colorscale='Reds',
                showscale=True,
                colorbar=dict(title="Packet Count")
            )
        ))
        
        fig.update_layout(
            title="Network Connections by Geographic Location",
            geo=dict(
                scope='world',
                showland=True,
                landcolor='rgb(243, 243, 243)',
                countrycolor='rgb(204, 204, 204)',
                showlakes=True,
                lakecolor='rgb(255, 255, 255)',
                showocean=True,
                oceancolor='rgb(230, 245, 255)'
            ),
            height=500
        )
        
        return fig
    
    def create_threat_analysis_chart(self, metrics: Dict) -> go.Figure:
        """Create a threat analysis chart."""
        threat_data = {
            'Active Alerts': metrics['active_alerts'],
            'External Connections': metrics['external_connections'],
            'Suspicious Countries': len(metrics['suspicious_countries']),
            'High Risk IPs': len([ip for ip, count in metrics['top_source_ips'].items() if count > 100])
        }
        
        fig = go.Figure(data=[
            go.Bar(
                x=list(threat_data.keys()),
                y=list(threat_data.values()),
                marker_color=['#f44336', '#ff9800', '#ff5722', '#e91e63']
            )
        ])
        
        fig.update_layout(
            title="Threat Analysis Overview",
            xaxis_title="Threat Indicators",
            yaxis_title="Count",
            height=400
        )
        
        return fig
    
    def display_threat_status(self, threat_level: str, metrics: Dict) -> None:
        """Display current threat status."""
        if threat_level == 'HIGH':
            status_class = 'status-danger'
            status_icon = '🔴'
            status_text = 'HIGH THREAT LEVEL'
        elif threat_level == 'MEDIUM':
            status_class = 'status-warning'
            status_icon = '🟡'
            status_text = 'MEDIUM THREAT LEVEL'
        else:
            status_class = 'status-good'
            status_icon = '🟢'
            status_text = 'LOW THREAT LEVEL'
        
        st.markdown(f"""
        <div class="threat-indicator">
            <h2>{status_icon} <span class="{status_class}">{status_text}</span></h2>
            <p>Active Alerts: {metrics['active_alerts']} | External Connections: {metrics['external_connections']}</p>
        </div>
        """, unsafe_allow_html=True)
    
    def run_enhanced_dashboard(self):
        """Main enhanced dashboard function."""
        # Header
        st.markdown('<h1 class="main-header">🛡️ Enhanced Network Security Dashboard</h1>', unsafe_allow_html=True)
        
        # Sidebar controls
        st.sidebar.header("Dashboard Controls")
        auto_refresh = st.sidebar.checkbox("Auto-refresh (5s)", value=True)
        refresh_interval = st.sidebar.slider("Refresh interval (seconds)", 1, 30, 5)
        show_geoip = st.sidebar.checkbox("Show GeoIP Analysis", value=True)
        
        if auto_refresh:
            time.sleep(refresh_interval)
            st.rerun()
        
        # Load data
        with st.spinner("Loading data..."):
            packets_df = self.load_packet_data()
            alerts_df = self.load_alerts_data()
            metrics = self.calculate_enhanced_metrics(packets_df, alerts_df)
        
        # Threat status
        self.display_threat_status(metrics['threat_level'], metrics)
        
        # Metrics cards
        st.subheader("📊 Network Overview")
        
        col1, col2, col3, col4, col5 = st.columns(5)
        
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
                label="External Connections",
                value=metrics['external_connections'],
                delta=None
            )
        
        with col5:
            st.metric(
                label="Packets/sec",
                value=f"{metrics['packets_per_second']:.1f}",
                delta=None
            )
        
        # Charts section
        st.subheader("📈 Network Traffic Analysis")
        
        col1, col2 = st.columns(2)
        
        with col1:
            # Packet traffic over time
            if not packets_df.empty:
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
                    height=400
                )
                st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            # Protocol distribution
            if metrics['protocol_distribution']:
                fig = go.Figure(data=[go.Pie(
                    labels=list(metrics['protocol_distribution'].keys()),
                    values=list(metrics['protocol_distribution'].values()),
                    hole=0.3
                )])
                
                fig.update_layout(
                    title="Traffic Distribution by Protocol",
                    height=400
                )
                st.plotly_chart(fig, use_container_width=True)
        
        # GeoIP and threat analysis
        if show_geoip:
            st.subheader("🌍 Geographic Analysis")
            
            col1, col2 = st.columns(2)
            
            with col1:
                world_map = self.create_world_map(metrics['geoip_data'])
                st.plotly_chart(world_map, use_container_width=True)
            
            with col2:
                threat_chart = self.create_threat_analysis_chart(metrics)
                st.plotly_chart(threat_chart, use_container_width=True)
        
        # Top IPs chart
        st.subheader("🌐 Top Source IPs")
        if metrics['top_source_ips']:
            fig = go.Figure(data=[
                go.Bar(
                    x=list(metrics['top_source_ips'].keys()),
                    y=list(metrics['top_source_ips'].values()),
                    marker_color='#1f77b4'
                )
            ])
            
            fig.update_layout(
                title="Top Source IPs by Packet Count",
                xaxis_title="Source IP",
                yaxis_title="Packet Count",
                height=400
            )
            st.plotly_chart(fig, use_container_width=True)
        
        # Alerts section
        st.subheader("🚨 Security Alerts")
        if metrics['recent_alerts']:
            for alert in metrics['recent_alerts']:
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
        else:
            st.info("No alerts found.")
        
        # Data summary
        with st.expander("📋 Data Summary"):
            st.write(f"**Last Updated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            st.write(f"**Packet Data:** {len(packets_df)} records")
            st.write(f"**Alert Data:** {len(alerts_df)} records")
            st.write(f"**Total Bytes:** {metrics['total_bytes']:,} bytes")
            st.write(f"**Threat Level:** {metrics['threat_level']}")
            st.write(f"**External Connections:** {metrics['external_connections']}")
            
            if metrics['suspicious_countries']:
                st.write(f"**Suspicious Countries:** {', '.join(set(metrics['suspicious_countries']))}")
            
            if not packets_df.empty:
                st.write(f"**Time Range:** {packets_df['timestamp'].min()} to {packets_df['timestamp'].max()}")


def main():
    """Main function to run the enhanced dashboard."""
    dashboard = EnhancedNetworkDashboard()
    dashboard.run_enhanced_dashboard()


if __name__ == "__main__":
    main()
