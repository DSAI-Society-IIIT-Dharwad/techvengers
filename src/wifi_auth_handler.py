#!/usr/bin/env python3
"""
WiFi Captive Portal Authentication Handler
==========================================

This module handles WiFi captive portal authentication by detecting
authentication requirements and providing a way to input credentials.
"""

import requests
import time
import webbrowser
from urllib.parse import urlparse
from typing import Optional, Dict, Any


class WiFiAuthHandler:
    """
    Handles WiFi captive portal authentication detection and credential input.
    """
    
    def __init__(self):
        self.auth_url = None
        self.auth_required = False
        self.credentials = {}
    
    def detect_captive_portal(self) -> bool:
        """
        Detect if we're behind a captive portal by trying to access common test URLs.
        
        Returns:
            True if captive portal is detected, False otherwise
        """
        test_urls = [
            "http://httpbin.org/status/200",
            "http://www.google.com/generate_204",
            "http://captive.apple.com/hotspot-detect.html",
            "http://connectivitycheck.gstatic.com/generate_204"
        ]
        
        print("Detecting captive portal...")
        
        for url in test_urls:
            try:
                response = requests.get(url, timeout=5, allow_redirects=True)
                
                # Check if we got redirected to an authentication page
                if response.url != url:
                    parsed_url = urlparse(response.url)
                    if any(keyword in parsed_url.netloc.lower() for keyword in 
                          ['login', 'auth', 'portal', 'wifi', 'hotspot']):
                        self.auth_url = response.url
                        self.auth_required = True
                        print("Captive portal detected!")
                        print(f"   Authentication URL: {self.auth_url}")
                        return True
                
                # Check response content for captive portal indicators
                content = response.text.lower()
                if any(keyword in content for keyword in 
                      ['login', 'password', 'wifi', 'hotspot', 'authentication']):
                    self.auth_url = response.url
                    self.auth_required = True
                    print("Captive portal detected!")
                    print(f"   Authentication URL: {self.auth_url}")
                    return True
                    
            except requests.exceptions.RequestException:
                continue
        
        print("No captive portal detected")
        return False
    
    def get_credentials(self) -> Dict[str, str]:
        """
        Get authentication credentials from user input.
        
        Returns:
            Dictionary containing username and password
        """
        print("\n" + "="*60)
        print("WIFI AUTHENTICATION REQUIRED")
        print("="*60)
        print("This network requires authentication to access the internet.")
        print("Please provide your WiFi credentials:")
        print("="*60)
        
        credentials = {}
        
        # Get username/email
        username = input("Enter username/email (or press Enter to skip): ").strip()
        if username:
            credentials['username'] = username
        
        # Get password
        password = input("Enter password (or press Enter to skip): ").strip()
        if password:
            credentials['password'] = password
        
        # Get additional fields that might be required
        print("\nAdditional fields (press Enter to skip):")
        room_number = input("Room number: ").strip()
        if room_number:
            credentials['room'] = room_number
            
        guest_code = input("Guest code: ").strip()
        if guest_code:
            credentials['guest_code'] = guest_code
        
        self.credentials = credentials
        return credentials
    
    def attempt_authentication(self) -> bool:
        """
        Attempt to authenticate with the captive portal.
        
        Returns:
            True if authentication successful, False otherwise
        """
        if not self.auth_url or not self.credentials:
            return False
        
        print(f"\nAttempting authentication...")
        print(f"   URL: {self.auth_url}")
        
        try:
            # Try to submit credentials
            response = requests.post(
                self.auth_url,
                data=self.credentials,
                timeout=10,
                allow_redirects=True
            )
            
            # Check if authentication was successful
            if response.status_code == 200:
                # Check if we're redirected away from auth page
                if self.auth_url not in response.url:
                    print("Authentication successful!")
                    return True
                else:
                    print("Authentication failed - still on auth page")
                    return False
            else:
                print(f"Authentication failed - HTTP {response.status_code}")
                return False
                
        except requests.exceptions.RequestException as e:
            print(f"Authentication error: {e}")
            return False
    
    def open_browser_auth(self):
        """
        Open the authentication page in the default browser for manual authentication.
        """
        if self.auth_url:
            print(f"\nOpening authentication page in browser...")
            print(f"   URL: {self.auth_url}")
            webbrowser.open(self.auth_url)
            
            input("\nPress Enter after completing authentication in the browser...")
            
            # Test if authentication was successful
            if self.test_internet_connection():
                print("Internet connection restored!")
                return True
            else:
                print("Internet connection still not available")
                return False
        return False
    
    def test_internet_connection(self) -> bool:
        """
        Test if internet connection is working.
        
        Returns:
            True if internet is accessible, False otherwise
        """
        try:
            response = requests.get("http://httpbin.org/status/200", timeout=5)
            return response.status_code == 200
        except:
            return False
    
    def handle_authentication(self) -> bool:
        """
        Complete authentication flow.
        
        Returns:
            True if authentication successful, False otherwise
        """
        if not self.auth_required:
            return True
        
        print("\n" + "="*60)
        print("HANDLING WIFI AUTHENTICATION")
        print("="*60)
        
        # Get credentials from user
        self.get_credentials()
        
        # Try automated authentication first
        if self.attempt_authentication():
            return True
        
        # If automated auth fails, try browser-based auth
        print("\nAutomated authentication failed. Trying browser-based authentication...")
        return self.open_browser_auth()


def main():
    """Test the WiFi authentication handler."""
    handler = WiFiAuthHandler()
    
    print("WiFi Captive Portal Authentication Handler")
    print("="*50)
    
    # Detect captive portal
    if handler.detect_captive_portal():
        # Handle authentication
        success = handler.handle_authentication()
        
        if success:
            print("\nAuthentication completed successfully!")
            print("You can now proceed with packet capture.")
        else:
            print("\nAuthentication failed.")
            print("Please check your credentials and try again.")
    else:
        print("\nNo authentication required.")
        print("You can proceed with packet capture.")


if __name__ == "__main__":
    main()
