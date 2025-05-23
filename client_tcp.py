#!/usr/bin/env python3
"""
Enhanced TCP Client
Inspired by Black Hat Python with additional improvements
"""

import socket
import sys
import argparse
from typing import Tuple, Optional
import ssl
from urllib.parse import urlparse

class TCPClient:
    def __init__(self, host: str, port: int, use_ssl: bool = False, timeout: float = 10.0):
        self.host = host
        self.port = port
        self.use_ssl = use_ssl
        self.timeout = timeout
        self.client = None
        self._setup_socket()

    def _setup_socket(self) -> None:
        """Initialize the socket with proper configuration."""
        try:
            self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client.settimeout(self.timeout)
            
            if self.use_ssl:
                context = ssl.create_default_context()
                self.client = context.wrap_socket(
                    self.client, server_hostname=self.host
                )
        except socket.error as e:
            print(f"Failed to create socket: {e}")
            sys.exit(1)

    def connect(self) -> bool:
        """Establish connection to the target."""
        try:
            self.client.connect((self.host, self.port))
            print(f"Connected to {self.host}:{self.port}")
            return True
        except socket.error as e:
            print(f"Connection failed: {e}")
            return False

    def send(self, data: bytes) -> bool:
        """Send data to the server."""
        try:
            self.client.send(data)
            return True
        except socket.error as e:
            print(f"Failed to send data: {e}")
            return False

    def receive(self, buffer_size: int = 4096) -> Optional[bytes]:
        """Receive data from the server."""
        try:
            response = self.client.recv(buffer_size)
            return response
        except socket.timeout:
            print("Receive timeout")
            return None
        except socket.error as e:
            print(f"Failed to receive data: {e}")
            return None

    def close(self) -> None:
        """Close the connection."""
        if self.client:
            self.client.close()

def parse_url(url: str) -> Tuple[str, int, bool]:
    """Parse URL to extract host, port, and SSL information."""
    parsed = urlparse(url)
    scheme = parsed.scheme or 'http'
    host = parsed.hostname or parsed.path
    port = parsed.port or (443 if scheme == 'https' else 80)
    use_ssl = scheme == 'https'
    return host, port, use_ssl

def main():
    parser = argparse.ArgumentParser(
        description='''Enhanced TCP Client Tool
        
A versatile TCP client that supports both plain TCP and SSL/TLS connections.
Features include:
- Automatic HTTP/HTTPS detection
- SSL/TLS support with proper certificate verification
- Configurable connection timeout
- URL parsing with automatic port detection
- Clean error handling and logging''',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''Examples:
    # Connect to HTTPS server
    python client_tcp.py https://www.example.com
    
    # Connect to specific port
    python client_tcp.py www.example.com -p 8443
    
    # Set custom timeout
    python client_tcp.py www.example.com -t 5.0
    
    # Connect to local server
    python client_tcp.py localhost -p 8080
        ''')
    parser.add_argument('url', 
                      help='Target URL (e.g., www.example.com or https://www.example.com). '
                           'The scheme (http/https) determines SSL usage.')
    parser.add_argument('-p', '--port', type=int, 
                      help='Target port (default: 80 for HTTP, 443 for HTTPS)')
    parser.add_argument('-t', '--timeout', type=float, default=10.0,
                      help='Connection timeout in seconds (default: 10.0)')
    args = parser.parse_args()

    # Parse URL and get connection details
    host, default_port, use_ssl = parse_url(args.url)
    port = args.port or default_port

    # Create and use client
    client = TCPClient(host, port, use_ssl, args.timeout)
    
    try:
        if client.connect():
            # Prepare HTTP request
            request = (
                f"GET / HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"User-Agent: PythonTCPClient/1.0\r\n"
                f"Connection: close\r\n"
                f"\r\n"
            )
            
            if client.send(request.encode()):
                # Receive and process response
                while True:
                    response = client.receive()
                    if not response:
                        break
                    try:
                        print(response.decode('utf-8', errors='replace'), end='')
                    except UnicodeDecodeError:
                        print(response.hex())
    finally:
        client.close()

if __name__ == "__main__":
    main() 