#!/usr/bin/env python3
"""
Enhanced UDP Client
Inspired by Black Hat Python with additional improvements
"""

import socket
import sys
import argparse
from typing import Tuple, Optional
import time

class UDPClient:
    def __init__(self, host: str, port: int, timeout: float = 5.0, retries: int = 3):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.retries = retries
        self.client = None
        self._setup_socket()

    def _setup_socket(self) -> None:
        """Initialize the UDP socket with proper configuration."""
        try:
            self.client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.client.settimeout(self.timeout)
        except socket.error as e:
            print(f"Failed to create socket: {e}")
            sys.exit(1)

    def send_with_retry(self, data: bytes) -> Tuple[Optional[bytes], Optional[Tuple[str, int]]]:
        """Send data with retry mechanism and return response."""
        for attempt in range(self.retries):
            try:
                self.client.sendto(data, (self.host, self.port))
                print(f"Sent {len(data)} bytes to {self.host}:{self.port}")
                
                response, addr = self.client.recvfrom(4096)
                return response, addr
                
            except socket.timeout:
                print(f"Attempt {attempt + 1}/{self.retries} timed out")
                if attempt < self.retries - 1:
                    time.sleep(0.5)  # Wait before retrying
                continue
                
            except socket.error as e:
                print(f"Error during attempt {attempt + 1}: {e}")
                if attempt < self.retries - 1:
                    time.sleep(0.5)
                continue
                
        print(f"Failed after {self.retries} attempts")
        return None, None

    def close(self) -> None:
        """Close the UDP socket."""
        if self.client:
            self.client.close()

def main():
    parser = argparse.ArgumentParser(
        description='''Enhanced UDP Client Tool

A reliable UDP client with retry mechanism and improved error handling.
Features include:
- Automatic retry on failed transmissions
- Configurable timeout settings
- Detailed error reporting
- Response verification
- Clean error handling and logging''',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''Examples:
    # Basic UDP message
    python client_udp.py -H 192.168.1.100 -p 9997 -m "Hello Server"
    
    # Custom timeout and retries
    python client_udp.py -H localhost -p 9997 -t 3.0 -r 5
    
    # Send to broadcast address
    python client_udp.py -H 255.255.255.255 -p 9997 -m "Broadcast message"
    
    # Local testing
    python client_udp.py -H 127.0.0.1 -p 9997 -m "Test message"
        ''')
    parser.add_argument('-H', '--host', default='127.0.0.1',
                      help='Target host (default: 127.0.0.1)')
    parser.add_argument('-p', '--port', type=int, default=9997,
                      help='Target port (default: 9997)')
    parser.add_argument('-m', '--message', default='PING',
                      help='Message to send (default: PING)')
    parser.add_argument('-t', '--timeout', type=float, default=5.0,
                      help='Timeout in seconds (default: 5.0)')
    parser.add_argument('-r', '--retries', type=int, default=3,
                      help='Number of retry attempts (default: 3)')
    args = parser.parse_args()

    client = UDPClient(args.host, args.port, args.timeout, args.retries)
    
    try:
        print(f"Sending message to {args.host}:{args.port}")
        response, addr = client.send_with_retry(args.message.encode())
        
        if response:
            print(f"\nReceived response from {addr[0]}:{addr[1]}")
            try:
                print(f"Data: {response.decode('utf-8')}")
            except UnicodeDecodeError:
                print(f"Data (hex): {response.hex()}")
    finally:
        client.close()

if __name__ == "__main__":
    main() 