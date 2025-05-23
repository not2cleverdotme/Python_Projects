#!/usr/bin/env python3
"""
Enhanced TCP Server
Inspired by Black Hat Python with additional improvements
"""

import socket
import threading
import argparse
import logging
import signal
import sys
from typing import Optional, Tuple
import ssl

class TCPServer:
    def __init__(self, host: str = '0.0.0.0', port: int = 9998,
                 backlog: int = 5, use_ssl: bool = False,
                 cert_file: Optional[str] = None,
                 key_file: Optional[str] = None):
        self.host = host
        self.port = port
        self.backlog = backlog
        self.use_ssl = use_ssl
        self.cert_file = cert_file
        self.key_file = key_file
        self.server = None
        self.ssl_context = None
        self.running = False
        self.clients = set()
        
        # Setup logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)

    def setup_ssl(self) -> None:
        """Configure SSL context if SSL is enabled."""
        if self.use_ssl:
            if not (self.cert_file and self.key_file):
                raise ValueError("Certificate and key files are required for SSL")
            
            self.ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            self.ssl_context.load_cert_chain(self.cert_file, self.key_file)

    def setup_socket(self) -> None:
        """Initialize and configure the server socket."""
        try:
            self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server.bind((self.host, self.port))
            self.server.listen(self.backlog)
        except socket.error as e:
            self.logger.error(f"Failed to create server socket: {e}")
            sys.exit(1)

    def handle_client(self, client_socket: socket.socket, address: Tuple[str, int]) -> None:
        """Handle individual client connections."""
        self.clients.add(client_socket)
        client_id = f"{address[0]}:{address[1]}"
        
        try:
            with client_socket:
                self.logger.info(f"New connection from {client_id}")
                while self.running:
                    request = client_socket.recv(1024)
                    if not request:
                        break
                    
                    try:
                        decoded_request = request.decode('utf-8').strip()
                        self.logger.info(f"Received from {client_id}: {decoded_request}")
                        
                        # Process the request and send response
                        response = self.process_request(decoded_request)
                        client_socket.send(response.encode())
                        
                    except UnicodeDecodeError:
                        self.logger.warning(f"Received binary data from {client_id}")
                        client_socket.send(b'Received binary data\n')
                        
        except socket.error as e:
            self.logger.error(f"Error handling client {client_id}: {e}")
        finally:
            self.logger.info(f"Connection closed from {client_id}")
            self.clients.remove(client_socket)

    def process_request(self, request: str) -> str:
        """Process client request and return response."""
        # This is a simple echo server - extend this method for more functionality
        return f"Server received: {request}\n"

    def shutdown(self) -> None:
        """Gracefully shutdown the server."""
        self.logger.info("Shutting down server...")
        self.running = False
        
        # Close all client connections
        for client in self.clients.copy():
            try:
                client.close()
            except socket.error:
                pass
        
        # Close server socket
        if self.server:
            self.server.close()

    def run(self) -> None:
        """Run the server and accept connections."""
        # Setup signal handlers for graceful shutdown
        signal.signal(signal.SIGINT, lambda s, f: self.shutdown())
        signal.signal(signal.SIGTERM, lambda s, f: self.shutdown())

        try:
            if self.use_ssl:
                self.setup_ssl()
            self.setup_socket()
            self.running = True
            
            self.logger.info(f"Server listening on {self.host}:{self.port}")
            self.logger.info("Press Ctrl+C to stop the server")
            
            while self.running:
                try:
                    client_socket, address = self.server.accept()
                    if self.use_ssl:
                        client_socket = self.ssl_context.wrap_socket(
                            client_socket, server_side=True
                        )
                    
                    client_thread = threading.Thread(
                        target=self.handle_client,
                        args=(client_socket, address)
                    )
                    client_thread.daemon = True
                    client_thread.start()
                    
                except socket.error as e:
                    if self.running:  # Only log if not shutting down
                        self.logger.error(f"Error accepting connection: {e}")
                        
        except Exception as e:
            self.logger.error(f"Server error: {e}")
        finally:
            self.shutdown()

def main():
    parser = argparse.ArgumentParser(
        description='''Enhanced TCP Server Tool

A multi-threaded TCP server with SSL/TLS support and advanced connection handling.
Features include:
- SSL/TLS encryption support
- Multi-threaded client handling
- Configurable connection backlog
- Detailed logging capabilities
- Graceful shutdown handling
- Clean error handling and reporting''',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''Examples:
    # Start basic server
    python server_tcp.py -p 8080
    
    # Start SSL server
    python server_tcp.py -p 443 --ssl --cert server.crt --key server.key
    
    # Custom host and backlog
    python server_tcp.py -H 192.168.1.100 -p 8080 -b 10
    
    # Local testing with SSL
    python server_tcp.py -H localhost -p 8443 --ssl --cert local.crt --key local.key
        ''')
    parser.add_argument('-H', '--host', default='0.0.0.0',
                      help='Host to bind to (default: 0.0.0.0, all interfaces)')
    parser.add_argument('-p', '--port', type=int, default=9998,
                      help='Port to listen on (default: 9998)')
    parser.add_argument('-b', '--backlog', type=int, default=5,
                      help='Connection backlog size (default: 5)')
    parser.add_argument('--ssl', action='store_true',
                      help='Enable SSL/TLS encryption')
    parser.add_argument('--cert',
                      help='Path to SSL certificate file (required if SSL enabled)')
    parser.add_argument('--key',
                      help='Path to SSL private key file (required if SSL enabled)')
    
    args = parser.parse_args()
    
    if args.ssl and not (args.cert and args.key):
        parser.error("--cert and --key are required when SSL is enabled")

    server = TCPServer(
        host=args.host,
        port=args.port,
        backlog=args.backlog,
        use_ssl=args.ssl,
        cert_file=args.cert,
        key_file=args.key
    )
    
    server.run()

if __name__ == '__main__':
    main() 