#!/usr/bin/env python3
"""
Enhanced Netcat Implementation
Inspired by Black Hat Python with additional security and features
"""

import argparse
import socket
import shlex
import subprocess
import sys
import textwrap
import threading
import logging
import ssl
import os
from typing import Optional, Union, BinaryIO
import signal
import time
import base64

class SecureExecutor:
    """Secure command execution handler"""
    BLOCKED_COMMANDS = {'rm', 'mkfs', 'dd', '>', '>>', '|'}
    
    @staticmethod
    def is_command_safe(cmd: str) -> bool:
        """Check if command is safe to execute"""
        cmd_parts = shlex.split(cmd.lower())
        return not any(blocked in cmd_parts for blocked in SecureExecutor.BLOCKED_COMMANDS)
    
    @staticmethod
    def execute(cmd: str) -> tuple[int, str, str]:
        """Execute command securely and return (return_code, stdout, stderr)"""
        cmd = cmd.strip()
        if not cmd:
            return 1, '', 'Empty command'
            
        if not SecureExecutor.is_command_safe(cmd):
            return 1, '', 'Command not allowed for security reasons'
            
        try:
            process = subprocess.Popen(
                shlex.split(cmd),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=False  # Prevent shell injection
            )
            stdout, stderr = process.communicate(timeout=30)  # 30 second timeout
            return process.returncode, stdout.decode(), stderr.decode()
        except subprocess.TimeoutExpired:
            return 1, '', 'Command timed out'
        except Exception as e:
            return 1, '', f'Error executing command: {str(e)}'

class NetCat:
    def __init__(self, args, buffer: Optional[bytes] = None):
        # Setup logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)
        
        self.args = args
        self.buffer = buffer
        self.socket = None
        self.ssl_context = None
        self.running = True
        
        # Signal handlers for graceful shutdown
        signal.signal(signal.SIGINT, self.handle_shutdown)
        signal.signal(signal.SIGTERM, self.handle_shutdown)

    def handle_shutdown(self, *args):
        """Handle graceful shutdown"""
        self.logger.info("Shutting down...")
        self.running = False
        if self.socket:
            self.socket.close()
        sys.exit(0)

    def setup_socket(self):
        """Initialize socket with proper configuration"""
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        if self.args.ssl:
            self.setup_ssl()

    def setup_ssl(self):
        """Configure SSL if enabled"""
        try:
            self.ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            if self.args.listen:
                if not (self.args.cert and self.args.key):
                    raise ValueError("Certificate and key required for SSL server")
                self.ssl_context.load_cert_chain(self.args.cert, self.args.key)
            else:
                if self.args.verify_cert:
                    self.ssl_context.verify_mode = ssl.CERT_REQUIRED
                    self.ssl_context.load_verify_locations(self.args.verify_cert)
                else:
                    self.ssl_context.check_hostname = False
                    self.ssl_context.verify_mode = ssl.CERT_NONE
        except Exception as e:
            self.logger.error(f"SSL setup failed: {e}")
            sys.exit(1)

    def run(self):
        """Main execution method"""
        self.setup_socket()
        if self.args.listen:
            self.listen()
        else:
            self.send()

    def send(self):
        """Client mode operation"""
        try:
            self.socket.connect((self.args.target, self.args.port))
            if self.args.ssl:
                self.socket = self.ssl_context.wrap_socket(
                    self.socket,
                    server_hostname=self.args.target
                )
            
            self.logger.info(f"Connected to {self.args.target}:{self.args.port}")
            
            if self.buffer:
                self._send_buffer(self.buffer)
            
            self._interactive_loop()
            
        except Exception as e:
            self.logger.error(f"Connection failed: {e}")
            sys.exit(1)

    def _send_buffer(self, buffer: bytes):
        """Send data with length prefix"""
        try:
            # Send length prefix
            length = len(buffer)
            self.socket.send(length.to_bytes(8, byteorder='big'))
            # Send actual data
            self.socket.send(buffer)
        except Exception as e:
            self.logger.error(f"Failed to send data: {e}")

    def _receive_buffer(self) -> Optional[bytes]:
        """Receive data with length prefix"""
        try:
            # Receive length prefix
            length_bytes = self.socket.recv(8)
            if not length_bytes:
                return None
            length = int.from_bytes(length_bytes, byteorder='big')
            
            # Receive data in chunks
            data = b''
            remaining = length
            while remaining > 0:
                chunk = self.socket.recv(min(remaining, 8192))
                if not chunk:
                    break
                data += chunk
                remaining -= len(chunk)
            return data
        except Exception as e:
            self.logger.error(f"Failed to receive data: {e}")
            return None

    def _interactive_loop(self):
        """Interactive client loop"""
        try:
            while self.running:
                response = self._receive_buffer()
                if not response:
                    break
                    
                print(response.decode())
                
                if self.args.interactive:
                    try:
                        buffer = input('nc> ').encode()
                        if buffer.lower() == b'exit':
                            break
                        self._send_buffer(buffer)
                    except EOFError:
                        break
                        
        except KeyboardInterrupt:
            self.logger.info("User terminated.")
        finally:
            self.socket.close()

    def listen(self):
        """Server mode operation"""
        try:
            self.socket.bind((self.args.target, self.args.port))
            self.socket.listen(self.args.backlog)
            self.logger.info(f"Listening on {self.args.target}:{self.args.port}")
            
            while self.running:
                client_socket, addr = self.socket.accept()
                if self.args.ssl:
                    try:
                        client_socket = self.ssl_context.wrap_socket(
                            client_socket,
                            server_side=True
                        )
                    except ssl.SSLError as e:
                        self.logger.error(f"SSL handshake failed: {e}")
                        client_socket.close()
                        continue
                
                self.logger.info(f"Accepted connection from {addr[0]}:{addr[1]}")
                client_handler = threading.Thread(
                    target=self.handle_client,
                    args=(client_socket,)
                )
                client_handler.daemon = True
                client_handler.start()
                
        except Exception as e:
            self.logger.error(f"Listener failed: {e}")
        finally:
            if self.socket:
                self.socket.close()

    def handle_client(self, client_socket: Union[socket.socket, ssl.SSLSocket]):
        """Handle individual client connections"""
        try:
            if self.args.execute:
                self._handle_execute(client_socket)
            elif self.args.upload:
                self._handle_upload(client_socket)
            elif self.args.download:
                self._handle_download(client_socket)
            elif self.args.command:
                self._handle_shell(client_socket)
            else:
                self._handle_echo(client_socket)
        except Exception as e:
            self.logger.error(f"Error handling client: {e}")
        finally:
            client_socket.close()

    def _handle_execute(self, client_socket):
        """Handle command execution"""
        retcode, stdout, stderr = SecureExecutor.execute(self.args.execute)
        response = f"Return Code: {retcode}\nStdout:\n{stdout}\nStderr:\n{stderr}"
        self._send_buffer(response.encode())

    def _handle_upload(self, client_socket):
        """Handle file upload"""
        try:
            file_data = self._receive_buffer()
            if not file_data:
                return
                
            # Ensure upload directory exists and is secure
            upload_dir = os.path.join(os.getcwd(), 'uploads')
            os.makedirs(upload_dir, exist_ok=True)
            
            # Secure file path
            filename = os.path.basename(self.args.upload)
            filepath = os.path.join(upload_dir, filename)
            
            with open(filepath, 'wb') as f:
                f.write(file_data)
            
            message = f'Successfully saved file to {filepath}'
            self._send_buffer(message.encode())
            
        except Exception as e:
            self._send_buffer(f"Upload failed: {str(e)}".encode())

    def _handle_download(self, client_socket):
        """Handle file download"""
        try:
            if not os.path.exists(self.args.download):
                raise FileNotFoundError(f"File not found: {self.args.download}")
                
            with open(self.args.download, 'rb') as f:
                file_data = f.read()
            self._send_buffer(file_data)
            
        except Exception as e:
            self._send_buffer(f"Download failed: {str(e)}".encode())

    def _handle_shell(self, client_socket):
        """Handle interactive shell"""
        self._send_buffer(b"Connected to netcat shell. Type 'exit' to quit.\n")
        
        while self.running:
            try:
                self._send_buffer(b'nc-shell> ')
                command = self._receive_buffer()
                
                if not command:
                    break
                    
                command = command.decode().strip()
                if command.lower() == 'exit':
                    break
                    
                retcode, stdout, stderr = SecureExecutor.execute(command)
                response = f"{stdout}{stderr}"
                if response:
                    self._send_buffer(response.encode())
                else:
                    self._send_buffer(b'Command completed without output\n')
                    
            except Exception as e:
                self._send_buffer(f"Error: {str(e)}\n".encode())
                break

    def _handle_echo(self, client_socket):
        """Handle echo mode"""
        while self.running:
            try:
                data = self._receive_buffer()
                if not data:
                    break
                self._send_buffer(data)
            except Exception:
                break

def main():
    parser = argparse.ArgumentParser(
        description='''Enhanced Netcat Replacement Tool

A versatile network utility that combines TCP/IP functionality with additional security features.
Features include:
- SSL/TLS encryption support
- Secure file transfer capabilities
- Command execution with security controls
- Interactive shell mode
- Upload/download functionality
- Comprehensive logging
- Advanced error handling''',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''Examples:
    # Start command shell
    python netcat.py -t 192.168.1.100 -p 5555 -l -c
    
    # Upload file
    python netcat.py -t 192.168.1.100 -p 5555 -l -u /path/to/file.txt
    
    # Download file
    python netcat.py -t 192.168.1.100 -p 5555 -l -d /path/to/save.txt
    
    # Execute command
    python netcat.py -t 192.168.1.100 -p 5555 -l -e "ls -la"
    
    # Interactive client mode with SSL
    python netcat.py -t 192.168.1.100 -p 5555 -i --ssl --verify-cert ca.pem
    
    # SSL server with certificate
    python netcat.py -t 0.0.0.0 -p 5555 -l --ssl --cert cert.pem --key key.pem
        ''')

    parser.add_argument('-l', '--listen', action='store_true',
                      help='Listen mode (server) - receive connections')
    parser.add_argument('-i', '--interactive', action='store_true',
                      help='Interactive mode - for command line interaction')
    parser.add_argument('-e', '--execute',
                      help='Execute specified command on target')
    parser.add_argument('-c', '--command', action='store_true',
                      help='Initialize command shell')
    parser.add_argument('-u', '--upload',
                      help='Upload file to target')
    parser.add_argument('-d', '--download',
                      help='Download file from target')
    parser.add_argument('-t', '--target', default='0.0.0.0',
                      help='Target host (default: 0.0.0.0)')
    parser.add_argument('-p', '--port', type=int, default=5555,
                      help='Target port (default: 5555)')
    parser.add_argument('-b', '--backlog', type=int, default=5,
                      help='Listen backlog for server mode (default: 5)')
    
    # SSL options
    parser.add_argument('--ssl', action='store_true',
                      help='Enable SSL/TLS encryption')
    parser.add_argument('--cert',
                      help='SSL certificate file (required for SSL server)')
    parser.add_argument('--key',
                      help='SSL private key file (required for SSL server)')
    parser.add_argument('--verify-cert',
                      help='CA certificate for client verification')
    
    args = parser.parse_args()

    # Input validation
    if args.listen:
        buffer = None
    else:
        buffer = sys.stdin.buffer.read() if not sys.stdin.isatty() else None

    if args.ssl and args.listen and not (args.cert and args.key):
        parser.error("SSL server requires --cert and --key")

    try:
        nc = NetCat(args, buffer)
        nc.run()
    except KeyboardInterrupt:
        print("\nExiting...")
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main() 