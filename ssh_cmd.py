#!/usr/bin/env python3
"""
Enhanced SSH Command Client
Inspired by Black Hat Python with additional security and features
"""

import argparse
import getpass
import logging
import os
import sys
import time
from typing import Optional, List, Dict, Any, Tuple
import socket
import paramiko
from paramiko.ssh_exception import SSHException, AuthenticationException
import json

class SSHClient:
    def __init__(self, host: str, username: str, port: int = 22,
                password: Optional[str] = None,
                key_filename: Optional[str] = None,
                timeout: int = 30,
                keepalive: int = 60):
        
        # Setup logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)
        
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.key_filename = key_filename
        self.timeout = timeout
        self.keepalive = keepalive
        self.client = None
        self.connected = False

    def connect(self) -> bool:
        """Establish SSH connection with retries"""
        max_retries = 3
        retry_delay = 5
        
        for attempt in range(max_retries):
            try:
                self.client = paramiko.SSHClient()
                self.client.load_system_host_keys()
                self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                
                connect_kwargs = {
                    'hostname': self.host,
                    'port': self.port,
                    'username': self.username,
                    'timeout': self.timeout
                }
                
                if self.password:
                    connect_kwargs['password'] = self.password
                if self.key_filename:
                    connect_kwargs['key_filename'] = self.key_filename
                
                self.client.connect(**connect_kwargs)
                
                # Enable keepalive
                transport = self.client.get_transport()
                if transport:
                    transport.set_keepalive(self.keepalive)
                
                self.connected = True
                self.logger.info(f"Successfully connected to {self.host}")
                return True
                
            except AuthenticationException:
                self.logger.error("Authentication failed")
                return False
                
            except (SSHException, socket.error) as e:
                if attempt < max_retries - 1:
                    self.logger.warning(f"Connection attempt {attempt + 1} failed: {str(e)}")
                    time.sleep(retry_delay)
                else:
                    self.logger.error(f"Failed to connect after {max_retries} attempts: {str(e)}")
                    return False
        
        return False

    def execute_command(self, command: str, timeout: Optional[int] = None) -> Tuple[int, str, str]:
        """Execute a command and return exit code, stdout, and stderr"""
        if not self.connected or not self.client:
            raise RuntimeError("Not connected to SSH server")
            
        try:
            self.logger.info(f"Executing command: {command}")
            stdin, stdout, stderr = self.client.exec_command(
                command,
                timeout=timeout or self.timeout,
                get_pty=True
            )
            
            exit_code = stdout.channel.recv_exit_status()
            stdout_data = stdout.read().decode().strip()
            stderr_data = stderr.read().decode().strip()
            
            return exit_code, stdout_data, stderr_data
            
        except Exception as e:
            self.logger.error(f"Command execution failed: {str(e)}")
            return 1, "", str(e)

    def execute_script(self, script_path: str) -> List[Dict[str, Any]]:
        """Execute a script file containing multiple commands"""
        if not os.path.exists(script_path):
            raise FileNotFoundError(f"Script file not found: {script_path}")
            
        results = []
        try:
            with open(script_path, 'r') as f:
                commands = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            
            for cmd in commands:
                exit_code, stdout, stderr = self.execute_command(cmd)
                results.append({
                    'command': cmd,
                    'exit_code': exit_code,
                    'stdout': stdout,
                    'stderr': stderr
                })
            
        except Exception as e:
            self.logger.error(f"Script execution failed: {str(e)}")
            
        return results

    def upload_file(self, local_path: str, remote_path: str) -> bool:
        """Upload a file to the remote server"""
        if not self.connected or not self.client:
            raise RuntimeError("Not connected to SSH server")
            
        try:
            sftp = self.client.open_sftp()
            sftp.put(local_path, remote_path)
            sftp.close()
            self.logger.info(f"Successfully uploaded {local_path} to {remote_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"File upload failed: {str(e)}")
            return False

    def download_file(self, remote_path: str, local_path: str) -> bool:
        """Download a file from the remote server"""
        if not self.connected or not self.client:
            raise RuntimeError("Not connected to SSH server")
            
        try:
            sftp = self.client.open_sftp()
            sftp.get(remote_path, local_path)
            sftp.close()
            self.logger.info(f"Successfully downloaded {remote_path} to {local_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"File download failed: {str(e)}")
            return False

    def close(self):
        """Close the SSH connection"""
        if self.client:
            self.client.close()
            self.connected = False
            self.logger.info("SSH connection closed")

def main():
    parser = argparse.ArgumentParser(
        description='''Enhanced SSH Command Client Tool

A powerful SSH client with advanced features for secure remote operations.
Features include:
- Key-based and password authentication
- Command execution with timeout
- File transfer capabilities
- Connection retry mechanism
- Detailed logging and error reporting
- JSON output support
- Comprehensive error handling''',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''Examples:
    # Execute single command
    python ssh_cmd.py -H example.com -u admin -c "ls -la"
    
    # Execute script file
    python ssh_cmd.py -H example.com -u admin -s commands.txt
    
    # Use key authentication
    python ssh_cmd.py -H example.com -u admin -k ~/.ssh/id_rsa -c "uptime"
    
    # Upload file
    python ssh_cmd.py -H example.com -u admin --upload local.txt /remote/path/file.txt
    
    # Download file
    python ssh_cmd.py -H example.com -u admin --download /remote/file.txt ./local_copy.txt
    
    # Custom timeout and JSON output
    python ssh_cmd.py -H example.com -u admin -c "long_command" -t 60 -o output.json
        ''')
    
    # Connection options
    parser.add_argument('-H', '--host', required=True,
                      help='Target SSH server hostname or IP')
    parser.add_argument('-p', '--port', type=int, default=22,
                      help='SSH port (default: 22)')
    parser.add_argument('-u', '--username', required=True,
                      help='SSH username for authentication')
    parser.add_argument('-k', '--key-file',
                      help='Path to private key file for key-based authentication')
    parser.add_argument('-t', '--timeout', type=int, default=30,
                      help='Connection/command timeout in seconds (default: 30)')
    
    # Command execution options
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-c', '--command',
                     help='Single command to execute on remote host')
    group.add_argument('-s', '--script',
                     help='Script file containing multiple commands to execute')
    group.add_argument('--upload', nargs=2, metavar=('LOCAL', 'REMOTE'),
                     help='Upload local file to remote path')
    group.add_argument('--download', nargs=2, metavar=('REMOTE', 'LOCAL'),
                     help='Download remote file to local path')
    
    # Output options
    parser.add_argument('-o', '--output',
                      help='Save command output to JSON file')
    parser.add_argument('-q', '--quiet', action='store_true',
                      help='Suppress informational output')
    
    args = parser.parse_args()
    
    # Configure logging
    if args.quiet:
        logging.getLogger().setLevel(logging.WARNING)
    
    # Get password if no key file provided
    password = None
    if not args.key_file:
        password = getpass.getpass(f"Password for {args.username}@{args.host}: ")
    
    # Create SSH client
    ssh = SSHClient(
        host=args.host,
        port=args.port,
        username=args.username,
        password=password,
        key_filename=args.key_file,
        timeout=args.timeout
    )
    
    try:
        # Connect to server
        if not ssh.connect():
            sys.exit(1)
        
        # Execute requested operation
        if args.command:
            exit_code, stdout, stderr = ssh.execute_command(args.command)
            
            if stdout:
                print("STDOUT:")
                print(stdout)
            if stderr:
                print("STDERR:")
                print(stderr)
            
            if args.output:
                with open(args.output, 'w') as f:
                    json.dump({
                        'command': args.command,
                        'exit_code': exit_code,
                        'stdout': stdout,
                        'stderr': stderr
                    }, f, indent=2)
            
            sys.exit(exit_code)
            
        elif args.script:
            results = ssh.execute_script(args.script)
            
            if args.output:
                with open(args.output, 'w') as f:
                    json.dump(results, f, indent=2)
            else:
                for result in results:
                    print(f"\nCommand: {result['command']}")
                    if result['stdout']:
                        print("STDOUT:")
                        print(result['stdout'])
                    if result['stderr']:
                        print("STDERR:")
                        print(result['stderr'])
            
        elif args.upload:
            if not ssh.upload_file(args.upload[0], args.upload[1]):
                sys.exit(1)
                
        elif args.download:
            if not ssh.download_file(args.download[0], args.download[1]):
                sys.exit(1)
    
    except KeyboardInterrupt:
        print("\nOperation interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {str(e)}")
        sys.exit(1)
    finally:
        ssh.close()

if __name__ == '__main__':
    main() 