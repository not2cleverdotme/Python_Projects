#!/usr/bin/env python3
"""
Security Tools Menu
A centralized launcher for various security tools
"""

import os
import sys
import signal
import subprocess
import time
from typing import Dict, List, Callable
import importlib.util

class SecurityToolsMenu:
    def __init__(self):
        self.tools: Dict[str, dict] = {
            "1": {
                "name": "TCP Client",
                "file": "client_tcp.py",
                "description": "Network TCP client for testing connections",
                "args": ["-t", "--target", "-p", "--port"]
            },
            "2": {
                "name": "UDP Client",
                "file": "client_udp.py",
                "description": "Network UDP client for testing connections",
                "args": ["-t", "--target", "-p", "--port"]
            },
            "3": {
                "name": "TCP Server",
                "file": "server_tcp.py",
                "description": "TCP server implementation",
                "args": ["-h", "--host", "-p", "--port"]
            },
            "4": {
                "name": "Netcat Tool",
                "file": "netcat.py",
                "description": "Netcat replacement tool for network operations",
                "args": ["-t", "--target", "-p", "--port", "-l", "--listen", "-c", "--command", "-u", "--upload"]
            },
            "5": {
                "name": "SSH Command Client",
                "file": "ssh_cmd.py",
                "description": "SSH command execution client",
                "args": ["-h", "--host", "-u", "--user", "-p", "--password", "-c", "--command"]
            },
            "6": {
                "name": "Hidden WiFi Scanner",
                "file": "hiddenwifi.py",
                "description": "Tool for detecting hidden WiFi networks",
                "args": ["-i", "--interface"]
            },
            "7": {
                "name": "MAC Address Spoofer",
                "file": "macspoof.py",
                "description": "Tool for MAC address manipulation",
                "args": ["-i", "--interface", "-m", "--mac"]
            },
            "8": {
                "name": "Reconnaissance Tool",
                "file": "recon.py",
                "description": "Network reconnaissance and information gathering",
                "args": ["-t", "--target", "-p", "--ports"]
            },
            "9": {
                "name": "WiFi Scanner",
                "file": "wifiscanner.py",
                "description": "Comprehensive WiFi network scanner",
                "args": ["-i", "--interface", "-c", "--channel", "--no-hop", "-o", "--output", "-v", "--verbose"]
            }
        }
        
        # Register signal handlers
        signal.signal(signal.SIGINT, self.handle_interrupt)
        signal.signal(signal.SIGTERM, self.handle_interrupt)
        
        # Store the current running process
        self.current_process = None

    def clear_screen(self):
        """Clear the terminal screen based on OS"""
        os.system('cls' if os.name == 'nt' else 'clear')

    def print_header(self):
        """Print the menu header"""
        print("="*50)
        print("Security Tools Menu".center(50))
        print("="*50)
        print("\nAvailable Tools:")
        print("-"*50)

    def print_menu(self):
        """Display the main menu"""
        self.clear_screen()
        self.print_header()
        
        # Print tool options
        for key, tool in self.tools.items():
            print(f"{key}. {tool['name']}")
            print(f"   {tool['description']}")
            print(f"   Arguments: {' '.join(tool['args'])}")
            print()
        
        print("0. Exit")
        print("-"*50)

    def handle_interrupt(self, signum, frame):
        """Handle interrupt signals (Ctrl+C)"""
        if self.current_process:
            self.current_process.terminate()
            self.current_process = None
            print("\nTool execution interrupted. Returning to main menu...")
            time.sleep(1)
        else:
            print("\nExiting Security Tools Menu...")
            sys.exit(0)

    def get_tool_arguments(self, tool: dict) -> List[str]:
        """Get command line arguments from user for the tool"""
        print(f"\nEntering arguments for {tool['name']}")
        print("Available arguments:", " ".join(tool['args']))
        print("Enter arguments in the format: -arg value or --argument value")
        print("Press Enter without input to run with no arguments")
        print("Enter 'back' to return to main menu")
        
        while True:
            args_input = input("\nEnter arguments: ").strip()
            
            if args_input.lower() == 'back':
                return []
            
            if not args_input:
                return []
                
            try:
                # Split the input into a list while preserving quoted strings
                args = []
                current_arg = ''
                in_quotes = False
                quote_char = None
                
                for char in args_input:
                    if char in ['"', "'"]:
                        if not in_quotes:
                            in_quotes = True
                            quote_char = char
                        elif char == quote_char:
                            in_quotes = False
                            quote_char = None
                        current_arg += char
                    elif char.isspace() and not in_quotes:
                        if current_arg:
                            args.append(current_arg)
                            current_arg = ''
                    else:
                        current_arg += char
                
                if current_arg:
                    args.append(current_arg)
                
                # Validate arguments
                for arg in args:
                    if arg.startswith('-'):
                        arg_name = arg.split('=')[0]
                        if arg_name not in tool['args']:
                            print(f"Warning: Unknown argument {arg_name}")
                            if not input("Continue anyway? (y/n): ").lower().startswith('y'):
                                continue
                
                return args
                
            except Exception as e:
                print(f"Error parsing arguments: {e}")
                print("Please try again")

    def run_tool(self, tool_file: str, tool: dict) -> None:
        """Run a security tool as a subprocess with arguments"""
        try:
            # Check if the tool exists
            if not os.path.exists(tool_file):
                print(f"\nError: Tool file '{tool_file}' not found!")
                return

            # Show help menu first
            print(f"\nShowing help menu for {tool['name']}...")
            print("="*50)
            help_process = subprocess.run(
                [sys.executable, tool_file, "--help"],
                capture_output=True,
                text=True
            )
            
            # Try -h if --help doesn't work
            if help_process.returncode != 0:
                help_process = subprocess.run(
                    [sys.executable, tool_file, "-h"],
                    capture_output=True,
                    text=True
                )
            
            if help_process.returncode == 0:
                print(help_process.stdout)
            else:
                print("Could not display help menu. Proceeding with argument input.")
            
            print("="*50)
            input("Press Enter to continue...")

            # Get arguments from user
            args = self.get_tool_arguments(tool)
            if not args and args != []:  # Empty list means user wants to go back
                return

            print(f"\nLaunching {tool_file}...")
            print("Press Ctrl+C to return to the main menu")
            
            # Construct command with arguments
            cmd = [sys.executable, tool_file] + args
            
            # Run the tool as a subprocess
            self.current_process = subprocess.Popen(
                cmd,
                stdin=sys.stdin,
                stdout=sys.stdout,
                stderr=sys.stderr
            )
            self.current_process.wait()
            
        except Exception as e:
            print(f"\nError running tool: {e}")
        finally:
            self.current_process = None
            input("\nPress Enter to return to the main menu...")

    def run(self):
        """Main menu loop"""
        while True:
            self.print_menu()
            
            try:
                choice = input("\nSelect a tool (0-9): ").strip()
                
                if choice == "0":
                    print("\nExiting Security Tools Menu...")
                    break
                
                if choice in self.tools:
                    tool = self.tools[choice]
                    self.run_tool(tool["file"], tool)
                else:
                    print("\nInvalid choice! Please select a number between 0-9")
                    time.sleep(1)
                    
            except Exception as e:
                print(f"\nError: {e}")
                time.sleep(1)

def main():
    """Main entry point"""
    # Change to the script's directory
    script_dir = os.path.dirname(os.path.abspath(__file__))
    os.chdir(script_dir)
    
    # Create and run the menu
    menu = SecurityToolsMenu()
    menu.run()

if __name__ == "__main__":
    main() 