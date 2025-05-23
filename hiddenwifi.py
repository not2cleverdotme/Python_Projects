#!/usr/bin/env python3
"""
Enhanced Hidden WiFi Scanner
Detects hidden wireless networks by monitoring probe requests/responses
and association requests.
"""

import argparse
import logging
import os
import signal
import sys
import time
from typing import Dict, Set, Optional
from datetime import datetime
import json
import platform
import subprocess
from scapy.all import (
    Dot11, Dot11ProbeReq, Dot11ProbeResp, Dot11AssoReq,
    Dot11Beacon, RadioTap, sniff
)

class InterfaceHandler:
    """Handles OS-specific wireless interface operations"""
    
    def __init__(self):
        self.os_type = platform.system().lower()
        self.logger = logging.getLogger(__name__)
        
    def _run_command(self, command: str) -> tuple[int, str, str]:
        """Execute command and return (return_code, stdout, stderr)"""
        try:
            process = subprocess.Popen(
                command.split(),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            stdout, stderr = process.communicate()
            return (
                process.returncode,
                stdout.decode(errors='ignore'),
                stderr.decode(errors='ignore')
            )
        except Exception as e:
            return 1, "", str(e)

    def setup_monitor_mode(self, interface: str) -> bool:
        """Configure interface for monitor mode based on OS"""
        if self.os_type == "linux":
            return self._setup_linux(interface)
        elif self.os_type == "darwin":  # macOS
            return self._setup_macos(interface)
        elif self.os_type == "windows":
            return self._setup_windows(interface)
        else:
            self.logger.error(f"Unsupported operating system: {self.os_type}")
            return False

    def _setup_linux(self, interface: str) -> bool:
        """Setup monitor mode on Linux using iw/iwconfig"""
        try:
            # Check if iw is available
            if self._run_command("which iw")[0] == 0:
                # Modern Linux with iw
                commands = [
                    f"sudo ip link set {interface} down",
                    f"sudo iw {interface} set monitor none",
                    f"sudo ip link set {interface} up"
                ]
            else:
                # Fallback to iwconfig
                commands = [
                    f"sudo ifconfig {interface} down",
                    f"sudo iwconfig {interface} mode monitor",
                    f"sudo ifconfig {interface} up"
                ]
            
            for cmd in commands:
                retcode, _, stderr = self._run_command(cmd)
                if retcode != 0:
                    self.logger.error(f"Command failed: {cmd}\nError: {stderr}")
                    return False
            
            self.logger.info(f"Successfully configured {interface} in monitor mode (Linux)")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to setup monitor mode on Linux: {e}")
            return False

    def _setup_macos(self, interface: str) -> bool:
        """Setup monitor mode on macOS using airport utility"""
        try:
            airport_path = "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport"
            
            commands = [
                f"sudo ifconfig {interface} down",
                f"sudo {airport_path} {interface} -z",  # Disassociate if associated
                f"sudo {airport_path} {interface} sniff",  # Enable monitor mode
                f"sudo ifconfig {interface} up"
            ]
            
            for cmd in commands:
                retcode, _, stderr = self._run_command(cmd)
                if retcode != 0:
                    self.logger.error(f"Command failed: {cmd}\nError: {stderr}")
                    return False
            
            self.logger.info(f"Successfully configured {interface} in monitor mode (macOS)")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to setup monitor mode on macOS: {e}")
            return False

    def _setup_windows(self, interface: str) -> bool:
        """Setup monitor mode on Windows using netsh"""
        try:
            # Note: Windows support is limited and may not work on all adapters
            commands = [
                f"netsh wlan set hostednetwork mode=allow interface={interface}",
                f"netsh wlan start hostednetwork"
            ]
            
            for cmd in commands:
                retcode, _, stderr = self._run_command(cmd)
                if retcode != 0:
                    self.logger.error(f"Command failed: {cmd}\nError: {stderr}")
                    return False
            
            self.logger.warning(
                "Windows support for monitor mode is limited and may not work "
                "on all wireless adapters. Consider using a Linux live USB for "
                "better compatibility."
            )
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to setup monitor mode on Windows: {e}")
            return False

    def set_channel(self, interface: str, channel: int) -> bool:
        """Set wireless interface channel based on OS"""
        try:
            if self.os_type == "linux":
                if self._run_command("which iw")[0] == 0:
                    cmd = f"sudo iw {interface} set channel {channel}"
                else:
                    cmd = f"sudo iwconfig {interface} channel {channel}"
            elif self.os_type == "darwin":
                airport_path = "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport"
                cmd = f"sudo {airport_path} {interface} -c{channel}"
            elif self.os_type == "windows":
                self.logger.warning("Channel hopping not supported on Windows")
                return False
            else:
                self.logger.error(f"Unsupported operating system: {self.os_type}")
                return False
            
            retcode, _, stderr = self._run_command(cmd)
            if retcode != 0:
                self.logger.error(f"Failed to set channel: {stderr}")
                return False
                
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to set channel: {e}")
            return False

class HiddenWiFiScanner:
    def __init__(self, interface: str, channel: Optional[int] = None,
                 hop_channels: bool = True, output_file: Optional[str] = None):
        # Setup logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)
        
        self.interface = interface
        self.channel = channel
        self.hop_channels = hop_channels
        self.output_file = output_file
        self.running = True
        
        # Initialize interface handler
        self.interface_handler = InterfaceHandler()
        
        # Data structures to store discovered networks
        self.hidden_networks: Dict[str, Dict] = {}  # BSSID -> network info
        self.seen_ssids: Set[str] = set()  # Track unique SSIDs
        
        # Channel hopping
        self.channels = list(range(1, 14))  # 2.4GHz channels
        self.current_channel_index = 0
        
        # Statistics
        self.start_time = None
        self.packets_processed = 0
        
        # Register signal handlers
        signal.signal(signal.SIGINT, self.handle_shutdown)
        signal.signal(signal.SIGTERM, self.handle_shutdown)

    def handle_shutdown(self, *args):
        """Handle graceful shutdown"""
        self.logger.info("\nShutting down...")
        self.running = False
        self.save_results()
        self.print_statistics()
        sys.exit(0)

    def setup_interface(self) -> bool:
        """Configure wireless interface for monitoring using OS-specific handler"""
        return self.interface_handler.setup_monitor_mode(self.interface)

    def set_channel(self, channel: int):
        """Set wireless interface channel using OS-specific handler"""
        self.interface_handler.set_channel(self.interface, channel)

    def channel_hopper(self):
        """Hop through channels if enabled"""
        if not self.hop_channels:
            return
            
        self.current_channel_index = (self.current_channel_index + 1) % len(self.channels)
        next_channel = self.channels[self.current_channel_index]
        self.set_channel(next_channel)

    def process_packet(self, packet):
        """Process captured packet and extract network information"""
        if not packet.haslayer(Dot11):
            return
            
        self.packets_processed += 1
        
        # Extract basic information
        if packet.haslayer(RadioTap):
            signal_strength = packet[RadioTap].dBm_AntSignal if hasattr(packet[RadioTap], 'dBm_AntSignal') else 'N/A'
        else:
            signal_strength = 'N/A'
            
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        # Process different packet types
        if packet.haslayer(Dot11Beacon):
            if packet[Dot11].addr3 not in self.hidden_networks:
                ssid = packet[Dot11Beacon].info.decode(errors='ignore')
                if not ssid:  # Hidden network
                    self.hidden_networks[packet[Dot11].addr3] = {
                        'bssid': packet[Dot11].addr3,
                        'ssid': None,
                        'type': 'Hidden',
                        'first_seen': timestamp,
                        'last_seen': timestamp,
                        'signal_strength': signal_strength,
                        'channel': self.current_channel_index + 1 if self.hop_channels else self.channel,
                        'probe_requests': set()
                    }
        
        elif packet.haslayer(Dot11ProbeReq):
            ssid = packet[Dot11ProbeReq].info.decode(errors='ignore')
            if ssid:
                self.seen_ssids.add(ssid)
                # Update any matching hidden networks
                for network in self.hidden_networks.values():
                    if not network['ssid']:
                        network['probe_requests'].add(ssid)
        
        elif packet.haslayer(Dot11ProbeResp):
            bssid = packet[Dot11].addr3
            ssid = packet[Dot11ProbeResp].info.decode(errors='ignore')
            if bssid in self.hidden_networks and ssid:
                self.hidden_networks[bssid]['ssid'] = ssid
                self.hidden_networks[bssid]['last_seen'] = timestamp
                self.hidden_networks[bssid]['signal_strength'] = signal_strength
        
        elif packet.haslayer(Dot11AssoReq):
            bssid = packet[Dot11].addr3
            if bssid in self.hidden_networks:
                self.hidden_networks[bssid]['last_seen'] = timestamp
                self.hidden_networks[bssid]['signal_strength'] = signal_strength

    def save_results(self):
        """Save results to file if output file is specified"""
        if not self.output_file:
            return
            
        try:
            # Convert set to list for JSON serialization
            results = {
                'scan_info': {
                    'interface': self.interface,
                    'start_time': self.start_time.strftime('%Y-%m-%d %H:%M:%S'),
                    'end_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    'packets_processed': self.packets_processed
                },
                'hidden_networks': {
                    bssid: {
                        **network,
                        'probe_requests': list(network['probe_requests'])
                    }
                    for bssid, network in self.hidden_networks.items()
                }
            }
            
            with open(self.output_file, 'w') as f:
                json.dump(results, f, indent=2)
                
            self.logger.info(f"Results saved to {self.output_file}")
            
        except Exception as e:
            self.logger.error(f"Failed to save results: {e}")

    def print_statistics(self):
        """Print scan statistics"""
        duration = datetime.now() - self.start_time
        print("\n=== Scan Statistics ===")
        print(f"Duration: {duration}")
        print(f"Packets Processed: {self.packets_processed}")
        print(f"Hidden Networks Found: {len(self.hidden_networks)}")
        print(f"Unique SSIDs Seen: {len(self.seen_ssids)}")
        
        print("\n=== Hidden Networks ===")
        for bssid, network in self.hidden_networks.items():
            print(f"\nBSSID: {bssid}")
            print(f"SSID: {network['ssid'] or 'Unknown'}")
            print(f"First Seen: {network['first_seen']}")
            print(f"Last Seen: {network['last_seen']}")
            print(f"Signal Strength: {network['signal_strength']}")
            print(f"Channel: {network['channel']}")
            if network['probe_requests']:
                print("Probe Requests:")
                for ssid in network['probe_requests']:
                    print(f"  - {ssid}")

    def start_scanning(self):
        """Start the scanning process"""
        if not self.setup_interface():
            return
            
        self.start_time = datetime.now()
        self.logger.info(f"Starting scan on interface {self.interface}")
        
        try:
            while self.running:
                # Sniff packets for a short duration
                sniff(
                    iface=self.interface,
                    prn=self.process_packet,
                    timeout=1,  # Sniff for 1 second at a time
                    store=False  # Don't store packets in memory
                )
                
                # Hop channels if enabled
                if self.hop_channels:
                    self.channel_hopper()
                    
        except Exception as e:
            self.logger.error(f"Scanning error: {e}")
        finally:
            self.save_results()
            self.print_statistics()

def main():
    parser = argparse.ArgumentParser(
        description='''Enhanced Hidden WiFi Scanner Tool

A sophisticated tool for detecting and analyzing hidden wireless networks.
Features include:
- Detection of hidden SSIDs through probe requests/responses
- Channel hopping for comprehensive scanning
- Signal strength monitoring
- Detailed network information gathering
- JSON output support
- Comprehensive logging
- Statistical analysis''',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''Examples:
    # Basic scan on default interface
    sudo python hiddenwifi.py -i wlan0
    
    # Scan specific channel
    sudo python hiddenwifi.py -i wlan0 -c 6
    
    # Disable channel hopping
    sudo python hiddenwifi.py -i wlan0 --no-hop
    
    # Save results to file
    sudo python hiddenwifi.py -i wlan0 -o scan_results.json
    
    # Verbose output with channel hopping
    sudo python hiddenwifi.py -i wlan0 -v
    
Note: This tool requires root privileges and a wireless interface that supports monitor mode.
        ''')
    
    parser.add_argument('-i', '--interface', required=True,
                      help='Wireless interface to use (must support monitor mode)')
    parser.add_argument('-c', '--channel', type=int,
                      help='Fixed channel to scan (1-14, disables channel hopping)')
    parser.add_argument('--no-hop', action='store_true',
                      help='Disable automatic channel hopping')
    parser.add_argument('-o', '--output',
                      help='Save scan results to JSON file')
    parser.add_argument('-v', '--verbose', action='store_true',
                      help='Enable verbose logging output')
    
    args = parser.parse_args()
    
    # Check if running as root
    if os.geteuid() != 0:
        print("This script must be run as root!")
        sys.exit(1)
    
    scanner = HiddenWiFiScanner(
        interface=args.interface,
        channel=args.channel,
        hop_channels=not args.no_hop,
        output_file=args.output
    )
    
    scanner.start_scanning()

if __name__ == '__main__':
    main() 