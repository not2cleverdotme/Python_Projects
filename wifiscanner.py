#!/usr/bin/env python3
"""
WiFi Network Scanner
Detects and analyzes all available wireless networks in range.
"""

import argparse
import logging
import os
import signal
import sys
import time
from typing import Dict, Set, Optional, List
from datetime import datetime
import json
import platform
import subprocess
from scapy.all import (
    Dot11, Dot11Beacon, Dot11ProbeResp, Dot11Elt, RadioTap,
    sniff, conf
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
                commands = [
                    f"sudo ip link set {interface} down",
                    f"sudo iw {interface} set monitor none",
                    f"sudo ip link set {interface} up"
                ]
            else:
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
                f"sudo {airport_path} {interface} -z",  # Disassociate
                f"sudo {airport_path} {interface} sniff",  # Enable monitor mode
                f"sudo ifconfig {interface} up"
            ]
            
            for cmd in commands:
                retcode, _, stderr = self._run_command(cmd)
                if retcode != 0:
                    self.logger.error(f"Command failed: {cmd}\nError: {stderr}")
                    return False
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to setup monitor mode on macOS: {e}")
            return False

    def _setup_windows(self, interface: str) -> bool:
        """Setup monitor mode on Windows using netsh"""
        try:
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
                "Windows support for monitor mode is limited. Consider using Linux for better compatibility."
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
            return retcode == 0
            
        except Exception as e:
            self.logger.error(f"Failed to set channel: {e}")
            return False

class WiFiNetwork:
    """Represents a discovered WiFi network"""
    
    def __init__(self, ssid: str, bssid: str):
        self.ssid = ssid
        self.bssid = bssid
        self.channel = 0
        self.signal_strength = 0
        self.encryption = set()
        self.cipher = set()
        self.authentication = set()
        self.first_seen = datetime.now()
        self.last_seen = datetime.now()
        self.beacons = 0
        self.data_packets = 0
        self.wps = False
        self.vendor = ""

    def update_signal(self, signal_strength: int):
        """Update signal strength using exponential moving average"""
        alpha = 0.3  # Smoothing factor
        if self.signal_strength == 0:
            self.signal_strength = signal_strength
        else:
            self.signal_strength = (alpha * signal_strength + 
                                  (1 - alpha) * self.signal_strength)

    def to_dict(self) -> Dict:
        """Convert network information to dictionary"""
        return {
            'ssid': self.ssid,
            'bssid': self.bssid,
            'channel': self.channel,
            'signal_strength': round(self.signal_strength, 2),
            'encryption': list(self.encryption),
            'cipher': list(self.cipher),
            'authentication': list(self.authentication),
            'first_seen': self.first_seen.strftime('%Y-%m-%d %H:%M:%S'),
            'last_seen': self.last_seen.strftime('%Y-%m-%d %H:%M:%S'),
            'beacons': self.beacons,
            'data_packets': self.data_packets,
            'wps': self.wps,
            'vendor': self.vendor
        }

class WiFiScanner:
    """WiFi network scanner with channel hopping and packet analysis"""
    
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
        
        # Data structures
        self.networks: Dict[str, WiFiNetwork] = {}  # BSSID -> Network
        self.seen_bssids: Set[str] = set()
        
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
        """Configure wireless interface for monitoring"""
        return self.interface_handler.setup_monitor_mode(self.interface)

    def channel_hopper(self):
        """Hop through channels if enabled"""
        if not self.hop_channels:
            return
            
        self.current_channel_index = (self.current_channel_index + 1) % len(self.channels)
        next_channel = self.channels[self.current_channel_index]
        self.interface_handler.set_channel(self.interface, next_channel)

    def parse_security(self, packet) -> tuple[Set[str], Set[str], Set[str], bool]:
        """Parse security information from beacon packet"""
        encryption = set()
        cipher = set()
        auth = set()
        wps = False
        
        # Extract security information from packet
        while Dot11Elt in packet:
            # Check for RSN (WPA2) information
            if packet[Dot11Elt].ID == 48:
                encryption.add("WPA2")
                rsn = packet[Dot11Elt].info
                
                # Parse RSN structure
                if len(rsn) >= 4:
                    auth_count = rsn[6]
                    if auth_count > 0:
                        if b'\x00\x0f\xac\x02' in rsn:
                            auth.add("PSK")
                        if b'\x00\x0f\xac\x04' in rsn:
                            auth.add("MGT")
                    
                    cipher_count = rsn[2]
                    if cipher_count > 0:
                        if b'\x00\x0f\xac\x04' in rsn:
                            cipher.add("CCMP")
                        if b'\x00\x0f\xac\x02' in rsn:
                            cipher.add("TKIP")
            
            # Check for WPA information
            elif packet[Dot11Elt].ID == 221 and packet[Dot11Elt].info.startswith(b'\x00\x50\xf2\x01\x01\x00'):
                encryption.add("WPA")
            
            # Check for WPS
            elif packet[Dot11Elt].ID == 221 and packet[Dot11Elt].info.startswith(b'\x00\x50\xf2\x04'):
                wps = True
            
            packet = packet[Dot11Elt].payload
        
        # Check for WEP
        if not encryption and packet.cap.privacy:
            encryption.add("WEP")
        elif not encryption and not packet.cap.privacy:
            encryption.add("OPN")
        
        return encryption, cipher, auth, wps

    def process_packet(self, packet):
        """Process captured packet and extract network information"""
        if not packet.haslayer(Dot11):
            return
            
        self.packets_processed += 1
        
        # Get the BSSID
        if packet.type == 0 and (packet.subtype == 8 or packet.subtype == 5):
            if packet.haslayer(Dot11Beacon) or packet.haslayer(Dot11ProbeResp):
                try:
                    bssid = packet[Dot11].addr3
                    if not bssid:
                        return
                    
                    # Extract network name
                    if packet.haslayer(Dot11Beacon):
                        packet_type = "Beacon"
                    else:
                        packet_type = "Probe Response"
                    
                    try:
                        ssid = packet[Dot11Elt].info.decode('utf-8')
                    except:
                        ssid = "<HIDDEN>"
                    
                    # Create or update network
                    if bssid not in self.networks:
                        self.networks[bssid] = WiFiNetwork(ssid, bssid)
                    
                    network = self.networks[bssid]
                    network.last_seen = datetime.now()
                    
                    if packet_type == "Beacon":
                        network.beacons += 1
                    
                    # Update signal strength
                    if packet.haslayer(RadioTap):
                        signal_strength = packet[RadioTap].dBm_AntSignal
                        network.update_signal(signal_strength)
                    
                    # Get channel
                    try:
                        channel = int(ord(packet[Dot11Elt:3].info))
                        network.channel = channel
                    except:
                        pass
                    
                    # Parse security information
                    encryption, cipher, auth, wps = self.parse_security(packet)
                    network.encryption.update(encryption)
                    network.cipher.update(cipher)
                    network.authentication.update(auth)
                    if wps:
                        network.wps = True
                    
                except Exception as e:
                    self.logger.debug(f"Error processing packet: {e}")

    def save_results(self):
        """Save results to file if output file is specified"""
        if not self.output_file:
            return
            
        try:
            results = {
                'scan_info': {
                    'interface': self.interface,
                    'start_time': self.start_time.strftime('%Y-%m-%d %H:%M:%S'),
                    'end_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    'packets_processed': self.packets_processed
                },
                'networks': {
                    bssid: network.to_dict()
                    for bssid, network in self.networks.items()
                }
            }
            
            with open(self.output_file, 'w') as f:
                json.dump(results, f, indent=2)
                
            self.logger.info(f"Results saved to {self.output_file}")
            
        except Exception as e:
            self.logger.error(f"Failed to save results: {e}")

    def print_statistics(self):
        """Print scan statistics and network information"""
        duration = datetime.now() - self.start_time
        
        print("\n=== Scan Statistics ===")
        print(f"Duration: {duration}")
        print(f"Packets Processed: {self.packets_processed}")
        print(f"Networks Found: {len(self.networks)}")
        
        print("\n=== Networks ===")
        # Sort networks by signal strength
        sorted_networks = sorted(
            self.networks.values(),
            key=lambda x: x.signal_strength,
            reverse=True
        )
        
        for network in sorted_networks:
            print(f"\nSSID: {network.ssid}")
            print(f"BSSID: {network.bssid}")
            print(f"Channel: {network.channel}")
            print(f"Signal Strength: {round(network.signal_strength, 2)} dBm")
            print(f"Security: {', '.join(network.encryption)}")
            if network.cipher:
                print(f"Cipher: {', '.join(network.cipher)}")
            if network.authentication:
                print(f"Authentication: {', '.join(network.authentication)}")
            print(f"WPS: {'Yes' if network.wps else 'No'}")
            print(f"First Seen: {network.first_seen.strftime('%H:%M:%S')}")
            print(f"Last Seen: {network.last_seen.strftime('%H:%M:%S')}")
            print(f"Beacons: {network.beacons}")

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
        description='''WiFi Network Scanner Tool

A comprehensive tool for discovering and analyzing wireless networks.
Features include:
- Detection of all WiFi networks (2.4GHz)
- Security information (WEP/WPA/WPA2, cipher, auth)
- Signal strength monitoring
- Channel hopping
- Detailed network statistics
- JSON output support
- Cross-platform support''',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''Examples:
    # Basic scan with channel hopping
    sudo python wifiscanner.py -i wlan0
    
    # Scan specific channel
    sudo python wifiscanner.py -i wlan0 -c 6
    
    # Disable channel hopping
    sudo python wifiscanner.py -i wlan0 --no-hop
    
    # Save results to file
    sudo python wifiscanner.py -i wlan0 -o scan_results.json
    
    # Verbose output
    sudo python wifiscanner.py -i wlan0 -v
    
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
    
    # Configure logging
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    scanner = WiFiScanner(
        interface=args.interface,
        channel=args.channel,
        hop_channels=not args.no_hop,
        output_file=args.output
    )
    
    scanner.start_scanning()

if __name__ == '__main__':
    main() 