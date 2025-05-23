#!/usr/bin/env python3
"""
Enhanced MAC Address Spoofer
Allows spoofing of MAC addresses with various options and better error handling
"""

import argparse
import logging
import os
import random
import re
import subprocess
import sys
import time
from typing import Optional, Tuple
import fcntl
import socket
import struct

class MACSpoofer:
    def __init__(self, interface: str, new_mac: Optional[str] = None,
                vendor_preserve: bool = False, random_vendor: bool = False):
        # Setup logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)
        
        self.interface = interface
        self.new_mac = new_mac
        self.vendor_preserve = vendor_preserve
        self.random_vendor = random_vendor
        self.original_mac = None
        
        # Common vendor MAC prefixes for random vendor selection
        self.common_vendors = [
            "00:0C:29",  # VMware
            "00:50:56",  # VMware
            "00:1A:11",  # Google
            "00:03:93",  # Apple
            "00:0D:3A",  # Microsoft
            "00:25:00",  # Apple
            "E4:E0:C5",  # Samsung
            "00:26:BB",  # Apple
            "00:16:EA",  # Intel
            "00:15:5D"   # Microsoft
        ]

    @staticmethod
    def is_valid_mac(mac: str) -> bool:
        """Validate MAC address format"""
        pattern = re.compile(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$')
        return bool(pattern.match(mac))

    def get_current_mac(self) -> Optional[str]:
        """Get current MAC address of interface"""
        try:
            # Try using system calls first
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            info = fcntl.ioctl(s.fileno(), 0x8927, struct.pack('256s', 
                             bytes(self.interface[:15], 'utf-8')))
            mac = ':'.join(['%02x' % b for b in info[18:24]])
            return mac
        except:
            # Fallback to ifconfig command
            try:
                output = subprocess.check_output(
                    ['ifconfig', self.interface],
                    stderr=subprocess.STDOUT
                ).decode()
                
                mac_search = re.search(r'ether\s+([0-9a-fA-F:]{17})', output)
                if mac_search:
                    return mac_search.group(1)
            except:
                return None
        
        return None

    def generate_random_mac(self) -> str:
        """Generate a random MAC address"""
        def get_random_hex() -> str:
            return random.choice('0123456789abcdef')
        
        if self.random_vendor:
            # Use a random vendor prefix
            prefix = random.choice(self.common_vendors)
            suffix = ':'.join(''.join(get_random_hex() for _ in range(2)) for _ in range(3))
            return f"{prefix}:{suffix}"
        elif self.vendor_preserve and self.original_mac:
            # Preserve original vendor prefix
            prefix = ':'.join(self.original_mac.split(':')[:3])
            suffix = ':'.join(''.join(get_random_hex() for _ in range(2)) for _ in range(3))
            return f"{prefix}:{suffix}"
        else:
            # Completely random MAC
            return ':'.join(''.join(get_random_hex() for _ in range(2)) for _ in range(6))

    def change_mac(self, new_mac: str) -> bool:
        """Change MAC address of interface"""
        try:
            # Bring interface down
            self.logger.info(f"Bringing {self.interface} down...")
            subprocess.check_call(['sudo', 'ifconfig', self.interface, 'down'],
                               stderr=subprocess.STDOUT)
            
            # Change MAC address
            self.logger.info(f"Changing MAC address to {new_mac}...")
            subprocess.check_call(
                ['sudo', 'ifconfig', self.interface, 'hw', 'ether', new_mac],
                stderr=subprocess.STDOUT
            )
            
            # Bring interface up
            self.logger.info(f"Bringing {self.interface} up...")
            subprocess.check_call(['sudo', 'ifconfig', self.interface, 'up'],
                               stderr=subprocess.STDOUT)
            
            # Verify change
            time.sleep(1)  # Give interface time to come up
            current_mac = self.get_current_mac()
            if current_mac and current_mac.lower() == new_mac.lower():
                self.logger.info("MAC address successfully changed")
                return True
            else:
                self.logger.error("Failed to verify MAC address change")
                return False
                
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Error changing MAC address: {e.output.decode() if e.output else str(e)}")
            return False
        except Exception as e:
            self.logger.error(f"Unexpected error: {str(e)}")
            return False

    def backup_original_mac(self):
        """Backup original MAC address"""
        self.original_mac = self.get_current_mac()
        if self.original_mac:
            self.logger.info(f"Original MAC: {self.original_mac}")
        else:
            self.logger.warning("Could not determine original MAC address")

    def restore_original_mac(self) -> bool:
        """Restore original MAC address"""
        if not self.original_mac:
            self.logger.error("Original MAC address not available")
            return False
            
        return self.change_mac(self.original_mac)

    def run(self) -> bool:
        """Main execution method"""
        # Check if running as root
        if os.geteuid() != 0:
            self.logger.error("This script must be run as root!")
            return False
            
        # Backup original MAC
        self.backup_original_mac()
        
        # Determine new MAC address
        target_mac = self.new_mac if self.new_mac else self.generate_random_mac()
        
        # Validate MAC address format
        if not self.is_valid_mac(target_mac):
            self.logger.error(f"Invalid MAC address format: {target_mac}")
            return False
            
        # Change MAC address
        return self.change_mac(target_mac)

def validate_interface(interface: str) -> bool:
    """Validate if interface exists"""
    try:
        with open('/proc/net/dev', 'r') as f:
            return any(line.split(':')[0].strip() == interface for line in f)
    except:
        return False

def main():
    parser = argparse.ArgumentParser(
        description='''Enhanced MAC Address Spoofer Tool

A powerful tool for MAC address manipulation with advanced features.
Features include:
- Random MAC address generation
- Vendor prefix preservation
- Common vendor MAC support
- Interface validation
- Backup and restore capabilities
- Comprehensive error handling
- Detailed logging''',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''Examples:
    # Set random MAC address
    sudo python macspoof.py -i eth0
    
    # Set specific MAC address
    sudo python macspoof.py -i eth0 -m 00:11:22:33:44:55
    
    # Random MAC with original vendor prefix
    sudo python macspoof.py -i eth0 --preserve-vendor
    
    # Use random vendor MAC
    sudo python macspoof.py -i eth0 --random-vendor
    
    # Restore original MAC
    sudo python macspoof.py -i eth0 --restore
    
    # Verbose output
    sudo python macspoof.py -i eth0 -v
    
Note: This tool requires root privileges to modify network interfaces.
        ''')
    
    parser.add_argument('-i', '--interface', required=True,
                      help='Network interface to modify (e.g., eth0, wlan0)')
    parser.add_argument('-m', '--mac',
                      help='Specific MAC address to set (format: XX:XX:XX:XX:XX:XX)')
    parser.add_argument('--preserve-vendor', action='store_true',
                      help='Keep original vendor prefix (first 3 octets) when generating random MAC')
    parser.add_argument('--random-vendor', action='store_true',
                      help='Use random vendor prefix from common manufacturers')
    parser.add_argument('--restore', action='store_true',
                      help='Restore interface to original MAC address')
    parser.add_argument('-v', '--verbose', action='store_true',
                      help='Enable verbose logging output')
    
    args = parser.parse_args()
    
    # Set logging level
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Validate interface
    if not validate_interface(args.interface):
        print(f"Error: Interface {args.interface} not found")
        sys.exit(1)
    
    # Check for root privileges
    if os.geteuid() != 0:
        print("This script must be run as root!")
        sys.exit(1)
    
    # Validate arguments
    if sum([bool(args.mac), args.preserve_vendor, args.random_vendor, args.restore]) > 1:
        print("Error: Please specify only one of: --mac, --preserve-vendor, --random-vendor, or --restore")
        sys.exit(1)
    
    # Create spoofer instance
    spoofer = MACSpoofer(
        interface=args.interface,
        new_mac=args.mac,
        vendor_preserve=args.preserve_vendor,
        random_vendor=args.random_vendor
    )
    
    try:
        if args.restore:
            success = spoofer.restore_original_mac()
        else:
            success = spoofer.run()
            
        sys.exit(0 if success else 1)
        
    except KeyboardInterrupt:
        print("\nOperation cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {str(e)}")
        sys.exit(1)

if __name__ == '__main__':
    main() 