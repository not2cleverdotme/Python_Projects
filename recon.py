#!/usr/bin/env python3
"""
Enhanced Reconnaissance Tool
Gathers information about domains/IPs including DNS, headers, GeoIP, and security details
"""

import argparse
import json
import logging
import os
import socket
import sys
import time
from typing import Dict, List, Optional, Any
import dns.resolver
import requests
import whois
import ssl
import OpenSSL
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

class ReconTool:
    def __init__(self, target: str, api_key: Optional[str] = None,
                timeout: int = 10, verify_ssl: bool = True,
                max_threads: int = 5):
        # Setup logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)
        
        self.target = self._clean_target(target)
        self.api_key = api_key or os.getenv('IPINFO_API_KEY')
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.max_threads = max_threads
        
        # Results storage
        self.results: Dict[str, Any] = {
            'target': self.target,
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'dns_info': {},
            'http_info': {},
            'ssl_info': {},
            'whois_info': {},
            'geoip_info': {},
            'security_headers': {}
        }

    @staticmethod
    def _clean_target(target: str) -> str:
        """Clean and validate target input"""
        target = target.lower().strip()
        if target.startswith(('http://', 'https://')):
            return urlparse(target).netloc
        return target

    def get_dns_info(self) -> Dict[str, Any]:
        """Gather DNS information"""
        dns_info = {}
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME']
        
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = self.timeout
            resolver.lifetime = self.timeout
            
            for record_type in record_types:
                try:
                    answers = resolver.resolve(self.target, record_type)
                    dns_info[record_type] = [str(answer) for answer in answers]
                except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN,
                        dns.resolver.NoNameservers):
                    continue
                except Exception as e:
                    self.logger.debug(f"Error getting {record_type} records: {str(e)}")
            
            # Attempt to get reverse DNS
            try:
                ip = socket.gethostbyname(self.target)
                dns_info['PTR'] = socket.gethostbyaddr(ip)[0]
            except:
                pass
                
        except Exception as e:
            self.logger.error(f"DNS lookup failed: {str(e)}")
        
        return dns_info

    def get_http_info(self) -> Dict[str, Any]:
        """Gather HTTP information"""
        http_info = {}
        
        for protocol in ['https', 'http']:
            url = f"{protocol}://{self.target}"
            try:
                response = requests.get(
                    url,
                    timeout=self.timeout,
                    verify=self.verify_ssl,
                    allow_redirects=True
                )
                
                http_info[protocol] = {
                    'status_code': response.status_code,
                    'headers': dict(response.headers),
                    'redirect_history': [
                        {'url': r.url, 'status_code': r.status_code}
                        for r in response.history
                    ],
                    'final_url': response.url
                }
                
                # Check security headers
                security_headers = {
                    'Strict-Transport-Security': 'HSTS not enabled',
                    'Content-Security-Policy': 'CSP not set',
                    'X-Frame-Options': 'X-Frame-Options not set',
                    'X-Content-Type-Options': 'X-Content-Type-Options not set',
                    'X-XSS-Protection': 'X-XSS-Protection not set',
                    'Referrer-Policy': 'Referrer-Policy not set'
                }
                
                for header, default_value in security_headers.items():
                    security_headers[header] = response.headers.get(header, default_value)
                
                http_info[protocol]['security_headers'] = security_headers
                
                # Server technology detection
                server = response.headers.get('Server', '')
                powered_by = response.headers.get('X-Powered-By', '')
                if server or powered_by:
                    http_info[protocol]['server_info'] = {
                        'server': server,
                        'powered_by': powered_by
                    }
                
                break  # Stop if successful
                
            except requests.exceptions.SSLError:
                self.logger.warning(f"SSL verification failed for {url}")
                if self.verify_ssl:
                    continue
            except requests.exceptions.RequestException as e:
                self.logger.debug(f"HTTP request failed for {url}: {str(e)}")
                continue
        
        return http_info

    def get_ssl_info(self) -> Dict[str, Any]:
        """Gather SSL/TLS certificate information"""
        ssl_info = {}
        
        try:
            cert = ssl.get_server_certificate((self.target, 443))
            x509 = OpenSSL.crypto.load_certificate(
                OpenSSL.crypto.FILETYPE_PEM, cert
            )
            
            ssl_info = {
                'subject': dict(x509.get_subject().get_components()),
                'issuer': dict(x509.get_issuer().get_components()),
                'version': x509.get_version(),
                'serial_number': x509.get_serial_number(),
                'not_before': x509.get_notBefore().decode(),
                'not_after': x509.get_notAfter().decode(),
                'has_expired': x509.has_expired(),
                'signature_algorithm': x509.get_signature_algorithm().decode(),
                'extensions': [
                    str(x509.get_extension(i))
                    for i in range(x509.get_extension_count())
                ]
            }
            
        except Exception as e:
            self.logger.debug(f"SSL certificate information gathering failed: {str(e)}")
        
        return ssl_info

    def get_whois_info(self) -> Dict[str, Any]:
        """Gather WHOIS information"""
        try:
            w = whois.whois(self.target)
            return w
        except Exception as e:
            self.logger.debug(f"WHOIS lookup failed: {str(e)}")
            return {}

    def get_geoip_info(self, ip: str) -> Dict[str, Any]:
        """Gather GeoIP information using ipinfo.io"""
        try:
            headers = {'Accept': 'application/json'}
            if self.api_key:
                headers['Authorization'] = f'Bearer {self.api_key}'
            
            response = requests.get(
                f"https://ipinfo.io/{ip}/json",
                headers=headers,
                timeout=self.timeout
            )
            
            if response.status_code == 200:
                return response.json()
            else:
                self.logger.error(f"GeoIP lookup failed: {response.status_code}")
                return {}
                
        except Exception as e:
            self.logger.error(f"GeoIP lookup failed: {str(e)}")
            return {}

    def run(self) -> Dict[str, Any]:
        """Execute all reconnaissance tasks"""
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            # Submit tasks
            future_to_task = {
                executor.submit(self.get_dns_info): 'dns_info',
                executor.submit(self.get_http_info): 'http_info',
                executor.submit(self.get_ssl_info): 'ssl_info',
                executor.submit(self.get_whois_info): 'whois_info'
            }
            
            # Gather results
            for future in as_completed(future_to_task):
                task_name = future_to_task[future]
                try:
                    self.results[task_name] = future.result()
                except Exception as e:
                    self.logger.error(f"{task_name} failed: {str(e)}")
            
            # Get GeoIP for all A records
            if 'A' in self.results['dns_info']:
                for ip in self.results['dns_info']['A']:
                    geoip = self.get_geoip_info(ip)
                    if geoip:
                        self.results['geoip_info'][ip] = geoip
        
        return self.results

    def save_results(self, filename: str):
        """Save results to file"""
        try:
            with open(filename, 'w') as f:
                json.dump(self.results, f, indent=2)
            self.logger.info(f"Results saved to {filename}")
        except Exception as e:
            self.logger.error(f"Failed to save results: {str(e)}")

def print_results(results: Dict[str, Any]):
    """Print results in a formatted way"""
    print("\n=== Reconnaissance Results ===")
    print(f"Target: {results['target']}")
    print(f"Timestamp: {results['timestamp']}")
    
    if results['dns_info']:
        print("\n=== DNS Information ===")
        for record_type, records in results['dns_info'].items():
            print(f"\n{record_type} Records:")
            for record in records:
                print(f"  - {record}")
    
    if results['http_info']:
        print("\n=== HTTP Information ===")
        for protocol, info in results['http_info'].items():
            print(f"\n{protocol.upper()}:")
            print(f"Status Code: {info['status_code']}")
            print("Security Headers:")
            for header, value in info['security_headers'].items():
                print(f"  {header}: {value}")
            if 'server_info' in info:
                print("Server Information:")
                for key, value in info['server_info'].items():
                    if value:
                        print(f"  {key}: {value}")
    
    if results['ssl_info']:
        print("\n=== SSL Certificate Information ===")
        ssl_info = results['ssl_info']
        print(f"Issuer: {ssl_info['issuer']}")
        print(f"Valid Until: {ssl_info['not_after']}")
        print(f"Has Expired: {ssl_info['has_expired']}")
    
    if results['whois_info']:
        print("\n=== WHOIS Information ===")
        whois_info = results['whois_info']
        for key, value in whois_info.items():
            if value:
                print(f"{key}: {value}")
    
    if results['geoip_info']:
        print("\n=== GeoIP Information ===")
        for ip, info in results['geoip_info'].items():
            print(f"\nIP: {ip}")
            for key, value in info.items():
                print(f"{key}: {value}")

def main():
    parser = argparse.ArgumentParser(
        description='Enhanced Reconnaissance Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic scan
  python3 recon.py example.com
  
  # Scan with API key
  python3 recon.py example.com -k your_api_key
  
  # Save results to file
  python3 recon.py example.com -o results.json
  
  # Increase timeout
  python3 recon.py example.com -t 20
  
  # Skip SSL verification
  python3 recon.py example.com --no-verify
"""
    )
    
    parser.add_argument('target', help='Target domain or IP address')
    parser.add_argument('-k', '--api-key',
                      help='IPinfo.io API key (can also be set via IPINFO_API_KEY env variable)')
    parser.add_argument('-o', '--output',
                      help='Save results to JSON file')
    parser.add_argument('-t', '--timeout', type=int, default=10,
                      help='Timeout in seconds for requests (default: 10)')
    parser.add_argument('--no-verify', action='store_true',
                      help='Skip SSL certificate verification')
    parser.add_argument('-v', '--verbose', action='store_true',
                      help='Enable verbose logging')
    
    args = parser.parse_args()
    
    # Set logging level
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Create and run recon tool
    recon = ReconTool(
        target=args.target,
        api_key=args.api_key,
        timeout=args.timeout,
        verify_ssl=not args.no_verify
    )
    
    try:
        results = recon.run()
        
        # Save results if output file specified
        if args.output:
            recon.save_results(args.output)
        
        # Print results
        print_results(results)
        
    except KeyboardInterrupt:
        print("\nOperation cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {str(e)}")
        sys.exit(1)

if __name__ == '__main__':
    main() 