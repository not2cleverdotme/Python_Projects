# Security Tools Suite 🛡️

A comprehensive collection of network security and analysis tools designed for security professionals, network administrators, and penetration testers.

![Python Version](https://img.shields.io/badge/python-3.6%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey)
![Status](https://img.shields.io/badge/status-active-success)
![Security](https://img.shields.io/badge/security-passing-success)

## 📚 Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Tools Description](#tools-description)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
- [Advanced Usage](#advanced-usage)
- [Troubleshooting](#troubleshooting)
- [Security Considerations](#security-considerations)
- [Best Practices](#best-practices)
- [Contributing](#contributing)
- [Changelog](#changelog)
- [FAQ](#faq)
- [Disclaimer](#disclaimer)

## 🔍 Overview

This Security Tools Suite provides a collection of Python-based network security tools integrated into a user-friendly menu system. The suite is designed for network analysis, security testing, and system administration tasks. Each tool is crafted with modern security practices in mind and includes extensive error handling and logging capabilities.

### Key Benefits
- **Centralized Management**: All tools accessible through a single interface
- **Consistent Experience**: Unified argument handling and output format
- **Enhanced Security**: Built-in security checks and validations
- **Professional Grade**: Suitable for enterprise security testing
- **Educational Value**: Excellent for learning network security concepts

## ✨ Features

- Unified menu interface for all tools
- Cross-platform compatibility
- Comprehensive error handling
- Detailed logging
- Command-line argument support
- Interactive user interface
- Modern security implementations
- JSON output capabilities

## 🛠️ Tools Description

1. **TCP Client** (`client_tcp.py`)
   - Network TCP client for testing connections
   - Supports custom targets and ports
   - Includes SSL/TLS capabilities

2. **UDP Client** (`client_udp.py`)
   - Network UDP client for testing connections
   - Datagram-based communication testing
   - Configurable timeout settings

3. **TCP Server** (`server_tcp.py`)
   - Multi-threaded TCP server implementation
   - Connection handling and logging
   - Configurable listening interface and port

4. **Netcat Tool** (`netcat.py`)
   - Enhanced netcat replacement
   - File transfer capabilities
   - Command execution features
   - Upload/download functionality

5. **SSH Command Client** (`ssh_cmd.py`)
   - Secure SSH command execution
   - Key-based authentication support
   - Command output capture and logging

6. **Hidden WiFi Scanner** (`hiddenwifi.py`)
   - Detection of hidden wireless networks
   - SSID discovery capabilities
   - Signal strength monitoring

7. **MAC Address Spoofer** (`macspoof.py`)
   - MAC address manipulation tool
   - Interface management
   - Vendor MAC validation

8. **Reconnaissance Tool** (`recon.py`)
   - Network reconnaissance capabilities
   - Port scanning functionality
   - Service enumeration

9. **WiFi Scanner** (`wifiscanner.py`)
   - Comprehensive wireless network analysis
   - Encryption detection
   - Signal strength monitoring
   - Channel hopping capabilities
   - Detailed network information gathering

## 📋 Requirements

### System Requirements
- Python 3.6 or higher
- Operating System: Linux, macOS, or Windows
- Root/Administrator privileges (for certain tools)
- Wireless network adapter (for WiFi tools)

### Python Dependencies
```
scapy>=2.4.5
paramiko>=2.7.2
cryptography>=3.4.7
netifaces>=0.11.0
python-nmap>=0.7.1
requests>=2.26.0
```

### Additional Requirements
- For WiFi tools:
  - Network interface with monitor mode support
  - `aircrack-ng` suite (recommended)
- For MAC spoofing:
  - Network interface with MAC modification support
- For SSH tools:
  - SSH server access
  - Appropriate credentials/keys

## 📥 Installation

### Quick Start
```bash
git clone https://github.com/yourusername/security-tools-suite.git
cd security-tools-suite
pip install -r requirements.txt
chmod +x security_tools_menu.py  # Linux/macOS only
```

### Virtual Environment (Recommended)
```bash
python -m venv venv
source venv/bin/activate  # Linux/macOS
.\venv\Scripts\activate   # Windows
pip install -r requirements.txt
```

### Docker Installation
```bash
docker build -t security-tools .
docker run -it --net=host --privileged security-tools
```

## 🚀 Usage

1. Launch the menu interface:
   ```bash
   sudo python3 security_tools_menu.py
   ```

2. Select a tool from the menu (1-9)

3. Review the tool's help menu for available options

4. Enter the required arguments when prompted

5. Use Ctrl+C to return to the main menu

### Example Usage

```bash
# Launch WiFi Scanner with specific interface
Select tool (1-9): 9
Enter arguments: -i wlan0 --no-hop -v

# Use TCP Client to test connection
Select tool (1-9): 1
Enter arguments: -t 192.168.1.1 -p 80
```

## 🔧 Advanced Usage

### TCP Client Advanced Features
```bash
# SSL/TLS Connection with Custom Certificate
Select tool (1-9): 1
Enter arguments: -t example.com -p 443 --ssl --cert /path/to/cert.pem

# Custom Timeout and Retry
Enter arguments: -t example.com -p 80 --timeout 30 --retry 3
```

### WiFi Scanner Advanced Features
```bash
# Custom Channel Scanning
Select tool (1-9): 9
Enter arguments: -i wlan0 -c 1,6,11 --dwell-time 2

# Save Results in JSON Format
Enter arguments: -i wlan0 -o scan_results.json --format json
```

### Netcat Tool Advanced Usage
```bash
# Reverse Shell Handler
Select tool (1-9): 4
Enter arguments: -l -p 4444 --execute /bin/bash

# File Transfer with Encryption
Enter arguments: -t 192.168.1.100 -p 4444 --upload secret.txt --encrypt
```

## ❗ Troubleshooting

### Common Issues

1. **Permission Denied**
   ```bash
   sudo chmod +x security_tools_menu.py
   sudo python3 security_tools_menu.py
   ```

2. **Module Not Found**
   ```bash
   pip install -r requirements.txt --user
   # or
   python3 -m pip install -r requirements.txt
   ```

3. **Network Interface Not Found**
   ```bash
   # List available interfaces
   ifconfig -a  # Linux/macOS
   ipconfig /all  # Windows
   ```

4. **Monitor Mode Failed**
   ```bash
   # Check interface capabilities
   sudo iw list
   # Enable monitor mode manually
   sudo airmon-ng start wlan0
   ```

### Debug Mode
```bash
# Enable debug logging
sudo python3 security_tools_menu.py --debug
```

## 🔒 Security Best Practices

### General Guidelines
1. **Access Control**
   - Use least privilege principle
   - Regularly rotate credentials
   - Implement proper access logging

2. **Network Security**
   - Use encrypted channels when possible
   - Monitor network traffic
   - Implement proper firewalls

3. **Data Handling**
   - Encrypt sensitive data
   - Implement secure storage
   - Regular data cleanup

### Tool-Specific Guidelines
1. **WiFi Tools**
   - Use dedicated testing networks
   - Monitor for interference
   - Follow wireless security standards

2. **Network Tools**
   - Implement rate limiting
   - Use proper timeout values
   - Handle connections securely

## 📈 Changelog

### Version 1.1.0 (Latest)
- Added unified menu interface
- Improved error handling
- Enhanced security features
- Added JSON output support

### Version 1.0.0
- Initial release
- Basic tool functionality
- Core features implementation

## ❓ FAQ

### General Questions
1. **Q: Do I need root privileges?**
   A: Yes, for tools that interact with network interfaces directly.

2. **Q: Is Windows supported?**
   A: Yes, but some network tools may have limited functionality.

3. **Q: Can I use these tools in production?**
   A: Yes, but thorough testing in a controlled environment is recommended.

### Technical Questions
1. **Q: How do I enable monitor mode?**
   A: Use the built-in interface handler or airmon-ng manually.

2. **Q: Can I extend the tools?**
   A: Yes, see the contributing guidelines for details.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit pull requests, report bugs, and suggest features.

1. Fork the repository
2. Create your feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## ⚠️ Disclaimer

This suite of tools is designed for legitimate network testing and security assessment purposes only. Users must:

- Obtain proper authorization before testing any network or system
- Comply with all applicable laws and regulations
- Use the tools responsibly and ethically
- Accept full responsibility for their actions

The authors and contributors are not responsible for any misuse or damage caused by these tools.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---
Created and maintained with ❤️ by [Your Name]

Last Updated: [Current Date]
Version: 1.1.0 