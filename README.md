# Security Audit and Hardening Script

This script is designed to perform a thorough security audit of a Linux server, providing detailed reports on user and group permissions, file and directory security, running services, firewall status, and more.
It also includes options for server hardening measures and custom security checks.

## Table of Contents

1. Installation
2. Configuration
3. Usage
4. Example Configuration Files

### Installation

# Prerequisites

Ensure that your system has the following tools installed:

- Bash shell
- systemctl
- awk, sed, grep
- iptables
- ufw
- netstat, ss
- dpkg, apt
- mail (for email alerts)

### Configuration

Basic Configuration
The script is designed to run without any additional configuration by default, performing a comprehensive security audit and applying hardening measures.
You can customize the security checks and hardening measures by creating a custom configuration file.

### Usage:

1. Download the Script or clone the repo:
2. Make the script executable:
        chmod +x Audit.sh
3. Run the script:
        ./Audit.sh

### Example Configuration Files (/etc/Audit.conf)
Move this content in /etc/Audit.conf:

**Example 1: Custom Security Checks**
To check world-writable directories in /home directory

echo "Checking for world-writable directories in /home"
find /home -xdev -type d -perm -0002 -exec ls -ld {} \; | tee -a "$report_file"

**Example 2: Custom Hardening Measures**
To disable unused services:

echo "Disabling Bluetooth service"
systemctl disable bluetooth.service | tee -a "$report_file"

### Conclusion
This script provides a solid foundation for securing a Linux server.
With detailed reporting, automated hardening measures, and customizable checks, it is a valuable tool for system administrators looking to improve their security posture.




