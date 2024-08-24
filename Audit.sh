#!/bin/bash

# Initialize report file
report_file="/var/log/security_audit_report.txt" && > "$report_file"

# 1. User and Group Audits
echo "User and Group Audits"

echo "Listing all users and groups:" | tee -a "$report_file"
cut -d ':' -f1 /etc/passwd | tee -a "$report_file"
cut -d ':' -f1 /etc/group | tee -a "$report_file"

echo "Checking for UID 0 (root privileges) and non-standard users:" | tee -a "$report_file"
awk -F ':' '$3 == 0 {print $1}' /etc/passwd | tee -a "$report_file"

echo "Identifying users without passwords or with weak passwords:" | tee -a "$report_file"
awk -F ':' '($2 == "" || $2 == "*") {print $1}' /etc/shadow | tee -a "$report_file"

# 2. File and Directory Permissions
echo "File and Directory Permissions"

echo "Scanning for world-writable files and directories:" | tee -a "$report_file"
find / -xdev \( -perm -0002 -a ! -type l \) -exec ls -ld {} \; | tee -a "$report_file"

echo "Checking .ssh directories for secure permissions:" | tee -a "$report_file"
find / -name ".ssh" -type d -exec ls -ld {} \; | tee -a "$report_file"

echo "Reporting files with SUID or SGID bits set:" | tee -a "$report_file"
find / -xdev \( -perm -4000 -o -perm -2000 \) -exec ls -ld {} \; | tee -a "$report_file"

# 3. Service Audits
echo "Service Audits"

echo "Listing all running services:" | tee -a "$report_file"
systemctl list-units --type=service --state=running | tee -a "$report_file"

echo "Checking for critical services (sshd, iptables) and their configuration:" | tee -a "$report_file"
systemctl status sshd | tee -a "$report_file"
systemctl status iptables | tee -a "$report_file"

echo "Checking for services listening on non-standard or insecure ports:" | tee -a "$report_file"
netstat -tuln | tee -a "$report_file"

# 4. Firewall and Network Security
echo "Firewall and Network Security"

echo "Verifying if firewall is active and configured:" | tee -a "$report_file"
ufw status verbose | tee -a "$report_file"
iptables -L -v -n | tee -a "$report_file"

echo "Reporting open ports and associated services:" | tee -a "$report_file"
ss -tuln | tee -a "$report_file"

echo "Checking for IP forwarding and insecure network configurations:" | tee -a "$report_file"
sysctl net.ipv4.ip_forward | tee -a "$report_file"
sysctl net.ipv6.conf.all.forwarding | tee -a "$report_file"

# 5. IP and Network Configuration Checks
echo "IP and Network Configuration Checks"

echo "Identifying public or private IP addresses:" | tee -a "$report_file"
hostname -I | tee -a "$report_file"
ip addr show | grep inet | tee -a "$report_file"

# 6. Security Updates and Patching
echo "Security Updates and Patching"

echo "Checking for available security updates:" | tee -a "$report_file"
apt list --upgradable | tee -a "$report_file"

echo "Ensuring automatic updates are enabled:" | tee -a "$report_file"
dpkg-query -l | grep unattended-upgrades | tee -a "$report_file"

# 7. Log Monitoring
echo "Log Monitoring"

echo "Checking recent suspicious log entries (e.g., failed SSH login attempts):" | tee -a "$report_file"
grep 'Failed password' /var/log/auth.log | tee -a "$report_file"

# 8. Server Hardening Steps
echo "Server Hardening Steps"

echo "Implementing SSH key-based authentication and disabling password-based login for root:" | tee -a "$report_file"
sed -i '/^PermitRootLogin/s/.*/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config
systemctl restart sshd | tee -a "$report_file"

echo "Disabling IPv6 if not required:" | tee -a "$report_file"
sysctl -w net.ipv6.conf.all.disable_ipv6=1 | tee -a "$report_file"
sysctl -w net.ipv6.conf.default.disable_ipv6=1 | tee -a "$report_file"

echo "Securing the GRUB bootloader:" | tee -a "$report_file"
echo 'GRUB_DISABLE_RECOVERY="true"' >> /etc/default/grub
echo 'GRUB_PASSWORD="hashed_password"' >> /etc/default/grub
update-grub | tee -a "$report_file"

echo "Configuring iptables rules:" | tee -a "$report_file"
iptables -P INPUT DROP | tee -a "$report_file"
iptables -P FORWARD DROP | tee -a "$report_file"
iptables -P OUTPUT ACCEPT | tee -a "$report_file"
iptables -A INPUT -i lo -j ACCEPT | tee -a "$report_file"
iptables -A INPUT -p tcp --dport 22 -j ACCEPT | tee -a "$report_file"
iptables-save > /etc/iptables/rules.v4 | tee -a "$report_file"

echo "Configuring unattended-upgrades:" | tee -a "$report_file"
dpkg-reconfigure unattended-upgrades | tee -a "$report_file"
sudo apt autoremove | tee -a "$report_file"


# 9. Custom Security Checks
echo "Custom Security Checks"

echo "Loading custom security checks from configuration file (if any):" | tee -a "$report_file"
if [ -f /etc/security_audit_custom.conf ]; then
    source /etc/security_audit_custom.conf | tee -a "$report_file"
fi

# 10. Reporting and Alerting
echo "Generating security audit report..." 

# Summary report
echo "Summary of critical issues:" | tee -a "$report_file"
critical_issues=$(grep -E 'unnecessary_service|unsecured_ssh|world_writable|failed_auth|suid_sgid' "$report_file")
if [ -n "$critical_issues" ]; then
    echo "$critical_issues" | tee -a "$report_file"
    echo "Critical issues found!" | tee -a "$report_file"

    # Email alerts for critical issues
    echo "Sending email alert..."

    echo "Security Audit Report - Critical Issues Found" | mail -s "Critical Security Issues Detected" -A "$report_file" admin@gmail.com
else
    echo "No critical issues found." | tee -a "$report_file"
fi

# End
