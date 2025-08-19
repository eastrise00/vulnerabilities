# Juniper SRX Vulnerability Monitoring System
## IT Security Specialist - ISP/NOC

A comprehensive vulnerability monitoring and security management system for Juniper SRX routers running Junos 20.2R3-S2.5. This system provides automated vulnerability scanning, security advisory tracking, configuration compliance checking, and alerting capabilities.

## 🚀 Features

### Core Capabilities
- **Automated Vulnerability Scanning**: Continuous monitoring of Juniper SRX routers for security vulnerabilities
- **Security Advisory Tracking**: Real-time monitoring of Juniper PSIRT and CVE databases
- **Configuration Compliance**: Automated security configuration auditing
- **Multi-Source Monitoring**: Integration with Juniper PSIRT, NIST NVD, and CVE databases
- **Automated Alerting**: Email notifications for critical security issues
- **Comprehensive Reporting**: Detailed security reports in multiple formats

### Security Checks
- **Authentication Security**: Default passwords, weak authentication methods
- **Service Security**: Unnecessary services, J-Web vulnerabilities
- **Policy Compliance**: Security policies, logging configuration
- **Management Access**: SSH configuration, access controls
- **Interface Security**: Interface documentation, unused interfaces
- **System Security**: NTP, DNS, hostname configuration

## 📋 Prerequisites

- Python 3.8 or higher
- Network access to Juniper SRX routers
- SSH access credentials
- SMTP server for email alerts (optional)

## 🛠️ Installation

1. **Clone the repository**:
```bash
git clone <repository-url>
cd vulnerabilities-
```

2. **Install dependencies**:
```bash
pip install -r requirements.txt
```

3. **Configure environment variables**:
Create a `.env` file in the project root:
```bash
# Router credentials
ROUTER_PASSWORD=your_router_password

# Email configuration (optional)
SMTP_USERNAME=your_email@company.com
SMTP_PASSWORD=your_email_password
```

4. **Update configuration**:
Edit `config.yaml` with your router details and monitoring preferences.

## ⚙️ Configuration

### Router Configuration
Update the `config.yaml` file with your router information:

```yaml
routers:
  - name: "SRX-01"
    ip: "192.168.1.1"
    username: "admin"
    model: "SRX3400"
    junos_version: "20.2R3-S2.5"
    location: "Primary DC"
    critical: true
```

### Monitoring Settings
```yaml
monitoring:
  scan_interval_hours: 6
  security_advisory_check_interval_hours: 2
  configuration_backup_interval_hours: 24
```

### Alert Configuration
```yaml
alerts:
  email:
    enabled: true
    smtp_server: "smtp.company.com"
    smtp_port: 587
    from_address: "security@company.com"
    to_addresses: ["noc@company.com", "security@company.com"]
```

## 🚀 Usage

### 1. Vulnerability Monitoring
Run a complete vulnerability scan:
```bash
python juniper_vulnerability_monitor.py scan
```

Start continuous monitoring:
```bash
python juniper_vulnerability_monitor.py monitor
```

### 2. Configuration Security Audit
Run configuration compliance checks:
```bash
python juniper_config_checker.py
```

### 3. Security Advisory Tracking
Check for new security advisories:
```bash
python juniper_security_advisory_tracker.py
```

## 📊 Output and Reports

### Generated Reports
- **Security Reports**: `security_report_YYYYMMDD_HHMMSS.txt`
- **Configuration Audits**: `config_audit_ROUTERNAME_YYYYMMDD_HHMMSS.txt`
- **Advisory Reports**: `advisory_report_YYYYMMDD_HHMMSS.txt`

### Report Contents
- Executive summary with vulnerability counts
- Detailed findings with severity levels
- Remediation recommendations
- Configuration compliance status
- Security advisory tracking

## 🔒 Security Features

### Vulnerability Detection
- **J-Web RCE Vulnerabilities**: Detection of known J-Web interface vulnerabilities
- **CVE Database Integration**: Real-time CVE checking for Juniper SRX
- **PSIRT Monitoring**: Juniper security advisory tracking
- **Configuration Vulnerabilities**: Security misconfiguration detection

### Compliance Checking
- **Authentication Security**: SSH, password policies
- **Service Security**: Unnecessary service detection
- **Policy Compliance**: Security policy verification
- **Logging Configuration**: Syslog and security logging checks

### Alerting System
- **Critical Alerts**: Immediate notification for critical vulnerabilities
- **High Severity**: Email alerts for high-priority issues
- **Configuration Changes**: Monitoring for unauthorized changes
- **Advisory Notifications**: New security advisory alerts

## 🛡️ Best Practices

### Router Security
1. **Disable J-Web**: Consider disabling J-Web interface if not required
2. **Strong Authentication**: Implement RADIUS/TACACS+ authentication
3. **Access Control**: Restrict management access to specific networks
4. **Regular Updates**: Keep Junos version updated
5. **Configuration Backups**: Regular configuration backups

### Monitoring Best Practices
1. **Scheduled Scans**: Run vulnerability scans during maintenance windows
2. **Alert Tuning**: Configure appropriate alert thresholds
3. **Report Review**: Regular review of security reports
4. **Remediation Tracking**: Track vulnerability remediation progress
5. **Documentation**: Maintain security documentation

## 🔧 Troubleshooting

### Common Issues

**Connection Failures**:
- Verify router IP addresses and credentials
- Check network connectivity
- Ensure SSH access is enabled

**Permission Errors**:
- Verify user has appropriate privileges
- Check SSH key authentication
- Review router access policies

**Alert Delivery Issues**:
- Verify SMTP configuration
- Check email server connectivity
- Review firewall rules for SMTP

### Log Files
- **Application Logs**: `juniper_monitor.log`
- **Database**: `security_advisories.db`
- **Reports**: Generated in project directory

## 📈 Monitoring Dashboard

The system provides rich console output with:
- **Progress Indicators**: Real-time scan progress
- **Color-coded Results**: Severity-based color coding
- **Summary Tables**: Quick overview of findings
- **Detailed Reports**: Comprehensive security analysis

## 🔄 Automation

### Scheduled Tasks
Set up automated monitoring using cron jobs:

```bash
# Daily vulnerability scan
0 2 * * * cd /path/to/project && python juniper_vulnerability_monitor.py scan

# Hourly advisory check
0 * * * * cd /path/to/project && python juniper_security_advisory_tracker.py

# Weekly configuration audit
0 3 * * 0 cd /path/to/project && python juniper_config_checker.py
```

### Continuous Monitoring
For 24/7 monitoring, run the monitor mode:
```bash
python juniper_vulnerability_monitor.py monitor
```

## 📞 Support

For issues and questions:
1. Check the troubleshooting section
2. Review log files for error details
3. Verify configuration settings
4. Test connectivity to routers

## 🔄 Updates and Maintenance

### Regular Maintenance
- **Weekly**: Review security reports and update configurations
- **Monthly**: Update Junos versions and security policies
- **Quarterly**: Comprehensive security assessment

### System Updates
- Monitor for new vulnerabilities
- Update monitoring scripts as needed
- Review and adjust alert thresholds
- Update router configurations based on findings

## 📚 Additional Resources

- [Juniper Security Advisories](https://supportportal.juniper.net/s/security-advisories)
- [Juniper PSIRT](https://supportportal.juniper.net/s/psirt)
- [NIST NVD](https://nvd.nist.gov/)
- [CVE Database](https://cve.mitre.org/)

## ⚠️ Disclaimer

This tool is designed for security professionals to monitor their own infrastructure. Always:
- Test in a lab environment first
- Follow your organization's security policies
- Obtain proper authorization before scanning
- Respect network and system resources
- Keep credentials secure

---

**Developed for IT Security Specialists in ISP/NOC environments**
**Compatible with Juniper SRX routers running Junos 20.2R3-S2.5**
