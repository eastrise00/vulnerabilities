#!/usr/bin/env python3
"""
Juniper SRX Configuration Security Checker
IT Security Specialist - ISP/NOC

This script performs detailed security configuration analysis on Juniper SRX routers
to identify misconfigurations, compliance issues, and security vulnerabilities.
"""

import os
import sys
import yaml
import json
import re
from datetime import datetime
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass
from netmiko import ConnectHandler
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

console = Console()

@dataclass
class SecurityCheck:
    """Data class for security check results"""
    check_name: str
    description: str
    status: str  # PASS, FAIL, WARNING
    details: str
    severity: str  # LOW, MEDIUM, HIGH, CRITICAL
    recommendation: str

@dataclass
class ConfigurationIssue:
    """Data class for configuration issues"""
    category: str
    issue: str
    severity: str
    line_number: Optional[int] = None
    configuration: Optional[str] = None
    remediation: Optional[str] = None

class JuniperConfigChecker:
    """Juniper SRX configuration security checker"""
    
    def __init__(self, config_file: str = "config.yaml"):
        """Initialize the configuration checker"""
        self.config = self._load_config(config_file)
        self.security_checks = []
        self.configuration_issues = []
        
    def _load_config(self, config_file: str) -> Dict:
        """Load configuration from YAML file"""
        try:
            with open(config_file, 'r') as f:
                return yaml.safe_load(f)
        except FileNotFoundError:
            console.print(f"[red]Configuration file {config_file} not found![/red]")
            sys.exit(1)
        except yaml.YAMLError as e:
            console.print(f"[red]Error parsing configuration file: {e}[/red]")
            sys.exit(1)
    
    def check_router_configuration(self, router_config: Dict) -> List[SecurityCheck]:
        """Check router configuration for security issues"""
        console.print(f"[blue]Checking configuration for {router_config['name']}...[/blue]")
        
        checks = []
        
        try:
            # Connect to router
            device = {
                'device_type': 'juniper_junos',
                'host': router_config['ip'],
                'username': router_config['username'],
                'password': os.getenv('ROUTER_PASSWORD'),
                'port': 22,
                'timeout': 30
            }
            
            with ConnectHandler(**device) as connection:
                # Get full configuration
                config_output = connection.send_command('show configuration | display set')
                
                # Perform security checks
                checks.extend(self._check_authentication_config(config_output))
                checks.extend(self._check_services_config(config_output))
                checks.extend(self._check_security_policies(config_output))
                checks.extend(self._check_logging_config(config_output))
                checks.extend(self._check_management_access(config_output))
                checks.extend(self._check_interface_security(config_output))
                checks.extend(self._check_system_security(config_output))
                
        except Exception as e:
            console.print(f"[red]Failed to check {router_config['name']}: {e}[/red]")
            checks.append(SecurityCheck(
                check_name="Connection Test",
                description="Test connection to router",
                status="FAIL",
                details=f"Connection failed: {e}",
                severity="CRITICAL",
                recommendation="Check network connectivity and credentials"
            ))
        
        return checks
    
    def _check_authentication_config(self, config: str) -> List[SecurityCheck]:
        """Check authentication configuration"""
        checks = []
        
        # Check for default passwords
        if re.search(r'set system root-authentication plain-text-password', config):
            checks.append(SecurityCheck(
                check_name="Default Password",
                description="Check for default or plain-text passwords",
                status="FAIL",
                details="Plain-text password found in configuration",
                severity="CRITICAL",
                recommendation="Use encrypted passwords and change default credentials"
            ))
        
        # Check for weak authentication methods
        if re.search(r'set system authentication-order password', config):
            checks.append(SecurityCheck(
                check_name="Weak Authentication",
                description="Check authentication methods",
                status="WARNING",
                details="Password-only authentication detected",
                severity="MEDIUM",
                recommendation="Implement stronger authentication (RADIUS, TACACS+)"
            ))
        
        # Check for SSH key authentication
        if re.search(r'set system authentication-order ssh', config):
            checks.append(SecurityCheck(
                check_name="SSH Authentication",
                description="Check for SSH key authentication",
                status="PASS",
                details="SSH authentication configured",
                severity="LOW",
                recommendation="Good security practice"
            ))
        
        return checks
    
    def _check_services_config(self, config: str) -> List[SecurityCheck]:
        """Check services configuration"""
        checks = []
        
        # Check for unnecessary services
        dangerous_services = [
            'telnet',
            'ftp',
            'http',
            'finger',
            'rsh',
            'rlogin'
        ]
        
        for service in dangerous_services:
            if re.search(f'set system services {service}', config):
                checks.append(SecurityCheck(
                    check_name=f"Unnecessary Service: {service.upper()}",
                    description=f"Check for {service.upper()} service",
                    status="FAIL",
                    details=f"{service.upper()} service is enabled",
                    severity="HIGH",
                    recommendation=f"Disable {service.upper()} service if not required"
                ))
        
        # Check for J-Web (potential vulnerability)
        if re.search(r'set system services web-management', config):
            checks.append(SecurityCheck(
                check_name="J-Web Interface",
                description="Check J-Web interface configuration",
                status="WARNING",
                details="J-Web interface is enabled",
                severity="HIGH",
                recommendation="Consider disabling J-Web or restrict access to management networks"
            ))
        
        # Check for HTTPS
        if re.search(r'set system services https', config):
            checks.append(SecurityCheck(
                check_name="HTTPS Service",
                description="Check for HTTPS service",
                status="PASS",
                details="HTTPS service is enabled",
                severity="LOW",
                recommendation="Good security practice"
            ))
        
        return checks
    
    def _check_security_policies(self, config: str) -> List[SecurityCheck]:
        """Check security policies configuration"""
        checks = []
        
        # Check for default security policies
        if re.search(r'set security policies default-policy', config):
            checks.append(SecurityCheck(
                check_name="Default Security Policy",
                description="Check for default security policy",
                status="WARNING",
                details="Default security policy is configured",
                severity="MEDIUM",
                recommendation="Review and customize security policies for your environment"
            ))
        
        # Check for explicit deny policies
        if re.search(r'set security policies from-zone.*to-zone.*policy.*then deny', config):
            checks.append(SecurityCheck(
                check_name="Explicit Deny Policies",
                description="Check for explicit deny policies",
                status="PASS",
                details="Explicit deny policies found",
                severity="LOW",
                recommendation="Good security practice"
            ))
        
        # Check for logging on policies
        if re.search(r'set security policies.*then.*log', config):
            checks.append(SecurityCheck(
                check_name="Policy Logging",
                description="Check for policy logging",
                status="PASS",
                details="Policy logging is configured",
                severity="LOW",
                recommendation="Good security practice"
            ))
        
        return checks
    
    def _check_logging_config(self, config: str) -> List[SecurityCheck]:
        """Check logging configuration"""
        checks = []
        
        # Check for syslog configuration
        if re.search(r'set system syslog', config):
            checks.append(SecurityCheck(
                check_name="Syslog Configuration",
                description="Check for syslog configuration",
                status="PASS",
                details="Syslog is configured",
                severity="LOW",
                recommendation="Good security practice"
            ))
        else:
            checks.append(SecurityCheck(
                check_name="Syslog Configuration",
                description="Check for syslog configuration",
                status="FAIL",
                details="No syslog configuration found",
                severity="MEDIUM",
                recommendation="Configure syslog for security monitoring"
            ))
        
        # Check for security logging
        if re.search(r'set system syslog.*security', config):
            checks.append(SecurityCheck(
                check_name="Security Logging",
                description="Check for security event logging",
                status="PASS",
                details="Security logging is configured",
                severity="LOW",
                recommendation="Good security practice"
            ))
        
        return checks
    
    def _check_management_access(self, config: str) -> List[SecurityCheck]:
        """Check management access configuration"""
        checks = []
        
        # Check for management interface restrictions
        if re.search(r'set system services ssh client-alive-interval', config):
            checks.append(SecurityCheck(
                check_name="SSH Timeout",
                description="Check SSH client timeout configuration",
                status="PASS",
                details="SSH timeout is configured",
                severity="LOW",
                recommendation="Good security practice"
            ))
        
        # Check for SSH protocol version
        if re.search(r'set system services ssh protocol-version v2', config):
            checks.append(SecurityCheck(
                check_name="SSH Protocol Version",
                description="Check SSH protocol version",
                status="PASS",
                details="SSH v2 is configured",
                severity="LOW",
                recommendation="Good security practice"
            ))
        
        # Check for management interface access lists
        if re.search(r'set system services ssh client-alive-count-max', config):
            checks.append(SecurityCheck(
                check_name="SSH Connection Limits",
                description="Check SSH connection limits",
                status="PASS",
                details="SSH connection limits are configured",
                severity="LOW",
                recommendation="Good security practice"
            ))
        
        return checks
    
    def _check_interface_security(self, config: str) -> List[SecurityCheck]:
        """Check interface security configuration"""
        checks = []
        
        # Check for interface descriptions
        if re.search(r'set interfaces.*description', config):
            checks.append(SecurityCheck(
                check_name="Interface Documentation",
                description="Check for interface descriptions",
                status="PASS",
                details="Interface descriptions are configured",
                severity="LOW",
                recommendation="Good operational practice"
            ))
        
        # Check for unused interfaces
        if re.search(r'set interfaces.*disable', config):
            checks.append(SecurityCheck(
                check_name="Unused Interfaces",
                description="Check for disabled unused interfaces",
                status="PASS",
                details="Unused interfaces are disabled",
                severity="LOW",
                recommendation="Good security practice"
            ))
        
        return checks
    
    def _check_system_security(self, config: str) -> List[SecurityCheck]:
        """Check system security configuration"""
        checks = []
        
        # Check for NTP configuration
        if re.search(r'set system ntp', config):
            checks.append(SecurityCheck(
                check_name="NTP Configuration",
                description="Check for NTP configuration",
                status="PASS",
                details="NTP is configured",
                severity="LOW",
                recommendation="Good operational practice"
            ))
        
        # Check for DNS configuration
        if re.search(r'set system name-server', config):
            checks.append(SecurityCheck(
                check_name="DNS Configuration",
                description="Check for DNS configuration",
                status="PASS",
                details="DNS is configured",
                severity="LOW",
                recommendation="Good operational practice"
            ))
        
        # Check for hostname configuration
        if re.search(r'set system host-name', config):
            checks.append(SecurityCheck(
                check_name="Hostname Configuration",
                description="Check for hostname configuration",
                status="PASS",
                details="Hostname is configured",
                severity="LOW",
                recommendation="Good operational practice"
            ))
        
        return checks
    
    def generate_compliance_report(self, router_name: str, checks: List[SecurityCheck]) -> str:
        """Generate compliance report for router"""
        report = f"""
# Juniper SRX Configuration Security Report
Router: {router_name}
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

## Executive Summary
- Total Checks: {len(checks)}
- Passed: {sum(1 for c in checks if c.status == 'PASS')}
- Failed: {sum(1 for c in checks if c.status == 'FAIL')}
- Warnings: {sum(1 for c in checks if c.status == 'WARNING')}
- Critical Issues: {sum(1 for c in checks if c.severity == 'CRITICAL')}
- High Issues: {sum(1 for c in checks if c.severity == 'HIGH')}

## Detailed Results
"""
        
        # Group by severity
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            severity_checks = [c for c in checks if c.severity == severity]
            if severity_checks:
                report += f"\n### {severity} Severity Issues\n"
                for check in severity_checks:
                    status_icon = "✅" if check.status == "PASS" else "❌" if check.status == "FAIL" else "⚠️"
                    report += f"""
#### {status_icon} {check.check_name}
- **Status**: {check.status}
- **Description**: {check.description}
- **Details**: {check.details}
- **Recommendation**: {check.recommendation}
"""
        
        return report
    
    def display_results(self, router_name: str, checks: List[SecurityCheck]):
        """Display results in rich format"""
        console.print(f"\n[bold blue]Configuration Security Results for {router_name}[/bold blue]")
        
        # Summary table
        summary_table = Table(title="Security Check Summary")
        summary_table.add_column("Status", style="cyan")
        summary_table.add_column("Count", style="green")
        summary_table.add_column("Severity", style="red")
        
        for status in ['PASS', 'FAIL', 'WARNING']:
            status_checks = [c for c in checks if c.status == status]
            if status_checks:
                summary_table.add_row(
                    status,
                    str(len(status_checks)),
                    f"{sum(1 for c in status_checks if c.severity == 'CRITICAL')} Critical"
                )
        
        console.print(summary_table)
        
        # Critical and High issues
        critical_issues = [c for c in checks if c.severity in ['CRITICAL', 'HIGH'] and c.status != 'PASS']
        if critical_issues:
            console.print("\n[bold red]Critical and High Issues:[/bold red]")
            for issue in critical_issues:
                console.print(f"[red]❌ {issue.check_name}[/red]")
                console.print(f"   {issue.details}")
                console.print(f"   Recommendation: {issue.recommendation}\n")
    
    def run_configuration_audit(self):
        """Run configuration audit on all routers"""
        console.print(Panel.fit("[bold blue]Juniper SRX Configuration Security Audit[/bold blue]"))
        
        all_checks = {}
        
        for router_config in self.config['routers']:
            checks = self.check_router_configuration(router_config)
            all_checks[router_config['name']] = checks
            
            # Display results
            self.display_results(router_config['name'], checks)
            
            # Generate report
            report = self.generate_compliance_report(router_config['name'], checks)
            
            # Save report
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            report_file = f"config_audit_{router_config['name']}_{timestamp}.txt"
            
            with open(report_file, 'w') as f:
                f.write(report)
            
            console.print(f"[green]Report saved to: {report_file}[/green]")
        
        # Generate overall summary
        self._generate_overall_summary(all_checks)
    
    def _generate_overall_summary(self, all_checks: Dict[str, List[SecurityCheck]]):
        """Generate overall summary across all routers"""
        console.print("\n[bold green]Overall Security Summary[/bold green]")
        
        summary_table = Table(title="Overall Security Status")
        summary_table.add_column("Router", style="cyan")
        summary_table.add_column("Pass", style="green")
        summary_table.add_column("Fail", style="red")
        summary_table.add_column("Warning", style="yellow")
        summary_table.add_column("Critical", style="red")
        
        for router_name, checks in all_checks.items():
            passed = sum(1 for c in checks if c.status == 'PASS')
            failed = sum(1 for c in checks if c.status == 'FAIL')
            warnings = sum(1 for c in checks if c.status == 'WARNING')
            critical = sum(1 for c in checks if c.severity == 'CRITICAL' and c.status != 'PASS')
            
            summary_table.add_row(router_name, str(passed), str(failed), str(warnings), str(critical))
        
        console.print(summary_table)

def main():
    """Main function"""
    console.print(Panel.fit("[bold green]Juniper SRX Configuration Security Checker[/bold green]\n[italic]IT Security Specialist - ISP/NOC[/italic]"))
    
    checker = JuniperConfigChecker()
    checker.run_configuration_audit()

if __name__ == "__main__":
    main()
