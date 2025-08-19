#!/usr/bin/env python3
"""
Setup script for Juniper SRX Vulnerability Monitoring System
IT Security Specialist - ISP/NOC

This script helps set up and configure the vulnerability monitoring system.
"""

import os
import sys
import yaml
import getpass
from pathlib import Path
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt, Confirm
from rich.table import Table

console = Console()

def main():
    """Main setup function"""
    console.print(Panel.fit("[bold green]Juniper SRX Vulnerability Monitoring System Setup[/bold green]\n[italic]IT Security Specialist - ISP/NOC[/italic]"))
    
    console.print("\n[blue]Welcome to the Juniper SRX Vulnerability Monitoring System setup![/blue]")
    console.print("This wizard will help you configure the system for your environment.\n")
    
    # Check if config.yaml exists
    if os.path.exists('config.yaml'):
        overwrite = Confirm.ask("Configuration file already exists. Overwrite?", default=False)
        if not overwrite:
            console.print("[yellow]Setup cancelled. Existing configuration preserved.[/yellow]")
            return
    
    # Get router information
    console.print("\n[bold]Step 1: Router Configuration[/bold]")
    
    routers = []
    while True:
        router = {}
        
        router['name'] = Prompt.ask("Router name", default=f"SRX-{len(routers)+1:02d}")
        router['ip'] = Prompt.ask("Router IP address")
        router['username'] = Prompt.ask("SSH username", default="admin")
        router['model'] = Prompt.ask("Router model", default="SRX3400")
        router['junos_version'] = Prompt.ask("Junos version", default="20.2R3-S2.5")
        router['location'] = Prompt.ask("Location", default="Data Center")
        router['critical'] = Confirm.ask("Is this a critical router?", default=True)
        
        routers.append(router)
        
        add_another = Confirm.ask("Add another router?", default=False)
        if not add_another:
            break
    
    # Get monitoring settings
    console.print("\n[bold]Step 2: Monitoring Configuration[/bold]")
    
    scan_interval = Prompt.ask("Vulnerability scan interval (hours)", default="6")
    advisory_check_interval = Prompt.ask("Security advisory check interval (hours)", default="2")
    config_backup_interval = Prompt.ask("Configuration backup interval (hours)", default="24")
    
    # Get alert configuration
    console.print("\n[bold]Step 3: Alert Configuration[/bold]")
    
    enable_email = Confirm.ask("Enable email alerts?", default=True)
    
    email_config = {}
    if enable_email:
        email_config['enabled'] = True
        email_config['smtp_server'] = Prompt.ask("SMTP server", default="smtp.company.com")
        email_config['smtp_port'] = Prompt.ask("SMTP port", default="587")
        email_config['from_address'] = Prompt.ask("From email address", default="security@company.com")
        
        to_addresses = []
        while True:
            to_address = Prompt.ask("To email address")
            to_addresses.append(to_address)
            
            add_another = Confirm.ask("Add another email address?", default=False)
            if not add_another:
                break
        
        email_config['to_addresses'] = to_addresses
    else:
        email_config['enabled'] = False
        email_config['smtp_server'] = ""
        email_config['smtp_port'] = 587
        email_config['from_address'] = ""
        email_config['to_addresses'] = []
    
    # Get vulnerability sources
    console.print("\n[bold]Step 4: Vulnerability Sources[/bold]")
    
    sources = {}
    sources['juniper_security_advisories'] = Confirm.ask("Monitor Juniper security advisories?", default=True)
    sources['cve_database'] = Confirm.ask("Monitor CVE database?", default=True)
    sources['nist_nvd'] = Confirm.ask("Monitor NIST NVD?", default=True)
    sources['juniper_psirt'] = Confirm.ask("Monitor Juniper PSIRT?", default=True)
    
    # Get reporting configuration
    console.print("\n[bold]Step 5: Reporting Configuration[/bold]")
    
    reporting = {}
    reporting['daily_report'] = Confirm.ask("Generate daily reports?", default=True)
    reporting['weekly_summary'] = Confirm.ask("Generate weekly summaries?", default=True)
    reporting['monthly_compliance'] = Confirm.ask("Generate monthly compliance reports?", default=True)
    reporting['report_retention_days'] = Prompt.ask("Report retention (days)", default="90")
    
    output_formats = []
    if Confirm.ask("Generate HTML reports?", default=True):
        output_formats.append("html")
    if Confirm.ask("Generate PDF reports?", default=False):
        output_formats.append("pdf")
    if Confirm.ask("Generate Excel reports?", default=True):
        output_formats.append("excel")
    
    reporting['output_format'] = output_formats
    
    # Get compliance settings
    console.print("\n[bold]Step 6: Compliance Settings[/bold]")
    
    compliance = {}
    compliance['check_configuration_changes'] = Confirm.ask("Check for configuration changes?", default=True)
    compliance['verify_firmware_integrity'] = Confirm.ask("Verify firmware integrity?", default=True)
    compliance['monitor_user_accounts'] = Confirm.ask("Monitor user accounts?", default=True)
    compliance['audit_logging'] = Confirm.ask("Audit logging configuration?", default=True)
    compliance['backup_verification'] = Confirm.ask("Verify configuration backups?", default=True)
    
    # Create configuration
    config = {
        'routers': routers,
        'monitoring': {
            'scan_interval_hours': int(scan_interval),
            'security_advisory_check_interval_hours': int(advisory_check_interval),
            'configuration_backup_interval_hours': int(config_backup_interval),
            'vulnerability_scan_timeout': 300,
            'max_concurrent_scans': 5
        },
        'alerts': {
            'email': email_config,
            'slack': {
                'enabled': False,
                'webhook_url': "",
                'channel': "#security-alerts"
            },
            'severity_levels': {
                'critical': ['email', 'slack'] if enable_email else [],
                'high': ['email'] if enable_email else [],
                'medium': ['email'] if enable_email else [],
                'low': []
            }
        },
        'vulnerability_sources': sources,
        'reporting': reporting,
        'compliance': compliance
    }
    
    # Save configuration
    with open('config.yaml', 'w') as f:
        yaml.dump(config, f, default_flow_style=False, indent=2)
    
    # Create .env file
    console.print("\n[bold]Step 7: Environment Configuration[/bold]")
    
    router_password = getpass.getpass("Enter router SSH password: ")
    
    env_content = f"""# Juniper SRX Vulnerability Monitoring System
# Environment Variables Configuration

# Router Authentication
ROUTER_PASSWORD={router_password}

# Email Configuration
"""
    
    if enable_email:
        smtp_username = Prompt.ask("SMTP username (optional)")
        smtp_password = getpass.getpass("SMTP password (optional): ")
        
        if smtp_username:
            env_content += f"SMTP_USERNAME={smtp_username}\n"
        if smtp_password:
            env_content += f"SMTP_PASSWORD={smtp_password}\n"
    
    env_content += """
# Optional: Logging Configuration
# LOG_LEVEL=INFO
# LOG_FILE=juniper_monitor.log

# Optional: Database Configuration
# DB_PATH=security_advisories.db
"""
    
    with open('.env', 'w') as f:
        f.write(env_content)
    
    # Display summary
    console.print("\n[bold green]Setup Complete![/bold green]")
    
    summary_table = Table(title="Configuration Summary")
    summary_table.add_column("Setting", style="cyan")
    summary_table.add_column("Value", style="green")
    
    summary_table.add_row("Routers Configured", str(len(routers)))
    summary_table.add_row("Scan Interval", f"{scan_interval} hours")
    summary_table.add_row("Email Alerts", "Enabled" if enable_email else "Disabled")
    summary_table.add_row("Vulnerability Sources", str(sum(sources.values())))
    summary_table.add_row("Report Formats", ", ".join(output_formats))
    
    console.print(summary_table)
    
    console.print("\n[blue]Next Steps:[/blue]")
    console.print("1. Review the generated config.yaml file")
    console.print("2. Test connectivity to your routers")
    console.print("3. Run: python juniper_vulnerability_monitor.py scan")
    console.print("4. Set up automated monitoring with cron jobs")
    
    console.print("\n[green]Configuration files created:[/green]")
    console.print("- config.yaml (main configuration)")
    console.print("- .env (environment variables)")
    
    console.print("\n[yellow]Important:[/yellow]")
    console.print("- Keep your .env file secure")
    console.print("- Test in a lab environment first")
    console.print("- Review security reports regularly")

if __name__ == "__main__":
    main()
