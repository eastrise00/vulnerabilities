#!/usr/bin/env python3
"""
Juniper Security Advisory Tracker
IT Security Specialist - ISP/NOC

This script monitors Juniper security advisories, PSIRT feeds, and CVE databases
for new vulnerabilities affecting Juniper SRX routers running Junos 20.2R3-S2.5.
"""

import os
import sys
import yaml
import json
import time
import requests
import sqlite3
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from pathlib import Path
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from bs4 import BeautifulSoup
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

console = Console()

@dataclass
class SecurityAdvisory:
    """Data class for security advisory information"""
    advisory_id: str
    title: str
    description: str
    severity: str
    affected_versions: List[str]
    published_date: str
    last_updated: str
    cve_ids: List[str]
    source: str
    url: str
    remediation: Optional[str] = None
    workaround: Optional[str] = None

class JuniperSecurityAdvisoryTracker:
    """Juniper security advisory tracker"""
    
    def __init__(self, config_file: str = "config.yaml"):
        """Initialize the advisory tracker"""
        self.config = self._load_config(config_file)
        self.db_path = "security_advisories.db"
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Juniper-Security-Tracker/1.0 (ISP-NOC)'
        })
        self._init_database()
        
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
    
    def _init_database(self):
        """Initialize SQLite database for tracking advisories"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS advisories (
                advisory_id TEXT PRIMARY KEY,
                title TEXT,
                description TEXT,
                severity TEXT,
                affected_versions TEXT,
                published_date TEXT,
                last_updated TEXT,
                cve_ids TEXT,
                source TEXT,
                url TEXT,
                remediation TEXT,
                workaround TEXT,
                first_seen TEXT,
                last_checked TEXT
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def check_juniper_psirt(self) -> List[SecurityAdvisory]:
        """Check Juniper PSIRT for new security advisories"""
        console.print("[blue]Checking Juniper PSIRT for new advisories...[/blue]")
        
        advisories = []
        
        # Juniper PSIRT RSS feed and advisory pages
        psirt_urls = [
            "https://supportportal.juniper.net/s/feed/0D52T00006i5TqPSAU",
            "https://supportportal.juniper.net/s/article/2023-12-Security-Bulletin-Junos-OS-SRX-Series-and-EX-Series-Multiple-vulnerabilities-in-J-Web-can-be-combined-to-achieve-Remote-Code-Execution-RCE",
            "https://supportportal.juniper.net/s/article/2023-11-Security-Bulletin-Junos-OS-SRX-Series-and-EX-Series-Multiple-vulnerabilities-in-J-Web-can-be-combined-to-achieve-Remote-Code-Execution-RCE",
            "https://supportportal.juniper.net/s/article/2023-10-Security-Bulletin-Junos-OS-SRX-Series-and-EX-Series-Multiple-vulnerabilities-in-J-Web-can-be-combined-to-achieve-Remote-Code-Execution-RCE"
        ]
        
        for url in psirt_urls:
            try:
                response = self.session.get(url, timeout=30)
                if response.status_code == 200:
                    if url.endswith('.xml') or 'feed' in url:
                        # Parse RSS feed
                        advisories.extend(self._parse_rss_feed(response.content))
                    else:
                        # Parse advisory page
                        advisory = self._parse_advisory_page(response.content, url)
                        if advisory:
                            advisories.append(advisory)
                            
            except Exception as e:
                console.print(f"[red]Error checking PSIRT URL {url}: {e}[/red]")
        
        return advisories
    
    def _parse_rss_feed(self, content: bytes) -> List[SecurityAdvisory]:
        """Parse RSS feed for security advisories"""
        advisories = []
        
        try:
            soup = BeautifulSoup(content, 'xml')
            items = soup.find_all('item')
            
            for item in items:
                title = item.find('title')
                description = item.find('description')
                pub_date = item.find('pubDate')
                link = item.find('link')
                
                if title and 'security' in title.text.lower():
                    advisory = SecurityAdvisory(
                        advisory_id=self._extract_advisory_id(title.text),
                        title=title.text.strip(),
                        description=description.text.strip() if description else "",
                        severity=self._extract_severity(title.text),
                        affected_versions=self._extract_affected_versions(description.text if description else ""),
                        published_date=pub_date.text if pub_date else datetime.now().strftime("%Y-%m-%d"),
                        last_updated=datetime.now().strftime("%Y-%m-%d"),
                        cve_ids=self._extract_cve_ids(description.text if description else ""),
                        source="Juniper PSIRT",
                        url=link.text if link else "",
                        remediation=self._extract_remediation(description.text if description else "")
                    )
                    advisories.append(advisory)
                    
        except Exception as e:
            console.print(f"[red]Error parsing RSS feed: {e}[/red]")
        
        return advisories
    
    def _parse_advisory_page(self, content: bytes, url: str) -> Optional[SecurityAdvisory]:
        """Parse individual advisory page"""
        try:
            soup = BeautifulSoup(content, 'html.parser')
            
            # Extract title
            title_elem = soup.find('title') or soup.find('h1')
            title = title_elem.text.strip() if title_elem else "Unknown Advisory"
            
            # Extract description
            description_elem = soup.find('div', class_='description') or soup.find('p')
            description = description_elem.text.strip() if description_elem else ""
            
            # Extract severity
            severity = self._extract_severity(title)
            
            # Extract affected versions
            affected_versions = self._extract_affected_versions(description)
            
            # Extract CVE IDs
            cve_ids = self._extract_cve_ids(description)
            
            advisory = SecurityAdvisory(
                advisory_id=self._extract_advisory_id(title),
                title=title,
                description=description,
                severity=severity,
                affected_versions=affected_versions,
                published_date=datetime.now().strftime("%Y-%m-%d"),
                last_updated=datetime.now().strftime("%Y-%m-%d"),
                cve_ids=cve_ids,
                source="Juniper PSIRT",
                url=url,
                remediation=self._extract_remediation(description)
            )
            
            return advisory
            
        except Exception as e:
            console.print(f"[red]Error parsing advisory page: {e}[/red]")
            return None
    
    def _extract_advisory_id(self, text: str) -> str:
        """Extract advisory ID from text"""
        import re
        # Look for patterns like "2023-12-Security-Bulletin" or "PSIRT-2023-001"
        patterns = [
            r'(\d{4}-\d{2}-Security-Bulletin)',
            r'(PSIRT-\d{4}-\d{3})',
            r'(JSA-\d{4}-\d{3})'
        ]
        
        for pattern in patterns:
            match = re.search(pattern, text)
            if match:
                return match.group(1)
        
        # Fallback to hash of title
        return f"ADV-{hash(text) % 1000000:06d}"
    
    def _extract_severity(self, text: str) -> str:
        """Extract severity from text"""
        text_lower = text.lower()
        
        if any(word in text_lower for word in ['critical', 'severe']):
            return "critical"
        elif any(word in text_lower for word in ['high', 'important']):
            return "high"
        elif any(word in text_lower for word in ['medium', 'moderate']):
            return "medium"
        elif any(word in text_lower for word in ['low', 'minor']):
            return "low"
        else:
            return "medium"
    
    def _extract_affected_versions(self, text: str) -> List[str]:
        """Extract affected Junos versions from text"""
        import re
        
        # Look for Junos version patterns
        patterns = [
            r'Junos\s+(\d+\.\d+R\d+(?:-S\d+)?)',
            r'(\d+\.\d+R\d+(?:-S\d+)?)',
            r'version\s+(\d+\.\d+R\d+(?:-S\d+)?)'
        ]
        
        versions = []
        for pattern in patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            versions.extend(matches)
        
        # Remove duplicates and sort
        return sorted(list(set(versions)))
    
    def _extract_cve_ids(self, text: str) -> List[str]:
        """Extract CVE IDs from text"""
        import re
        
        # Look for CVE patterns
        cve_pattern = r'CVE-\d{4}-\d{4,7}'
        matches = re.findall(cve_pattern, text, re.IGNORECASE)
        
        return list(set(matches))
    
    def _extract_remediation(self, text: str) -> Optional[str]:
        """Extract remediation information from text"""
        # Look for remediation sections
        remediation_keywords = [
            'remediation',
            'solution',
            'fix',
            'patch',
            'update',
            'upgrade'
        ]
        
        lines = text.split('\n')
        for i, line in enumerate(lines):
            if any(keyword in line.lower() for keyword in remediation_keywords):
                # Return next few lines as remediation
                return '\n'.join(lines[i:i+5])
        
        return None
    
    def check_cve_database(self) -> List[SecurityAdvisory]:
        """Check CVE database for Juniper-related vulnerabilities"""
        console.print("[blue]Checking CVE database for Juniper vulnerabilities...[/blue]")
        
        advisories = []
        
        # Search terms for Juniper SRX
        search_terms = [
            "juniper srx",
            "junos 20.2",
            "juniper firewall",
            "juniper security"
        ]
        
        for term in search_terms:
            try:
                # Using NIST NVD API
                url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
                params = {
                    'keywordSearch': term,
                    'resultsPerPage': 20,
                    'pubStartDate': (datetime.now() - timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%S:000 UTC-00:00")
                }
                
                response = self.session.get(url, params=params, timeout=30)
                if response.status_code == 200:
                    data = response.json()
                    
                    for vuln_data in data.get('vulnerabilities', []):
                        cve = vuln_data.get('cve', {})
                        cve_id = cve.get('id', '')
                        
                        # Check if this affects Junos 20.2R3-S2.5
                        if self._affects_junos_version(cve, "20.2R3-S2.5"):
                            advisory = SecurityAdvisory(
                                advisory_id=cve_id,
                                title=cve.get('descriptions', [{}])[0].get('value', ''),
                                description=cve.get('descriptions', [{}])[0].get('value', ''),
                                severity=self._get_cvss_severity(cve),
                                affected_versions=["20.2R3-S2.5"],
                                published_date=cve.get('published', ''),
                                last_updated=cve.get('lastModified', ''),
                                cve_ids=[cve_id],
                                source="NIST NVD",
                                url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                                remediation="Check Juniper PSIRT for specific remediation guidance"
                            )
                            advisories.append(advisory)
                            
            except Exception as e:
                console.print(f"[red]Error checking CVE database for term '{term}': {e}[/red]")
        
        return advisories
    
    def _affects_junos_version(self, cve_data: Dict, junos_version: str) -> bool:
        """Check if a CVE affects the specific Junos version"""
        descriptions = cve_data.get('descriptions', [])
        for desc in descriptions:
            desc_text = desc.get('value', '').lower()
            if 'juniper' in desc_text and 'junos' in desc_text:
                # Check if our version is mentioned or implied
                if '20.2' in desc_text or 'srx' in desc_text:
                    return True
        return False
    
    def _get_cvss_severity(self, cve_data: Dict) -> str:
        """Extract CVSS severity from CVE data"""
        try:
            metrics = cve_data.get('metrics', {})
            cvss_v3 = metrics.get('cvssMetricV31', [{}])[0] or metrics.get('cvssMetricV30', [{}])[0]
            if cvss_v3:
                base_severity = cvss_v3.get('cvssData', {}).get('baseSeverity', 'MEDIUM')
                return base_severity.lower()
        except:
            pass
        return "medium"
    
    def save_advisory(self, advisory: SecurityAdvisory):
        """Save advisory to database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT OR REPLACE INTO advisories 
            (advisory_id, title, description, severity, affected_versions, 
             published_date, last_updated, cve_ids, source, url, remediation, 
             workaround, first_seen, last_checked)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            advisory.advisory_id,
            advisory.title,
            advisory.description,
            advisory.severity,
            json.dumps(advisory.affected_versions),
            advisory.published_date,
            advisory.last_updated,
            json.dumps(advisory.cve_ids),
            advisory.source,
            advisory.url,
            advisory.remediation,
            advisory.workaround,
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        ))
        
        conn.commit()
        conn.close()
    
    def get_new_advisories(self) -> List[SecurityAdvisory]:
        """Get new advisories that haven't been seen before"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('SELECT advisory_id FROM advisories')
        existing_ids = {row[0] for row in cursor.fetchall()}
        
        conn.close()
        
        # Check for new advisories
        psirt_advisories = self.check_juniper_psirt()
        cve_advisories = self.check_cve_database()
        
        all_advisories = psirt_advisories + cve_advisories
        new_advisories = []
        
        for advisory in all_advisories:
            if advisory.advisory_id not in existing_ids:
                new_advisories.append(advisory)
                self.save_advisory(advisory)
        
        return new_advisories
    
    def send_advisory_alert(self, advisory: SecurityAdvisory):
        """Send alert for new security advisory"""
        if not self.config['alerts']['email']['enabled']:
            return
        
        subject = f"New Juniper Security Advisory: {advisory.advisory_id}"
        
        message = f"""
New Juniper Security Advisory Detected

Advisory ID: {advisory.advisory_id}
Title: {advisory.title}
Severity: {advisory.severity.upper()}
Source: {advisory.source}
Published: {advisory.published_date}

Description:
{advisory.description[:500]}...

Affected Versions: {', '.join(advisory.affected_versions)}
CVE IDs: {', '.join(advisory.cve_ids)}

URL: {advisory.url}

Remediation:
{advisory.remediation or 'Check Juniper PSIRT for specific guidance'}

This advisory affects your Juniper SRX routers running Junos 20.2R3-S2.5.
Please review and take appropriate action.
        """
        
        try:
            msg = MIMEMultipart()
            msg['From'] = self.config['alerts']['email']['from_address']
            msg['To'] = ', '.join(self.config['alerts']['email']['to_addresses'])
            msg['Subject'] = f"[{advisory.severity.upper()}] {subject}"
            
            msg.attach(MIMEText(message, 'plain'))
            
            server = smtplib.SMTP(
                self.config['alerts']['email']['smtp_server'],
                self.config['alerts']['email']['smtp_port']
            )
            server.starttls()
            
            # Note: In production, use proper authentication
            # server.login(username, password)
            
            server.send_message(msg)
            server.quit()
            
            console.print(f"[green]Alert sent for advisory: {advisory.advisory_id}[/green]")
            
        except Exception as e:
            console.print(f"[red]Failed to send advisory alert: {e}[/red]")
    
    def generate_advisory_report(self) -> str:
        """Generate comprehensive advisory report"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT * FROM advisories 
            ORDER BY last_checked DESC
        ''')
        
        rows = cursor.fetchall()
        conn.close()
        
        report = f"""
# Juniper Security Advisory Report
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

## Executive Summary
- Total Advisories Tracked: {len(rows)}
- Critical Advisories: {sum(1 for row in rows if row[3] == 'critical')}
- High Severity Advisories: {sum(1 for row in rows if row[3] == 'high')}
- Advisories Affecting Junos 20.2R3-S2.5: {sum(1 for row in rows if '20.2R3-S2.5' in row[4])}

## Recent Advisories
"""
        
        # Show recent advisories
        for row in rows[:10]:  # Last 10 advisories
            report += f"""
### {row[1]} ({row[0]})
- **Severity**: {row[3].upper()}
- **Source**: {row[8]}
- **Published**: {row[5]}
- **Affected Versions**: {row[4]}
- **CVE IDs**: {row[7]}
- **URL**: {row[9]}

{row[2][:300]}...

---
"""
        
        return report
    
    def display_advisories(self, advisories: List[SecurityAdvisory]):
        """Display advisories in rich format"""
        if not advisories:
            console.print("[green]No new advisories found.[/green]")
            return
        
        table = Table(title="New Security Advisories")
        table.add_column("Advisory ID", style="cyan")
        table.add_column("Title", style="white")
        table.add_column("Severity", style="red")
        table.add_column("Source", style="blue")
        table.add_column("Affected Versions", style="yellow")
        
        for advisory in advisories:
            severity_color = {
                'critical': 'red',
                'high': 'orange',
                'medium': 'yellow',
                'low': 'green'
            }.get(advisory.severity, 'white')
            
            table.add_row(
                advisory.advisory_id,
                advisory.title[:50] + "..." if len(advisory.title) > 50 else advisory.title,
                f"[{severity_color}]{advisory.severity.upper()}[/{severity_color}]",
                advisory.source,
                ', '.join(advisory.affected_versions)
            )
        
        console.print(table)
    
    def run_advisory_check(self):
        """Run complete advisory check"""
        console.print(Panel.fit("[bold blue]Checking for New Security Advisories[/bold blue]"))
        
        new_advisories = self.get_new_advisories()
        
        if new_advisories:
            console.print(f"[yellow]Found {len(new_advisories)} new advisories![/yellow]")
            self.display_advisories(new_advisories)
            
            # Send alerts for critical and high severity advisories
            for advisory in new_advisories:
                if advisory.severity in ['critical', 'high']:
                    self.send_advisory_alert(advisory)
        else:
            console.print("[green]No new advisories found.[/green]")
        
        # Generate report
        report = self.generate_advisory_report()
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_file = f"advisory_report_{timestamp}.txt"
        
        with open(report_file, 'w') as f:
            f.write(report)
        
        console.print(f"[green]Advisory report saved to: {report_file}[/green]")

def main():
    """Main function"""
    console.print(Panel.fit("[bold green]Juniper Security Advisory Tracker[/bold green]\n[italic]IT Security Specialist - ISP/NOC[/italic]"))
    
    tracker = JuniperSecurityAdvisoryTracker()
    tracker.run_advisory_check()

if __name__ == "__main__":
    main()
