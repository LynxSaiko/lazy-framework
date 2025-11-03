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
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Connection': 'keep-alive',
        })
    
    def detect_device(self):
        """Detect MyRepublic router with improved detection"""
        console.print("\n[bold yellow]=== MyRepublic DETECTION ===[/bold yellow]")
        
        detection_results = {
            'is_myrepublic': False,
            'router_model': 'Unknown',
            'manufacturer': 'Unknown',
            'firmware': 'Unknown',
            'backdoors_found': []
        }
        
        try:
            # Try multiple endpoints for detection
            endpoints = [
                "/", "/index.html", "/main.html", "/status.html",
                "/login.html", "/admin/", "/cgi-bin/luci"
            ]
            
            for endpoint in endpoints:
                try:
                    url = f"{self.base_url}{endpoint}"
                    console.print(f"[*] Testing endpoint: {url}")
                    
                    r = self.session.get(url, timeout=10, allow_redirects=True)
                    html_content = r.text
                    
                    # Improved MyRepublic detection
                    myrepublic_indicators = self._check_myrepublic_indicators(html_content, r.headers)
                    
                    if myrepublic_indicators['detected']:
                        detection_results['is_myrepublic'] = True
                        detection_results['router_model'] = myrepublic_indicators.get('model', 'Unknown')
                        detection_results['manufacturer'] = myrepublic_indicators.get('manufacturer', 'Unknown')
                        detection_results['firmware'] = myrepublic_indicators.get('firmware', 'Unknown')
                        
                        console.print("[green]✓ MyRepublic router detected![/green]")
                        console.print(f"    [cyan]Model: {detection_results['router_model']}[/cyan]")
                        console.print(f"    [cyan]Manufacturer: {detection_results['manufacturer']}[/cyan]")
                        console.print(f"    [cyan]Firmware: {detection_results['firmware']}[/cyan]")
                        
                        # Test backdoors
                        detection_results['backdoors_found'] = self.test_backdoors()
                        return detection_results
                        
                except Exception as e:
                    continue
            
            # If no MyRepublic detected, show what was found
            console.print("[yellow]⚠ MyRepublic not directly detected, showing router info:[/yellow]")
            try:
                r = self.session.get(f"{self.base_url}/", timeout=10)
                self._analyze_router_info(r.text, r.headers)
            except:
                pass
                
            # Test backdoors anyway (might work on similar routers)
            detection_results['backdoors_found'] = self.test_backdoors()
            
        except Exception as e:
            console.print(f"[red]✗ Detection failed: {str(e)}[/red]")
        
        return detection_results
    
    def _check_myrepublic_indicators(self, html_content, headers):
        """Check for MyRepublic specific indicators"""
        html_lower = html_content.lower()
        indicators = {
            'detected': False,
            'model': 'Unknown',
            'manufacturer': 'Unknown', 
            'firmware': 'Unknown'
        }
        
        # MyRepublic specific keywords (case insensitive)
        myrepublic_keywords = [
            'myrepublic', 'republic', 'my republic',
            'myrepublicwifi', 'republicwifi', 'myrepublic router',
            'myrepublic.com', 'myrepublic.la', 'myrepublic.sg'
        ]
        
        # Check HTML content
        for keyword in myrepublic_keywords:
            if keyword in html_lower:
                indicators['detected'] = True
                console.print(f"[green]✓ Found MyRepublic keyword: {keyword}[/green]")
                break
        
        # Check page title
        title_match = re.search(r'<title>(.*?)</title>', html_content, re.IGNORECASE)
        if title_match:
            title = title_match.group(1).lower()
            for keyword in myrepublic_keywords:
                if keyword in title:
                    indicators['detected'] = True
                    console.print(f"[green]✓ MyRepublic in page title: {title_match.group(1)}[/green]")
                    break
        
        # Check for common router manufacturers used by MyRepublic
        common_manufacturers = {
            'zte': 'ZTE', 'huawei': 'Huawei', 'fiberhome': 'FiberHome',
            'nokia': 'Nokia', 'sercomm': 'Sercomm', 'technicolor': 'Technicolor',
            'sagemcom': 'Sagemcom', 'arcadyan': 'Arcadyan'
        }
        
        for mfg_key, mfg_name in common_manufacturers.items():
            if mfg_key in html_lower:
                indicators['manufacturer'] = mfg_name
                console.print(f"[cyan]✓ Manufacturer: {mfg_name}[/cyan]")
        
        # Try to extract model information
        model_patterns = [
            r'model[:\s]*([a-zA-Z0-9\-_]+)',
            r'product[:\s]*([a-zA-Z0-9\-_]+)',
            r'router[:\s]*([a-zA-Z0-9\-_]+)',
            r'device[:\s]*([a-zA-Z0-9\-_]+)',
        ]
        
        for pattern in model_patterns:
            matches = re.findall(pattern, html_content, re.IGNORECASE)
            for match in matches:
                if len(match) > 2 and match not in ['model', 'product', 'router', 'device']:
                    indicators['model'] = match
                    console.print(f"[cyan]✓ Possible model: {match}[/cyan]")
                    break
        
        # Check headers for server info
        server_header = headers.get('Server', '').lower()
        if server_header:
            console.print(f"[cyan]Server: {headers.get('Server')}[/cyan]")
            if any(mfg in server_header for mfg in common_manufacturers.keys()):
                indicators['detected'] = True
        
        return indicators
    
    def _analyze_router_info(self, html_content, headers):
        """Analyze router information even if not MyRepublic"""
        html_lower = html_content.lower()
        
        # Common router indicators
        router_indicators = [
            'router', 'gateway', 'modem', 'broadband',
            'wireless', 'wifi', 'admin', 'login', 'password'
        ]
        
        found_indicators = [ind for ind in router_indicators if ind in html_lower]
        
        if found_indicators:
            console.print(f"[yellow]Router indicators found: {', '.join(found_indicators[:5])}[/yellow]")
        
        # Check for manufacturer
        manufacturers = [
            'tp-link', 'tplink', 'd-link', 'dlink', 'linksys',
            'netgear', 'asus', 'tenda', 'mercush', 'cisco',
            'huawei', 'zte', 'nokia', 'fiberhome', 'sercomm'
        ]
        
        for mfg in manufacturers:
            if mfg in html_lower:
                console.print(f"[cyan]✓ Manufacturer detected: {mfg.title()}[/cyan]")
                break
        
        # Check page title
        title_match = re.search(r'<title>(.*?)</title>', html_content, re.IGNORECASE)
        if title_match:
            console.print(f"[cyan]Page title: {title_match.group(1)}[/cyan]")
        
        # Server header
        if 'Server' in headers:
            console.print(f"[cyan]Web server: {headers['Server']}[/cyan]")
    
    def test_backdoors(self):
        """Test MyRepublic specific backdoors"""
        console.print("\n[bold yellow][*] Testing MyRepublic backdoors...[/bold yellow]")
        
        backdoors_found = []
        
        # Comprehensive list of backdoor endpoints
        backdoor_endpoints = [
            # MyRepublic specific
            "/api/debug", "/cgi-bin/debug", "/backdoor", "/debug",
            "/technician", "/support", "/maintenance", "/diag",
            "/cgi-bin/luci/admin", "/cgi-bin/luci/admin/system",
            
            # Common router backdoors
            "/cgi-bin/ping.cgi", "/cgi-bin/tracert.cgi", "/cgi-bin/diagnostic.cgi",
            "/cgi-bin/debug.cgi", "/api/ping", "/diag/ping",
            
            # Configuration endpoints
            "/config.bin", "/backup.cfg", "/romfile.cfg", "/rom.cfg",
            "/userconfig/cfg", "/cfg/download.xml", "/backup/config.bin",
            
            # Hidden endpoints
            "/hidden.html", "/secret", "/private", "/admin/debug",
            "/cgi-bin/test.cgi", "/cgi-bin/status.cgi",
            
            # Telnet/SSH enable endpoints
            "/cgi-bin/luci/admin/telnet", "/api/telnet", "/admin/telnet.cgi",
            
            # Factory reset endpoints
            "/cgi-bin/reset.cgi", "/admin/reset.html", "/factoryreset.cgi"
        ]
        
        for endpoint in backdoor_endpoints:
            try:
                url = f"{self.base_url}{endpoint}"
                
                # Try GET request
                r = self.session.get(url, timeout=5, allow_redirects=False)
                
                if r.status_code == 200:
                    backdoors_found.append({
                        'endpoint': endpoint,
                        'method': 'GET',
                        'status': r.status_code,
                        'size': len(r.content)
                    })
                    console.print(f"[green]✓ Backdoor found: {endpoint} (GET - {r.status_code})[/green]")
                
                # Try POST for interactive endpoints
                if any(keyword in endpoint for keyword in ['cgi-bin', 'api', 'admin']):
                    test_data = {"test": "1", "action": "status"}
                    r = self.session.post(url, data=test_data, timeout=5, allow_redirects=False)
                    
                    if r.status_code == 200:
                        backdoors_found.append({
                            'endpoint': endpoint,
                            'method': 'POST', 
                            'status': r.status_code,
                            'size': len(r.content)
                        })
                        console.print(f"[green]✓ Backdoor found: {endpoint} (POST - {r.status_code})[/green]")
                        
            except requests.exceptions.Timeout:
                console.print(f"[yellow]⚠ Timeout on: {endpoint}[/yellow]")
            except requests.exceptions.ConnectionError:
                console.print(f"[red]✗ Connection error on: {endpoint}[/red]")
            except Exception as e:
                continue
        
        if backdoors_found:
            console.print(f"\n[green]✓ Found {len(backdoors_found)} potential backdoors[/green]")
        else:
            console.print("[red]✗ No backdoors found[/red]")
        
        return backdoors_found

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
                console.print("\n[bold green]✓ MyRepublic Router Confirmed![/bold green]")
                console.print(f"    Model: {result['router_model']}")
                console.print(f"    Manufacturer: {result['manufacturer']}")
                console.print(f"    Backdoors found: {len(result['backdoors_found'])}")
            else:
                console.print("\n[red]✗ Not a MyRepublic router[/red]")
                console.print("[yellow]But continuing with backdoor tests...[/yellow]")
                
                if result['backdoors_found']:
                    console.print(f"[green]Found {len(result['backdoors_found'])} potential backdoors anyway![/green]")
        
        return True
        
    except Exception as e:
        console.print(f"[bold red]✗ Error: {str(e)}[/bold red]")
        return False
