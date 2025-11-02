#!/usr/bin/env python3
# fix_markup.py - Auto fix markup errors

import re

def fix_framework_file():
    with open('/root/lazy-framework/bin/framework.py', 'r') as f:
        content = f.read()
    
    # Fix patterns
    fixes = [
        # Fix Panel dengan markup tidak konsisten
        (r'Panel\(f"\[\*\] Reloading modules from all \[\*\]\[bold\]\{key\}\[/bold\]", style="green"\)', 
         'Panel(f"[green][*][/green] Reloading modules from all [bold]{key}[/bold]", style="green")'),
        
        # Fix error message dengan style=
        (r'console\.print\(f"\[\*\] Reloading Error modules from all \[\*\] \{e\}", style="bold red"\)',
         'console.print(f"[bold red][!][/bold red] Reloading Error: {e}")'),
        
        # Fix run error dengan style=
        (r'console\.print\(f"Run error: \{e\}", style="red"\)',
         'console.print(f"[red]Run error: {e}[/red]")'),
        
        # Fix unknown command dengan style=
        (r'lambda a: console\.print\("Unknown command", style="red"\)',
         'lambda a: console.print("[red]Unknown command[/red]")'),
        
        # Fix CMD_SHOW message
        (r'console\.print\("\[bold green\]\[✓\]\[/bold green\] Valid parameters for the", "show modules\|payloads"\)',
         'console.print("[bold green][✓][/bold green] Valid parameters for: show modules|payloads")')
    ]
    
    for pattern, replacement in fixes:
        content = re.sub(pattern, replacement, content)
    
    # Write fixed content
    with open('/root/lazy-framework/bin/framework.py', 'w') as f:
        f.write(content)
    
    print("✅ Markup errors fixed!")

if __name__ == "__main__":
    fix_framework_file()
