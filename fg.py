#!/usr/bin/env python3
# fix_line_185.py - Hanya perbaiki line 185

def fix_line_185():
    with open('/root/lazy-framework/bin/framework.py', 'r') as f:
        lines = f.readlines()
    
    # Perbaiki hanya line 185 (index 184 dalam list)
    if 184 < len(lines):
        lines[184] = '            console.print(Panel(f"[green][*][/green] Reloading modules from all [bold]{key}[/bold]", style="green"))\n'
    
    # Write back
    with open('/root/lazy-framework/bin/framework.py', 'w') as f:
        f.writelines(lines)
    
    print("✅ Line 185 fixed!")

if __name__ == "__main__":
    fix_line_185()
