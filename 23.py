#!/usr/bin/env python3
# fix_line_213.py - Hanya perbaiki line 213

def fix_line_213():
    with open('/root/lazy-framework/bin/framework.py', 'r') as f:
        lines = f.readlines()
    
    # Perbaiki hanya line 213 (index 212 dalam list)
    if 212 < len(lines):
        lines[212] = '            console.print("[red]No module loaded.[/red]")\n'
    
    # Write back
    with open('/root/lazy-framework/bin/framework.py', 'w') as f:
        f.writelines(lines)
    
    print("✅ Line 213 fixed!")

if __name__ == "__main__":
    fix_line_213()
