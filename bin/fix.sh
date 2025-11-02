cd /root/lazy-framework/bin/

# Buat script bash
cat > find_markup_errors.sh << 'EOF'
#!/bin/bash
echo "🔍 Mencari markup error di framework.py..."
echo "=========================================="

python3 << 'PYTHON_SCRIPT'
import re

with open('framework.py', 'r') as f:
    lines = f.readlines()

errors_found = 0

for i, line in enumerate(lines, 1):
    if 'console.print' in line:
        # Cari pattern [color]...[/different_color]
        matches = re.findall(r'\[(blue|red|green|yellow)\].*?\[\/(blue|red|green|yellow)\]', line)
        for open_tag, close_tag in matches:
            if open_tag != close_tag:
                print(f'❌ LINE {i}: [/{close_tag}] tidak match dengan [{open_tag}]')
                print(f'   CONTENT: {line.strip()}')
                print()
                errors_found += 1
                
        # Cari style= dengan markup
        if 'style=' in line and any(tag in line for tag in ['[red]', '[blue]', '[green]', '[yellow]']):
            print(f'❌ LINE {i}: Mixing style= dengan markup tags')
            print(f'   CONTENT: {line.strip()}')
            print()
            errors_found += 1

print('==========================================')
if errors_found == 0:
    print('✅ Tidak ada markup error ditemukan!')
else:
    print(f'🎯 Total {errors_found} markup error ditemukan')
PYTHON_SCRIPT

EOF


