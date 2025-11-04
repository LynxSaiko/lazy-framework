# modules/auxiliary/multi/reverse_tcp.py
import subprocess
import threading
import time
from pathlib import Path

MODULE_INFO = {
    "name": "Multi Reverse TCP Handler",
    "description": "Interactive multi-session handler (LAN + WAN)",
    "rank": "Excellent"
}

OPTIONS = {
    "LHOST": {"required": True, "default": "0.0.0.0"},
    "LPORT": {"required": True, "default": 4444}
}

_handler = None

def run(session, options):
    global _handler

    # AMBIL CONSOLE → PASTI ADA SEKARANG
    console = session.get("console")
    if not console:
        print("[!] FATAL: console missing in session")  # Hanya untuk debug
        return

    lhost = options.get("LHOST", "0.0.0.0")
    lport = options.get("LPORT", 4444)

    if not lhost or not lport:
        console.print("[red][!] LHOST and LPORT required![/red]")
        return

    bin_path = Path(__file__).parent / "multi_handler"
    if not bin_path.exists():
        console.print("[red][!] multi_handler not found![/red]")
        console.print("[yellow]    gcc multi_handler.c -o multi_handler -lpthread[/yellow]")
        return

    if _handler and _handler.poll() is None:
        console.print("[yellow][!] Handler already running[/yellow]")
        return

    cmd = [str(bin_path), str(lhost), str(lport)]
    try:
        _handler = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, bufsize=0)
    except Exception as e:
        console.print(f"[red][!] Failed: {e}[/red]")
        return

    def forward():
        try:
            for line in _handler.stdout:
                console.print(line.decode(errors='ignore').rstrip())
        except:
            pass

    threading.Thread(target=forward, daemon=True).start()
    time.sleep(1.5)

    console.print(f"[green][+] Handler aktif: {lhost}:{lport}[/green]")
    console.print("[dim]   list | interact <id> | kill <id>[/dim]")
