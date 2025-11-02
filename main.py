# main.py
import sys
from pathlib import Path

# --- PENTING: TAMBAHKAN FOLDER BIN DAN lzf_core KE PYTHON PATH ---
BASE_DIR = Path(__file__).parent
sys.path.append(str(BASE_DIR))        
sys.path.append(str(BASE_DIR / "bin"))  

import os, platform, time

# Import class/fungsi dari lzf_core
from lzfconsole import LazyFramework # Dari bin/framework.py
from core import SingleLineMarquee, load_banners_from_folder # Dari lzf_core/utils.py

def main():
    # 1. Animasi Pertama
    anim = SingleLineMarquee(
        "[*] Starting the Lazy Framework Console...",
        text_speed=0.20,
        spinner_speed=0.06,
        reset_delay=1.0, # Jeda 1 detik antar ulangan
        max_loops=2      # Berjalan 2 kali lalu berhe>
    )
    anim.start()
    anim.wait()

    # time.sleep(0.6) <-- Dihapus karena delay sudah >

    if platform.system() == "Windows":
        os.system('cls')
    else:
        os.system('clear')
    load_banners_from_folder()
    LazyFramework().repl()

if __name__ == "__main__":
    main()
