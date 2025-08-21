#!/usr/bin/env python3
"""
game_watcher_with_gogdb_pretty.py

Watches the current directory for game-... folders, requires the .url file,
runs innoextract on EXEs, uses local GOGDB product JSON to determine main vs sub,
prints a formatted 4-column table, and then installs the detected GAME installer
(and then DLCs) into a sanitized folder under the watch directory.

Install flags used:
  /VERYSILENT /SP- /LANG=english /DIR="..." /LOG="..."

Log analysis is used to determine success (preferred over raw exit code).
"""
from pathlib import Path
import re
import time
import tarfile
import shutil
import sys
import os
import ctypes
import datetime
import json
import plyvel
import psutil
import pythoncom
import subprocess
from urllib.parse import urljoin
from win32com.client import Dispatch

# Constants
VERBOSE = False  # Set to True for more detailed output
INSTALLER_TIMEOUT = 3600  # 1 hour timeout for installers

# Check if running as admin, if not, restart with admin rights
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

if not is_admin():
    # Re-run the program with admin rights
    ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
    sys.exit(0)
from urllib.parse import urljoin
from win32com.client import Dispatch

def get_processes_using_db():
    """Find all processes that have a lock on the hydra-db."""
    processes = []
    try:
        for proc in psutil.process_iter(['pid', 'name', 'exe', 'open_files']):
            try:
                if not proc.info['open_files']:
                    continue
                for f in proc.info['open_files']:
                    if 'hydra-db' in f.path.lower():
                        processes.append(proc)
                        break  # No need to check other files for this process
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
    except Exception as e:
        print(f"Warning: Could not scan processes: {e}")
    return processes

# Hydra DB Configuration
HYDRA_DB_PATH = Path(os.getenv('APPDATA')) / 'hydralauncher' / 'hydra-db'
RESTART_HYDRA = True

# optional dependency; fallback to urllib
try:
    import requests
except Exception:
    requests = None
    import urllib.request

# watchdog
try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
except Exception:
    print("ERROR: watchdog is required. Install with: pip install watchdog")
    sys.exit(1)

# ---- Config ----
BASE_DIR = Path.cwd()
DATA_DIR = BASE_DIR / "_databases" / "gogdb"
META_FILE = DATA_DIR / "gogdb_meta.json"

FOLDER_PATTERN = re.compile(r"^game-[a-zA-Z0-9._]+-\(\d+\)$")
REQUIRED_FILE = "GOG-Games.to - Free GOG PC Games.url"
GOGDB_ROOT_LISTING = "https://www.gogdb.org/backups_v3/products/"
DB_MAX_AGE_S = 24 * 3600  # 24 hours

# installer flags (we append /DIR= and /LOG= dynamically)
INNO_FLAGS = ['/VERYSILENT', '/SP-', '/LANG=english']

# ---- GOGDB helper functions (meta-driven freshness) ----
def parse_href_listing(html_text):
    return re.findall(r'href=["\']([^"\']+)["\']', html_text, flags=re.IGNORECASE)

def get_remote_latest_gogdb_info():
    try:
        if requests:
            r = requests.get(GOGDB_ROOT_LISTING, timeout=20)
            r.raise_for_status()
            root_html = r.text
        else:
            with urllib.request.urlopen(GOGDB_ROOT_LISTING, timeout=20) as resp:
                root_html = resp.read().decode(errors="ignore")
    except Exception as e:
        print(f"Failed to fetch GOGDB root listing: {e}")
        return None, None

    hrefs = parse_href_listing(root_html)
    month_dirs = [h for h in hrefs if re.match(r'^\d{4}-\d{2}/$', h)]
    if not month_dirs:
        return None, None

    latest_month = sorted(month_dirs)[-1]
    month_url = urljoin(GOGDB_ROOT_LISTING, latest_month)

    try:
        if requests:
            r = requests.get(month_url, timeout=20)
            r.raise_for_status()
            month_html = r.text
        else:
            with urllib.request.urlopen(month_url, timeout=20) as resp:
                month_html = resp.read().decode(errors="ignore")
    except Exception as e:
        print(f"Failed to fetch GOGDB month listing ({month_url}): {e}")
        return None, None

    hrefs = parse_href_listing(month_html)
    archive_files = [h for h in hrefs if re.match(r'^gogdb_\d{4}-\d{2}-\d{2}\.tar\.xz$', h)]
    if not archive_files:
        return None, None

    latest_file = sorted(archive_files)[-1]
    download_url = urljoin(month_url, latest_file)
    return download_url, latest_file

def read_meta_date(meta_path: Path):
    try:
        if not meta_path.exists():
            return None
        with open(meta_path, "r", encoding="utf-8") as f:
            meta = json.load(f)
        ds = meta.get("downloaded_at")
        if not ds:
            return None
        return datetime.datetime.fromisoformat(ds)
    except Exception:
        return None

def local_db_age_seconds():
    meta_date = read_meta_date(META_FILE)
    if not meta_date:
        return float('inf')
    return (datetime.datetime.now() - meta_date).total_seconds()

def download_file_stream(url: str, dest_path: Path):
    tmp = dest_path.with_suffix(dest_path.suffix + ".part")
    print(f"Downloading {url} -> {dest_path} ...")
    try:
        if requests:
            with requests.get(url, stream=True, timeout=60) as r:
                r.raise_for_status()
                with open(tmp, "wb") as f:
                    for chunk in r.iter_content(chunk_size=8192):
                        if chunk:
                            f.write(chunk)
        else:
            with urllib.request.urlopen(url, timeout=60) as resp, open(tmp, "wb") as f:
                while True:
                    chunk = resp.read(8192)
                    if not chunk:
                        break
                    f.write(chunk)
        tmp.replace(dest_path)
        print("Download complete.")
    except Exception:
        if tmp.exists():
            try:
                tmp.unlink()
            except Exception:
                pass
        raise

def extract_tar_xz_into_gogdb(archive_path: Path, target_dir: Path, keep_archive_name: str):
    tmp_extract = target_dir.with_name(target_dir.name + "_extract_tmp")
    if tmp_extract.exists():
        shutil.rmtree(tmp_extract, ignore_errors=True)
    tmp_extract.mkdir(parents=True, exist_ok=True)
    try:
        with tarfile.open(archive_path, mode="r:xz") as tar:
            tar.extractall(path=tmp_extract)
        target_dir.mkdir(parents=True, exist_ok=True)
        for entry in list(target_dir.iterdir()):
            try:
                if entry.is_file() and entry.name == keep_archive_name:
                    continue
                if entry.is_file():
                    entry.unlink()
                else:
                    shutil.rmtree(entry)
            except Exception:
                pass
        for item in tmp_extract.iterdir():
            shutil.move(str(item), str(target_dir / item.name))
        if tmp_extract.exists():
            shutil.rmtree(tmp_extract, ignore_errors=True)
        print("Extraction complete.")
    except Exception:
        if tmp_extract.exists():
            shutil.rmtree(tmp_extract, ignore_errors=True)
        raise

def write_meta(meta_path: Path, archive_filename: str):
    try:
        meta_path.parent.mkdir(parents=True, exist_ok=True)
        meta = {
            "downloaded_at": datetime.datetime.now().isoformat(),
            "archive": archive_filename
        }
        with open(meta_path, "w", encoding="utf-8") as f:
            json.dump(meta, f, indent=2)
    except Exception as e:
        print("Warning: failed to write meta file:", e)

def ensure_gogdb_local():
    age = local_db_age_seconds()
    if age < DB_MAX_AGE_S:
        print("Local GOGDB is fresh (age {:.0f}s). No download required.".format(age))
        return

    download_url, filename = get_remote_latest_gogdb_info()
    if not download_url:
        print("Could not find remote GOGDB archive. Skipping update.")
        return

    dest_archive = DATA_DIR / filename
    try:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        download_file_stream(download_url, dest_archive)
        extract_tar_xz_into_gogdb(dest_archive, DATA_DIR, filename)
        write_meta(META_FILE, filename)
        print("GOGDB updated and extracted into:", DATA_DIR)
    except Exception as e:
        print("Error while updating GOGDB:", e)
        try:
            if dest_archive.exists():
                dest_archive.unlink()
        except Exception:
            pass

# ---- innoextract + product lookup & main detection ----
def query_innoextract(exe_path: Path):
    try:
        result = subprocess.run(
            ["innoextract", "-i", str(exe_path)],
            capture_output=True,
            text=True,
            check=True
        )
        output = (result.stdout or "") + "\n" + (result.stderr or "")
    except subprocess.CalledProcessError as e:
        output = ((e.stdout or "") + "\n" + (e.stderr or ""))
        print(f"Warning: innoextract returned non-zero for {exe_path}. Continuing parse if possible.")

    game_name = None
    gog_id = None
    m_name = re.search(r'Inspecting\s+"(.+?)"\s+-', output, flags=re.IGNORECASE)
    if m_name:
        game_name = m_name.group(1)
    m_id = re.search(r'GOG\.com game ID is (\d+)', output)
    if m_id:
        gog_id = m_id.group(1)
    return game_name, gog_id

def read_product_json_for_gid(gid: str):
    if not gid:
        return None
    p = DATA_DIR / "products" / gid / "product.json"
    if not p.is_file():
        return None
    try:
        with open(p, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None

def pick_main_software(folder_name: str, softwares: list):
    folder_lower = folder_name.lower()
    for s in softwares:
        prod = s.get("product")
        s["product_type"] = prod.get("type") if prod else None
        s["product_title"] = prod.get("title") if prod else None

    game_candidates = [i for i,s in enumerate(softwares) if s["product_type"] == "game"]
    if len(game_candidates) == 1:
        return game_candidates[0], "unique type=='game'"
    if len(game_candidates) > 1:
        for i in game_candidates:
            title = (softwares[i].get("product_title") or "").lower()
            exname = (softwares[i].get("extracted_name") or "").lower()
            if exname and exname == title:
                return i, "matched product title == extracted_name"
            if title and title in folder_lower:
                return i, "matched product title in folder name"
        return game_candidates[0], f"multiple type=='game' candidates, picked first ({game_candidates[0]})"

    non_dlc_candidates = [i for i,s in enumerate(softwares) if s["product_type"] and s["product_type"] != "dlc"]
    if len(non_dlc_candidates) == 1:
        return non_dlc_candidates[0], "single non-dlc product type"
    if len(non_dlc_candidates) > 1:
        for i in non_dlc_candidates:
            title = (softwares[i].get("product_title") or "").lower()
            exname = (softwares[i].get("extracted_name") or "").lower()
            if exname and exname == title:
                return i, "matched product title == extracted_name (non-dlc candidate)"
            if title and title in folder_lower:
                return i, "matched product title in folder name (non-dlc candidate)"
        return non_dlc_candidates[0], f"multiple non-dlc candidates, picked first ({non_dlc_candidates[0]})"

    with_names = [(i, s["extracted_name"]) for i,s in enumerate(softwares) if s.get("extracted_name")]
    if with_names:
        best = min(with_names, key=lambda t: len(t[1]))
        return best[0], "fallback: shortest extracted_name heuristic"

    return 0, "final fallback: picked first entry (undetermined)"

# ---- Pretty printing ----
def normalize_type(t):
    if not t:
        return "UNKNOWN"
    tt = t.lower()
    if tt == "game":
        return "GAME"
    if tt == "dlc":
        return "DLC"
    return t.upper()

# ---- Installer support ----
if sys.platform == "win32":
    import ctypes
    from ctypes import wintypes

    SEE_MASK_NOCLOSEPROCESS = 0x00000040

    class SHELLEXECUTEINFOW(ctypes.Structure):
        _fields_ = [
            ("cbSize", ctypes.c_ulong),
            ("fMask", ctypes.c_ulong),
            ("hwnd", ctypes.c_void_p),
            ("lpVerb", ctypes.c_wchar_p),
            ("lpFile", ctypes.c_wchar_p),
            ("lpParameters", ctypes.c_wchar_p),
            ("lpDirectory", ctypes.c_wchar_p),
            ("nShow", ctypes.c_int),
            ("hInstApp", ctypes.c_void_p),
            ("lpIDList", ctypes.c_void_p),
            ("lpClass", ctypes.c_wchar_p),
            ("hkeyClass", ctypes.c_void_p),
            ("dwHotKey", ctypes.c_ulong),
            ("hIcon", ctypes.c_void_p),
            ("hProcess", ctypes.c_void_p),
        ]

    ShellExecuteExW = ctypes.windll.shell32.ShellExecuteExW
    Kernel32 = ctypes.windll.kernel32
    WAIT_INFINITE = 0xFFFFFFFF

    def run_elevated_and_wait(exe_path: Path, args: str, workdir: str = None, show_cmd: int = 1, timeout=None):
        sei = SHELLEXECUTEINFOW()
        sei.cbSize = ctypes.sizeof(sei)
        sei.fMask = SEE_MASK_NOCLOSEPROCESS
        sei.hwnd = None
        sei.lpVerb = "runas"
        sei.lpFile = str(exe_path)
        sei.lpParameters = args
        sei.lpDirectory = workdir or None
        sei.nShow = show_cmd
        ok = ShellExecuteExW(ctypes.byref(sei))
        if not ok:
            return None
        hproc = sei.hProcess
        if not hproc:
            return None
        if timeout is None:
            Kernel32.WaitForSingleObject(hproc, WAIT_INFINITE)
        else:
            Kernel32.WaitForSingleObject(hproc, int(timeout*1000))
        exit_code = ctypes.c_ulong()
        got = Kernel32.GetExitCodeProcess(hproc, ctypes.byref(exit_code))
        try:
            Kernel32.CloseHandle(hproc)
        except Exception:
            pass
        if not got:
            return None
        return int(exit_code.value)
else:
    def run_elevated_and_wait(exe_path: Path, args: str, workdir: str = None, show_cmd: int = 1, timeout=None):
        cmd = [str(exe_path)] + args.split()
        try:
            res = subprocess.run(cmd, cwd=workdir, check=False)
            return res.returncode
        except Exception:
            return None

_invalid_chars = r'<>:"/\\|?*\0'
def sanitize_filename(name: str) -> str:
    if not name:
        return "unknown"
    out = ''.join('_' if c in _invalid_chars else c for c in name)
    out = out.strip().rstrip('.')
    return out

def build_inno_args(install_dir: Path, log_path: Path):
    dir_param = f'/DIR="{str(install_dir)}"'
    log_param = f'/LOG="{str(log_path)}"'
    params = INNO_FLAGS + [dir_param, log_param]
    return ' '.join(params)

# ---- Installer success detection (patched) ----
def resolve_shortcut(lnk_path):
    """Resolve .lnk file to target executable."""
    try:
        pythoncom.CoInitialize()
        shell = Dispatch('WScript.Shell')
        return shell.CreateShortcut(str(lnk_path)).TargetPath
    except Exception as e:
        print(f"Failed to resolve shortcut {lnk_path}: {e}")
        return None

def update_hydra_db(game_name, install_dir):
    """Update Hydra's database with the game's executable path."""
    print(f"Updating Hydra DB for {game_name}...")
    
    # Find all processes using the DB and get their info
    db_processes = get_processes_using_db()
    processes_info = []
    
    for proc in db_processes:
        try:
            proc_info = {
                'process': proc,
                'exe': proc.info['exe'],
                'name': proc.info['name']
            }
            processes_info.append(proc_info)
            print(f"Found process using hydra-db: {proc.info['name']} (PID: {proc.pid})")
        except Exception as e:
            print(f"Could not get process info for PID {proc.pid}: {e}")
    
    # Find the main Hydra executable path (prioritize Hydra.exe over hydra-python-rpc.exe)
    hydra_path = None
    for proc_info in processes_info:
        proc_name = proc_info.get('name', '').lower()
        proc_exe = proc_info.get('exe', '')
        if 'hydra.exe' in proc_name:
            hydra_path = proc_exe
            break
        elif 'hydra-python-rpc.exe' in proc_name and not hydra_path:
            # Fallback to rpc exe if main exe not found
            hydra_path = proc_exe
    
    # Find launch shortcut
    launch_shortcut = None
    for ext in ('*.lnk', '*.exe'):
        for path in install_dir.glob(f"**/{ext}"):
            if path.suffix == '.lnk':
                exe_path = resolve_shortcut(path)
                if exe_path and os.path.exists(exe_path):
                    launch_shortcut = Path(exe_path)
                    break
            elif path.is_file():
                launch_shortcut = path
                break
        if launch_shortcut:
            break
    
    if not launch_shortcut:
        print(f"No executable found in {install_dir}")
        return False
    
    # Track processes to restart later
    processes_to_restart = []
    
    # Close all processes using the DB gracefully
    if db_processes:
        print("Requesting processes to close gracefully...")
        for proc in db_processes:
            try:
                proc_info = {
                    'pid': proc.pid,
                    'name': proc.info.get('name', 'unknown'),
                    'exe': proc.info.get('exe', ''),
                    'cwd': proc.cwd() if hasattr(proc, 'cwd') else None,
                    'cmdline': proc.cmdline() if hasattr(proc, 'cmdline') else None
                }
                print(f"Requesting process to close: {proc_info['name']} (PID: {proc_info['pid']})")
                processes_to_restart.append(proc_info)
                
                # Try to close gracefully first
                try:
                    proc.terminate()
                except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
                    print(f"Could not request process {proc.pid} to close: {e}")
                    continue
                
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess) as e:
                print(f"Could not access process {proc.pid}: {e}")
        
        # Wait for processes to terminate with a longer timeout
        print("Waiting for processes to close gracefully (max 60 seconds)...")
        gone, alive = psutil.wait_procs(db_processes, timeout=60)
        
        if alive:
            print("Warning: The following processes did not close gracefully:")
            for proc in alive:
                try:
                    print(f"- {proc.name()} (PID: {proc.pid}) - State: {proc.status()}")
                except:
                    print(f"- Unknown process (PID: {proc.pid})")
            print("Please close these processes manually and try again.")
            return False
    
    try:
        # Repair and open DB
        print("Repairing LevelDB...")
        plyvel.repair_db(str(HYDRA_DB_PATH))
        
        db = plyvel.DB(str(HYDRA_DB_PATH), create_if_missing=False)
        updated = False
        
        # Update matching game entries
        for key, value in db:
            try:
                data = json.loads(value.decode('utf-8'))
                if data.get("title") == game_name:
                    print(f"Updating {game_name} path to {launch_shortcut}")
                    data["executablePath"] = str(launch_shortcut)
                    db.put(key, json.dumps(data).encode('utf-8'))
                    updated = True
            except Exception as e:
                print(f"Error processing DB entry: {e}")
        
        db.close()
        
        # Restart all processes that were closed
        if RESTART_HYDRA and processes_to_restart:
            print("Restarting Hydra processes...")
            for proc_info in processes_to_restart:
                try:
                    exe_path = proc_info['exe']
                    if not exe_path or not os.path.exists(exe_path):
                        print(f"Skipping restart for {proc_info['name']} - executable not found")
                        continue
                        
                    # Get working directory
                    cwd = proc_info.get('cwd') or os.path.dirname(exe_path)
                    if not os.path.exists(cwd):
                        cwd = os.path.dirname(exe_path)
                    
                    print(f"Restarting process: {proc_info['name']} ({exe_path})")
                    # Start the process with original working directory if available
                    subprocess.Popen(
                        f'start "" "{exe_path}"',
                        shell=True,
                        cwd=cwd,
                        start_new_session=True
                    )
                except Exception as e:
                    print(f"Error restarting process {proc_info.get('name', 'unknown')}: {e}")
        
        return updated
    except Exception as e:
        print(f"Error updating Hydra DB: {e}")
        return False

SUCCESS_PATTERNS = re.compile(r'Installation process succeeded\.|setup finished|installation completed|setup successful|installed successfully|completed successfully', re.I)

def run_installer_with_log_and_check(exe_path: Path, install_dir: Path):
    """
    Run installer elevated with /LOG and analyze the log to determine success.
    Only trust explicit success messages in the log.
    Runs with elevated privileges without showing UAC prompt.
    """
    try:
        install_dir.mkdir(parents=True, exist_ok=True)
        
        # Build installer arguments
        log_path = install_dir / f"{exe_path.stem}.log"
        inno_args = build_inno_args(install_dir, log_path)
        
        print(f"Running installer: {exe_path} with args: {inno_args}")
        
        # Run installer with elevation (no UAC prompt since we're already admin)
        exit_code = run_elevated_and_wait(
            exe_path,
            inno_args,
            workdir=str(exe_path.parent),
            show_cmd=1 if VERBOSE else 0,  # Show window only in verbose mode
            timeout=INSTALLER_TIMEOUT
        )
        
        # Check log for success
        success = False
        reason = "unknown"
        
        try:
            log_text = log_path.read_text(encoding='utf-8', errors='ignore')
            if SUCCESS_PATTERNS.search(log_text):
                success = True
                reason = "log explicitly indicates success"
                # Update Hydra DB after successful installation
                game_name = install_dir.name
                update_hydra_db(game_name, install_dir)
            else:
                success = False
                reason = "log does not indicate success"
        except Exception as e:
            print(f"Error reading log file: {e}")
            success = False
            reason = f"error reading log: {e}"
        
        print(f"Main installer result: success={success} (exit_code={exit_code}) - {reason}")
        print(f"Log file: {log_path}")
        
        # Read log snippets for the return value
        head_lines = []
        tail_lines = []
        try:
            log_text = log_path.read_text(encoding='utf-8', errors='ignore')
            lines = log_text.splitlines()
            head_lines = lines[:10]
            tail_lines = lines[-10:]
        except Exception as e:
            print(f"Error reading log file for snippets: {e}")
            
        return success, exit_code, log_path, (head_lines, tail_lines), reason
        
    except Exception as e:
        error_msg = f"Error in run_installer_with_log_and_check: {e}"
        print(error_msg)
        return False, -1, None, ([], []), error_msg

    head_lines = []
    tail_lines = []
    if log_text:
        lines = log_text.splitlines()
        head_lines = lines[:10]
        tail_lines = lines[-10:]
    return success, exit_code, log_path, (head_lines, tail_lines), reason

# ---- Process folder ----
def process_folder(folder: Path):
    softwares = []
    for exe in sorted(folder.glob("*.exe")):
        extracted_name, gid = query_innoextract(exe)
        prod = read_product_json_for_gid(gid) if gid else None
        softwares.append({
            "exe": exe.name,
            "exe_path": exe,
            "extracted_name": extracted_name,
            "gid": gid,
            "product": prod
        })

    if not softwares:
        print(f"⚠️ No EXE installers found in {folder.name}")
        return

    main_idx, reason = pick_main_software(folder.name, softwares)

    rows = []
    for idx, s in enumerate(softwares):
        prod = s.get("product") or {}
        prod_type = s.get("product_type") or prod.get("type") or None
        prod_title = s.get("product_title") or prod.get("title") or None
        type_label = normalize_type(prod_type)
        name = prod_title or s.get("extracted_name") or "<unknown name>"
        gid = s.get("gid") or "<no GOG ID>"
        local_file = s.get("exe")
        if idx == main_idx:
            type_label = type_label + " *"
        rows.append((type_label, name, gid, local_file))

    header_type = "Type"
    header_name = "Name"
    header_gid = "GOG ID"
    header_file = "Local File"

    type_w = max(len(header_type), max(len(r[0]) for r in rows))
    name_w = max(len(header_name), max(len(r[1]) for r in rows))
    gid_w = max(len(header_gid), max(len(r[2]) for r in rows))
    file_w = max(len(header_file), max(len(r[3]) for r in rows))

    print(f"\n📦 Folder: {folder.name}")
    print(f"  {header_type:<{type_w}} | {header_name:<{name_w}} | {header_gid:<{gid_w}} | {header_file}")
    print(f"  {'-'*type_w} | {'-'*name_w} | {'-'*gid_w} | {'-'*file_w}")

    for t, n, g, f in rows:
        print(f"  {t:<{type_w}} | {n:<{name_w}} | {g:<{gid_w}} | {f}")

    main_item = softwares[main_idx]
    prod = main_item.get("product") or {}
    product_title = prod.get("title") or main_item.get("extracted_name") or "Unknown Game"
    folder_name = sanitize_filename(product_title)
    target_dir = BASE_DIR / folder_name

    print(f"\nmain detection reason: {reason}")
    print(f'Installing game "{product_title}" to: "{target_dir}"')

    # --- Main installer check: launch shortcut ---
    launch_shortcut = target_dir / f"Launch {product_title}.lnk"
    if target_dir.exists():
        if launch_shortcut.exists():
            print(f'Game "{product_title}" appears already installed (launch shortcut found). Skipping main install.')
            main_success = True
        else:
            print(f'Warning: "{target_dir}" exists but launch shortcut missing. Deleting folder to reinstall.')
            try:
                shutil.rmtree(target_dir)
            except Exception as e:
                print(f"Error deleting folder: {e}")
            main_success = False
    else:
        main_success = False
    # --- End main installer check ---

    if not main_success:
        main_exe_path = main_item.get("exe_path")
        main_success, exit_code, log_path, snippets, log_reason = run_installer_with_log_and_check(main_exe_path, target_dir)
        print(f"Main installer result: success={main_success} (exit_code={exit_code}) - {log_reason}")
        print(f"Log file: {log_path}")
        if not main_success:
            head, tail = snippets
            if head:
                print("\n--- Log head ---")
                print("\n".join(head))
            if tail:
                print("\n--- Log tail ---")
                print("\n".join(tail))
            print("Aborting DLC installs.")
            return
        else:
            print("Main installer succeeded (per log analysis).")

    # --- Supplemental/DLC installers: skip if log exists ---
    all_dlc_success = True
    for idx, s in enumerate(softwares):
        if idx == main_idx:
            continue

        log_path = target_dir / f"{s['exe_path'].stem}.log"
        if log_path.exists():
            print(f"\nSkipping supplemental: {s['exe']} (log already exists, assuming installed)")
            continue

        print(f"\nInstalling supplemental: {s['exe']} into \"{target_dir}\"")
        ok, ec, log_path, snippets, log_reason = run_installer_with_log_and_check(s['exe_path'], target_dir)
        print(f"Supplement installer result: success={ok} (exit_code={ec}) - {log_reason}")
        print(f"Log file: {log_path}")
        if not ok:
            all_dlc_success = False
            head, tail = snippets
            if head:
                print("\n--- Log head ---")
                print("\n".join(head))
            if tail:
                print("\n--- Log tail ---")
                print("\n".join(tail))
            print("Continuing with next supplemental installer.")
        else:
            print(f"Installed {s['exe']} successfully.")

    # --- Delete installer folder if main + all DLC succeeded ---
    if main_success and all_dlc_success:
        try:
            print(f"\nAll installers succeeded. Deleting installer folder: {folder}")
            shutil.rmtree(folder)
        except Exception as e:
            print(f"Error deleting installer folder: {e}")

    print()

# ---- Watcher with debouncing ----
from collections import defaultdict

class GameFolderHandler(FileSystemEventHandler):
    def __init__(self, debounce_s=0.5):
        self._last_processed = defaultdict(lambda: 0.0)
        self.debounce_s = debounce_s

    def handle_folder(self, folder: Path):
        now = time.time()
        folder_key = str(folder.resolve())
        if now - self._last_processed[folder_key] < self.debounce_s:
            return  # Skip: recently processed
        if folder.is_dir() and FOLDER_PATTERN.match(folder.name) and (folder / REQUIRED_FILE).is_file():
            print(f"[MATCH] {folder.name}")
            process_folder(folder)
            self._last_processed[folder_key] = now

    def on_created(self, event):
        path = Path(event.src_path)
        if event.is_directory:
            time.sleep(0.2)  # give time for files to appear
            self.handle_folder(path)
        else:
            # File created inside folder
            self.handle_folder(path.parent)

    def on_moved(self, event):
        self.handle_folder(Path(event.dest_path))

    def on_modified(self, event):
        # Catch newly written .url files in existing folder
        self.handle_folder(Path(event.src_path).parent)

def scan_existing(path: Path):
    for folder in sorted(path.iterdir()):
        if folder.is_dir() and FOLDER_PATTERN.match(folder.name):
            if (folder / REQUIRED_FILE).is_file():
                print(f"[EXISTING MATCH] {folder.name}")
                process_folder(folder)
            else:
                print(f"[IGNORED] {folder.name} (missing required .url file)")

def watch_directory(path: Path):
    scan_existing(path)
    event_handler = GameFolderHandler()
    observer = Observer()
    observer.schedule(event_handler, str(path), recursive=True)  # recursive ensures nested events captured
    observer.start()
    print(f"📂 Watching for game folders in: {path.resolve()}")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()


# ---- Main ----
if __name__ == "__main__":
    current_dir = Path(".").resolve()
    print("Starting watcher in:", current_dir)
    ensure_gogdb_local()
    watch_directory(current_dir)
