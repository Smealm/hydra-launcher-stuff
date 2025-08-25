import os
import time
import asyncio
import logging
import shutil
import getpass
import subprocess
import json
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
import pathlib

try:
    import pefile
except ImportError:
    print("The 'pefile' library is required. Install it with: pip install pefile")
    exit(1)

# Setup logging
logging.basicConfig(
    format="%(asctime)s [%(levelname)s] %(message)s",
    level=logging.INFO,
    datefmt="%H:%M:%S",
)
log = logging.getLogger("goldberg_watcher")

root_dir = os.getcwd()
target_files = {"steam_api.dll", "steam_api64.dll"}

executor = ThreadPoolExecutor(max_workers=os.cpu_count() or 4)

REPLACEMENT_DLLS = {
    "steam_api.dll": os.path.join(root_dir, "_databases", "goldberg", "emu", "release", "regular", "x32", "steam_api.dll"),
    "steam_api64.dll": os.path.join(root_dir, "_databases", "goldberg", "emu", "release", "regular", "x64", "steam_api64.dll"),
}

tools_dir = os.path.join(root_dir, "_databases", "goldberg", "tools", "generate_emu_config")
refresh_tokens_file = os.path.join(tools_dir, "refresh_tokens.json")
cache_file = os.path.join(root_dir, "_databases", "goldberg", "cache", "processed.json")
os.makedirs(os.path.dirname(cache_file), exist_ok=True)

TOKEN = os.path.exists(refresh_tokens_file)
if TOKEN:
    log.info(f"Found refresh_tokens.json at {refresh_tokens_file}")
else:
    log.warning(f"refresh_tokens.json not found at {refresh_tokens_file}, TOKEN set to False")

DEBOUNCE_SECONDS = 5

def load_cache():
    if os.path.exists(cache_file):
        with open(cache_file, "r", encoding="utf-8") as f:
            return json.load(f)
    return {}

def save_cache(cache):
    with open(cache_file, "w", encoding="utf-8") as f:
        json.dump(cache, f, indent=4)

def ensure_login_file():
    login_file = os.path.join(tools_dir, "my_login.txt")
    env_username = os.getenv("GSE_CFG_USERNAME")
    env_password = os.getenv("GSE_CFG_PASSWORD")
    if env_username and env_password:
        log.info("Using Steam credentials from environment variables.")
        return env_username, env_password

    if os.path.exists(login_file):
        log.info(f"Found existing login file: {login_file}")
        try:
            with open(login_file, "r", encoding="utf-8") as f:
                lines = f.read().splitlines()
                if len(lines) >= 2:
                    return lines[0].strip(), lines[1].strip()
        except Exception as e:
            log.error(f"Failed to read {login_file}: {e}")

    print("Goldberg Steam credentials are required.")
    username = input("Enter your Steam username: ").strip()
    password = getpass.getpass("Enter your Steam password: ").strip()

    try:
        os.makedirs(tools_dir, exist_ok=True)
        with open(login_file, "w", encoding="utf-8") as f:
            f.write(f"{username}\n{password}\n")
        log.info(f"Created login file at {login_file}")
    except Exception as e:
        log.error(f"Failed to create {login_file}: {e}")

    return username, password

def timed(action_name):
    def wrapper(func):
        def inner(*args, **kwargs):
            start = time.perf_counter()
            result = func(*args, **kwargs)
            elapsed = (time.perf_counter() - start) * 1000
            log.info(f"{action_name} finished in {elapsed:.2f} ms")
            return result
        return inner
    return wrapper

@timed("check_goldberg_pe")
def check_goldberg_pe(file_path: str) -> bool:
    try:
        pe = pefile.PE(file_path)
        if hasattr(pe, "VS_VERSIONINFO"):
            for fileinfo in pe.FileInfo:
                for entry in fileinfo:
                    for key, value in entry.StringTable[0].entries.items():
                        if isinstance(value, bytes):
                            value = value.decode(errors="ignore")
                        if "GSE Client API" in value:
                            return True
        with open(file_path, "rb") as f:
            if b"GSE Client API" in f.read():
                return True
    except Exception as e:
        log.debug(f"PE parse failed for {file_path}: {e}")
    return False

@timed("read_appid")
def read_appid(file_path: str) -> str | None:
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read().strip()
            if content.isdigit():
                return content
    except Exception as e:
        log.debug(f"Failed to read {file_path}: {e}")
    return None

def folder_ready(folder_path: str) -> bool:
    """Check folder for debounce and locked files."""
    now = time.time()
    folder = pathlib.Path(folder_path)

    # Debounce: folder not modified recently
    if now - folder.stat().st_mtime < DEBOUNCE_SECONDS:
        return False

    # Check all files
    for f in folder.rglob("*"):
        if f.is_file():
            # Debounce individual file
            if now - f.stat().st_mtime < DEBOUNCE_SECONDS:
                return False
            # Check if file is in use
            try:
                with open(f, "r+"):
                    pass
            except Exception:
                return False
    return True

async def replace_goldberg_dlls(game_path: str):
    log.info(f"Replacing DLLs in {game_path}")
    for dirpath, _, filenames in os.walk(game_path):
        for file in filenames:
            lower = file.lower()
            if lower in REPLACEMENT_DLLS:
                src = REPLACEMENT_DLLS[lower]
                dst = os.path.join(dirpath, file)
                try:
                    backup = dst + ".bak"
                    if not os.path.exists(backup):
                        shutil.copy2(dst, backup)
                        log.info(f"Backed up {dst} to {backup}")
                    shutil.copy2(src, dst)
                    log.info(f"Replaced {dst} with {src}")
                except Exception as e:
                    log.error(f"Failed to replace {dst}: {e}")

def get_game_name(game_path: str) -> str | None:
    info_file = os.path.join(game_path, "info", "app_details.json")
    if not os.path.exists(info_file):
        return None
    try:
        with open(info_file, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data.get("data", {}).get("name")
    except Exception as e:
        log.error(f"Failed to read game name from {info_file}: {e}")
        return None

def get_achievement_count(game_path: str) -> int:
    achievements_file = os.path.join(game_path, "steam_settings", "achievements.json")
    if not os.path.exists(achievements_file):
        return 0
    try:
        with open(achievements_file, "r", encoding="utf-8") as f:
            achievements = json.load(f)
            unique_names = {entry["name"] for entry in achievements if "name" in entry}
            return len(unique_names)
    except Exception as e:
        log.error(f"Failed to read achievements from {achievements_file}: {e}")
        return 0

async def scan_game_folder(game_folder: str) -> tuple[str, str] | None:
    game_path = os.path.join(root_dir, game_folder)
    if not os.path.isdir(game_path):
        return None

    if not folder_ready(game_path):
        log.info(f"Skipping {game_folder}, folder not ready or files in use.")
        return None

    log.info(f"Scanning folder: {game_folder}")
    goldberg_found = False
    appid = None

    for dirpath, _, filenames in os.walk(game_path):
        for file in filenames:
            lower = file.lower()
            if lower in target_files:
                dll_path = os.path.join(dirpath, file)
                is_goldberg = await asyncio.get_event_loop().run_in_executor(executor, check_goldberg_pe, dll_path)
                if is_goldberg:
                    goldberg_found = True
            if lower == "steam_appid.txt":
                appid_file_path = os.path.join(dirpath, file)
                appid = await asyncio.get_event_loop().run_in_executor(executor, read_appid, appid_file_path)

    if goldberg_found and not appid:
        user_input = input(f"Enter the AppID for {game_folder}: ").strip()
        if user_input.isdigit():
            appid = user_input
            with open(os.path.join(game_path, "steam_appid.txt"), "w", encoding="utf-8") as f:
                f.write(appid)

    if goldberg_found and appid:
        await replace_goldberg_dlls(game_path)
        return appid, game_path
    return None

def generate_steam_settings(appid: str, game_path: str, cache: dict, rerun_old=False):
    global TOKEN
    if appid in cache and not rerun_old:
        log.info(f"AppID {appid} already processed, skipping.")
        return

    exe_path = os.path.join(tools_dir, "generate_emu_config.exe")
    if not os.path.exists(exe_path):
        log.error(f"{exe_path} not found.")
        return

    cmd = [exe_path] + ([] if TOKEN else ["-token"]) + [appid]
    subprocess.run(cmd, cwd=tools_dir)

    dll_dir = next((dirpath for dirpath, _, files in os.walk(game_path)
                    if any(f.lower() in target_files for f in files)), None)
    if dll_dir:
        for folder_name in ("steam_settings", "info"):
            src = os.path.join(tools_dir, "output", appid, folder_name)
            dst = os.path.join(dll_dir, folder_name)
            if os.path.exists(src):
                if os.path.exists(dst):
                    shutil.rmtree(dst)
                shutil.move(src, dst)

    # Update cache with game_name and achievements
    cache[appid] = {
        "folder": game_path,
        "game_name": get_game_name(game_path),
        "achievements": get_achievement_count(game_path),
        "last_checked": datetime.now().isoformat()
    }
    save_cache(cache)
    
async def process_all(cache, rerun_old=False):
    tasks = []
    for game_folder in os.listdir(root_dir):
        if game_folder.lower() == "_databases":
            continue
        task = asyncio.create_task(scan_game_folder(game_folder))
        tasks.append(task)
    results = await asyncio.gather(*tasks)
    for result in results:
        if result:
            appid, folder = result
            generate_steam_settings(appid, folder, cache, rerun_old=rerun_old)

async def watch_directory(cache):
    log.info("Entering watcher mode. Monitoring for new folders...")
    known_folders = set(os.listdir(root_dir))
    while True:
        await asyncio.sleep(5)
        current_folders = set(os.listdir(root_dir))
        new_folders = current_folders - known_folders
        for folder in new_folders:
            if folder.lower() == "_databases":
                continue
            folder_path = os.path.join(root_dir, folder)
            if folder_ready(folder_path):
                log.info(f"New folder detected: {folder}. Triggering processing...")
                await process_all(cache, rerun_old=False)
        known_folders = current_folders

async def main():
    cache = load_cache()
    rerun_old = False
    if cache:
        answer = input("Do you want to rerun previously processed AppIDs? (y/N): ").strip().lower()
        rerun_old = answer == "y"

    ensure_login_file()
    await process_all(cache, rerun_old=rerun_old)
    await watch_directory(cache)

if __name__ == "__main__":
    asyncio.run(main())
