# -----------------------
# IMPORTS
# -----------------------
import os, time, ctypes, re, json, urllib.request, shutil, subprocess
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from tqdm import tqdm
import concurrent.futures

# -----------------------
# CONFIG
# -----------------------
WATCHED_FOLDER = os.getcwd()
SCAN_INTERVAL = 10

# Multiple variants per canonical key
FILENAMES_TO_DETECT = {
    "SteamGG": ["SteamGG – Free Download Pre-installed Steam Games"],
    "AtopGames": ["AtopGames.com - Free Preinstalled Games"],
    "SteamRIP": [
        "STEAMRIP  » Free Pre-installed Steam Games",
        "STEAMRIP » Free Pre-installed Steam Games"
    ]
}

IGNORE_PATTERNS = {
    "SteamGG": {"files": {"Read-Me-Instructions.txt", "Read_Me_Instructions.txt"}, "folders": {"_Redist"}},
    "AtopGames": {"files": {"Read_Me_How_To_Play.txt"}, "folders": {"_Redist"}},
    "SteamRIP": {"files": {"Read_Me_Instructions.txt"}, "folders": {"_CommonRedist"}}
}

TEXT_FILE_PATTERNS = {
    "steam_appid.txt": r"\b(\d+)\b",
    "valve.ini": r"^\s*APP\s*ID\s*=\s*(\d+)\b",
    "steam_emu.ini": r"^\s*AppId\s*=\s*(\d+)\s*$",
    "tenoke.ini": r"^\s*id\s*=\s*(\d+)"
}

# -----------------------
# STATE
# -----------------------
processed_urls = set()  # track URL files already processed

# -----------------------
# HELPERS
# -----------------------
def is_hidden_or_system(path):
    try:
        attrs = ctypes.windll.kernel32.GetFileAttributesW(str(path))
        return bool(attrs & 0x2 or attrs & 0x4)
    except:
        return True

def match_filename(filename):
    name_without_ext = os.path.splitext(filename)[0]
    for canonical, variants in FILENAMES_TO_DETECT.items():
        for variant in variants:
            if variant in name_without_ext:
                print(f"[Matcher] '{filename}' matched variant '{variant}' -> canonical '{canonical}'")
                return canonical
    return None

def is_file_locked(path):
    try:
        fd = os.open(path, os.O_RDWR | os.O_EXCL)
        os.close(fd)
        return False
    except OSError:
        return True

def folder_in_use_async(folder):
    files_to_check = []
    for root, _, files in os.walk(folder):
        for f in files:
            files_to_check.append(os.path.join(root, f))

    if not files_to_check:
        return False

    with concurrent.futures.ThreadPoolExecutor() as executor:
        results = executor.map(is_file_locked, files_to_check)
        return any(results)

# -----------------------
# PHASE 4: MOVE GAME FILES AND DELETE PARENTS (ASYNC + PROGRESS)
# -----------------------
def phase4_finalize(game_dir, parent_folder):
    from concurrent.futures import ThreadPoolExecutor, as_completed

    game_name = os.path.basename(game_dir)
    dest = os.path.join(WATCHED_FOLDER, game_name)

    items = [os.path.join(game_dir, f) for f in os.listdir(game_dir)]

    def calc_size(path):
        if os.path.isfile(path):
            return os.path.basename(path), 1, os.path.getsize(path)
        total_size = 0
        total_files = 0
        for root, _, files in os.walk(path):
            total_files += len(files)
            total_size += sum(os.path.getsize(os.path.join(root, f)) for f in files)
        return os.path.basename(path), total_files, total_size

    total_files = 0
    total_bytes = 0
    sizes = {}
    with ThreadPoolExecutor(max_workers=min(8, len(items))) as executor:
        futures = {executor.submit(calc_size, i): i for i in items}
        for future in as_completed(futures):
            name, fcount, fsize = future.result()
            sizes[name] = (fcount, fsize)
            total_files += fcount
            total_bytes += fsize

    moved_files = 0
    moved_bytes = 0
    os.makedirs(dest, exist_ok=True)

    def move_item(src):
        name = os.path.basename(src)
        fcount, fsize = sizes.get(name, (0, 0))
        try:
            shutil.move(src, dest)
        except Exception as e:
            print(f"[Phase 4] Failed to move {src}: {e}")
        return fcount, fsize

    with ThreadPoolExecutor(max_workers=min(8, len(items))) as executor:
        futures = {executor.submit(move_item, item): item for item in items}
        with tqdm(total=total_files, unit="file", desc=f"[Phase 4] Moving '{game_name}'") as pbar:
            for future in as_completed(futures):
                fcount, fsize = future.result()
                moved_files += fcount
                moved_bytes += fsize
                pbar.update(fcount)

    print(f"[Phase 4] Finished moving '{game_name}' to '{dest}'")

    current = parent_folder
    while os.path.abspath(current) != os.path.abspath(WATCHED_FOLDER):
        try:
            shutil.rmtree(current)
            print(f"[Phase 4] Force-deleted original folder: {current}")
        except Exception as e:
            print(f"[Phase 4] Failed to delete folder {current}: {e}")
            break
        current = os.path.dirname(current)

# -----------------------
# PHASE 3: EXTRACT VALUES AND RENAME
# -----------------------
def phase3_process(game_folder, parent_folder):
    if not os.path.isdir(game_folder):
        return

    found_types = set()
    steam_game_name = None
    patterns_found = False

    all_files = [os.path.join(root, f) for root, _, files in os.walk(game_folder) for f in files]
    for path in tqdm(all_files, desc="[Phase 3] Scanning for AppID / GOG info", unit="file", leave=False):
        f = os.path.basename(path)
        key = f.lower()
        if key in TEXT_FILE_PATTERNS and key not in found_types:
            patterns_found = True
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                    content = fh.read()
            except Exception as e:
                tqdm.write(f"[Phase 3] Read failed: {path} -> {e}")
                continue

            m = re.search(TEXT_FILE_PATTERNS[key], content, flags=re.IGNORECASE | re.MULTILINE)
            if m:
                appid = m.group(1)
                tqdm.write(f"[Phase 3] {f}: AppID={appid} ({path})")
                try:
                    url = f"https://store.steampowered.com/api/appdetails?appids={appid}"
                    with urllib.request.urlopen(url) as response:
                        data = json.load(response)
                    if data.get(appid, {}).get("success"):
                        steam_game_name = data[appid]["data"].get("name")
                        tqdm.write(f"[Phase 3] AppID {appid} -> Game Name: {steam_game_name}")
                    else:
                        tqdm.write(f"[Phase 3] AppID {appid}: Failed to get game info from Steam")
                except Exception as e:
                    tqdm.write(f"[Phase 3] Steam API request failed for AppID {appid} -> {e}")
            else:
                tqdm.write(f"[Phase 3] {f}: no value found ({path})")
            found_types.add(key)
        if found_types == set(TEXT_FILE_PATTERNS.keys()):
            break

    if not patterns_found:
        gog_files = [f for f in os.listdir(game_folder) if f.lower().startswith("goggame-") and f.lower().endswith(".info")]
        for f in tqdm(gog_files, desc="[Phase 3] Scanning GOG info", unit="file", leave=False):
            path = os.path.join(game_folder, f)
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                    data = json.load(fh)
            except Exception as e:
                tqdm.write(f"[Phase 3] Failed to read GOG info file {path} -> {e}")
                continue

            play_tasks = data.get("playTasks") or data.get("playtasks")
            if play_tasks:
                for task in play_tasks:
                    if task.get("category") == "game" and task.get("name"):
                        steam_game_name = task["name"]
                        patterns_found = True
                        tqdm.write(f"[Phase 3] GOG info found: Game Name = {steam_game_name}")
                        break
            if patterns_found:
                break

    # -----------------------
    # Fallback: single EXE detection
    # -----------------------
    if not steam_game_name:
        exe_files = [f for f in os.listdir(game_folder) if f.lower().endswith(".exe")]
        if len(exe_files) == 1:
            exe_name = os.path.splitext(exe_files[0])[0]
            steam_game_name = exe_name
            patterns_found = True
            tqdm.write(f"[Phase 3] Fallback EXE detected -> Using '{exe_name}' as game name")

    # -----------------------
    # Rename folder if name found
    # -----------------------
    if patterns_found and steam_game_name and os.path.basename(game_folder) != steam_game_name:
        new_path = os.path.join(os.path.dirname(game_folder), steam_game_name)
        try:
            os.rename(game_folder, new_path)
            tqdm.write(f"[Phase 3] Renamed folder to match game name: {new_path}")
            game_folder = new_path
        except Exception as e:
            tqdm.write(f"[Phase 3] Failed to rename folder {game_folder} -> {e}")

    phase4_finalize(game_folder, parent_folder)

# -----------------------
# PHASE 2: CLEAN FOLDER
# -----------------------
def phase2_clean(folder, detected_file, target_subfolder="game files"):
    canonical = match_filename(detected_file) or detected_file
    ignore_files = {detected_file} | IGNORE_PATTERNS.get(canonical, {}).get("files", set())
    ignore_folders = IGNORE_PATTERNS.get(canonical, {}).get("folders", set())

    items = [i for i in os.listdir(folder) if i not in ignore_files and i not in ignore_folders]

    if len(items) == 1 and os.path.isdir(os.path.join(folder, items[0])):
        print(f"[Phase 2] Already clean: {folder}")
        game_dir = os.path.join(folder, items[0])
    else:
        game_dir = os.path.join(folder, target_subfolder)
        os.makedirs(game_dir, exist_ok=True)
        print(f"[Phase 2] Cleaning folder: {folder} -> {target_subfolder}")
        for item in tqdm(items, desc="[Phase 2] Moving files", unit="file"):
            try:
                os.rename(os.path.join(folder, item), os.path.join(game_dir, item))
            except Exception as e:
                print(f"[Phase 2] Failed to move {item}: {e}")

    phase3_process(game_dir, folder)

# -----------------------
# PHASE 1: DETECT FILES (RECURSIVE)
# -----------------------
def phase1_detect(folder):
    print(f"[Phase 1] Scanning folder recursively: {folder}")
    for root, dirs, files in os.walk(folder):
        for f in files:
            path = os.path.join(root, f)
            matched = match_filename(f)
            if matched and path not in processed_urls:
                print(f"[Phase 1] Found file: {path} (matched as {matched})")
                phase2_clean(root, f)
                processed_urls.add(path)

# -----------------------
# WATCHDOG HANDLER
# -----------------------
class WatchHandler(FileSystemEventHandler):
    def on_created(self, event):
        if event.is_directory:
            phase1_detect(event.src_path)

# -----------------------
# RUN WATCHER + SCAN
# -----------------------
if __name__ == "__main__":
    observer = Observer()
    observer.schedule(WatchHandler(), WATCHED_FOLDER, recursive=True)
    observer.start()
    STABILITY_WAIT = 5

    skipped_folders = set()

    try:
        while True:
            current_folders = [
                os.path.join(WATCHED_FOLDER, name)
                for name in os.listdir(WATCHED_FOLDER)
                if os.path.isdir(os.path.join(WATCHED_FOLDER, name))
            ]

            folders_to_check = set(current_folders) | skipped_folders
            skipped_folders.clear()

            for p in folders_to_check:
                try:
                    latest_mod = max(
                        os.path.getmtime(os.path.join(root, f))
                        for root, _, files in os.walk(p) for f in files
                    )
                except ValueError:
                    latest_mod = time.time()

                if time.time() - latest_mod >= STABILITY_WAIT:
                    if not folder_in_use_async(p):
                        phase1_detect(p)
                    else:
                        skipped_folders.add(p)
                else:
                    skipped_folders.add(p)

            time.sleep(SCAN_INTERVAL)

    except KeyboardInterrupt:
        observer.stop()
    observer.join()

