# dir_watcher.py
import collections
import os, re, time, chardet, requests, json, asyncio, aiohttp, time, hashlib, shutil
import pefile
import win32api
from pathlib import Path
from pathlib import Path
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from tqdm.asyncio import tqdm_asyncio

# ---------------------------
# Constants
# ---------------------------
CACHE_DIR = os.path.join(os.getcwd(), "_databases", "steamachievements")
os.makedirs(CACHE_DIR, exist_ok=True)

ACH_NAME    = "name"        # internal ID
ACH_TITLE   = "displayName" # user-visible name
ACH_DESC    = "description" # description text
ACH_HIDDEN  = "hidden"      # 0=visible, 1=hidden
ACH_DEFAULT = "defaultvalue"# default value (usually 0)
ACH_ICON    = "icon"        # color icon URL
ACH_GRAY    = "icongray"    # gray/locked icon URL

# ---------------------------
# Configuration
# ---------------------------
WATCH_DIR = os.getcwd()

STEAM_WEB_API_KEY = ""

TEXT_FILE_PATTERNS = {
    "steam_appid.txt": r"\b(\d+)\b",
    "valve.ini": r"^\s*APP\s*ID\s*=\s*(\d+)\b",
    "steam_emu.ini": r"^\s*AppId\s*=\s*(\d+)\s*$",
    "tenoke.ini": r"^\s*id\s*=\s*(\d+)"
}

# ---------------------------
# Achievement Handlers
# ---------------------------
ACHIEVEMENT_HANDLERS = {
    "CODEX": {
        "USERDIR": [r"%PUBLIC%\Documents\Steam\CODEX"],
        "GAMEDIR": [],
        "type": "INI",
        "file": None,
        "mapper": None
    },
    "Tenoke": {
        "USERDIR": [],
        "GAMEDIR": [""],  # Look in the game root directory
        "type": "INI",
        "look_for": "tenoke.ini",  # Look for this specific file
        "file": "tenoke.ini",
        "mapper": {
            ACH_NAME: "id",
            ACH_TITLE: "name",
            ACH_DESC: "description",
            ACH_HIDDEN: "hidden",
            ACH_ICON: {"key": "icon", "filename": "{id}.jpg", "folder": "icons"},
            ACH_GRAY: {"key": "icon_gray", "filename": "{id}_gray.jpg", "folder": "icons"},
            "_structure": ["id", "name", "description", "hidden"]
        },
        "post_process": {
            "section": "ACHIEVEMENTS",
            "transform": {
                "hidden": lambda x: "1" if x.lower() == "true" else "0"
            }
        }
},
    "Goldberg": {
        "USERDIR": [r"%APPDATA%\Goldberg SteamEmu Saves"],
        "GAMEDIR": [],
        "type": "JSON",
        "file": "achievements.json",
        "mapper": {
            ACH_NAME: "name",
            ACH_TITLE: "displayName",
            ACH_DESC: "description",
            ACH_HIDDEN: "hidden",
            ACH_ICON: {"key": "icon", "filename": "{id}.jpg", "folder": "images"},
            ACH_GRAY: {"key": "icongray", "filename": "{id}_gray.jpg", "folder": "images"},
            "_structure": [ACH_NAME, ACH_TITLE, ACH_DESC, ACH_HIDDEN, ACH_ICON, ACH_GRAY]
        },
        "post_process": {
            "transform": {
                "name": lambda x: x.upper().replace(" ", "_") if x else "",
                "hidden": lambda x: 1 if str(x).lower() == "true" else 0,
                "icon": lambda x: f"images/{x}" if x else None,
                "icongray": lambda x: f"images/{x}" if x else None
            }
        }
    },
    "RUNE": {
        "USERDIR": [r"%PUBLIC%\Documents\Steam\RUNE"],
        "GAMEDIR": [],
        "type": "INI",
        "file": None,
        "mapper": None
    },
    "OnlineFix": {
        "USERDIR": [r"%PUBLIC%\Documents\OnlineFix"],
        "GAMEDIR": [],
        "type": "INI",
        "file": "Achievements.ini",
        "mapper": "Auto"
    },
    "RLD": {
        "PROGRAMDATA": [r"%PROGRAMDATA%\RLD!"],
        "GAMEDIR": [],
        "type": "INI",
        "file": "achievements.ini",
        "mapper": {
            ACH_NAME: "name",
            ACH_TITLE: "title",
            ACH_DESC: "desc",
            ACH_HIDDEN: "hidden",
            "_structure": [ACH_NAME, ACH_TITLE, ACH_DESC, ACH_HIDDEN]
        }
    },
    "FLT": {
        "USERDIR": [],
        "GAMEDIR": [],
        "type": "Directory",
        "file": None,
        "mapper": None
    },
    "SKIDROW": {
        "USERDIR": [r"%USERPROFILE%\Documents\SKIDROW"],
        "GAMEDIR": [],
        "type": "INI",
        "file": r"SteamEmu\UserStats\achiev.ini",
        "mapper": {
            ACH_NAME: "name",
            ACH_TITLE: "title",
            ACH_DESC: "desc",
            ACH_HIDDEN: "hidden",
            "_structure": [ACH_NAME, ACH_TITLE, ACH_DESC, ACH_HIDDEN]
        }
    },
    "EMPRESS": {
        "USERDIR": [r"%APPDATA%\EMPRESS"],
        "GAMEDIR": [],
        "type": "JSON",
        "file": "achievements.json",
        "mapper": {
            ACH_NAME: "name",
            ACH_TITLE: "displayName",
            ACH_DESC: "description",
            ACH_HIDDEN: "hidden",
            "_structure": [ACH_NAME, ACH_TITLE, ACH_DESC, ACH_HIDDEN]
        }
    }
}

# ---------------------------
# Phase 1 Steam App IDs
# ---------------------------
def phase_1_checks():
    print("[Phase 1] Running initial checks...")
    app_id_map, processed_folders, seen_app_ids = {}, set(), set()

    for root, dirs, files in os.walk(WATCH_DIR):
        top_folder = os.path.relpath(root, WATCH_DIR).split(os.sep)[0] if os.path.relpath(root, WATCH_DIR) != '.' else '.'
        if top_folder in processed_folders:
            continue

        folder_app_id_found = False
        for filename in files:
            if filename in TEXT_FILE_PATTERNS and not folder_app_id_found:
                file_path = os.path.join(root, filename)
                try:
                    raw_bytes = open(file_path, "rb").read()
                    encoding = chardet.detect(raw_bytes)['encoding'] or 'utf-8'
                    lines = raw_bytes.decode(encoding, errors="ignore").splitlines()

                    for line in lines:
                        match = re.search(TEXT_FILE_PATTERNS[filename], line)
                        if match:
                            app_id = match.group(1)
                            if app_id not in seen_app_ids:
                                # Store AppID -> root folder mapping
                                app_id_map[app_id] = root
                                seen_app_ids.add(app_id)
                            processed_folders.add(top_folder)
                            folder_app_id_found = True
                            break  # stop scanning lines in this file
                except Exception as e:
                    print(f"Failed to read {file_path}: {e}")

            if folder_app_id_found:
                break  # stop scanning other files in this folder

    print(f"[Phase 1] Found {len(app_id_map)} App IDs:")
    for app_id, folder in app_id_map.items():
        print(f"  {app_id} gamedir={folder}")

    return app_id_map  # returns {app_id: root_folder}

# ---------------------------
# Phase 2 Check achievement folders
# ---------------------------
def phase_2_checks(app_ids):
    print("[Phase 2] Checking achievement folders...\n")
    for app_id, app_root_folder in app_ids.items():
        print(f"AppID: {app_id}, Folder: {app_root_folder}")
        for profile, sections in ACHIEVEMENT_HANDLERS.items():
            line = f"- {profile}:"
            section_entries = []

            # Only check USERDIR / PROGRAMDATA / GAMEDIR directories
            for section_name in ("USERDIR", "PROGRAMDATA", "GAMEDIR"):
                dirs = sections.get(section_name)
                if not dirs:
                    section_entries.append("N/A")
                    continue

                # Expand environment variables in paths
                expanded_dirs = [os.path.expandvars(d) for d in dirs]
                found = False
                for folder_path in expanded_dirs:
                    if not os.path.exists(folder_path):
                        continue
                        
                    # Use look_for if specified, otherwise use file
                    file_to_check = sections.get("look_for") or sections.get("file")
                    if not file_to_check:
                        section_entries.append("No file specified")
                        continue
                        
                    full_path = os.path.join(folder_path, file_to_check)
                    status = "OK" if os.path.exists(full_path) else "MISSING"
                    section_entries.append(f"{section_name} [{status}] [{folder_path}] [{file_to_check}]")

            line += " " + ", ".join(section_entries)
            print(line)
        print("")  # blank line between AppIDs
    return True


# ---------------------------
# Phase 3: Fetch and cache achievements
# ---------------------------
def phase_3_fetch_achievements(app_id, handler_name=None, expiry_hours=24):
    """
    Fetch achievements from Steam Web API, cache locally in CACHE_DIR/steamdata,
    apply ACHIEVEMENT_HANDLERS mapping if handler_name is provided, and return structured list.
    Cached data expires after expiry_hours (default 24).
    """
    import requests
    steam_cache_dir = os.path.join(CACHE_DIR, "steamdata")
    os.makedirs(steam_cache_dir, exist_ok=True)

    cache_file = os.path.join(steam_cache_dir, f"{app_id}.json")

    # Check cache age
    recache_needed = True
    if os.path.exists(cache_file):
        file_age = (time.time() - os.path.getmtime(cache_file)) / 3600  # hours
        if file_age < expiry_hours:
            try:
                with open(cache_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                recache_needed = False
                print(f"[Phase 3] Loaded cached achievements for AppID {app_id}")
            except Exception as e:
                print(f"[Phase 3] Failed to load cache for {app_id}: {e}")
                data = None
        else:
            print(f"[Phase 3] Cache expired for AppID {app_id} (age {file_age:.1f}h)")
            data = None
    else:
        data = None

    # Fetch from Steam Web API if needed
    if recache_needed:
        if not STEAM_WEB_API_KEY:
            print("[Phase 3] No Steam API key configured.")
            return None
        try:
            url = f"https://api.steampowered.com/ISteamUserStats/GetSchemaForGame/v2/?key={STEAM_WEB_API_KEY}&appid={app_id}"
            resp = requests.get(url)
            resp.raise_for_status()
            data = resp.json()
            with open(cache_file, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
            print(f"[Phase 3] Fetched and cached achievements for AppID {app_id}")
        except Exception as e:
            print(f"[Phase 3] Failed to fetch achievements for {app_id}: {e}")
            return None

    # Apply mapping if handler provided
    mapper = None
    if handler_name and handler_name in ACHIEVEMENT_HANDLERS:
        mapper = ACHIEVEMENT_HANDLERS[handler_name].get("mapper")

    raw_achievements = data.get("game", {}).get("availableGameStats", {}).get("achievements", [])
    results = []

    for ach in raw_achievements:
        normalized = {}
        if mapper == "Auto" or mapper is None:
            normalized = {
                ACH_NAME: ach.get(ACH_NAME),
                ACH_TITLE: ach.get(ACH_TITLE),
                ACH_DESC: ach.get(ACH_DESC),
                ACH_HIDDEN: ach.get(ACH_HIDDEN),
                ACH_DEFAULT: ach.get(ACH_DEFAULT),
                ACH_ICON: ach.get(ACH_ICON),
                ACH_GRAY: ach.get(ACH_GRAY)
            }
        else:
            for std_key, src in mapper.items():
                if isinstance(src, dict):
                    value = ach.get(src.get("key"))
                    normalized[std_key] = value
                else:
                    normalized[std_key] = ach.get(src)
        results.append(normalized)

    game_name = data.get("game", {}).get("gameName", f"AppID {app_id}")
    if results:
        print(f"[Phase 3] Fetched {len(results)} achievements for {game_name} (ID: {app_id})")
    else:
        print(f"[Phase 3] No achievements found for {game_name} (ID: {app_id})")

    return results

# ---------------------------
# Phase 4: Async Download achievement icons with retries
# ---------------------------
async def download_icon(session, url, save_path, progress, failed_tasks):
    if not url or Path(save_path).exists():
        progress.update(1)
        return 0  # skip existing file
    try:
        start = time.time()
        async with session.get(url, timeout=10) as resp:
            resp.raise_for_status()
            content = await resp.read()
            with open(save_path, "wb") as f:
                f.write(content)
            size_mb = len(content) / (1024 * 1024)
            elapsed = max(time.time() - start, 0.001)
            progress.set_postfix({"Speed": f"{size_mb/elapsed:.2f} MB/s"})
            progress.update(1)
            return len(content)
    except Exception as e:
        progress.update(1)
        failed_tasks.append((url, save_path))
        return 0

async def phase_4_process_achievements_async(app_id, achievements, max_connections=10, max_retries=3):
    images_dir = Path(CACHE_DIR) / "steamdata" / "images" / str(app_id)
    images_dir.mkdir(parents=True, exist_ok=True)

    # Build initial task list
    tasks = []
    total_files = 0
    for ach in achievements:
        ach_id = ach.get(ACH_NAME)
        if ach_id:
            if ach.get(ACH_ICON):
                total_files += 1
            if ach.get(ACH_GRAY):
                total_files += 1

    connector = aiohttp.TCPConnector(limit=max_connections)
    async with aiohttp.ClientSession(connector=connector) as session:
        failed_tasks = []

        with tqdm_asyncio(total=total_files, desc=f"AppID {app_id} Icons") as progress:
            for ach in achievements:
                ach_id = ach.get(ACH_NAME)
                if ach_id and ach.get(ACH_ICON):
                    icon_path = images_dir / f"{ach_id}.jpg"
                    tasks.append(download_icon(session, ach[ACH_ICON], icon_path, progress, failed_tasks))
                if ach_id and ach.get(ACH_GRAY):
                    gray_path = images_dir / f"{ach_id}_gray.jpg"
                    tasks.append(download_icon(session, ach[ACH_GRAY], gray_path, progress, failed_tasks))

            await asyncio.gather(*tasks)

            # Retry failed downloads
            retry_count = 0
            while failed_tasks and retry_count < max_retries:
                retry_count += 1
                current_failures = failed_tasks.copy()
                failed_tasks.clear()
                retry_tasks = [
                    download_icon(session, url, path, progress, failed_tasks)
                    for url, path in current_failures
                ]
                if retry_tasks:
                    await asyncio.gather(*retry_tasks)

def phase_4_process_achievements(app_id, achievements):
    """Wrapper to run async download in synchronous code."""
    asyncio.run(phase_4_process_achievements_async(app_id, achievements))

# ---------------------------
# Phase 5: Achievement mapper / export
# ---------------------------
def find_tenoke_ini(game_root):
    """Search for tenoke.ini in the game directory."""
    # First check the game root directory
    tenoke_ini = os.path.join(game_root, 'tenoke.ini')
    if os.path.isfile(tenoke_ini):
        return tenoke_ini
        
    # If not found in root, check subdirectories
    for root, _, files in os.walk(game_root):
        if 'tenoke.ini' in files:
            return os.path.join(root, 'tenoke.ini')
    return None

def read_tenoke_achievements(ini_path):
    """Read achievements from a Tenoke INI file with localization support."""
    if not ini_path or not os.path.exists(ini_path):
        return []
        
    from configparser import ConfigParser, Interpolation
    
    # Read the file content first to handle duplicate sections
    with open(ini_path, 'r', encoding='utf-8') as f:
        lines = f.readlines()
    
    # Process lines to handle duplicate sections
    section_count = {}
    processed_lines = []
    
    for line in lines:
        line = line.strip()
        if line.startswith('[') and line.endswith(']'):
            section = line[1:-1]
            section_count[section] = section_count.get(section, 0) + 1
            if section_count[section] > 1:
                # Rename duplicate section by appending a number
                section = f"{section}_{section_count[section]-1}"
            processed_lines.append(f"[{section}]")
        else:
            processed_lines.append(line)
    
    # Parse the processed content
    config = ConfigParser(interpolation=None)
    config.read_string('\n'.join(processed_lines))
    
    achievements = []
    processed_achievements = set()
    
    # First pass: collect all achievement IDs
    for section in config.sections():
        if section.startswith('ACHIEVEMENTS.') and not (section.endswith('.name') or section.endswith('.desc')):
            ach_id = section.split('.', 1)[1]
            processed_achievements.add(ach_id)
    
    # Second pass: process each achievement
    for ach_id in processed_achievements:
        section = f'ACHIEVEMENTS.{ach_id}'
        name_section = f'{section}.name'
        desc_section = f'{section}.desc'
        
        # Get basic achievement data
        ach = {
            'id': ach_id,
            'hidden': config.get(section, 'hidden', fallback='0'),
            'icon': config.get(section, 'icon', fallback=''),
            'icon_gray': config.get(section, 'icon_gray', fallback=''),
            'name': {},
            'description': {}
        }
        
        # Get localized names
        if name_section in config:
            for lang, name in config[name_section].items():
                ach['name'][lang] = name
        
        # Get localized descriptions
        if desc_section in config:
            for lang, desc in config[desc_section].items():
                ach['description'][lang] = desc
        
        # Ensure we have at least the English name/description
        if not ach['name'] and name_section in config and 'english' in config[name_section]:
            ach['name']['english'] = config[name_section]['english']
        if not ach['description'] and desc_section in config and 'english' in config[desc_section]:
            ach['description']['english'] = config[desc_section]['english']
            
        achievements.append(ach)
    
    return achievements

def phase_5_post_process(app_id, achievements, handler_name):
    """
    Map normalized achievements into output files according to handler.
    Supports JSON or INI output based on handler configuration.

    Copies images from Phase 4 into handler's folder when applicable.
    """
    if not handler_name or handler_name not in ACHIEVEMENT_HANDLERS:
        print(f"[Phase 5] No handler specified or unknown handler: {handler_name}")
        return

    handler = ACHIEVEMENT_HANDLERS[handler_name]
    target_type = handler.get("type")
    target_file = handler.get("file")
    mapper = handler.get("mapper")
    
    # Special handling for Tenoke
    if handler_name == "Tenoke":
        # First try to find tenoke.ini in the game directory
        tenoke_ini = find_tenoke_ini(os.path.join("games", str(app_id)))
        if not tenoke_ini:
            # If not found in game directory, check _databases directory
            db_tenoke_ini = os.path.join("_databases", "steamachievements", "emulators", "Tenoke", str(app_id), "tenoke.ini")
            if os.path.exists(db_tenoke_ini):
                tenoke_ini = db_tenoke_ini
                
        if tenoke_ini:
            print(f"[Phase 5] Found tenoke.ini at {tenoke_ini}")
            tenoke_achievements = read_tenoke_achievements(tenoke_ini)
            if tenoke_achievements:
                print(f"[Phase 5] Loaded {len(tenoke_achievements)} achievements from tenoke.ini")
                achievements = tenoke_achievements

    # Skip handlers with no file
    if not target_file:
        print(f"[Phase 5] Handler {handler_name} has no target file configured. Skipping.")
        return

    # Root export path (always under _databases)
    base_dir = os.path.join(
        "_databases", "steamachievements", "emulators", handler_name, str(app_id)
    )
    
    # Ensure the target directory exists
    os.makedirs(base_dir, exist_ok=True)
    output_path = os.path.join(base_dir, target_file)
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    # Handle "auto" mapper (blank file)
    if mapper == "Auto":
        with open(output_path, "w", encoding="utf-8") as f:
            f.write("")  # just create an empty file
        print(f"[Phase 5] Created blank file for handler {handler_name}")
        return

    mapped_achievements = []
    image_tasks = []  # list of (src, dst) to copy

    for ach in achievements:
        mapped = {}

        for std_key, rule in mapper.items():
            if not rule:
                continue

            value = ach.get(std_key)

            # Image mapping logic
            if isinstance(rule, dict) and "key" in rule:
                if rule.get("key") is None:
                    continue  # skip if no key

                # Determine destination folder
                image_folder = rule.get("folder")
                filename = rule.get("filename", "{id}.jpg").format(
                    id=ach.get(ACH_NAME, "unknown")
                )

                if image_folder:
                    dest_dir = os.path.join(base_dir, image_folder)
                    os.makedirs(dest_dir, exist_ok=True)
                    dest_path = os.path.join(dest_dir, filename)
                    rel_path = os.path.join(image_folder, filename)
                else:
                    dest_dir = base_dir
                    dest_path = os.path.join(base_dir, filename)
                    rel_path = filename

                # Use the local downloaded image from Phase 4
                src_dir = os.path.join(
                    "_databases", "steamachievements", "steamdata", "images", str(app_id)
                )
                if std_key == ACH_ICON:
                    src_path = os.path.join(src_dir, f"{ach.get(ACH_NAME)}.jpg")
                elif std_key == ACH_GRAY:
                    src_path = os.path.join(src_dir, f"{ach.get(ACH_NAME)}_gray.jpg")
                else:
                    src_path = None

                if src_path and os.path.exists(src_path):
                    image_tasks.append((src_path, dest_path))
                    mapped[rule["key"]] = rel_path.replace("\\", "/")
                else:
                    # skip images if source not available
                    mapped[rule["key"]] = None
                continue

            # Normal mapping (string)
            if isinstance(rule, str):
                mapped[rule] = value

        mapped_achievements.append(mapped)

    # Copy images
    import shutil
    for src, dst in image_tasks:
        try:
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            shutil.copy2(src, dst)
        except Exception as e:
            print(f"[Phase 5] Failed to copy {src} -> {dst}: {e}")

    # Write output
    try:
        if target_type.lower() == "json":
            with open(output_path, "w", encoding="utf-8") as f:
                if handler_name == "Goldberg":
                    # For Goldberg, we need to ensure the correct field order and format
                    formatted = []
                    for ach in mapped_achievements:
                        # Create a new dictionary with the exact field order we want
                        formatted_ach = collections.OrderedDict()
                        formatted_ach["description"] = ach.get("description", "")
                        formatted_ach["displayName"] = ach.get("displayName", "")
                        formatted_ach["hidden"] = ach.get("hidden", 0)
                        formatted_ach["icon"] = ach.get("icon", "")
                        formatted_ach["icongray"] = ach.get("icongray", "")
                        formatted_ach["name"] = ach.get("name", "")
                        formatted.append(formatted_ach)
                    json.dump(formatted, f, indent=2, ensure_ascii=False)
                else:
                    json.dump(mapped_achievements, f, indent=2, ensure_ascii=False)
        elif target_type.lower() == "ini":
            # Initialize config parser for INI operations
            from configparser import ConfigParser
            config = ConfigParser()
            
            if handler_name == "Tenoke":
                # Try to find tenoke.ini in the game directory
                tenoke_ini_path = find_tenoke_ini(os.path.join("games", str(app_id)))
                if tenoke_ini_path and os.path.exists(tenoke_ini_path):
                    # Read existing INI file if it exists
                    config.read(tenoke_ini_path, encoding='utf-8')
                
                # Special handling for Tenoke INI format
                with open(output_path, "w", encoding="utf-8") as f:
                    f.write("# Achievement definitions for Tenoke emulator\n\n")
                    
                    # Write TENOKE section if it exists in the original
                    if 'TENOKE' in config:
                        f.write("[TENOKE]\n")
                        for key, value in config['TENOKE'].items():
                            f.write(f"{key} = {value}\n")
                        f.write("\n")
                    
                    # Write DLC section if it exists in the original
                    if 'DLC' in config:
                        f.write("[DLC]\n")
                        for key, value in config['DLC'].items():
                            f.write(f"{key} = {value}\n")
                        f.write("\n")
                    
                    # Write achievements
                    for ach in mapped_achievements:
                        ach_id = ach.get('id', 'unknown')
                        section = f"ACHIEVEMENTS.{ach_id}"
                        
                        # Write main achievement section
                        f.write(f"[{section}]\n")
                        if 'hidden' in ach:
                            f.write(f"  hidden = {ach['hidden']}\n")
                        if 'icon' in ach and ach['icon']:
                            f.write(f"  icon = {ach['icon']}\n")
                        if 'icon_gray' in ach and ach['icon_gray']:
                            f.write(f"  icon_gray = {ach['icon_gray']}\n")
                        f.write("\n")
                        
                        # Write localized names
                        if 'name' in ach and isinstance(ach['name'], dict) and ach['name']:
                            f.write(f"[{section}.name]\n")
                            for lang, name in ach['name'].items():
                                f.write(f"  {lang} = {name}\n")
                            f.write("\n")
                        
                        # Write localized descriptions
                        if 'description' in ach and isinstance(ach['description'], dict) and ach['description']:
                            f.write(f"[{section}.desc]\n")
                            for lang, desc in ach['description'].items():
                                f.write(f"  {lang} = {desc}\n")
                            f.write("\n")
            else:
                # Standard INI format for other handlers
                from configparser import RawConfigParser
                config = RawConfigParser()  # disable interpolation
                for ach in mapped_achievements:
                    section = ach.get("name", "Unknown")
                    if section not in config:
                        config[section] = {}
                    for key, value in ach.items():
                        if value is not None and key != "name":
                            config[section][key] = str(value)
                with open(output_path, "w", encoding="utf-8") as f:
                    config.write(f)
        else:
            print(f"[Phase 5] Unsupported handler type: {target_type}")
            return

        print(f"[Phase 5] Wrote {len(mapped_achievements)} achievements to {output_path}")
    except Exception as e:
        print(f"[Phase 5] Failed to write achievements for AppID {app_id} to {output_path}: {e}")
    finally:
        print(f"[Phase 5] Finished exporting for AppID {app_id}.")

# ---------------------------
# DLL Management
# ---------------------------
GOLDBERG_DLL_DIR = os.path.join("_databases", "steamachievements", "emulators", "goldberg")
os.makedirs(GOLDBERG_DLL_DIR, exist_ok=True)

def get_file_checksum(filepath):
    """Calculate SHA-256 checksum of a file."""
    try:
        sha256_hash = hashlib.sha256()
        with open(filepath, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except Exception as e:
        print(f"[Error] Failed to calculate checksum for {filepath}: {e}")
        return None

def is_goldberg_dll(dll_path):
    """Check if a DLL is a Goldberg Steam Emulator DLL."""
    if not os.path.exists(dll_path):
        return False
        
    try:
        # First try to get file description
        try:
            info = win32api.GetFileVersionInfo(dll_path, '\\')
            file_desc = info.get('FileDescription', '')
            if 'GSE Client API' in file_desc:
                return True
        except:
            # Fall back to pefile if win32api fails
            try:
                pe = pefile.PE(dll_path)
                if hasattr(pe, 'FileInfo') and pe.FileInfo:
                    for info in pe.FileInfo:
                        if hasattr(info, 'StringTable'):
                            for st in info.StringTable:
                                if hasattr(st, 'entries'):
                                    for entry in st.entries.items():
                                        if str(entry[0]).lower() == 'filedescription':
                                            desc = entry[1].decode('utf-8', errors='ignore') if isinstance(entry[1], bytes) else str(entry[1])
                                            if 'GSE Client API' in desc:
                                                return True
            except:
                pass
        
        # If we get here, either the file description check failed or we couldn't read it
        # Now check against known Goldberg DLL checksums
        dll_name = os.path.basename(dll_path).lower()
        goldberg_dll_path = os.path.join(GOLDBERG_DLL_DIR, dll_name)
        
        if os.path.exists(goldberg_dll_path):
            # Calculate checksums for both files
            target_checksum = get_file_checksum(dll_path)
            goldberg_checksum = get_file_checksum(goldberg_dll_path)
            
            if target_checksum == goldberg_checksum:
                return True
            
            # If checksums don't match, replace the DLL with our known good version
            try:
                backup_path = f"{dll_path}.bak"
                shutil.copy2(dll_path, backup_path)  # Backup original
                shutil.copy2(goldberg_dll_path, dll_path)  # Replace with Goldberg version
                print(f"[DLL] Replaced {dll_path} with Goldberg version")
                return True
            except Exception as e:
                print(f"[DLL] Failed to replace {dll_path}: {e}")
                return False
                
    except Exception as e:
        print(f"[DLL] Error checking {dll_path}: {e}")
    
    return False

# ---------------------------
# Phase 6: Deploy exported achievements to target directories
# ---------------------------
import shutil

def phase_6_post_process(app_id, game_root=None):
    """
    Copy the exported achievements from _databases to the actual handler directories.
    Replaces any existing app ID folder in the target.
    
    Args:
        app_id: The Steam App ID
        game_root: Optional root directory of the game (used for steam_settings check)
    """
    base_emulators_dir = os.path.join("_databases", "steamachievements", "emulators")

    for handler_name, handler in ACHIEVEMENT_HANDLERS.items():
        src_folder = os.path.join(base_emulators_dir, handler_name, str(app_id))
        if not os.path.exists(src_folder):
            continue  # nothing to copy

        # Check for Goldberg handler first
        if handler_name == "Goldberg" and game_root:
            steam_settings_dir = os.path.join(game_root, "steam_settings")
            
            # If steam_settings doesn't exist, check for steam_api*.dll and verify if it's Goldberg
            if not os.path.exists(steam_settings_dir):
                for dll_name in ["steam_api64.dll", "steam_api.dll"]:
                    dll_path = os.path.join(game_root, dll_name)
                    if os.path.exists(dll_path) and is_goldberg_dll(dll_path):
                        try:
                            os.makedirs(steam_settings_dir, exist_ok=True)
                            print(f"[Phase 6] Created {steam_settings_dir} (found Goldberg {dll_name})")
                            break
                        except Exception as e:
                            print(f"[Phase 6] Failed to create {steam_settings_dir}: {e}")
                            continue
            
            # If steam_settings exists (either existed or was just created)
            if os.path.exists(steam_settings_dir):
                try:
                    # Copy achievements.json
                    src_file = os.path.join(src_folder, "achievements.json")
                    if os.path.exists(src_file):
                        dest_file = os.path.join(steam_settings_dir, "achievements.json")
                        shutil.copy2(src_file, dest_file)
                        print(f"[Phase 6] Copied Goldberg achievements to {dest_file}")
                    
                    # Copy images folder if it exists
                    src_images = os.path.join(src_folder, "images")
                    if os.path.exists(src_images):
                        dest_images = os.path.join(steam_settings_dir, "images")
                        if os.path.exists(dest_images):
                            shutil.rmtree(dest_images)
                        shutil.copytree(src_images, dest_images)
                        print(f"[Phase 6] Copied Goldberg achievement images to {dest_images}")
                    
                    continue  # Skip normal deployment for Goldberg with steam_settings
                except Exception as e:
                    print(f"[Phase 6] Failed to copy Goldberg files to {steam_settings_dir}: {e}")

        # Normal deployment for other handlers or Goldberg without steam_settings
        target_dirs = handler.get("USERDIR", []) + handler.get("GAMEDIR", [])
        if not target_dirs:
            continue  # no target directories defined

        for target_base in target_dirs:
            target_base_expanded = os.path.expandvars(target_base)
            if not os.path.exists(target_base_expanded):
                continue

            dest_folder = os.path.join(target_base_expanded, str(app_id))

            try:
                # Remove old folder if exists
                if os.path.exists(dest_folder):
                    shutil.rmtree(dest_folder)

                # Copy new exported folder
                shutil.copytree(src_folder, dest_folder)
                print(f"[Phase 6] Deployed achievements for AppID {app_id} to {dest_folder}")
            except Exception as e:
                print(f"[Phase 6] Failed to deploy achievements for AppID {app_id} to {dest_folder}: {e}")


# ---------------------------
# Event Handler
# ---------------------------
class Watcher(FileSystemEventHandler):
    def __init__(self, processed_folders=None):
        super().__init__()
        self.processed_folders = processed_folders or set()
        self.pending_folders = set()
        self.last_processed = time.time()
    
    def check_folder_for_app_id(self, folder_path):
        """Check if folder contains a file with an App ID and process it if found."""
        folder_path = os.path.normpath(folder_path)
        
        # Skip if we've already processed this folder
        if folder_path in self.processed_folders or not os.path.isdir(folder_path):
            return False
            
        # Check for app ID files in the root of the folder
        for filename, pattern in TEXT_FILE_PATTERNS.items():
            file_path = os.path.join(folder_path, filename)
            if os.path.exists(file_path):
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        content = f.read()
                        if match := re.search(pattern, content, re.MULTILINE | re.IGNORECASE):
                            app_id = match.group(1)
                            print(f"\n[Watcher] Found AppID {app_id} in {folder_path}")
                            self.processed_folders.add(folder_path)
                            process_app_id(app_id, folder_path)
                            return True
                except Exception as e:
                    print(f"[Watcher] Error reading {file_path}: {e}")
        return False
    
    def on_created(self, event):
        if not event.is_directory:
            return
            
        folder_path = os.path.normpath(event.src_path)
        if folder_path in self.processed_folders:
            return
            
        print(f"\n[Watcher] New folder detected: {folder_path}")
        self.pending_folders.add(folder_path)
        self.process_pending()
    
    def process_pending(self):
        """Process any pending folders that haven't been handled yet."""
        current_time = time.time()
        
        # Only process every 5 seconds to avoid excessive processing
        if current_time - self.last_processed < 5:
            return
            
        self.last_processed = current_time
        processed_any = False
        
        for folder_path in list(self.pending_folders):
            if self.check_folder_for_app_id(folder_path):
                self.pending_folders.discard(folder_path)
                processed_any = True
            
            # Also check parent directory in case this is a subdirectory of a game folder
            parent_dir = os.path.dirname(folder_path)
            if parent_dir and parent_dir != folder_path:  # Prevent infinite loops
                if self.check_folder_for_app_id(parent_dir):
                    self.pending_folders.discard(folder_path)
                    processed_any = True
        
        # If we processed anything, wait a moment for any file operations to complete
        if processed_any:
            time.sleep(2)  # Give time for any file operations to complete
    
    def on_any_event(self, event):
        # Process pending folders on any event to catch folder creation that might have been missed
        if time.time() - self.last_processed >= 5:  # Only check every 5 seconds
            self.process_pending()

# ---------------------------
# Watcher Setup
# ---------------------------
def process_app_id(app_id, game_root):
    """Process a single AppID through all phases"""
    print(f"\n=== Processing AppID {app_id} ===")
    
    # Phase 3: fetch achievements
    print("[Phase 3] Fetching achievements...")
    achievements = phase_3_fetch_achievements(app_id)
    if not achievements:
        print(f"[Phase 3] No achievements for AppID {app_id}, skipping remaining phases.")
        return

    # Phase 4: download achievement icons
    print("[Phase 4] Downloading achievement icons...")
    phase_4_process_achievements(app_id, achievements)
    print("[Phase 4] Icon download complete.")

    # Phase 5: map achievements and export for all handlers
    print("[Phase 5] Mapping and exporting achievements...")
    for handler_name in ACHIEVEMENT_HANDLERS.keys():
        phase_5_post_process(app_id, achievements, handler_name)
    print(f"[Phase 5] Finished exporting for AppID {app_id}.")

    # Phase 6: deploy exported achievements
    phase_6_post_process(app_id, game_root)

def start_watching(path):
    # Get initial set of processed folders
    processed_folders = set()
    for root, dirs, files in os.walk(path):
        for file in files:
            if file in TEXT_FILE_PATTERNS:
                folder_path = os.path.normpath(root)
                processed_folders.add(folder_path)
                print(f"[Watcher] Found existing game folder: {folder_path}")
    
    event_handler = Watcher(processed_folders)
    observer = Observer()
    observer.schedule(event_handler, path, recursive=True)
    observer.start()
    print(f"[Watcher] Started watching {path} for new game folders")
    print("[Watcher] Press Ctrl+C to stop watching")
    
    # Initial processing of any existing folders
    for folder in processed_folders:
        event_handler.check_folder_for_app_id(folder)
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

if __name__ == "__main__":
    # Phase 1
    app_ids = phase_1_checks()
    if not app_ids:
        print("[Phase 1] Checks failed or no App IDs found. Exiting.")
        exit(1)

    # Phase 2
    if not phase_2_checks(app_ids):
        print("[Phase 2] Checks failed. Exiting.")
        exit(1)

    # Sequentially process each AppID
    for app_id, app_root_folder in app_ids.items():
        print(f"\n=== Processing AppID {app_id} ===")

        # Phase 3: fetch achievements
        print("[Phase 3] Fetching achievements...")
        achievements = phase_3_fetch_achievements(app_id)
        if not achievements:
            print(f"[Phase 3] No achievements for AppID {app_id}, skipping remaining phases.")
            continue  # skip if nothing fetched

        # Phase 4: download achievement icons (blocking)
        print("[Phase 4] Downloading achievement icons...")
        phase_4_process_achievements(app_id, achievements)
        print("[Phase 4] Icon download complete.")

        # Phase 5: map achievements and export for all handlers
        print("[Phase 5] Mapping and exporting achievements...")
        for handler_name in ACHIEVEMENT_HANDLERS.keys():
            phase_5_post_process(app_id, achievements, handler_name)
        print(f"[Phase 5] Finished exporting for AppID {app_id}.")

        # Phase 6: deploy exported achievements
        game_root = app_ids.get(app_id)  # Get the game root directory from phase_1_checks
        phase_6_post_process(app_id, game_root)

    # Start watching directory after all AppIDs are processed
    print("\n[Watcher] Starting directory watcher...")
    start_watching(WATCH_DIR)

