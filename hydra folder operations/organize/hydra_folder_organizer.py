import argparse
import json
import os
import time
import requests
import re
from pathlib import Path

# ----------------------------
# In-script fetcher config
# ----------------------------
fetchers_config = {
    "steam": {
        "files": [
            {"pattern": "steam_appid.txt", "regex": r"(\d+)"}
        ],
        "api": {
            "url": "https://store.steampowered.com/api/appdetails?appids={id}",
            "method": "GET",
            "json_path": ["{id}", "data", "name"],
            "success_path": ["{id}", "success"]
        }
    },
    "gog": {
        "files": [
            {"pattern": "goggame-*.info", "json_path": ["rootGameId"]}
        ],
        "api": {
            "url": "https://api.gog.com/products/{id}?expand=description",
            "method": "GET",
            "json_path": ["title"]
        }
    }
}

# ----------------------------
# Config loading
# ----------------------------
def load_profiles():
    json_path = Path('profiles.json')
    with open(json_path, 'r', encoding='utf-8') as f:
        return json.load(f)

# ----------------------------
# Filter utilities
# ----------------------------
def passes_filters(file_path, filters):
    for rule in filters:
        if rule.get("type") == "ignore_if_contains":
            if rule["value"].lower() in str(file_path).lower():
                return False
        if rule.get("type") == "only_process_if_extension":
            if not file_path.suffix.lower() in [ext.lower() for ext in rule["value"]]:
                return False
    return True

# ----------------------------
# Fetcher utilities
# ----------------------------
def find_files_recursive(folder_path: Path, pattern: str):
    yield from folder_path.rglob(pattern)

def extract_with_regex(file_path: Path, regex: str):
    try:
        text = file_path.read_text(encoding='utf-8', errors='ignore')
    except Exception:
        try:
            text = file_path.read_text(encoding='latin-1', errors='ignore')
        except Exception:
            return None
    m = re.search(regex, text, re.IGNORECASE)
    if not m:
        return None
    return m.group(1) if m.groups() else m.group(0)

def traverse_json_path(json_obj, path_list, id_value):
    cur = json_obj
    for p in path_list:
        key = id_value if p == "{id}" else p
        if isinstance(cur, dict):
            cur = cur.get(key)
        elif isinstance(cur, list):
            try:
                idx = int(key)
                cur = cur[idx]
            except Exception:
                return None
        else:
            return None
        if cur is None:
            return None
    return cur

def call_api_for_name(api_conf: dict, id_value: str):
    url = api_conf.get("url", "").format(id=id_value)
    method = api_conf.get("method", "GET").upper()
    try:
        resp = requests.request(method, url, timeout=8)
        resp.raise_for_status()
        data = resp.json()
    except Exception as e:
        print(f"[WARN] API call failed for {id_value} -> {e}")
        return None
    success_path = api_conf.get("success_path")
    if success_path:
        ok = traverse_json_path(data, success_path, id_value)
        if not ok:
            return None
    json_path = api_conf.get("json_path")
    if not json_path:
        return None
    return traverse_json_path(data, json_path, id_value)

def fetch_name_for_folder(folder_path: Path, preferred_fetcher: str = None):
    fetcher_items = [(preferred_fetcher, fetchers_config[preferred_fetcher])] \
        if preferred_fetcher and preferred_fetcher in fetchers_config else list(fetchers_config.items())

    for fname, fconf in fetcher_items:
        files_conf = fconf.get("files", [])
        for file_rule in files_conf:
            pattern = file_rule.get("pattern")
            file_json_path = file_rule.get("json_path")  # optional JSON extraction path
            regex = file_rule.get("regex")               # optional regex extraction

            if not pattern:
                continue

            for candidate in folder_path.rglob(pattern):
                if not candidate.is_file():
                    continue

                # Read the file content
                content = None
                try:
                    content = candidate.read_text(encoding='utf-8', errors='ignore')
                except Exception:
                    continue

                # Extract ID/value via regex
                extracted_value = None
                if regex:
                    m = re.search(regex, content)
                    if m:
                        extracted_value = m.group(1) if m.groups() else m.group(0)

                # Extract ID/value via JSON path
                elif file_json_path:
                    try:
                        j = json.loads(content)
                        extracted_value = traverse_json_path(j, file_json_path, None)
                    except Exception:
                        continue

                # If no extraction specified, use raw content
                else:
                    extracted_value = content.strip()

                if not extracted_value:
                    continue

                # Call API if defined
                api_conf = fconf.get("api")
                if api_conf and api_conf.get("url"):
                    name = call_api_for_name(api_conf, extracted_value)
                    if name:
                        print(f"[INFO] Fetcher '{fname}' used file {candidate} -> id {extracted_value} -> name '{name}'")
                        return name
                else:
                    # Otherwise return the extracted value
                    return extracted_value.strip()

    return None

# ----------------------------
# Sanitization + rename
# ----------------------------
def sanitize_folder_name(name: str):
    name = re.sub(r'[<>:"/\\|?*]', "", name)
    name = name.strip(" .")
    return name

def rename_game_folder(folder_path: Path, profile: dict) -> Path:
    preferred = profile.get("fetcher")
    name = fetch_name_for_folder(folder_path, preferred_fetcher=preferred)
    if not name:
        print(f"[INFO] No name found for {folder_path.name} (fetcher: {preferred})")
        return folder_path
    safe = sanitize_folder_name(name)
    if not safe:
        return folder_path

    new_path = folder_path.parent / safe
    if folder_path.resolve() == new_path.resolve():
        return folder_path

    final_path = new_path
    suffix = 1
    while final_path.exists():
        final_path = new_path.parent / f"{new_path.name} ({suffix})"
        suffix += 1

    try:
        folder_path.rename(final_path)
        print(f"[ACTION] Renamed '{folder_path.name}' -> '{final_path.name}'")
        return final_path
    except Exception as e:
        print(f"[ERROR] Failed to rename {folder_path} -> {final_path}: {e}")
        return folder_path

# ----------------------------
# Organizer Actions
# ----------------------------
def denest_folder(folder_path: Path, ignore_patterns=None, catalyst_pattern=None, created_profile_folders=None, profile_names=None) -> Path:
    if ignore_patterns is None:
        ignore_patterns = []
    if created_profile_folders is None:
        created_profile_folders = set()
    if profile_names is None:
        profile_names = set()

    while True:
        items = list(folder_path.iterdir())

        # Collect folders to ignore: profile folders + created profile folders + top-level profile names
        ignored_dirs = set(created_profile_folders)
        ignored_dirs.update(i for i in items if i.name in ignore_patterns and i.is_dir())
        ignored_dirs.update(i for i in items if i.name in profile_names and i.is_dir())

        # Consider subfolders not ignored
        subfolders = [i for i in items if i.is_dir() and i not in ignored_dirs]
        files = [i for i in items if i.is_file() and i.name not in ignore_patterns]

        # Single-subfolder denest
        if len(subfolders) == 1 and len(files) == 0:
            child = subfolders[0]
            for item in child.iterdir():
                target = folder_path / item.name
                if target.exists():
                    base = target.stem
                    ext = target.suffix
                    count = 1
                    new_target = folder_path / f"{base} ({count}){ext}"
                    while new_target.exists():
                        count += 1
                        new_target = folder_path / f"{base} ({count}){ext}"
                    target = new_target
                item.rename(target)
            try:
                child.rmdir()
            except Exception:
                pass
            print(f"[INFO] De-nested {child} into {folder_path}")
            continue

        # No profile folder creation; just ignore items
        break

    return folder_path

# ----------------------------
# Folder polling + main loop
# ----------------------------
processed_folders = set()

def has_blocking_file(folder_path):
    parent = folder_path.parent
    folder_name = folder_path.name
    for item in parent.iterdir():
        if item.is_file() and item.stem.lower() == folder_name.lower():
            return True
    return False

def process_folder(folder_path: Path, profiles: list) -> Path:
    all_profile_names = {p.get("name") for p in profiles if p.get("name")}

    for profile in profiles:
        created_profile_folders = set()
        # initial denest
        folder_path = denest_folder(
            folder_path,
            ignore_patterns=profile.get("ignore_patterns", []),
            catalyst_pattern=profile.get("catalyst_pattern"),
            created_profile_folders=created_profile_folders,
            profile_names=all_profile_names
        )
        # rename
        folder_path = rename_game_folder(folder_path, profile)
        # final denest
        folder_path = denest_folder(
            folder_path,
            ignore_patterns=profile.get("ignore_patterns", []),
            catalyst_pattern=profile.get("catalyst_pattern"),
            created_profile_folders=created_profile_folders,
            profile_names=all_profile_names
        )

    return folder_path

def main():
    parser = argparse.ArgumentParser(description="Poll watch folder and organize top-level game folders.")
    parser.add_argument("watch_folder", help="Folder to watch")
    parser.add_argument("--interval", type=int, default=1, help="Polling interval (seconds)")
    args = parser.parse_args()

    watch_folder = Path(args.watch_folder)
    if not watch_folder.exists():
        print(f"[ERROR] Folder {watch_folder} does not exist")
        return

    profiles = load_profiles()
    print(f"[INFO] Polling {watch_folder} every {args.interval}s")

    while True:
        try:
            for item in watch_folder.iterdir():
                if not item.is_dir():
                    continue
                if has_blocking_file(item):
                    print(f"[INFO] Skipping {item}, blocking file exists.")
                    continue
                if any(item.resolve() == f.resolve() for f in processed_folders):
                    continue

                print(f"[INFO] Processing folder: {item}")
                resolved_path = process_folder(item, profiles)
                processed_folders.add(resolved_path.resolve())

            time.sleep(args.interval)
        except KeyboardInterrupt:
            print("\n[INFO] Stopping watcher.")
            break

if __name__ == "__main__":
    main()
