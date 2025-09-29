import subprocess
import requests
from pathlib import Path
import sys
import re
import time
import json
import shutil

SCRIPT_DIR = Path(__file__).parent
INNOEXTRACT_PATH = str(SCRIPT_DIR / "innoextract.exe")
POLL_INTERVAL = 1.0  # seconds

def run_innoextract(args, cwd=None):
    """Run innoextract with args, return stdout."""
    result = subprocess.run(
        [INNOEXTRACT_PATH, *args],
        capture_output=True,
        text=True,
        cwd=cwd
    )
    return result.stdout

def inspect_installer(installer_path):
    """Get GOG Game ID from installer."""
    out = run_innoextract(["--gog-game-id", str(installer_path)])
    for line in out.splitlines():
        if "GOG.com game ID is" in line:
            return line.split("is")[-1].strip()
    return None

def get_installer_info(installer_path):
    """Run --info to get title and language codes."""
    out = run_innoextract(["--info", str(installer_path)])
    title, languages = "Unknown Game", []
    default_lang = None
    for line in out.splitlines():
        if line.startswith("Inspecting"):
            # Example: Inspecting "Don't Starve"
            title = line.split('"')[1] if '"' in line else title
        if line.strip().startswith("-"):
            # Example: " - en-US"
            m = re.match(r"\s*-\s*([a-z]{2}(?:-[A-Z]{2})?)", line)
            if m:
                languages.append(m.group(1))
    if "en-US" in languages:
        default_lang = "English"
    return title, languages, default_lang

def query_gog_root_id(game_id, depth=0):
    """Resolve root game ID via GOG API (follows requiresGames links)."""
    indent = "    " * depth
    url = f"https://api.gog.com/v2/games/{game_id}?locale=en-US"
    try:
        resp = requests.get(url, timeout=10)
        resp.raise_for_status()
        data = resp.json()
    except Exception as e:
        print(f"{indent}⚠️ Failed GOG API for {game_id}: {e}")
        return int(game_id)

    product = data.get("_embedded", {}).get("product", {})
    title = product.get("title", "Unknown Title")
    product_type = product.get("productType", "Game")
    requires = data.get("_links", {}).get("requiresGames", [])

    if product_type != "Game" and requires:
        required_href = requires[0].get("href", "")
        required_id = int(required_href.split("/")[-1])
        print(f"{indent}🔗 {title} is {product_type} → requires {required_id}")
        return query_gog_root_id(required_id, depth + 1)

    print(f"{indent}✅ Found Core Game: {title} (Root Game ID: {game_id})")
    return int(game_id)

def extract_installer(installer, out_dir, lang_code, lang_name):
    print(f"📦 Extracting {installer.name} → {out_dir}")
    subprocess.run([
        INNOEXTRACT_PATH,
        f"--language={lang_code}",
        f"--default-language={lang_name}",
        str(installer),
        "-d", str(out_dir)
    ])

def validate_install(out_dir, expected_root_id):
    """Verify goggame-*.info files match rootGameId and language = English.
    If language is wrong, rewrite the file to set it to English.
    If rootGameId is wrong, warn but do not fail validation."""
    info_files = list(out_dir.glob("goggame-*.info"))
    if not info_files:
        print("⚠️ No goggame-*.info found, validation skipped.")
        return True  # Don't fail, just warn

    all_good = True
    for f in info_files:
        try:
            with open(f, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except:
            print(f"⚠️ Could not parse {f}")
            all_good = False
            continue

        root_id = data.get("rootGameId")
        lang = data.get("language")

        # Warn on root ID mismatch, but do not fail
        if str(root_id) != str(expected_root_id):
            print(f"⚠️ WARNING: RootGameID mismatch in {f.name}: {root_id} != {expected_root_id}")
            print("   → This may indicate DLC/base game were installed out of order.")
            print("   → This could cause missing/overwritten files, check game manually if issues occur.")

        # Fix language if not English
        if lang != "English":
            print(f"🔧 Fixing language in {f.name}: {lang} → English")
            data["language"] = "English"
            try:
                with open(f, "w", encoding="utf-8") as fh:
                    json.dump(data, fh, indent=4)
            except Exception as e:
                print(f"⚠️ Failed to rewrite {f}: {e}")
                all_good = False

    return all_good

def is_ignored(folder: Path) -> bool:
    """Ignore folder if a sibling archive file with the same base name exists."""
    for f in folder.parent.glob(f"{folder.name}.*"):
        if f.is_file():
            return True
    return False

def process_folder(folder: Path):
    exe_files = sorted(folder.glob("*.exe"))
    if not exe_files:
        print(f"⚠️ No .exe files in {folder.name}")
        return

    # Identify core exe (no requiresGames link)
    core_exe, core_id = None, None
    dlc_exes = []
    for exe in exe_files:
        gid = inspect_installer(exe)
        if not gid:
            continue
        try:
            data = requests.get(f"https://api.gog.com/v2/games/{gid}?locale=en-US", timeout=10).json()
        except Exception as e:
            print(f"⚠️ Failed GOG API for {exe.name}: {e}")
            continue
        if data.get("_links", {}).get("requiresGames"):
            dlc_exes.append(exe)
        else:
            core_exe, core_id = exe, gid
    if not core_exe:
        # fallback: just pick first exe
        core_exe, core_id = exe_files[0], inspect_installer(exe_files[0])

    # Get title + language list
    game_name, langs, default_lang = get_installer_info(core_exe)
    if not default_lang:
        print(f"⚠️ No en-US available for {game_name}")
        return

    # Extract to {watch_dir}/{game_name}
    out_dir = folder.parent / game_name
    if out_dir.exists():
        shutil.rmtree(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    # Resolve root id
    root_id = query_gog_root_id(core_id)

    # Extract core + DLC
    extract_installer(core_exe, out_dir, "en-US", default_lang)
    for exe in dlc_exes:
        extract_installer(exe, out_dir, "en-US", default_lang)

    # Validate and cleanup
    if validate_install(out_dir, root_id):
        print(f"✅ Install validated for {game_name}, cleaning up {folder}")
        shutil.rmtree(folder, ignore_errors=True)
    else:
        print(f"⚠️ Validation issues detected, keeping {folder} for manual review")


def main():
    if len(sys.argv) < 2:
        print("Usage: python gog-install.py <path_to_watch>")
        sys.exit(1)
    root = Path(sys.argv[1])
    pattern = re.compile(r"^game-.*-\(\d+\)$", re.IGNORECASE)
    print(f"Watching {root}...")

    try:
        while True:
            for p in root.iterdir():
                if p.is_dir() and pattern.match(p.name):
                    if not is_ignored(p):
                        process_folder(p)
            time.sleep(POLL_INTERVAL)
    except KeyboardInterrupt:
        print("\nStopped.")

if __name__ == "__main__":
    main()
