import asyncio
import aiohttp
from selectolax.parser import HTMLParser
from datetime import datetime
import re
import json
import sys
import os
import time
from tqdm.asyncio import tqdm_asyncio
import unicodedata

BASE_URL = "https://worldofpcgames.com/game-list/"
CONCURRENCY = 150
OUTPUT_FILE = "worldofpcgames.json"

# ✅ Use uvloop only on non-Windows systems
if sys.platform != "win32":
    try:
        import uvloop
        asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
        print("[INFO] Using uvloop for faster asyncio event loop")
    except ImportError:
        print("[WARN] uvloop not installed. Falling back to default event loop.")
else:
    print("[INFO] Windows detected — skipping uvloop")

TITLE_STRIP_KEYWORDS = [
    "free download",
    "direct download",
    "pc game download",
    "download pc",
    "for pc download",
    "pc download",
    "download free"
]

def normalize_title(title: str) -> str:
    if not title:
        return ""
    title = unicodedata.normalize("NFKD", title)
    title = title.encode("ascii", "ignore").decode()
    title = re.sub(r"[^\x20-\x7E]", "", title)
    lower_title = title.lower()
    for keyword in TITLE_STRIP_KEYWORDS:
        idx = lower_title.find(keyword)
        if idx != -1:
            title = title[:idx]
            break
    title = re.sub(r"\s*\(.*?\)\s*$", "", title)
    title = " ".join(title.split()).title()
    return title

def parse_date_from_text(text: str) -> str:
    match = re.search(r"\((\w+ \d{1,2}, \d{4})\)$", text.strip())
    if match:
        try:
            dt = datetime.strptime(match.group(1), "%B %d, %Y")
            return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
        except:
            return "Unknown"
    return "Unknown"

def extract_file_size(tree: HTMLParser) -> str:
    panel = tree.css_first("#tablist1-panel2")
    if panel:
        text = panel.text(separator="\n")
        match = re.search(r"Space Storage::\s*([\d\.]+\s?(GB|MB|TB))", text, flags=re.I)
        if match:
            return match.group(1).strip()
    return "Unknown"

async def fetch_html(session, url):
    async with session.get(url) as resp:
        resp.raise_for_status()
        return await resp.text()

# Define your filter table
FILTER_KEYWORDS = {
    "main": [
        "-switch-",      # Main category keywords
        "-yuzu-",        # Emulation
        "-ryujinx-"
    ],
    "sub": [
        "-nsp-",         # Subcategory keywords
        "-emu-",         # Emulation
        "-emus-",
        "-emulator-"
    ]
}

def is_filtered_game(url: str) -> bool:
    """
    Return True if a game URL should be filtered out.
    Logic: if a main keyword is found AND any subkeyword is found in the URL, filter it.
    This is easy to extend: just add new keywords to FILTER_KEYWORDS.
    """
    url_lower = url.lower()
    for main_kw in FILTER_KEYWORDS["main"]:
        if main_kw in url_lower:
            for sub_kw in FILTER_KEYWORDS["sub"]:
                if sub_kw in url_lower:
                    return True
    return False


async def scrape_game_page(session, url, sem, results, progress, listing_text=None):
    start_time = time.time()
    async with sem:
        try:
            html = await fetch_html(session, url)
            tree = HTMLParser(html)

            # Title
            title_el = tree.css_first(".article-title")
            raw_title = title_el.text(strip=True) if title_el else url.rstrip("/").split("/")[-1].replace("-", " ")

            # Upload date from listing text
            upload_date = parse_date_from_text(listing_text) if listing_text else "Unknown"

            # File size
            file_size = extract_file_size(tree)

            # First attempt: normal selector
            uris = [
                a.attributes.get("href")
                for a in tree.css(".DownloadButtonContainer a")
                if a.attributes.get("href") and not a.attributes.get("href").endswith("-TRNT.rar")
            ]

            # Fallback: scan the entire HTML for known download hosts if no links found
            if not uris:
                known_hosts = [
                    r"https?://datanodes\.to/[^\s'\"<>]+",
                    r"https?://gofile\.io/d/[^\s'\"<>]+",
                    r"https?://1fichier\.com/\?[^\s'\"<>]+",
                    r"https?://pixeldrain\.com/u/[^\s'\"<>]+",
                    r"https?://qiwi\.gg/file/[^\s'\"<>]+"
                ]
                for pattern in known_hosts:
                    found = re.findall(pattern, html)
                    uris.extend(found)
                uris = list(dict.fromkeys(uris))  # remove duplicates

            results.append({
                "title": raw_title,
                "uploadDate": upload_date,
                "fileSize": file_size,
                "uris": uris,
                "repackLinkSource": url
            })

            progress.update(1)
        except Exception as e:
            print(f"[ERROR] Failed to scrape {url}: {e}")

async def main():
    sem = asyncio.Semaphore(CONCURRENCY)
    results = []

    existing_links = set()
    if os.path.exists(OUTPUT_FILE):
        try:
            with open(OUTPUT_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                results = data.get("downloads", [])
                existing_links = {g.get("repackLinkSource") for g in results if g.get("repackLinkSource")}
            print(f"[INFO] Loaded {len(existing_links)} previously scraped games.")
        except Exception as e:
            print(f"[WARN] Failed to read existing JSON: {e}")

    async with aiohttp.ClientSession() as session:
        html = await fetch_html(session, BASE_URL)
        tree = HTMLParser(html)

        # Extract links and listing text for date parsing
        link_items = tree.css(".aioseo-html-post-sitemap > ul:nth-child(2) > li > a")
        all_links = [(a.attributes.get("href"), a.text(strip=True)) 
                     for a in link_items if a.attributes.get("href") and "-free-download" in a.attributes.get("href")]

        # Remove already scraped links
        new_links = [(url, text) for url, text in all_links if url not in existing_links]

        # Two-layer emulator filter
        filtered_links = [(url, text) for url, text in new_links if not is_filtered_game(url)]
        print(f"[INFO] {len(filtered_links)} links remaining after filtering emulated games.")

        progress = tqdm_asyncio(total=len(filtered_links), desc="Scraping Games", ncols=100, unit="game")
        tasks = [scrape_game_page(session, url, sem, results, progress, listing_text=text) 
                 for url, text in filtered_links]
        await asyncio.gather(*tasks)
        progress.close()

    # Normalize titles
    for g in results:
        g["title"] = normalize_title(g.get("title", ""))

    # Sort and save
    results = sorted(results, key=lambda g: g.get("title", "").lower())
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump({"name": "WorldOfPCGames", "downloads": results}, f, indent=2)

    print(f"[DONE] Scraping complete. Total games in dataset: {len(results)}")

if __name__ == "__main__":
    asyncio.run(main())
