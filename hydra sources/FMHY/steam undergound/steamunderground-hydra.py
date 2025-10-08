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
import argparse

BASE_URL = "https://steamunderground.net/a-to-z-games/"
CONCURRENCY = 150
OUTPUT_FILE = "steamunderground.json"

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

# ✅ Keywords to strip from titles/slugs
TITLE_STRIP_KEYWORDS = [
    "free download",
    "direct download",
    "pc game download",
    "download pc",
    "for pc download",
    "pc download",
    "download for pc"
]

def normalize_title(title: str) -> str:
    """Normalize a game title for final JSON output."""
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

def parse_date(raw_date: str) -> str:
    try:
        dt = datetime.strptime(raw_date.strip(), "%B %d, %Y")
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    except Exception:
        return "Unknown"

def extract_file_size(tree: HTMLParser) -> str:
    for li in tree.css(".article-content li"):
        strong = li.css_first("strong")
        if strong and "Storage:" in strong.text():
            match = re.search(r"(\d+(\.\d+)?)\s?(GB|MB|TB)", li.text(), flags=re.I)
            if match:
                return match.group(0).strip()
    return "Unknown"

async def fetch_html(session, url):
    async with session.get(url) as resp:
        resp.raise_for_status()
        return await resp.text()

async def scrape_game_page(session, url, sem, progress, existing_game=None):
    async with sem:
        try:
            html = await fetch_html(session, url)
            tree = HTMLParser(html)

            # Title
            title_el = tree.css_first(".s-post-header > h1:nth-child(2)")
            raw_title = title_el.text(strip=True) if title_el else url.rstrip("/").split("/")[-1].replace("-", " ")

            # Upload date
            date_el = tree.css_first(".post-date")
            upload_date = parse_date(date_el.text(strip=True)) if date_el else "Unknown"

            # File size
            file_size = extract_file_size(tree)

            # URIs (filter out TRNT files)
            uris = [
                a.attributes.get("href")
                for a in tree.css(".enjoy-css")
                if a.attributes.get("href") and not a.attributes.get("href").endswith("-TRNT.rar")
            ] or []

            # If updating, merge old URIs intelligently
            if existing_game:
                prev_uris = existing_game.get("uris", [])
                merged_uris = prev_uris.copy()

                for new_uri in uris:
                    host = re.match(r"https?://([^/]+)/", new_uri)
                    if host:
                        host = host.group(1)
                        merged_uris = [u for u in merged_uris if host not in u]
                    merged_uris.append(new_uri)

                uris = list(dict.fromkeys(merged_uris))
                if upload_date == "Unknown":
                    upload_date = existing_game.get("uploadDate", "Unknown")

            progress.update(1)

            return {
                "title": raw_title,
                "uploadDate": upload_date,
                "fileSize": file_size,
                "uris": uris,
                "repackLinkSource": url
            }

        except Exception as e:
            print(f"[ERROR] Failed to scrape {url}: {e}")
            progress.update(1)
            return None

async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--update-uri", action="store_true", help="Refresh URIs and upload dates for existing games")
    args = parser.parse_args()

    sem = asyncio.Semaphore(CONCURRENCY)
    existing_games = {}

    # ✅ Load existing JSON
    if os.path.exists(OUTPUT_FILE):
        try:
            with open(OUTPUT_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                for g in data.get("downloads", []):
                    link = g.get("repackLinkSource")
                    if link:
                        existing_games[link] = g
            print(f"[INFO] Loaded {len(existing_games)} previously scraped games.")
        except Exception as e:
            print(f"[WARN] Failed to read existing JSON: {e}")

    async with aiohttp.ClientSession() as session:
        html = await fetch_html(session, BASE_URL)
        tree = HTMLParser(html)

        all_links = [
            a.attributes.get("href")
            for a in tree.css(".post-content > ul:nth-child(2) a")
            if a.attributes.get("href")
            and "free-download" in a.attributes.get("href")
            and "-switch-nsp" not in a.attributes.get("href")
            and "switch-xci" not in a.attributes.get("href")
        ]

        if args.update_uri:
            links_to_scrape = [(url, existing_games[url]) for url in existing_games.keys()]
            print(f"[INFO] Updating URIs for {len(links_to_scrape)} existing games...")
        else:
            new_links = [link for link in all_links if link not in existing_games]
            links_to_scrape = [(url, None) for url in new_links]
            print(f"[INFO] Found {len(all_links)} total games, {len(new_links)} new to scrape.")

        progress = tqdm_asyncio(total=len(links_to_scrape), desc="Scraping Games", ncols=100, unit="game")

        async def scrape_and_merge(url, existing):
            game_data = await scrape_game_page(session, url, sem, progress, existing_game=existing)
            if not game_data:
                return
            existing_games[url] = {
                **existing_games.get(url, {}),
                **game_data,
                "title": normalize_title(game_data.get("title", "")),
            }

        await asyncio.gather(*[scrape_and_merge(url, existing) for url, existing in links_to_scrape])
        progress.close()

    # ✅ Sort and write to JSON
    results = sorted(existing_games.values(), key=lambda g: g.get("title", "").lower())
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump({"name": "SteamUnderground", "downloads": results}, f, indent=2)

    print(f"[DONE] Scraping complete. Total games in dataset: {len(results)}")

if __name__ == "__main__":
    asyncio.run(main())
