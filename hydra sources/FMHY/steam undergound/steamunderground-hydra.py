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

    # Normalize unicode and remove non-ASCII
    title = unicodedata.normalize("NFKD", title)
    title = title.encode("ascii", "ignore").decode()
    title = re.sub(r"[^\x20-\x7E]", "", title)

    # Strip blacklisted keywords
    lower_title = title.lower()
    for keyword in TITLE_STRIP_KEYWORDS:
        idx = lower_title.find(keyword)
        if idx != -1:
            title = title[:idx]
            break

    # Remove trailing parentheses like (v1.0.0), (Build 1234)
    title = re.sub(r"\s*\(.*?\)\s*$", "", title)

    # Normalize spaces and title-case
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
        return await resp.text()

async def scrape_game_page(session, url, sem, results, progress):
    start_time = time.time()
    async with sem:
        html = await fetch_html(session, url)
        tree = HTMLParser(html)

        # Try to get title from page
        title_el = tree.css_first(".s-post-header > h1:nth-child(2)")
        if title_el:
            raw_title = title_el.text(strip=True)
        else:
            # Fallback: derive from slug if no title found
            slug = url.rstrip("/").split("/")[-1]
            slug = slug.replace("-", " ")
            raw_title = slug
            print(f"\n[WARN] No title found on page, using slug as title: {raw_title}")

        # Parse upload date
        date_el = tree.css_first(".post-date")
        upload_date = parse_date(date_el.text(strip=True)) if date_el else "Unknown"

        # File size
        file_size = extract_file_size(tree)

        # URIs, filter out -TRNT.rar files
        uris = [
            a.attributes.get("href")
            for a in tree.css(".enjoy-css")
            if a.attributes.get("href") and not a.attributes.get("href").endswith("-TRNT.rar")
        ] or []

        game_data = {
            "title": raw_title or slug,  # fallback to slug if raw_title empty
            "uploadDate": upload_date or "Unknown",
            "fileSize": file_size or "Unknown",
            "uris": uris,
            "repackLinkSource": url
        }

        results.append(game_data)

        elapsed = time.time() - start_time
        avg_time = sum([elapsed for _ in results]) / len(results)
        remaining = avg_time * (progress.total - progress.n - 1)

        progress.set_postfix_str(f"Last: {raw_title[:30].ljust(30)} | ETA: {time.strftime('%H:%M:%S', time.gmtime(remaining))}")
        progress.update(1)

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

        all_links = [
            a.attributes.get("href")
            for a in tree.css(".post-content > ul:nth-child(2) a")
            if a.attributes.get("href")
            and "free-download" in a.attributes.get("href")
            and "-switch-nsp" not in a.attributes.get("href")
            and "switch-xci" not in a.attributes.get("href")
        ]

        new_links = [link for link in all_links if link not in existing_links]

        print(f"[INFO] Found {len(all_links)} total games, {len(new_links)} new to scrape.")
        print(f"[INFO] Writing live results to {OUTPUT_FILE}")

        progress = tqdm_asyncio(total=len(new_links), desc="Scraping Games", ncols=100, unit="game")
        tasks = [scrape_game_page(session, url, sem, results, progress) for url in new_links]
        await asyncio.gather(*tasks)
        progress.close()

    # ✅ Normalize all titles after scraping
    for g in results:
        g["title"] = normalize_title(g.get("title", ""))

    # ✅ Final sort and write JSON
    results = sorted(results, key=lambda g: g.get("title", "").lower())
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump({"name": "SteamUnderground", "downloads": results}, f, indent=2)

    print(f"[DONE] Scraping complete. Total games in dataset: {len(results)}")

if __name__ == "__main__":
    asyncio.run(main())

