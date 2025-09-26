import asyncio
import aiohttp
from selectolax.parser import HTMLParser
from datetime import datetime
import re
import json
import sys
import time
from tqdm.asyncio import tqdm_asyncio  # tqdm for async tasks

BASE_URL = "https://steamunderground.net/a-to-z-games/"
CONCURRENCY = 150  # Max concurrent requests
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

def clean_title(raw_title: str) -> str:
    """
    Removes 'Free Download' or 'Direct Download' and everything after it.
    """
    match = re.search(r"(Free Download|Direct Download)", raw_title, flags=re.I)
    if match:
        title = raw_title[:match.start()]
    else:
        title = raw_title
    title = re.sub(r"\s*\(.*?\)\s*$", "", title)
    return title.strip()

def parse_date(raw_date: str) -> str:
    dt = datetime.strptime(raw_date.strip(), "%B %d, %Y")
    return dt.strftime("%Y-%m-%dT00:00:00+00:00")

def extract_file_size(tree: HTMLParser) -> str:
    for li in tree.css(".article-content li"):
        strong = li.css_first("strong")
        if strong and "Storage:" in strong.text():
            match = re.search(r"(\d+(\.\d+)?)\s?(GB|MB|TB)", li.text(), flags=re.I)
            if match:
                return match.group(0).strip()
    return None

async def fetch_html(session, url):
    async with session.get(url) as resp:
        return await resp.text()

async def scrape_game_page(session, url, sem, results, progress):
    start_time = time.time()
    async with sem:
        html = await fetch_html(session, url)
        tree = HTMLParser(html)

        # Title
        title_el = tree.css_first(".s-post-header > h1:nth-child(2)")
        if not title_el:
            tqdm_asyncio.write(f"[WARN] No title found on page: {url}")
            progress.update(1)
            return
        raw_title = title_el.text(strip=True)
        title = clean_title(raw_title)

        # Upload Date
        date_el = tree.css_first(".post-date")
        upload_date = parse_date(date_el.text(strip=True)) if date_el else None
        if not upload_date:
            tqdm_asyncio.write(f"[WARN] No upload date found on page: {url}")

        # File Size
        file_size = extract_file_size(tree)
        if not file_size:
            tqdm_asyncio.write(f"[WARN] No file size found on page: {url}")

        # URIs
        uris = [a.attributes.get("href") for a in tree.css(".enjoy-css")]
        if not uris:
            tqdm_asyncio.write(f"[WARN] No download links found on page: {url}")

        game_data = {
            "title": title,
            "uploadDate": upload_date,
            "fileSize": file_size,
            "uris": uris,
        }

        results.append(game_data)

        # Write partial JSON after each game
        with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
            json.dump({"name": "SteamUnderground", "downloads": results}, f, indent=2)

        elapsed = time.time() - start_time
        avg_time = sum([elapsed for _ in results]) / len(results)
        remaining = avg_time * (progress.total - progress.n - 1)

        # Fixed-width game name to prevent bar jumping
        fixed_width_name = (title[:30] + '..') if len(title) > 30 else title.ljust(32)
        progress.set_postfix_str(
            f"Last: {fixed_width_name} | ETA: {time.strftime('%H:%M:%S', time.gmtime(remaining))}"
        )
        progress.update(1)

async def main():
    sem = asyncio.Semaphore(CONCURRENCY)
    results = []

    async with aiohttp.ClientSession() as session:
        html = await fetch_html(session, BASE_URL)
        tree = HTMLParser(html)

        # Filter unwanted Switch URLs
        links = [
            a.attributes.get("href")
            for a in tree.css(".post-content > ul:nth-child(2) a")
            if a.attributes.get("href")
            and "free-download" in a.attributes.get("href")
            and "-switch-nsp" not in a.attributes.get("href")
            and "switch-xci" not in a.attributes.get("href")
        ]

        total_games = len(links)
        print(f"[INFO] Found {total_games} game links to scrape.")
        print(f"[INFO] Writing live results to {OUTPUT_FILE}")

        # Fixed-size progress bar
        progress = tqdm_asyncio(total=total_games, desc="Scraping Games", ncols=100, unit="game")

        tasks = [scrape_game_page(session, url, sem, results, progress) for url in links]
        await asyncio.gather(*tasks)

        progress.close()

    print(f"[DONE] Scraping complete. Total games scraped: {len(results)}")

if __name__ == "__main__":
    asyncio.run(main())
