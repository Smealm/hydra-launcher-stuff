# hydra-launcher-stuff

Stuff relating to [Hydra Launcher](https://hydralauncher.gg/), mainly just ideas I had for it with primitive examples of such ideas where applicable.

---

## Scrapers / Sources

**Disclaimer:** no pirated content is hosted by this repo. This repo does not upload or distribute any copyrighted material. It contains code (mainly simple web scrapers) that fetch data from sites listed on [FMHY](https://github.com/fmhy) and organizes the plain text into JSON files that Hydra can use. This repo is not related to these sites in any way.

### 1. Steam Underground
- **Explanation:** A starred source on FMHY, offering preinstalled games.  
- **Scraping logic:** Uses simple HTML pattern recognition.  
- **Update frequency:** Refreshed daily via workers.  
- **Scraper load on host site:** Hard to determine without being the site owner. The initial scrape pulls all games from a single HTTP request. For new entries not already in the JSON, the scraper visits individual game pages to collect details such as URIs, titles, file sizes, and release dates.  

### 2. World of PC Games
- **Explanation:** Another FMHY source, also providing preinstalled games.  
- **Note:** Works similarly to Steam Underground.  

## Future improvements (potential)
### 1. Weekly refresh
- Once a week, the script should re-fetch download links for games already listed in the JSON.  
- This helps prevent outdated or dead links from accumulating over time.  
- Currently, this functionality is only implemented in the World of PC Games scraper.  

## How the scrapers operate

1. **Load existing dataset (if available)**  
   - Each scraper checks for an existing JSON file.  
   - Previously scraped games are loaded so the scraper can skip duplicates or refresh old entries (if run with update mode).  

2. **Fetch the game listing page**  
   - Each source provides an index page containing links to all available games.  
   - The scraper requests this page and extracts the game URLs (and sometimes metadata like upload dates).  

3. **Filter out unwanted entries**  
   - Non-PC or unsupported platforms (e.g., Switch builds, emulators) are filtered out using keyword rules.  

4. **Scrape each game page**  
   For every valid game URL:  
   - **Title:** Extracted from the page and cleaned of filler words.  
   - **Upload date:** Parsed from listing text or page content.  
   - **File size:** Collected if the site provides it.  
   - **Download URIs:**  
     - First, the scraper looks for standard download buttons/containers.  
     - If none are found, it falls back to scanning the raw HTML for known file host patterns (GoFile, Pixeldrain, etc.).  

5. **Merge results with existing data**  
   - Old links from the same host are replaced with updated ones.  
   - Upload dates are preserved unless newer information is available.  

6. **Normalize and save**  
   - Titles are cleaned and normalized for consistency.  
   - The final dataset is sorted alphabetically and saved as JSON in this format:  
     ```json
     {
       "name": "SourceName",
       "downloads": [
         {
           "title": "Game Name",
           "uploadDate": "2025-10-04T00:00:00Z",
           "fileSize": "25 GB",
           "uris": ["https://gofile.io/...", "..."],
           "repackLinkSource": "https://example.com/..."
         }
       ]
     }
     ```
---

## Ideas

1. **Crack detection** — identify the crack a game uses.  
   - Optional features: goldberg username setting, automatic achievement fetching/generation for games detected as being Goldberg.

2. **Source detection** — identify where a game initially came from.  
   - Some games may come from SteamRIP, SteamGG, etc. These sites may put URL files in the game directory. The launcher could detect these and store the source for the user.  
3. **Automatic game organization:** Some sources contain nested folders instead of placing the game in the root folder. By detecting the source, Hydra could move and rename folders automatically. 

     Example for SteamGG:
     ```text
     Game-Name (version) SteamGG/
     ├─ game name/
     ├─ _redist
     ├─ steamGG.url
     └─ readme_instructions.txt
     ```
     - Detect the source as SteamGG.  
     - Deduce the real game folder (`game name/`) from known patterns.  
     - Move files in the folder up one level, removing nesting.  
     - Rename the root folder to match the game name.  
     - Optionally, use Steam app ID to fetch official game name from Steam store.
     - Proof of concept is available [here](https://github.com/Smealm/hydra-launcher-stuff/tree/main/hydra%20folder%20operations/organize), add profile and ignore patterns for them in the profiles.json, script normalizes your game folders for you
4. **Automatic EXE setting** — automatically set the executable of preinstalled games using the game’s Steam ID or other metadata.  
   - Example: Hydra downloads "Cult of the Lamb" from SteamGG. Source detection fixes folder nesting. Hydra uses SteamDB or other APIs to set the correct EXE. Custom entries can be used for games that can’t launch directly from the main EXE (e.g., cracked versions).

5. **Automatic installation of repacks** — extract and install repacks (FitGirl, Dodi, etc.) automatically.  
   - Option to delete repacks after installation.  
   - GOG games: extract first (not DLCs), select default language, update `goggame-*.info` with correct language codes.  
   - Proof of concept for auto installing GOG games can be found [here](https://github.com/Smealm/hydra-launcher-stuff/tree/main/hydra%20folder%20operations/install/GOG), relies on the [innoextract windows binary](https://constexpr.org/innoextract/#download) which is already included in the repo for convinience, you can source the innoextract binary yourself if you want to however. reason why the script uses innoextract instead of innosetup cli args is because innosetup has a habit of for brief moments unfocusing whatever window you have focused, like if you are doing something else while innosetup is installing in the background headless / silently it will just randomly take over focus making your computer unusable at times, innoextract gets around this entirely, downside however is that gog specific metadata like registries for the game being installed among some other things are not automatically created by default, i imagine you could add to this so those registries get created the same way innosetup would create them but with its own implementation but i dont really care about that either way.

6. **Implement [Webtor](https://webtor.io/) as a debrid service** — free torrent-to-DDL service with 5MB/s speed cap.  
   - Hydra would pass magnet links to Webtor and receive DDL links for downloading.  

7. **Optional seamless downloads** — automatically download the first source (e.g., SteamGG) and first host (e.g., GoFile) without prompting the user.  
   - Combined with automatic EXE setting, this streamlines Hydra for casual users.  

6. **Implement [Webtor](https://webtor.io/) as a debrid service** — free torrent-to-DDL service with a 5MB/s speed cap.  
   - Hydra would forward magnet links to Webtor and receive DDL links in return.  

7. **Optional seamless downloads** — automatically download the first available source (e.g., SteamGG) and first host (e.g., GoFile) without prompting the user.  
   - Combined with automatic EXE configuration, this streamlines Hydra for casual users.  

8. **Automatic Steam depot identification** — currently, You rely on sources to specify the version of the game being provided.  
   - By collecting depot data (update manifests) from Steam, Hydra can compare the listed files and their MD5 hashes against the local game files.  
   - The depot manifest that most closely matches indicates which Steam build the game is based on.  
   - This is especially useful when downloading from sources that don’t explicitly state the game version, allowing Hydra to automatically determine the exact Steam build of a local copy.
