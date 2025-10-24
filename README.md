# hydra-launcher-stuff

Stuff relating to [Hydra Launcher](https://hydralauncher.gg/), mainly just ideas I had for it with primitive examples of such ideas where applicable.

---

## Scrapers / Sources

**Disclaimer:** This repository does **not** host or distribute any pirated content. It contains code—mainly simple web scrapers—that fetches data from sites listed on [FMHY](https://github.com/fmhy) and organizes it into JSON files usable by Hydra. This repository is **not affiliated** with these sites in any way.

---

### Scrapers (currently supported)

#### 1. Steam Underground ✅ Active [visit site](https://steamunderground.net/)
- **Description:** A well-known FMHY source providing preinstalled PC games.  
- **Scraping method:** Uses HTML pattern recognition to extract game data.  
- **Update frequency:** Daily via automated workers.  
- **Load on host site:** The scraper initially requests the full game list, then visits individual game pages only for new entries to collect details such as download URLs, titles, file sizes, and release dates.

#### 2. World of PC Games ✅ Active [visit site](https://worldofpcgames.com/)
- **Description:** Another FMHY source offering preinstalled PC games.
- **Status:** Scrapers back up and running for the foreseeable future. (hopefully)
- **Note:** The scraper would operate similarly to Steam Underground.

---

### Scraper Workflow

1. **Load existing dataset**  
   - Each scraper checks for an existing JSON file. Previously scraped games are loaded to skip duplicates or refresh old entries (if update mode is enabled).

2. **Fetch the game listing page**  
   - Scrapers request the source's index page to collect all available game URLs and metadata such as upload dates.

3. **Filter unwanted entries**  
   - Non-PC or unsupported platforms (e.g., Switch builds, emulators) are filtered out using keyword rules.

4. **Scrape individual game pages**  
   For each valid game URL:  
   - **Title:** Extracted and cleaned of filler words.  
   - **Upload date:** Parsed from the page or listing.  
   - **File size:** Collected if available.  
   - **Download URLs:**  
     - First, standard download buttons/containers are checked.  
     - If none are found, the scraper scans the raw HTML for known file host patterns (e.g., GoFile, Pixeldrain).

5. **Merge with existing data**  
   - Old links from the same host are replaced with updated ones.  
   - Upload dates are preserved unless newer information is found.

6. **Normalize and save**  
   - Titles are normalized for consistency.  
   - Dataset is alphabetically sorted and saved as JSON in this format:

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

### Recommended Sources (no scraper available) 🌟 Recommended

Some sources are highly recommended for Hydra users, even if scrapers are not available. These sources typically come **preconfigured for Goldberg achievements**, ensuring that most games work correctly out of the box:

#### Astral Games [visit site](https://astral-games.xyz/)
- **Advantages:** Games from Astral Games usually have Goldberg achievements preconfigured. Launching these games through Hydra will trigger achievements automatically in the vast majority of cases.  
- **Notes:**  
  - Works reliably if the game supports achievements via Goldberg.  
  - Some Steam games may fail to unlock achievements, but Astral Games repacks are generally set up correctly.  
  - If Goldberg cannot unlock achievements for a specific game, Astral Games cannot override this limitation.

---

### Planned Improvements
- **Weekly refresh:** Re-fetch download links for games already in the JSON to prevent outdated or dead links from accumulating. (this has been implemented)

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

8. **Automatic Steam depot identification** — currently, You rely on sources to specify the version of the game being provided.  
   - By collecting depot data (update manifests) from Steam, Hydra can compare the listed files and their MD5 hashes against the local game files.  
   - The depot manifest that most closely matches indicates which Steam build the game is based on.  
   - This is especially useful when downloading from sources that don’t explicitly state the game version, allowing Hydra to automatically determine the exact Steam build of a local copy.
