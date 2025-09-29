# hydra-launcher-stuff

Stuff relating to [Hydra Launcher](https://hydralauncher.gg/), mainly just ideas I had for it with primitive examples of such ideas where applicable.

---

## Scrapers / Sources

**Disclaimer:** no pirated content is hosted by this repo. This repo does not upload or distribute any copyrighted material. It contains code (mainly simple web scrapers) that fetch data from sites listed on [FMHY](https://github.com/fmhy) and organizes the plain text into JSON files that Hydra can use. This repo is not related to these sites in any way.

### 1. Steam Underground
- **Explanation:** a starred source on FMHY, contains preinstalled games  
- **Scraping logic:** simple HTML pattern recognition  
- **Updated:** daily via workers  
- **Scraper load on host site:** impossible to tell 100% due to not being a site owner. All games are fetched from a single HTTP request. After that, the scraper visits pages for games not already in the JSON to fetch details like URIs, titles, storage sizes, and dates.

### 2. World of PC Games
- **Explanation:** a source on FMHY, contains preinstalled games  
- **Note:** works similarly to Steam Underground  

## Future improvements (maybe)

### 1. Weekly refresh
- every week the script should fetch new download links from games already in the JSON, this is to help prevent dead or outdated links from clouding the json over time.
currently only implemented in world of pc games scraper

---

## Ideas

1. **Crack detection** — identify the crack a game uses.  
   - Optional features: goldberg username setting, automatic achievement fetching/generation for games detected as being Goldberg.

2. **Source detection** — identify where a game initially came from.  
   - Some games may come from SteamRIP, SteamGG, etc. These sites may put URL files in the game directory. The launcher could detect these and store the source for the user.  
   - **Automatic game organization:** Some sources contain nested folders instead of placing the game in the root folder. By detecting the source, Hydra could move and rename folders automatically.  
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

3. **Automatic EXE setting** — automatically set the executable of preinstalled games using the game’s Steam ID or other metadata.  
   - Example: Hydra downloads "Cult of the Lamb" from SteamGG. Source detection fixes folder nesting. Hydra uses SteamDB or other APIs to set the correct EXE. Custom entries can be used for games that can’t launch directly from the main EXE (e.g., cracked versions).

4. **Automatic installation of repacks** — extract and install repacks (FitGirl, Dodi, etc.) automatically.  
   - Option to delete repacks after installation.  
   - GOG games: extract first (not DLCs), select default language, update `goggame-*.info` with correct language codes.  

5. **Implement [Webtor](https://webtor.io/) as a debrid service** — free torrent-to-DDL service with 5MB/s speed cap.  
   - Hydra would pass magnet links to Webtor and receive DDL links for downloading.  

6. **Optional seamless downloads** — automatically download the first source (e.g., SteamGG) and first host (e.g., GoFile) without prompting the user.  
   - Combined with automatic EXE setting, this streamlines Hydra for casual users.
