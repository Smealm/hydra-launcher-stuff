# Hydra GOG Games Auto-Installer

A Python script that integrates with Hydra launcher to automatically install GOG games as they're downloaded by Hydra. It watches your Hydra games folder, detects new GOG installers, and handles the installation process seamlessly.

## Prerequisites

- innoextract (must be in system PATH)
- Windows 10/11 (for full functionality)

## Setup

1. **Install Prerequisites**
   - Install [innoextract](https://constexpr.org/innoextract/) and add it to your system PATH
   - Verify both are installed:
     ```bash
     innoextract --version  # Should show version info
     ```

2. **Install Python Dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Place Script in Hydra Games Folder**
   - Copy `gog-games.watcher.py` to your Hydra games folder (e.g., `D:\Games\Hydra`)
   - This is the same folder where Hydra downloads and extracts games

## Usage

1. **Start the Watcher**
   - Open a command prompt in your Hydra games folder
   - Run: `python gog-games.watcher.py`
   - The script will start monitoring for new GOG installers

2. **Download Games in Hydra**
   - Use Hydra launcher to download GOG games as usual
   - The script will automatically detect and process new installers
   - Point Hydra Launcher to your game manually

### Running at Startup (Recommended)
1. Create a shortcut to the script
2. Place it in Windows Startup folder (`shell:startup` in Run dialog)
3. The watcher will now start automatically when you log in

## How It Works

1. **Detection**: The script monitors your Hydra games folder for new GOG installers

2. **Verification**: When a new installer is detected:
   - Uses `innoextract` to extract the GOG game ID from the installer
   - Cross-references this ID with the local gogdb file to determine if it's a game or DLC
   - Ensures proper installation order (games before their DLCs)

3. **Installation**:
   - Creates a clean folder for the game
   - Installs the game or DLC with proper file structure
   - Removes installer files afterwards

## Features

- Handles GOG setup files
- Clean error handling and logging
- Runs in the background with minimal resource usage

## Notes

- The script requires administrator privileges to install games without UAC prompt
- Game installations are logged in the respective game directories (as well as in the gogdb_meta.json in the _database folder)

## Troubleshooting

- If you get `innoextract not found` errors, ensure it's properly added to your system PATH
- Run with `--verbose` flag for detailed error messages
- Check the generated log files in the game installation directories
