# Goldberg Achievement Watcher

A Python script that automatically detects and configures Goldberg Emulator settings for Steam games, including achievements support.

## Features

- Automatically detects game folders in the current directory
- Replaces Steam API DLLs with Goldberg Emulator versions
- Generates and updates emulator configuration
- Supports both x86 (32-bit) and x64 (64-bit) games
- Watches for new game folders and processes them automatically
- Caches processed games to avoid reprocessing

## Prerequisites

- Python 3.7 or higher
- Windows operating system
- Steam account (for achievement data)

## Installation

1. Clone or download this repository
2. Install the required dependencies:
   ```
   pip install -r requirements.txt
   ```
3. Place your Goldberg Emulator files in the `_databases/goldberg` directory with the following structure:
   ```
   _databases/
   └── goldberg/
       ├── emu/
       │   └── release/
       │       ├── regular/
       │       │   ├── x32/
       │       │   │   └── steam_api.dll
       │       │   └── x64/
       │       │       └── steam_api64.dll
       └── tools/
           └── generate_emu_config/
               └── generate_emu_config.exe
   ```

## Usage

1. Place your game folders in the same directory as the script
2. Run the script:
   ```
   python goldbergachievement.watcher.py
   ```
3. On first run, you'll be prompted to enter your Steam credentials
4. The script will automatically detect and process any supported games
5. For each game, you'll be prompted to enter the Steam AppID if it can't be determined automatically

## Configuration

You can set the following environment variables:

- `GSE_CFG_USERNAME`: Your Steam username
- `GSE_CFG_PASSWORD`: Your Steam password

## Notes

- The script creates backups of original DLLs with a `.bak` extension
- Processed game information is cached in `_databases/goldberg/cache/processed.json`
- The script runs in watch mode by default and will process new game folders as they're added