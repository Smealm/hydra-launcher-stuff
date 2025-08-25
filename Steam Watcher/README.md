# Steam Watcher

A Python script that monitors your downloads folder for game files from various sources (SteamGG, AtopGames, SteamRIP, etc.) and automatically organizes them into a clean, consistent folder structure.

## Features

- Monitors a specified folder for new game downloads
- Detects games from multiple sources (SteamGG, AtopGames, SteamRIP, etc.)
- Automatically organizes game files into a clean folder structure
- Handles file extraction and cleanup
- Progress tracking with tqdm
- Asynchronous processing for better performance

## Prerequisites

- Python 3.7+
- Windows OS (for full functionality)
- Required Python packages (see requirements.txt)

## Installation

1. Clone or download this repository
2. Install the required dependencies:
   ```
   pip install -r requirements.txt
   ```

## Usage

1. Place the script in the directory you want to monitor
2. Run the script:
   ```
   python steamgeneric.watcher.py
   ```
3. The script will automatically monitor the directory for new game downloads

## Configuration

You can modify the following variables in the script:
- `WATCHED_FOLDER`: The directory to monitor (defaults to current directory)
- `SCAN_INTERVAL`: How often to check for changes (in seconds)
- `FILENAMES_TO_DETECT`: Patterns to identify different game sources

## How It Works

The script operates in several phases:
1. **Detection**: Scans for new game files in the watched directory
2. **Cleaning**: Removes unnecessary files and folders based on patterns
3. **Processing**: Extracts and organizes game files
4. **Finalization**: Moves files to their final location and cleans up

## Supported Sources

- SteamGG
- AtopGames
- SteamRIP

## Troubleshooting

- Ensure all dependencies are installed
- Run the script with administrator privileges if you encounter permission issues
- Check that the watched directory exists and is accessible

## License

[Specify your license here]
