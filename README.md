# hydra-launcher-stuff
stuff relating to [hydra launcher](https://hydralauncher.gg/), mainly just ideas i had for it with primitave examples of such ideas where applicable

---

## scrapers / sources
Disclaimer: no pirated content is hosted by this repo, this repo does not upload or distribute any copyrighted material. This repo contains code (mainly in the form of simple web scrapers) that go to sites listed on [FMHY](https://github.com/fmhy) and collects plain text present on these sites and organizes them into json files for which hydra can then use. this repo is not at all related to these sites in any way.

1. Steam Underground
Explaination: a starred source on FMHY, contains preinstalled games
Scraping logic: simple html pattern recognization
Updated: daily via workers
Scraper load on host site: impossible to tell 100% due to me not being a site owner, however all the list of games are fetched from a single HTTP request, at that point the heavyness comes into play as the scraper then goes to the games that arent already present in the json and for each game page then fetches game specific details like URI's, titles storage sizes and dates.

2. World of PC Games
Explaination: a source on FMHY, contains preinstalled games
Note: works pretty much the same as steam underground

---

## ideas
1. crack detection (identify the crack a game uses)
   
   1a. using crack detection optional other features (e.g goldberg username setting, automatic achievement fetching and generation, so achievements work out of the box, for games detected as being goldberg)
2. source detection (identify where the game initially came from) 
   explaination: some games may come from SteamRIP or SteamGG or something. these sites tend to put url files pointing to their sites in the directory of the game somewhere. launcher could detect these and store the value                      somewhere for something, makes it easier for the user to know exactly where a game they installed came from, useful for sources where they contain multiple game sources, (e.g one source containing both                        SteamGG and SteamRIP titles in it)
   
   2a. automatic game organization. some sources like SteamRIP and SteamGG contain patterns when their games are installed, instead of the installed folder being the root game folder like you would expect instead the actual         game folder is nested within the initial extracted folder. combining source detection with game organization we can detect the source then apply a move pattern after the game is extracted, example for steamgg instead         of finished folder being 
      ```Game-Name (version) SteamGG/
       L game name/
       L _redist
       L steamGG.url
       L readme_instructions.txt

       we can identify the source as being SteamGG, then look at a table of known steamGG folder patterns to deduce real game folder (in this case game name/) then do the following operations.
       1. take all files in the game folder and push them up by one directory, this effectively removes the nesting.
       2. now we take the name of the game folder and rename the root folder to be the name of the game folder.
       2a. for folder name we could take the steam app id of the game hydra downloaded (im pretty sure hydra has the steam id stored for the title we attempt to download) and can use steam store api (which is public) to              
           get game name then it can just use the actual game name as the folder name instead.
3. automatic exe setting. currently hydra doesn't automatic set the exe of a preinstalled game, probably because hydra cant distinguish between preinstalled and repacked games currently. regardless, hydra can use its built-     in knowledge of a games steam id for steam games to attempt to automatically set the exe.
   Example: lets say i download cult of the lamb from steamgg source through hydra. hydra downloads the game then extracts it. then source detection kicks in and detects source then removes detected nesting to make the game              files be in folder root and renames the folder to match the actual name of the game. now hydra launcher can take that organized game and derive steams launch option for that game. one way to fetch this would be               to use something like steamdb which has game launch options in game configuration. or some other method. some games that cant be launched directly from the main exe can be accounted for by using crack detection               mixed with a custom entry system that hydra can later reference. for example game: watch dogs 2 with crack by codex can't be launched from main exe point to this other exe in the directory and use that one. 
4. automatic installation of repacks. when you download lets say a fitgirl repack, dodi repack or the like we should have the option to toggle something like automatic repack installation, and another setting called          automatic repack deletion after install, the idea behind this when the repack is installed hydra will attempt to in the background unpack the game to expected game directory automatically in the background, this is        pretty much just like extraction after download in a sort of roundabout way. for GOG games its the same concept. although for gog games you dont want to use the built in innosetup commands instead you can use a            tool like innoxetract to extract the game, but you want to extract the game 1st, not the dlcs. you also need to know the languages the game uses, mainly to verify if english is a valid option for that game, then           extract the game, take the language the game uses by default and go into goggame-*.info and set the used language codes to english ones or whatever language you use. im pretty sure similiar stuff has to be done with       other repacks as well
5. implement [webtor](https://webtor.io/) as a debrid service
   webtor is a free torrent to DDL service with a free download speed cap of 5mb/s, this service being implemented into hydra would be useful for albiet slow but secure and free downloads of torrents over ddl. 
   hydra needs to take the mag link from a source, and instead of torrenting itself it just talks to webtor somehow to get a ddl link from webtor after passing the magnet link to it, then hydra adds that ddl to its download handler (not currently possible as of writing this but passing generic ddl links straight to its python RPC is something people working on hydra are looking into / working on)
6. optional seamless downloads. when clicking download on a game it will always fetch the first source (like steamgg) and the first download host (like gofile) and download that instead of asking you among which of the sources you want for the game in question. combined with automatic exe setting this could make the launcher way more streamlined for casual users.
