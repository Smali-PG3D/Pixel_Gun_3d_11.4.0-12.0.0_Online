# C++ IL2CPP Mod for Pixel Gun 3D (v11.4.0 & v12.0.0)

This project is a C++ modification (mod) for the Android game **Pixel Gun 3D (specifically targeting versions 11.4.0 and 12.0.0)**, which is built with Unity and uses the IL2CPP runtime. The primary goals of this mod are to **enable online functionality (potentially on custom servers), bypass anti-cheat measures, grant in-game currency, and set player level/experience.** It leverages several techniques to alter game behavior.

**Note:** Due to changes in the game, this mod is unlikely to work on versions newer than 12.0.0 without significant updates to offsets and potentially logic.

## Core Technologies Used

* **IL2CPP API:** Directly interacts with the game's managed code by calling exported IL2CPP functions to find classes, methods, fields, and invoke them or modify their values.
* **Dobby Hooking Framework:** Used to intercept and redirect the execution flow of specific native functions within the game's `libil2cpp.so` library (e.g., `UIRoot.Awake`, `LobbyItem.get_IsExists`).
* **KittyMemory:** Employed for patching memory locations within the loaded `libil2cpp.so`, primarily to disable anti-cheat related functions by overwriting their starting instructions with return (`RET`) or branch (`BX LR`) instructions.
* **JNI (Java Native Interface):** Utilized to retrieve application information like version name and package name from the Android environment.
* **C++:** The primary language for implementing the mod logic, hooking, and patching.

## Key Features

* **Online Activation / Photon Network Modification:** Intercepts game initialization (`UIRoot.Awake`) to modify Photon networking settings (`AppID`, `PreferredRegion`, `HostType`) by accessing the static `PhotonNetwork.PhotonServerSettings` field. This is done on every `Awake` call to ensure settings persistence, enabling connection to specific servers/regions.
* **Anti-Cheat Bypass:** Disables several anti-cheat mechanisms (like cheat detection banners, progress clearing, signature checks, and currency thresholds) using memory patches applied via KittyMemory.
* **Currency Addition:** Adds a large amount of in-game currency (coins, gems, tickets) once upon the first run, using a flag file (`currency_added.flag`) in the app's data directory to prevent repeated additions.
* **Player Stat Modification:** Sets the player's level and experience to predefined values on every `UIRoot.Awake` call using `Storager.setInt`.
* **Training Completion:** Checks and sets the training completion flag once using `Defs` and `Storager` classes.
* **Crafting Bypass / Lobby Customization:** Hooks `LobbyItem.get_IsExists` (or a similar function) to always return `true`. This makes all craftable items appear as owned, bypassing server connection checks for these items and allowing lobby customization without restrictions.
* **Multi-Version/Arch Support:** Includes specific memory offsets for game versions 11.4.0 and 12.0.0, and architectures (armeabi-v7a, x86), allowing the mod to function across various device configurations for these specific versions.
* **Debugging:** Implements file-based logging (`MyModLog.txt`) that overwrites on each game launch, aiding in development and troubleshooting.

## How it Works

The mod runs in a background thread initiated from `JNI_OnLoad`, waits for `libil2cpp.so` to be loaded, performs initialization (offset selection, API resolution), and then applies hooks and patches.

## Credits

* **Template:** Based on [Octowolve/Hooking-Template-With-Mod-Menu](https://github.com/Octowolve/Hooking-Template-With-Mod-Menu)
* **Hooking Framework:** [Dobby](https://github.com/jmpews/Dobby) by jmpews
* **Memory Patching Library:** [KittyMemory](https://github.com/MJx0/KittyMemory) by MJx0
