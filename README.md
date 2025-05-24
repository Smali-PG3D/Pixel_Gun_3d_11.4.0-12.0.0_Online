# C++ IL2CPP Mod for Pixel Gun 3D (v11.4.0 & v12.0.0)

This project is a C++ modification (mod) for the Android game **Pixel Gun 3D** (specifically targeting versions **11.4.0** and **12.0.0**), which is built with Unity and uses the IL2CPP runtime. The primary goals of this mod are to **enable online functionality** (potentially on custom servers), **bypass anti-cheat measures**, **grant in-game currency**, **set player level/experience**, and **unlock the frame rate.** It leverages several techniques to alter game behavior.

> **Disclaimer:** This code is provided for educational purposes ONLY. Modifying applications might violate their Terms of Service. Use responsibly and at your own risk. The memory offsets included are specific to versions 11.4.0 and 12.0.0 and **will not function** on current game versions.

## Core Technologies Used

* **IL2CPP API:** Directly interacts with the game's managed code by calling exported IL2CPP functions to find classes, methods, fields, and invoke them or modify their values.
* **Dobby Hooking Framework:** Used to intercept and redirect the execution flow of specific native functions within the game's `libil2cpp.so` library (e.g., `UIRoot.Awake`, `LobbyItem.get_IsExists`).
* **KittyMemory:** Employed for patching memory locations within the loaded `libil2cpp.so`, primarily to disable anti-cheat related functions by overwriting their starting instructions with return (`RET`) or branch (`BX LR`) instructions.
* **JNI (Java Native Interface):** Utilized to retrieve application information like version name and package name from the Android environment.
* **C++:** The primary language for implementing the mod logic, hooking, and patching.

## Key Features

* **Online Activation / Photon Network Modification:** Intercepts game initialization (`UIRoot.Awake`) to modify Photon networking settings (`AppID`, `PreferredRegion`, `HostType`) by accessing the static `PhotonNetwork.PhotonServerSettings` field. This is done on every `Awake` call to ensure settings persistence, enabling connection to specific servers/regions.
* **Anti-Cheat Bypass (Outdated):** Disables several older anti-cheat mechanisms (like cheat detection banners, progress clearing, signature checks, and currency thresholds) using memory patches applied via KittyMemory.
* **Currency Addition (One-Time):** Adds a large amount of in-game currency (coins, gems, tickets) once upon the first run, using a flag file (`currency_added.flag`) in the app's data directory to prevent repeated additions.
* **Player Stat Modification:** Sets the player's level and experience to predefined values on every `UIRoot.Awake` call using `Storager.setInt`.
* **Training Completion:** Checks and sets the training completion flag once using `Defs` and `Storager` classes.
* **Crafting Bypass / Lobby Customization (Version Specific):** Hooks `LobbyItem.get_IsExists` (or a similar function) to always return `true`. This makes all craftable items appear as owned, bypassing server connection checks for these items and allowing lobby customization without restrictions (relevant for v12.0.0).
* **Uncap FPS:** Sets the game's target FPS to a higher value (e.g., 360 FPS) for potentially smoother gameplay on capable devices.
* **Multi-Version/Arch Support:** Includes specific memory offsets for game versions 11.4.0 and 12.0.0, and architectures (`armeabi-v7a`, `x86`), allowing the mod to function across various device configurations for these specific versions.

## How it Works

The mod runs in a background thread initiated from `JNI_OnLoad`. This thread waits for the game's main library (`libil2cpp.so`) to be loaded into memory. Once loaded, it performs initialization steps:

1.  Retrieves the app's version and package name using JNI.
2.  Selects the correct set of memory offsets based on the detected version and architecture.
3.  Finds the base address of the loaded `libil2cpp.so`.
4.  Resolves the addresses of required IL2CPP API functions using `dlsym`.

If initialization is successful, it proceeds to apply the modifications:

* **Memory Patches:** KittyMemory is used to overwrite the beginning of specific anti-cheat functions with instructions that make them return immediately, effectively disabling them.
* **Function Hooks:** Dobby is used to replace the starting address of target game functions (like `UIRoot.Awake`) with the address of custom C++ functions (`UIRoot_Awake_Hook`). The original function's address is saved so it can be called from within the hook.
* **Runtime Modifications:** Inside the hook functions (primarily `UIRoot_Awake_Hook`), the IL2CPP API is used to interact with game objects and methods to change Photon settings, add currency, set stats, etc.

## Prerequisites

* **Android NDK:** Required to build the C++ native code. Make sure it's installed via Android Studio or standalone and the path is configured.
* **CMake:** Used for the build process. Usually included with the NDK/Android Studio.
* **Dobby:** Function hooking framework. ([https://github.com/jmpews/Dobby](https://github.com/jmpews/Dobby)) - You'll need to build or obtain prebuilt libraries for your target ABIs.
* **KittyMemory:** Memory patching library. ([https://github.com/MJx0/KittyMemory](https://github.com/MJx0/KittyMemory)) - Integrate its headers and potentially build its static library if needed.

## Building

There are two primary ways to build the native library:

**Method 1: Using CMake and NDK directly (Command Line)**

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/Smali-PG3D/Pixel_Gun_3d_11.4.0-12.0.0_Online.git
    cd Pixel_Gun_3d_11.4.0-12.0.0_Online
    ```

2.  **Place Dependencies:**
    * Ensure the Dobby library files (`libdobby.so` or `.a` for static linking) for your target architectures (e.g., `armeabi-v7a`, `x86`) are placed in a location accessible by CMake (e.g., a `libs` directory within the project).
    * Ensure the KittyMemory header files (`MemoryPatch.hpp`, etc.) are included in your project's include path (e.g., in an `include/KittyMemory` directory within the project).

3.  **Configure `CMakeLists.txt`:**
    * Verify the paths to Dobby and KittyMemory includes and libraries are correctly set in the `CMakeLists.txt` file. Pay attention to `target_include_directories` and `target_link_libraries`.
    * Adjust target architectures (`ANDROID_ABI`) if necessary.

4.  **Build using CMake and NDK:**
    * Create a build directory:
        ```bash
        mkdir build && cd build
        ```
    * Run CMake (adjust the path `$ANDROID_NDK` to your actual NDK location):
        ```bash
        cmake .. -DCMAKE_TOOLCHAIN_FILE=$ANDROID_NDK/build/cmake/android.toolchain.cmake \
                 -DANDROID_ABI=armeabi-v7a \ # Or x86, arm64-v8a, etc.
                 -DANDROID_PLATFORM=android-21 # Minimum API level
        ```
    * Compile the code:
        ```bash
        make
        ```
    * The compiled native library (e.g., `libnative-lib.so`) will be located in the `build/libs/<ABI>` directory or similar, depending on your `CMakeLists.txt` configuration.

**Method 2: Using Android Studio**

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/Smali-PG3D/Pixel_Gun_3d_11.4.0-12.0.0_Online.git
    ```
2.  **Place Dependencies:** Ensure Dobby libraries and KittyMemory headers are placed correctly within the project structure as described in Method 1, step 2. The `CMakeLists.txt` needs to be able to find them.
3.  **Open Project in Android Studio:**
    * Launch Android Studio.
    * Select "Open an Existing Project" (or "Open").
    * Navigate to and select the cloned repository folder (the one containing the `CMakeLists.txt` file). Android Studio should recognize it as a native project.
4.  **Configure NDK (if needed):**
    * Android Studio might prompt you to configure the NDK location if it hasn't been set up globally. Go to `File -> Project Structure -> SDK Location` and set the "Android NDK Location".
5.  **Build Project:**
    * Select the desired build variant (e.g., `debug` or `release`, and the target ABI like `armeabi-v7a`) from the "Build Variants" panel (usually accessible via `View -> Tool Windows -> Build Variants`).
    * Go to `Build -> Build Bundle(s) / APK(s) -> Build APK(s)` or use the Gradle panel (`View -> Tool Windows -> Gradle`) to run the `assembleDebug` or `assembleRelease` task. This will compile the native code and package the application.
    * Android Studio will invoke CMake and NDK automatically based on the `CMakeLists.txt` and `build.gradle` settings (if a gradle wrapper exists, otherwise it uses the CMake file directly).
6.  **Locate the Library:** The compiled `libnative-lib.so` will typically be located in a path like `app/build/intermediates/cmake/<buildVariant>/obj/<ABI>/` or a similar location within the project's `build` directory managed by Android Studio. If you configured a custom output directory in `CMakeLists.txt` (e.g., `output_libs`), the library will also be copied there.

## Integration (Smali Injection)

To load the mod (`.so` file) into the target application, you need to modify the app's Smali code to add a `System.loadLibrary` call early in the application's startup sequence.

1.  **Decompile the APK:** Use a tool like `apktool` to decompile the target APK:
    ```bash
    apktool d target_app.apk
    ```

2.  **Add the Native Library:** Copy your compiled `libnative-lib.so` file into the appropriate ABI directory within the decompiled APK's `lib` folder (e.g., `target_app/lib/armeabi-v7a/`).

3.  **Inject the Loader Code:**
    * Locate a suitable Smali file that executes early. Common choices are the `onCreate` methods of the main `Activity` classes:
        * `smali*/com/unity3d/player/UnityPlayerActivity.smali`
        * `smali*/com/prime31/UnityPlayerNativeActivity.smali` (May exist in older/specific Unity versions or if using Prime31 plugins)
        * Or the `onCreate` method of the primary `Application` class if one exists.
    * Inside the `.method public onCreate(Landroid/os/Bundle;)V` method, add the following Smali line near the beginning (but typically *after* the `super->onCreate()` call):
        ```smali
        const-string v0, "native-lib" # Load the native library
        invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V
        ```
    * **Important:** Ensure the register used (`v0` in this example) doesn't conflict with existing code in the method. You might need to adjust the register number or increase the `.locals` directive at the beginning of the method if necessary.

4.  **Recompile the APK:** Use `apktool` to rebuild the modified application:
    ```bash
    apktool b target_app -o modded_app.apk
    ```

5.  **Sign the APK:** The rebuilt APK needs to be signed before it can be installed. Use `uber-apk-signer` or `apksigner`:
    ```bash
    # Example using uber-apk-signer
    java -jar uber-apk-signer.jar --apks modded_app.apk
    ```

6.  **Install:** Install the signed, modded APK onto your device or emulator.

## Credits

* **Template Inspiration:** Based on concepts from [Octowolve/Hooking-Template-With-Mod-Menu](https://github.com/Octowolve/Hooking-Template-With-Mod-Menu)
* **Hooking Framework:** [Dobby](https://github.com/jmpews/Dobby) by jmpews
* **Memory Patching Library:** [KittyMemory](https://github.com/MJx0/KittyMemory) by MJx0
