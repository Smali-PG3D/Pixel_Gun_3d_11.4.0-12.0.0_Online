# C++ IL2CPP Mod for Pixel Gun 3D (v11.4.0 & v12.0.0)

This project is a C++ modification (mod) for the Android game **Pixel Gun 3D** (specifically targeting versions **11.4.0** and **12.0.0**), which is built with Unity and uses the IL2CPP runtime. The primary goals of this mod are to **enable online functionality** (potentially on custom servers), **bypass anti-cheat measures**, **grant in-game currency**, **set player level/experience**, and **unlock the frame rate.** It leverages several techniques to alter game behavior.

> **Disclaimer:** This code is provided for educational purposes ONLY. Modifying applications might violate their Terms of Service. Use responsibly and at your own risk. The memory offsets included are specific to versions 11.4.0 and 12.0.0 and **will not function** on current game versions.

## Before you start

This project builds a **native library**, not a standalone game or a launchable mod-menu app. The Android manifest has no launcher activity: installing the wrapper APK will not provide a screen or launcher icon. The library must be loaded by a compatible host app.

The configured ABIs are **`armeabi-v7a` and `x86`** only. Match the host app's ABI, not just the device's architecture; no 64-bit target is configured. The supported host versions are **`11.4.0` and `12.0.0`** only.

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

* **JDK 17 or newer** and **Android SDK Platform 35** for the Gradle build.
* **Android NDK:** Install the revision declared in `app/build.gradle` (`29.0.13113456 rc1`).
* **CMake 3.13 or newer** for the commands below: Install it using Android Studio's SDK Manager or as a standalone tool.
* **Bundled dependencies:** Dobby, KittyMemory, and Keystone are already under `app/src/main/cpp/`. Keep them in place; the CMake configuration references these paths directly. No separate download or relocation is needed for the configured ABIs.

## Building

### Recommended: Gradle or Android Studio

1. Clone the supported branch and enter the repository root:
   ```bash
   git clone --branch 11.4.0-12.0.0 https://github.com/Smali-PG3D/Pixel_Gun_3d_11.4.0-12.0.0_Online.git
   cd Pixel_Gun_3d_11.4.0-12.0.0_Online
   ```
2. Open this root folder (containing `settings.gradle`) in Android Studio, configure the SDK location, and build the `app` module. Alternatively, set `ANDROID_HOME` to your SDK directory and run the included Gradle wrapper from the repository root:
   ```bash
   bash ./gradlew :app:assembleDebug
   ```
   On Windows, use Android Studio; this repository does not include `gradlew.bat`. A separate Gradle installation is not required for the included shell wrapper.
3. Find the native libraries at the paths set by `LIBRARY_OUTPUT_PATH` in `app/src/main/cpp/CMakeLists.txt`:
   ```text
   app/src/main/cpp/output_libs/armeabi-v7a/libnative-lib.so
   app/src/main/cpp/output_libs/x86/libnative-lib.so
   ```
   Use the library matching the host app's ABI. The wrapper APK is not a standalone user interface.

### Alternative: CMake directly

From the repository root, set `ANDROID_NDK` to the installed NDK directory, then run:

```bash
cmake -S app/src/main/cpp -B build/android-armeabi-v7a \
  -DCMAKE_TOOLCHAIN_FILE="$ANDROID_NDK/build/cmake/android.toolchain.cmake" \
  -DANDROID_ABI=armeabi-v7a \
  -DANDROID_PLATFORM=android-21 \
  -DCMAKE_BUILD_TYPE=Release
cmake --build build/android-armeabi-v7a
```

For `x86`, replace `armeabi-v7a` in both the build directory and `ANDROID_ABI`. Use a separate build directory per ABI. The output remains `app/src/main/cpp/output_libs/<ABI>/libnative-lib.so`, not `build/libs/<ABI>`.

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
