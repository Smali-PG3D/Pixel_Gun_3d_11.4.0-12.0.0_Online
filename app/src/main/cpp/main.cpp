#include <jni.h>
#include <pthread.h>
#include <cstring>
#include <vector>
#include <cstdint>
#include <dlfcn.h>
#include <android/log.h>
#include <cstdio>
#include <cstdlib>
#include <thread>
#include <chrono>
#include <mutex>
#include <ctime>
#include <cerrno>
#include <string>
#include <unistd.h>
#include <sys/types.h>
#include <libgen.h>
#include <memory>
#include <fstream> // For /proc/self/maps parsing
#include <sstream> // For string manipulation
#include <map>     // For storing offsets per version (if needed, not used in current approach)
#include <dobby.h>
#include "KittyMemory/MemoryPatch.hpp" // Assuming this is available

#pragma clang diagnostic push
#pragma ide diagnostic ignored "ConstantFunctionResult" // Ignore specific IDE warnings

// --- JNI Globals ---
static JavaVM* g_JavaVM = nullptr; // Global JavaVM pointer, needed for JNI calls in threads

// --- App Info Struct ---
struct AppInfo {
    std::string versionName = "unknown";
    std::string packageName = "unknown";
    bool success = false; // Flag to indicate if info retrieval was successful
};

// --- IL2CPP Type Declarations ---
// Basic IL2CPP type definitions used throughout the code.
typedef struct Il2CppDomain Il2CppDomain;
typedef struct Il2CppAssembly Il2CppAssembly;
typedef struct Il2CppImage Il2CppImage;
typedef struct Il2CppClass Il2CppClass;
typedef struct Il2CppObject Il2CppObject;
typedef struct Il2CppString Il2CppString;
typedef struct MethodInfo MethodInfo;
typedef struct FieldInfo FieldInfo;
typedef struct Il2CppException Il2CppException;
typedef struct Il2CppType Il2CppType;

// --- IL2CPP API Function Pointers ---
// Pointers to core IL2CPP functions resolved dynamically at runtime.
static Il2CppDomain* (*il2cpp_domain_get)() = nullptr;
static Il2CppAssembly* (*il2cpp_domain_assembly_open)(Il2CppDomain* domain, const char* name) = nullptr;
static Il2CppImage* (*il2cpp_assembly_get_image)(Il2CppAssembly* assembly) = nullptr;
static Il2CppClass* (*il2cpp_class_from_name)(Il2CppImage* image, const char* namespaze, const char* name) = nullptr;
static MethodInfo* (*il2cpp_class_get_method_from_name)(Il2CppClass* klass, const char* name, int argsCount) = nullptr;
static Il2CppString* (*il2cpp_string_new)(const char* str) = nullptr;
static Il2CppObject* (*il2cpp_runtime_invoke)(MethodInfo* method, void* obj, void** params, Il2CppObject** exc) = nullptr;
static FieldInfo* (*il2cpp_class_get_field_from_name)(Il2CppClass* klass, const char* name) = nullptr;
static void (*il2cpp_field_static_get_value)(FieldInfo* field, void* value) = nullptr; // Required for static field access
static void (*il2cpp_field_set_value)(Il2CppObject* obj, FieldInfo* field, void* value) = nullptr;
static void (*il2cpp_field_get_value)(Il2CppObject *obj, FieldInfo *field, void *value) = nullptr; // Optional, previously used for verification
static void* (*il2cpp_object_unbox)(Il2CppObject* obj) = nullptr;
static char* (*il2cpp_string_to_utf8)(Il2CppString* str) = nullptr; // Optional
static const Il2CppType* (*il2cpp_class_get_type)(Il2CppClass* klass) = nullptr; // Optional
static Il2CppObject* (*il2cpp_type_get_object)(const Il2CppType* type) = nullptr; // Optional
static Il2CppClass* (*il2cpp_get_exception_class)() = nullptr; // Optional
static Il2CppString* (*il2cpp_object_to_string)(Il2CppObject* obj, Il2CppObject** exc) = nullptr; // Optional - For exception logging

// --- Global Variables ---
static FILE* log_file = nullptr; // File pointer for logging
static std::mutex log_mutex;     // Mutex to protect log file access
const char* LOG_FILENAME = "MyModLog.txt"; // Name of the log file
const char* FALLBACK_APP_PACKAGE_NAME = "com.pg12a.gun3d"; // Fallback package name if detection fails
const char* IL2CPP_SO_NAME = "libil2cpp.so"; // Target library name
const char* TARGET_ASSEMBLY_NAME = "Assembly-CSharp.dll"; // Main game assembly
const char* FIRSTPASS_ASSEMBLY_NAME = "Assembly-CSharp-firstpass.dll"; // First pass assembly
const char* LibraryToLoad = IL2CPP_SO_NAME; // Library to wait for before initialization
static uintptr_t il2cpp_base = 0; // Base address of libil2cpp.so
static AppInfo g_appInfo;         // Store detected app info globally

// --- Constants for Modifications ---
// Photon related constants
const char* PHOTON_NAMESPACE = ""; // Namespace for PhotonNetwork and ServerSettings (usually empty)
const char* PHOTON_CLASS_NAME = "PhotonNetwork";
const char* PHOTON_SETTINGS_STATIC_FIELD_NAME = "PhotonServerSettings"; // Static field name in PhotonNetwork
const char* SERVER_SETTINGS_CLASS_NAME = "ServerSettings";
const char* SERVERSETTINGS_APPID_FIELD_NAME = "AppID";         // Field name for App ID in ServerSettings
const char* SERVERSETTINGS_REGION_FIELD_NAME = "PreferredRegion"; // Field name for Region in ServerSettings
const char* SERVERSETTINGS_HOSTTYPE_FIELD_NAME = "HostType";      // Field name for Host Type in ServerSettings

// BankController related constants
const char* BANKCONTROLLER_CLASS_NAME = "BankController";
const char* ADD_COINS_METHOD_NAME = "AddCoins";
const char* ADD_GEMS_METHOD_NAME = "AddGems";
const char* ADD_TICKETS_METHOD_NAME = "AddTickets";

// Defs/Storager related constants
const char* DEFS_CLASS_NAME = "Defs";
const char* TRAINING_KEY_GETTER_METHOD_NAME = "get_TrainingCompleted_4_4_Sett";
const char* STORAGER_CLASS_NAME = "Storager";
const char* STORAGER_GETINT_METHOD_NAME = "getInt";
const char* STORAGER_SETINT_METHOD_NAME = "setInt";

// Values used for modifications
const char* NEW_PHOTON_APP_ID = "yourappid"; // Your Photon App ID
const int NEW_PHOTON_HOST_TYPE = 1; // 1 corresponds to ServerSettings.HostingOption.PhotonCloud
const int NEW_PHOTON_REGION = 0;    // 0 corresponds to CloudRegionCode.eu
const int ACCRUAL_TYPE_DEFAULT = 0; // Default accrual type for currency addition
const int EXPERIENCE_TO_SET = 1000000; // Experience value to set
const int TICKETS_TO_ADD = 999999999; // Amount of tickets to add
const int COINS_TO_ADD = 999999999;   // Amount of coins to add
const int GEMS_TO_ADD = 999999999;    // Amount of gems to add
const int LEVEL_KEY_VALUE_TO_SET = 1; // Value to set for the level key

// --- Logging Macro Redefinition ---
#define LOG_TAG_CUSTOM "SMALI_HOOK"

// Custom logging function (writes to logcat and file)
inline void LogToFileAndLogcat(int original_prio __attribute__((unused)), const char* tag, const char* fmt, ...) {
    // Log to Android logcat
    va_list args1;
    va_start(args1, fmt);
    __android_log_vprint(ANDROID_LOG_DEBUG, tag, fmt, args1);
    va_end(args1);

    // Log to file (thread-safe)
    std::lock_guard<std::mutex> lock(log_mutex);
    if (log_file) {
        time_t now = time(nullptr);
        tm *ltm = localtime(&now);
        // Timestamp prefix
        fprintf(log_file, "%04d-%02d-%02d %02d:%02d:%02d ", 1900 + ltm->tm_year, 1 + ltm->tm_mon, ltm->tm_mday, ltm->tm_hour, ltm->tm_min, ltm->tm_sec);
        // Level/Tag prefix
        fprintf(log_file, "[DEBUG/%s] ", tag);
        // Message
        va_list args2;
        va_start(args2, fmt);
        vfprintf(log_file, fmt, args2);
        va_end(args2);
        fprintf(log_file, "\n");
        fflush(log_file); // Ensure the message is written immediately
    } else {
        // Fallback to logcat if log file isn't open
        va_list args3;
        va_start(args3, fmt);
        __android_log_vprint(ANDROID_LOG_WARN, tag, "[LogToFile FAILED] ", args3); // Log failure notice
        va_end(args3);
    }
}
// Define LOGDEBUG and LOGE macros using the custom logging function
#ifndef LOGDEBUG
#define LOGDEBUG(...) LogToFileAndLogcat(ANDROID_LOG_DEBUG, LOG_TAG_CUSTOM, __VA_ARGS__)
#endif
#ifndef LOGE
#define LOGE(...) LOGDEBUG("ERROR: %s", __VA_ARGS__) // LOGE uses LOGDEBUG to ensure it's written to the file too
#endif

// --- Base Offsets Structure ---
// Defines common offsets needed for different game versions.
struct BaseOffsets {
    virtual ~BaseOffsets() = default;
    uintptr_t UIRoot_Awake = 0;                // RVA for UIRoot.Awake method
    uintptr_t CraftHack = 0;                   // RVA for LobbyItem.get_IsExists (or similar for craft hack)
    uintptr_t cheatDetectedBanner = 0;         // RVA for function showing "Cheat Detected" banner
    uintptr_t clearProgress = 0;               // RVA for function clearing progress on cheat detection
    uintptr_t showClearProgress = 0;           // RVA for function showing the clear progress UI
    uintptr_t awakeCheat = 0;                  // RVA for cheat detection Awake method
    uintptr_t updateCheat = 0;                 // RVA for cheat detection Update method
    uintptr_t get_cheaterConfig = 0;           // RVA for getter of cheater config/status
    uintptr_t set_cheaterConfig = 0;           // RVA for setter of cheater config/status
    uintptr_t get_CheckSignatureTampering = 0; // RVA for signature tampering check getter
    uintptr_t get_coinThreshold = 0;           // RVA for coin cheat threshold getter
    uintptr_t get_gemThreshold = 0;            // RVA for gem cheat threshold getter
};

// --- Specific Offset Structures ---
// Inherit from BaseOffsets and provide version/architecture specific RVAs.
struct Offsets_12_0_0_x86 : BaseOffsets {
    Offsets_12_0_0_x86() {
        UIRoot_Awake = 0xCBF798;
        CraftHack = 0xF247BC;
        cheatDetectedBanner = 0xF61FFC;
        clearProgress = 0xF620BB;
        showClearProgress = 0xF6202B;
        awakeCheat = 0xF6237E;
        updateCheat = 0xF62680;
        get_cheaterConfig = 0x138443F;
        set_cheaterConfig = 0x1386BE3;
        get_CheckSignatureTampering = 0xCF94C0;
        get_coinThreshold = 0xCF94D1;
        get_gemThreshold = 0xCF94E1;
    }
};

struct Offsets_12_0_0_armv7 : BaseOffsets {
    Offsets_12_0_0_armv7() {
        UIRoot_Awake = 0xDFBA60;
        CraftHack = 0x10BE904;
        cheatDetectedBanner = 0x1103220;
        clearProgress = 0x11032F0;
        showClearProgress = 0x1103228;
        awakeCheat = 0x1103654;
        updateCheat = 0x11039B4;
        get_cheaterConfig = 0x15ADA68;
        set_cheaterConfig = 0x15B09D4;
        get_CheckSignatureTampering = 0xE3F020;
        get_coinThreshold = 0xE3F028;
        get_gemThreshold = 0xE3F030;
    }
};

struct Offsets_11_4_0_x86 : BaseOffsets {
    Offsets_11_4_0_x86() {
        UIRoot_Awake = 0xBBA111;
        CraftHack = 0; // No crafts in 11.4.0
        cheatDetectedBanner = 0xF1C667;
        clearProgress = 0xF1C726;
        showClearProgress = 0xF1C696;
        awakeCheat = 0xF1C9E9;
        updateCheat = 0xF1CD07;
        get_cheaterConfig = 0xF2EF53;
        set_cheaterConfig = 0xF315DA;
        get_CheckSignatureTampering = 0x126F0FC;
        get_coinThreshold = 0x126F10D;
        get_gemThreshold = 0x126F11D;
    }
};

struct Offsets_11_4_0_armv7 : BaseOffsets {
    Offsets_11_4_0_armv7() {
        UIRoot_Awake = 0xCD1A08;
        CraftHack = 0; // No crafts in 11.4.0
        cheatDetectedBanner = 0x10B4F5C;
        clearProgress = 0x10B502C;
        showClearProgress = 0x10B4F64;
        awakeCheat = 0x10B5390;
        updateCheat = 0x10B5714;
        get_cheaterConfig = 0x10CB664;
        set_cheaterConfig = 0x10CE44C;
        get_CheckSignatureTampering = 0x147E64C;
        get_coinThreshold = 0x147E654;
        get_gemThreshold = 0x147E65C;
    }
};

// Global pointer to the currently loaded offsets structure.
static std::unique_ptr<BaseOffsets> current_offsets = nullptr;

// --- Utility Functions ---

// Helper to create an Il2CppString from a C-style string.
Il2CppString* CreateIl2cppString(const char* str) {
    if (!il2cpp_string_new) { LOGE("CreateIl2cppString: il2cpp_string_new is null!"); return nullptr; }
    if (!str) { LOGE("CreateIl2cppString: input string is null!"); return nullptr; }
    return il2cpp_string_new(str);
}

// Get the application's files directory path using the detected package name (or fallback).
std::string get_files_dir() {
    std::string packageNameToUse = g_appInfo.success ? g_appInfo.packageName : FALLBACK_APP_PACKAGE_NAME;
    if (!g_appInfo.success) {
        LOGE("get_files_dir: App info not available, using fallback package name: %s", FALLBACK_APP_PACKAGE_NAME);
    }
    return "/data/data/" + packageNameToUse + "/files";
}

// Finds the base address of a loaded library by parsing /proc/self/maps.
uintptr_t findLibraryBaseAddress(const char* libraryName) {
    std::ifstream maps_file("/proc/self/maps");
    std::string line;
    uintptr_t base_addr = 0;
    if (!maps_file.is_open()) { LOGE("findLibraryBaseAddress: Failed to open /proc/self/maps"); return 0; }
    while (getline(maps_file, line)) {
        // Look for the library name and read-execute-private permissions
        if (line.find(libraryName) != std::string::npos && line.find("r-xp") != std::string::npos) {
            std::stringstream ss(line);
            std::string segment;
            // Extract the start address segment
            getline(ss, segment, '-');
            try {
                // Convert hex string to uintptr_t
                base_addr = std::stoull(segment, nullptr, 16);
                break; // Found the first r-xp segment, exit
            } catch (const std::exception& e) { // Catch standard exceptions
                LOGE("findLibraryBaseAddress: Error parsing address '%s' in line '%s': %s", segment.c_str(), line.c_str(), e.what());
                base_addr = 0; // Reset on error
            } catch (...) {
                LOGE("findLibraryBaseAddress: Unknown error parsing address in line: %s", line.c_str());
                base_addr = 0; // Reset on error
            }
        }
    }
    maps_file.close();
    if (base_addr == 0) LOGE("findLibraryBaseAddress: Lib '%s' not found or address parsing failed", libraryName);
    else LOGDEBUG("findLibraryBaseAddress: Found %s -> Base Address: 0x%lx", libraryName, base_addr);
    return base_addr;
}

// --- JNI Helper Function to Get App Version and Package Name ---
// Retrieves app info using JNI calls (alternative non-SDK method via AppGlobals).
// Returns an AppInfo struct. Check AppInfo.success before using other fields.
AppInfo get_app_info(JNIEnv* env) {
    AppInfo result; // Default: success = false, names = "unknown"
    if (!env) { LOGE("get_app_info: JNIEnv is null!"); return result; }

    // --- Get Application Context using AppGlobals ---
    jclass appGlobalsClass = env->FindClass("android/app/AppGlobals");
    jobject application = nullptr;
    if (appGlobalsClass) {
        jmethodID getInitialApplicationMethod = env->GetStaticMethodID(appGlobalsClass, "getInitialApplication", "()Landroid/app/Application;");
        if (getInitialApplicationMethod) {
            application = env->CallStaticObjectMethod(appGlobalsClass, getInitialApplicationMethod);
            if (!application) { LOGE("get_app_info: AppGlobals.getInitialApplication returned null"); }
        } else { LOGE("get_app_info: Failed to find AppGlobals.getInitialApplication method"); }
        env->DeleteLocalRef(appGlobalsClass); // Clean up class ref
    } else { LOGE("get_app_info: Failed to find AppGlobals class"); }

    if (!application) {
        LOGE("get_app_info: Could not get Application object via AppGlobals. Aborting info retrieval.");
        return result; // Cannot proceed without application context
    }

    // Get Context class (needed for getPackageName, getPackageManager)
    jclass contextClass = env->FindClass("android/content/Context");
    if (!contextClass) { LOGE("get_app_info: Failed to find Context class"); env->DeleteLocalRef(application); return result; }

    // --- Get Package Name ---
    jmethodID getPackageNameMethod = env->GetMethodID(contextClass, "getPackageName", "()Ljava/lang/String;");
    if (!getPackageNameMethod) { LOGE("get_app_info: Failed to find getPackageName method"); env->DeleteLocalRef(contextClass); env->DeleteLocalRef(application); return result; }
    jstring packageNameJString = (jstring)env->CallObjectMethod(application, getPackageNameMethod);
    if (!packageNameJString) { LOGE("get_app_info: getPackageName returned null"); env->DeleteLocalRef(contextClass); env->DeleteLocalRef(application); return result; }
    const char* packageNameCStr = env->GetStringUTFChars(packageNameJString, nullptr);
    if (packageNameCStr) {
        result.packageName = packageNameCStr;
        env->ReleaseStringUTFChars(packageNameJString, packageNameCStr);
    } else {
        LOGE("get_app_info: GetStringUTFChars failed for packageName");
        env->DeleteLocalRef(contextClass); env->DeleteLocalRef(application); env->DeleteLocalRef(packageNameJString); return result;
    }

    // --- Get Version Name ---
    jmethodID getPackageManagerMethod = env->GetMethodID(contextClass, "getPackageManager", "()Landroid/content/pm/PackageManager;");
    if (!getPackageManagerMethod) { LOGE("get_app_info: Failed to find getPackageManager method"); env->DeleteLocalRef(contextClass); env->DeleteLocalRef(application); env->DeleteLocalRef(packageNameJString); return result; }
    jobject packageManager = env->CallObjectMethod(application, getPackageManagerMethod);
    if (!packageManager) { LOGE("get_app_info: getPackageManager returned null"); env->DeleteLocalRef(contextClass); env->DeleteLocalRef(application); env->DeleteLocalRef(packageNameJString); return result; }
    jclass packageManagerClass = env->GetObjectClass(packageManager);
    if (!packageManagerClass) { LOGE("get_app_info: Failed to get PackageManager class"); env->DeleteLocalRef(contextClass); env->DeleteLocalRef(application); env->DeleteLocalRef(packageNameJString); env->DeleteLocalRef(packageManager); return result; }
    jmethodID getPackageInfoMethod = env->GetMethodID(packageManagerClass, "getPackageInfo", "(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;");
    if (!getPackageInfoMethod) { LOGE("get_app_info: Failed to find getPackageInfo method"); env->DeleteLocalRef(contextClass); env->DeleteLocalRef(application); env->DeleteLocalRef(packageNameJString); env->DeleteLocalRef(packageManager); env->DeleteLocalRef(packageManagerClass); return result; }
    jobject packageInfo = env->CallObjectMethod(packageManager, getPackageInfoMethod, packageNameJString, 0);
    if (!packageInfo) { LOGE("get_app_info: getPackageInfo returned null"); env->DeleteLocalRef(contextClass); env->DeleteLocalRef(application); env->DeleteLocalRef(packageNameJString); env->DeleteLocalRef(packageManager); env->DeleteLocalRef(packageManagerClass); return result; }
    jclass packageInfoClass = env->GetObjectClass(packageInfo);
    if (!packageInfoClass) { LOGE("get_app_info: Failed to get PackageInfo class"); env->DeleteLocalRef(contextClass); env->DeleteLocalRef(application); env->DeleteLocalRef(packageNameJString); env->DeleteLocalRef(packageManager); env->DeleteLocalRef(packageManagerClass); env->DeleteLocalRef(packageInfo); return result; }
    jfieldID versionNameField = env->GetFieldID(packageInfoClass, "versionName", "Ljava/lang/String;");
    if (!versionNameField) { LOGE("get_app_info: Failed to find versionName field"); env->DeleteLocalRef(contextClass); env->DeleteLocalRef(application); env->DeleteLocalRef(packageNameJString); env->DeleteLocalRef(packageManager); env->DeleteLocalRef(packageManagerClass); env->DeleteLocalRef(packageInfo); env->DeleteLocalRef(packageInfoClass); return result; }
    jstring versionNameJString = (jstring)env->GetObjectField(packageInfo, versionNameField);
    if (versionNameJString) {
        const char* versionNameCStr = env->GetStringUTFChars(versionNameJString, nullptr);
        if (versionNameCStr) {
            result.versionName = versionNameCStr;
            env->ReleaseStringUTFChars(versionNameJString, versionNameCStr);
        } else { LOGE("get_app_info: GetStringUTFChars failed for versionName"); }
        env->DeleteLocalRef(versionNameJString);
    } else { LOGE("get_app_info: versionName field is null"); }

    // --- Cleanup JNI Local References ---
    env->DeleteLocalRef(contextClass);
    env->DeleteLocalRef(application);
    env->DeleteLocalRef(packageNameJString);
    env->DeleteLocalRef(packageManager);
    env->DeleteLocalRef(packageManagerClass);
    env->DeleteLocalRef(packageInfo);
    env->DeleteLocalRef(packageInfoClass);

    // --- Final Check and Return ---
    if (result.packageName != "unknown" && result.versionName != "unknown") {
        result.success = true;
        LOGDEBUG("get_app_info: Detected Version: %s, Package: %s", result.versionName.c_str(), result.packageName.c_str());
    } else {
        LOGE("get_app_info: Failed to retrieve full app info (Version: %s, Package: %s)", result.versionName.c_str(), result.packageName.c_str());
    }

    return result;
}


// --- IL2CPP API Resolution Function ---
// Resolves pointers to necessary IL2CPP functions using dlsym.
bool resolve_il2cpp_api() {
    LOGDEBUG("Resolving IL2CPP API functions...");
    void* handle = dlopen(IL2CPP_SO_NAME, RTLD_LAZY);
    if (!handle) { LOGE("Failed to get handle for %s. Trying RTLD_DEFAULT.", IL2CPP_SO_NAME); handle = RTLD_DEFAULT; }
    if (!handle) { LOGE("Failed to get any handle for dlsym. Cannot resolve API."); return false; }

    bool success = true;
    // Macro to resolve a function pointer and log error on failure
#define RESOLVE_API(name) *(void**)(&name) = dlsym(handle, #name); if (!name) { LOGE("Failed to resolve critical API %s", #name); success = false; }
    // Macro to resolve an optional function pointer and log debug message on failure
#define RESOLVE_OPTIONAL_API(name) *(void**)(&name) = dlsym(handle, #name); if (!name) { LOGDEBUG("Optional API %s not found.", #name); }

    // Resolve critical API functions
    RESOLVE_API(il2cpp_domain_get)
    RESOLVE_API(il2cpp_domain_assembly_open)
    RESOLVE_API(il2cpp_assembly_get_image)
    RESOLVE_API(il2cpp_class_from_name)
    RESOLVE_API(il2cpp_class_get_method_from_name)
    RESOLVE_API(il2cpp_string_new)
    RESOLVE_API(il2cpp_runtime_invoke)
    RESOLVE_API(il2cpp_class_get_field_from_name)
    RESOLVE_API(il2cpp_field_static_get_value)
    RESOLVE_API(il2cpp_field_set_value)
    RESOLVE_API(il2cpp_object_unbox)

    // Resolve optional API functions
    RESOLVE_OPTIONAL_API(il2cpp_field_get_value) // Optional, was used for verification
    RESOLVE_OPTIONAL_API(il2cpp_string_to_utf8)  // Optional, was used for verification
    RESOLVE_OPTIONAL_API(il2cpp_class_get_type)
    RESOLVE_OPTIONAL_API(il2cpp_type_get_object)
    RESOLVE_OPTIONAL_API(il2cpp_get_exception_class)
    RESOLVE_OPTIONAL_API(il2cpp_object_to_string) // Optional, for exception logging

#undef RESOLVE_API
#undef RESOLVE_OPTIONAL_API

    // Do not dlclose(handle) if it might be RTLD_DEFAULT or needed later.

    if (!success) LOGE("One or more critical IL2CPP API functions failed to resolve.");
    else LOGDEBUG("IL2CPP API functions resolved successfully (optional API may be missing).");
    return success;
}


// --- Hook for UIRoot.Awake ---
// This function replaces the original UIRoot.Awake method.
void (*Original_UIRoot_Awake)(void* instance) = nullptr; // Pointer to the original function

void UIRoot_Awake_Hook(void* instance) {
    static bool uiroot_hook_logged_once = false; // Flag for one-time actions
    bool log_this_time = !uiroot_hook_logged_once;

    if (log_this_time) {
        LOGDEBUG("UIRoot_Awake_Hook ENTERED (First time). Instance: %p", instance);
    }

    // Call the original UIRoot.Awake function if the pointer is valid
    if (Original_UIRoot_Awake) {
        Original_UIRoot_Awake(instance);
    } else {
        LOGE("Original_UIRoot_Awake pointer is NULL! Cannot call original function.");
    }


    // --- Modifications ---
    // Check if essential IL2CPP API functions are available
    if (il2cpp_domain_get && il2cpp_domain_assembly_open && il2cpp_assembly_get_image &&
        il2cpp_class_from_name && il2cpp_class_get_method_from_name && il2cpp_runtime_invoke &&
        il2cpp_string_new && il2cpp_class_get_field_from_name && il2cpp_field_set_value &&
        il2cpp_field_static_get_value)
    {
        Il2CppDomain* domain = il2cpp_domain_get();
        Il2CppAssembly* mainAssembly = il2cpp_domain_assembly_open(domain, TARGET_ASSEMBLY_NAME);
        Il2CppAssembly* firstpassAssembly = il2cpp_domain_assembly_open(domain, FIRSTPASS_ASSEMBLY_NAME);

        const Il2CppImage* mainImage = mainAssembly ? il2cpp_assembly_get_image(mainAssembly) : nullptr;
        const Il2CppImage* firstpassImage = firstpassAssembly ? il2cpp_assembly_get_image(firstpassAssembly) : nullptr;

        // Ensure required assembly images were loaded
        if (mainImage && firstpassImage) {

            // --- 1. Modify Photon Settings via Static Field (EXECUTED EVERY CALL) ---
            {
                Il2CppClass* photonNetworkClass = il2cpp_class_from_name((Il2CppImage*)mainImage, PHOTON_NAMESPACE, PHOTON_CLASS_NAME);
                Il2CppClass* serverSettingsClass = il2cpp_class_from_name((Il2CppImage*)mainImage, PHOTON_NAMESPACE, SERVER_SETTINGS_CLASS_NAME);

                if (photonNetworkClass && serverSettingsClass) {
                    FieldInfo* settingsStaticField = il2cpp_class_get_field_from_name(photonNetworkClass, PHOTON_SETTINGS_STATIC_FIELD_NAME);

                    if (settingsStaticField) {
                        Il2CppObject* serverSettingsInstance = nullptr;
                        il2cpp_field_static_get_value(settingsStaticField, &serverSettingsInstance);

                        if (serverSettingsInstance) {
                            FieldInfo* appIdField = il2cpp_class_get_field_from_name(serverSettingsClass, SERVERSETTINGS_APPID_FIELD_NAME);
                            FieldInfo* hostTypeField = il2cpp_class_get_field_from_name(serverSettingsClass, SERVERSETTINGS_HOSTTYPE_FIELD_NAME);
                            FieldInfo* regionField = il2cpp_class_get_field_from_name(serverSettingsClass, SERVERSETTINGS_REGION_FIELD_NAME);

                            // Set AppID
                            if (appIdField) {
                                Il2CppString* newAppIdStr = CreateIl2cppString(NEW_PHOTON_APP_ID);
                                if (newAppIdStr) {
                                    il2cpp_field_set_value(serverSettingsInstance, appIdField, newAppIdStr);
                                } else { LOGE("  Failed to create Il2CppString for new AppID."); }
                            } else { LOGE("  Failed to find ServerSettings field: %s", SERVERSETTINGS_APPID_FIELD_NAME); }

                            // Set HostType
                            if (hostTypeField) {
                                int hostTypeValue = NEW_PHOTON_HOST_TYPE;
                                il2cpp_field_set_value(serverSettingsInstance, hostTypeField, &hostTypeValue);
                            } else { LOGE("  Failed to find ServerSettings field: %s", SERVERSETTINGS_HOSTTYPE_FIELD_NAME); }

                            // Set PreferredRegion
                            if (regionField) {
                                int regionValue = NEW_PHOTON_REGION;
                                il2cpp_field_set_value(serverSettingsInstance, regionField, &regionValue);
                            } else { LOGE("  Failed to find ServerSettings field: %s", SERVERSETTINGS_REGION_FIELD_NAME); }

                        } else { LOGE("  Failed to get ServerSettings instance from static field '%s'.", PHOTON_SETTINGS_STATIC_FIELD_NAME); }
                    } else { LOGE("  Failed to find static field '%s' in PhotonNetwork class.", PHOTON_SETTINGS_STATIC_FIELD_NAME); }
                } else {
                    if (!photonNetworkClass) LOGE("  PhotonNetwork class not found in %s.", TARGET_ASSEMBLY_NAME);
                    if (!serverSettingsClass) LOGE("  ServerSettings class not found in %s.", TARGET_ASSEMBLY_NAME);
                }
            } // End Photon modification block

            // --- 2. Add Currency/Tickets (One-time action using a flag file) ---
            if (log_this_time) { // Only execute on the first call
                std::string files_dir_curr = get_files_dir();
                std::string flag_path_curr = files_dir_curr + "/currency_added.flag";
                FILE* flag_file_curr = fopen(flag_path_curr.c_str(), "r");
                if (flag_file_curr) {
                    fclose(flag_file_curr);
                    LOGDEBUG("Currency/Tickets already added flag found. Skipping.");
                } else {
                    LOGDEBUG("Attempting to add currency/tickets (one-time)...");
                    Il2CppClass* bankControllerClass = il2cpp_class_from_name((Il2CppImage*)mainImage, "", BANKCONTROLLER_CLASS_NAME);
                    if (bankControllerClass) {
                        bool item_added = false;
                        MethodInfo* addCoinsMethod = il2cpp_class_get_method_from_name(bankControllerClass, ADD_COINS_METHOD_NAME, 3);
                        MethodInfo* addGemsMethod = il2cpp_class_get_method_from_name(bankControllerClass, ADD_GEMS_METHOD_NAME, 3);
                        MethodInfo* addTicketsMethod = il2cpp_class_get_method_from_name(bankControllerClass, ADD_TICKETS_METHOD_NAME, 3);
                        Il2CppObject* ex = nullptr;
                        if (addCoinsMethod) { int v=COINS_TO_ADD; bool i=true; int a=ACCRUAL_TYPE_DEFAULT; void* args[]={&v,&i,&a}; ex=nullptr; il2cpp_runtime_invoke(addCoinsMethod, nullptr, args, &ex); if(!ex) item_added=true; else LOGE("Exception adding coins."); }
                        if (addGemsMethod) { int v=GEMS_TO_ADD; bool i=true; int a=ACCRUAL_TYPE_DEFAULT; void* args[]={&v,&i,&a}; ex=nullptr; il2cpp_runtime_invoke(addGemsMethod, nullptr, args, &ex); if(!ex) item_added=true; else LOGE("Exception adding gems."); }
                        if (addTicketsMethod) { int v=TICKETS_TO_ADD; bool i=true; int a=ACCRUAL_TYPE_DEFAULT; void* args[]={&v,&i,&a}; ex=nullptr; il2cpp_runtime_invoke(addTicketsMethod, nullptr, args, &ex); if(!ex) item_added=true; else LOGE("Exception adding tickets."); }
                        if (item_added) {
                            FILE* f = fopen(flag_path_curr.c_str(), "w");
                            if (f) { fprintf(f, "Added on %ld", time(nullptr)); fclose(f); LOGDEBUG("Currency/Tickets added flag created."); }
                            else LOGE("Failed to create flag file '%s': %s", flag_path_curr.c_str(), strerror(errno));
                        } else { LOGE("Currency/Ticket addition failed (no successful calls or all methods missing)."); }
                    } else { LOGE("BankController class not found."); }
                } // End Currency block
            }


            // --- 3. Set Level Key and Experience (EXECUTED EVERY CALL) ---
            {
                Il2CppClass* storagerClass = il2cpp_class_from_name((Il2CppImage*)mainImage, "", STORAGER_CLASS_NAME);
                if (storagerClass) {
                    MethodInfo* setIntMethod = il2cpp_class_get_method_from_name(storagerClass, STORAGER_SETINT_METHOD_NAME, 2);
                    if (setIntMethod) {
                        Il2CppObject* ex = nullptr;
                        const char* levelKey = nullptr; // <<< Initialize levelKey

                        // --- Determine level key based on game version ---
                        if (g_appInfo.versionName == "11.4.0") {
                            levelKey = "currentLevel31";
                        } else if (g_appInfo.versionName == "12.0.0") {
                            levelKey = "currentLevel36";
                        } else {
                            // Default or fallback if version is unknown or different
                            levelKey = "currentLevel36"; // Or handle error, log warning, etc.
                            if (log_this_time) { // Log warning only once
                                LOGE("Unknown game version '%s' for level key, defaulting to 'currentLevel36'", g_appInfo.versionName.c_str());
                            }
                        }

                        // Set Level Key (using the determined key)
                        if (levelKey) { // Check if a key was determined
                            int levelValue = LEVEL_KEY_VALUE_TO_SET; // Set to 1
                            Il2CppString* levelKeyStr = CreateIl2cppString(levelKey);
                            if (levelKeyStr) {
                                void* args[] = {levelKeyStr, &levelValue};
                                ex = nullptr;
                                il2cpp_runtime_invoke(setIntMethod, nullptr, args, &ex);
                                if (ex) LOGE("Exception setting level key '%s'.", levelKey);
                            } else { LOGE("Failed to create string for level key '%s'.", levelKey); }
                        }

                        // Set Experience (remains the same)
                        const char* expKey = "currentExperience";
                        int expValue = EXPERIENCE_TO_SET;
                        Il2CppString* expKeyStr = CreateIl2cppString(expKey);
                        if (expKeyStr) {
                            void* args[] = {expKeyStr, &expValue};
                            ex = nullptr;
                            il2cpp_runtime_invoke(setIntMethod, nullptr, args, &ex);
                            if (ex) LOGE("Exception setting experience key '%s'.", expKey);
                        } else { LOGE("Failed to create string for experience key '%s'.", expKey); }
                    } else { LOGE("Storager.setInt method not found (for level/exp)."); }
                } else { LOGE("Storager class not found (for level/exp)."); }
            } // End Level/Exp block


            // --- 4. Check/Set Training Flag (One-time action) ---
            if (log_this_time) { // Only execute on the first call
                LOGDEBUG("Checking training status (one-time)...");
                Il2CppString* trainingKeyStr = nullptr;
                if (firstpassImage) {
                    Il2CppClass* defsClass = il2cpp_class_from_name((Il2CppImage*)firstpassImage, "", DEFS_CLASS_NAME);
                    if (defsClass) {
                        MethodInfo* getKeyMethod = il2cpp_class_get_method_from_name(defsClass, TRAINING_KEY_GETTER_METHOD_NAME, 0);
                        if (getKeyMethod) {
                            Il2CppObject* keyRes=nullptr; Il2CppObject* getKeyEx=nullptr;
                            keyRes=il2cpp_runtime_invoke(getKeyMethod, nullptr, nullptr, &getKeyEx);
                            if(!getKeyEx && keyRes) {
                                trainingKeyStr=(Il2CppString*)keyRes;
                            } else { LOGE("Failed to get training key string or exception occurred."); }
                        } else { LOGE("Defs.%s method not found.", TRAINING_KEY_GETTER_METHOD_NAME); }
                    } else { LOGE("Defs class not found in %s.", FIRSTPASS_ASSEMBLY_NAME); }
                } else { LOGE("Failed to get %s image previously.", FIRSTPASS_ASSEMBLY_NAME); }

                Il2CppClass* storagerClass = il2cpp_class_from_name((Il2CppImage*)mainImage, "", STORAGER_CLASS_NAME);
                if (trainingKeyStr && storagerClass) {
                    MethodInfo* getIntMethod = il2cpp_class_get_method_from_name(storagerClass, STORAGER_GETINT_METHOD_NAME, 1);
                    if (getIntMethod) {
                        void* getArgs[] = {trainingKeyStr}; Il2CppObject* getRes=nullptr; Il2CppObject* getEx=nullptr;
                        getRes=il2cpp_runtime_invoke(getIntMethod, nullptr, getArgs, &getEx);
                        if (!getEx && getRes && il2cpp_object_unbox) {
                            int currentVal = *(static_cast<int*>(il2cpp_object_unbox(getRes)));
                            if (currentVal == 0) {
                                MethodInfo* setIntMethod = il2cpp_class_get_method_from_name(storagerClass, STORAGER_SETINT_METHOD_NAME, 2);
                                if (setIntMethod) {
                                    int newVal=1;
                                    void* setArgs[]={trainingKeyStr, &newVal}; Il2CppObject* setEx=nullptr;
                                    il2cpp_runtime_invoke(setIntMethod, nullptr, setArgs, &setEx);
                                    if(!setEx) LOGDEBUG("Training flag set to 1.");
                                    else LOGE("Exception setting training flag.");
                                } else { LOGE("Storager.setInt method not found (needed for setting training flag)."); }
                            } else { LOGDEBUG("Training already completed (flag is not 0)."); }
                        } else { LOGE("Failed to get training key value or unbox it. Exception occurred? %s", getEx ? "Yes" : "No"); }
                    } else { LOGE("Storager.getInt method not found (for training check)."); }
                } else { LOGE("Skipping training check (key string %s or storager class %p missing).", trainingKeyStr ? "found" : "not found", (void*)storagerClass); }
            } // End Training block

        } else { // Failed to load one of the required assembly images
            if (!mainImage && log_this_time) LOGE("Failed to get main assembly image (%s).", TARGET_ASSEMBLY_NAME);
            if (!firstpassImage && log_this_time) LOGE("Failed to get first pass assembly image (%s).", FIRSTPASS_ASSEMBLY_NAME);
        }
    } else if (log_this_time) { // Log if essential APIs are missing on the first run
        LOGE("Essential IL2CPP API functions missing for modifications.");
        if (!il2cpp_field_static_get_value) LOGE("Missing API: il2cpp_field_static_get_value (needed for static field access)");
    }

    // Set the flag so one-time actions don't run again this session
    if (log_this_time) {
        uiroot_hook_logged_once = true;
        LOGDEBUG("UIRoot_Awake_Hook: One-time actions finished.");
    }
}


// --- Hook for LobbyItem.get_IsExists (Craft Hack) ---
// Always returns true to bypass crafting checks (if applicable).
bool (*Original_LobbyItem_get_IsExists)(void* instance) = nullptr; // Pointer to original
bool CraftHack_Hook(void* instance) {
    static bool logged_once = false;
    if (!logged_once) { LOGDEBUG("CraftHack_Hook (LobbyItem.get_IsExists) active. Instance: %p", instance); logged_once = true; }
    return true; // Always return true
}

// --- Memory Patching Function ---
// Applies NOP/RET patches to disable certain functions based on offsets.
void ApplyMemoryPatches() {
    LOGDEBUG("Applying memory patches...");
    if (!current_offsets) { LOGE("Cannot apply patches: offsets not loaded!"); return; }
    if (il2cpp_base == 0) { LOGE("Cannot apply patches: il2cpp_base is 0."); return; }
    const char* patchHex = nullptr;
#if defined(__arm__)
    patchHex = "1E FF 2F E1"; // BX LR (ARM Thumb)
#elif defined(__i386__)
    patchHex = "C3"; // RET (x86)
    #else
    LOGE("Unsupported architecture for patches!"); return;
#endif
    if (!patchHex) { LOGE("Patch hex is null! This should not happen."); return; }

    // Lambda helper function to apply a patch
    auto applyMemPatch = [&](const char* name, uintptr_t rva) {
        if (rva == 0) { LOGDEBUG("Skipping patch '%s' (RVA is 0)", name); return; } // Skip if RVA is 0
        uintptr_t addr = il2cpp_base + rva;
        if (addr <= il2cpp_base) { LOGE("Invalid address (0x%lx) calculated for patch '%s'", addr, name); return; }
        // Use KittyMemory to create and apply the patch
        MemoryPatch patch = MemoryPatch::createWithHex(addr, patchHex);
        if (!patch.isValid()) { LOGE("Patch creation failed for '%s' at 0x%lx.", name, addr); return; }
        if (!patch.Modify()) { LOGE("Patch modify failed for '%s' at 0x%lx.", name, addr); }
    };

    // Apply patches using the loaded offsets
    applyMemPatch("cheatDetectedBanner", current_offsets->cheatDetectedBanner);
    applyMemPatch("clearProgress", current_offsets->clearProgress);
    applyMemPatch("showClearProgress", current_offsets->showClearProgress);
    applyMemPatch("awakeCheat", current_offsets->awakeCheat);
    applyMemPatch("updateCheat", current_offsets->updateCheat);
    applyMemPatch("get_cheaterConfig", current_offsets->get_cheaterConfig);
    applyMemPatch("set_cheaterConfig", current_offsets->set_cheaterConfig);
    applyMemPatch("get_CheckSignatureTampering", current_offsets->get_CheckSignatureTampering);
    applyMemPatch("get_coinThreshold", current_offsets->get_coinThreshold);
    applyMemPatch("get_gemThreshold", current_offsets->get_gemThreshold);
    LOGDEBUG("Finished applying memory patches.");
}

// --- Hook Installation Function ---
// Installs function hooks using Dobby.
void InstallHooks() {
    LOGDEBUG("Installing function hooks...");
    if (!current_offsets) { LOGE("Cannot install hooks: offsets not loaded!"); return; }
    if (il2cpp_base == 0) { LOGE("Cannot install hooks: il2cpp_base is 0."); return; }

    // Lambda helper function to install a hook
    auto installHook = [&](const char* name, uintptr_t rva, void* hook_func, void** orig_func_ptr) {
        if (rva == 0) { LOGDEBUG("Skipping hook '%s' (RVA is 0)", name); return; } // Skip if RVA is 0
        uintptr_t addr = il2cpp_base + rva;
        if (addr <= il2cpp_base) { LOGE("Invalid address (0x%lx) calculated for hook '%s'", addr, name); return; }
        // Use Dobby to install the hook
        int status = DobbyHook((void*)addr, hook_func, orig_func_ptr);
        if (status == RT_SUCCESS) {
            if (*orig_func_ptr) {
                LOGDEBUG("Hooked %s at 0x%lx.", name, addr);
            } else {
                // This shouldn't happen on RT_SUCCESS, but check just in case
                LOGE("Hooked %s at 0x%lx BUT original function pointer is NULL!", name, addr);
            }
        } else {
            LOGE("Failed to hook %s at 0x%lx. DobbyHook status: %d", name, addr, status);
            *orig_func_ptr = nullptr; // Ensure original pointer is null on failure
        }
    };

    // Install hooks using the loaded offsets
    installHook("UIRoot.Awake", current_offsets->UIRoot_Awake, (void*)UIRoot_Awake_Hook, (void**)&Original_UIRoot_Awake);
    installHook("LobbyItem.get_IsExists", current_offsets->CraftHack, (void*)CraftHack_Hook, (void**)&Original_LobbyItem_get_IsExists);

    LOGDEBUG("Finished installing function hooks.");
}


// --- Core Initialization Function ---
// Performs essential setup: gets app info, selects offsets, finds library base, resolves API.
bool PerformInitialization(JNIEnv* env) {
    LOGDEBUG("PerformInitialization started.");

    // 1. Get App Version and Package Name using JNI
    g_appInfo = get_app_info(env); // Store globally
    if (!g_appInfo.success) {
        LOGE("Failed to get app info. Aborting initialization.");
        return false;
    }

    // 2. Select Offsets based on Version and Architecture
    LOGDEBUG("Selecting offsets for version '%s'...", g_appInfo.versionName.c_str());
    if (g_appInfo.versionName == "12.0.0") {
#if defined(__i386__)
        LOGDEBUG("Using offsets for v12.0.0 x86");
        current_offsets = std::make_unique<Offsets_12_0_0_x86>();
#elif defined(__arm__)
        LOGDEBUG("Using offsets for v12.0.0 armeabi-v7a");
            current_offsets = std::make_unique<Offsets_12_0_0_armv7>();
#else
            LOGE("Unsupported architecture for v12.0.0");
            return false;
#endif
    } else if (g_appInfo.versionName == "11.4.0") {
#if defined(__i386__)
        LOGDEBUG("Using offsets for v11.4.0 x86");
        current_offsets = std::make_unique<Offsets_11_4_0_x86>();
#elif defined(__arm__)
        LOGDEBUG("Using offsets for v11.4.0 armeabi-v7a");
            current_offsets = std::make_unique<Offsets_11_4_0_armv7>();
#else
            LOGE("Unsupported architecture for v11.4.0");
            return false;
#endif
    } else {
        LOGE("Unsupported version: '%s'. Aborting initialization.", g_appInfo.versionName.c_str());
        return false; // Unsupported version
    }

    if (!current_offsets) {
        LOGE("Failed to create offsets structure! Aborting initialization.");
        return false;
    }

    // 3. Find libil2cpp.so base address (only if not already found)
    if (il2cpp_base == 0) {
        LOGDEBUG("Finding base address for %s...", IL2CPP_SO_NAME);
        il2cpp_base = findLibraryBaseAddress(IL2CPP_SO_NAME);
        if (il2cpp_base == 0) {
            LOGE("Failed to find base address for %s. Aborting initialization.", IL2CPP_SO_NAME);
            current_offsets.reset(); // Clean up allocated offsets
            return false;
        }
    } else {
        LOGDEBUG("Using previously found il2cpp_base: 0x%lx", il2cpp_base);
    }


    // 4. Resolve IL2CPP API functions (only if not already resolved)
    if (!il2cpp_domain_get) { // Check one critical function as an indicator
        LOGDEBUG("IL2CPP API not resolved yet, attempting resolution...");
        if (!resolve_il2cpp_api()) {
            LOGE("Failed to resolve IL2CPP API. Aborting initialization.");
            current_offsets.reset(); // Clean up allocated offsets
            return false;
        }
    } else {
        LOGDEBUG("IL2CPP API functions appear to be already resolved.");
    }


    LOGDEBUG("Core initialization finished successfully.");
    return true;
}

// --- Background Thread Function ---
// This thread waits for the target library, performs initialization, and applies patches/hooks.
void *hack_thread(void* vm_ptr) {
    JavaVM* vm = (JavaVM*)vm_ptr;
    JNIEnv* env = nullptr;
    bool attached = false;

    // Attach current thread to JVM to get JNIEnv
    jint attachResult = vm->GetEnv((void**)&env, JNI_VERSION_1_6);
    if (attachResult == JNI_EDETACHED) {
        if (vm->AttachCurrentThread(&env, nullptr) == JNI_OK) {
            attached = true;
        } else {
            __android_log_print(ANDROID_LOG_ERROR, LOG_TAG_CUSTOM, "Failed to attach current thread to JVM!");
            return nullptr; // Cannot proceed without JNIEnv
        }
    } else if (attachResult != JNI_OK) {
        __android_log_print(ANDROID_LOG_ERROR, LOG_TAG_CUSTOM, "Failed to get JNIEnv in thread! GetEnv result: %d", attachResult);
        return nullptr; // Cannot proceed without JNIEnv
    }

    pthread_t current_thread = pthread_self();
    LOGDEBUG("Initialization thread started (ID: %lu). Waiting for library '%s' to load...", (unsigned long)current_thread, LibraryToLoad);

    int wait_seconds = 0;
    const int max_wait_seconds = 120; // 2 minutes timeout
    bool library_found = false;

    // Wait loop for the target library (libil2cpp.so)
    while (wait_seconds < max_wait_seconds) {
        // Use dlopen with RTLD_NOLOAD to check if the library is loaded
        void* libHandle = dlopen(LibraryToLoad, RTLD_NOLOAD | RTLD_LAZY);
        if (libHandle) {
            dlclose(libHandle); // Close the handle immediately after checking
            library_found = true;
            LOGDEBUG("Library '%s' found after %d seconds.", LibraryToLoad, wait_seconds);
            break; // Exit the loop
        }
        // Log progress periodically
        if (wait_seconds > 0 && wait_seconds % 15 == 0) {
            LOGDEBUG("Still waiting for '%s' (%d/%d seconds)...", LibraryToLoad, wait_seconds, max_wait_seconds);
        }
        // Wait for 1 second before checking again
        std::this_thread::sleep_for(std::chrono::seconds(1));
        wait_seconds++;
    }

    if (!library_found) {
        LOGE("Library '%s' not found after %d seconds. Aborting mod initialization.", LibraryToLoad, max_wait_seconds);
        if (attached) vm->DetachCurrentThread();
        return nullptr;
    }

    // --- Initialize File Logging ---
    // Perform core initialization first to get the package name needed for the log path
    LOGDEBUG("Proceeding with core initialization...");
    bool init_success = PerformInitialization(env); // Pass the valid JNIEnv

    // Now initialize file logging using the detected package name (or fallback)
    std::string files_dir = get_files_dir();
    std::string log_path_str = files_dir + "/" + LOG_FILENAME;
    const char* log_path = log_path_str.c_str();
    bool log_file_ready = false;
    { // Scope for mutex lock
        std::lock_guard<std::mutex> lock(log_mutex);
        // Close existing log file if open (e.g., from a previous run without proper unload)
        if (log_file) {
            fclose(log_file);
            log_file = nullptr;
        }
        // Open log file in write mode ('w') to overwrite existing content
        log_file = fopen(log_path, "w"); // Use "w" to overwrite the log file
        if (!log_file) {
            __android_log_print(ANDROID_LOG_ERROR, LOG_TAG_CUSTOM, "!!! CRITICAL: Failed to open log file for writing: %s (Error: %s)", log_path, strerror(errno));
        } else {
            __android_log_print(ANDROID_LOG_INFO, LOG_TAG_CUSTOM, "Log file opened for writing (overwrite): %s", log_path);
            // Log a header for this session
            fprintf(log_file, "--- Log Session Start [%s] ---\nTimestamp: %ld\nPID: %d\nPackage: %s\nVersion: %s\nLib '%s' loaded after %d s.\nInitialization Status: %s\n---------------------------\n",
                    LOG_TAG_CUSTOM, time(nullptr), getpid(),
                    g_appInfo.success ? g_appInfo.packageName.c_str() : "N/A (Fallback used)",
                    g_appInfo.success ? g_appInfo.versionName.c_str() : "N/A",
                    LibraryToLoad, wait_seconds,
                    init_success ? "SUCCESS" : "FAILED");
            fflush(log_file); // Ensure header is written immediately
            log_file_ready = true;
        }
    } // Mutex lock released here

    if (!log_file_ready) {
        LOGE("Aborting initialization thread due to log file opening error.");
        if (attached) vm->DetachCurrentThread();
        return nullptr;
    }

    // --- Apply Patches and Hooks only if Initialization Succeeded ---
    if (init_success) {
        LOGDEBUG("Core initialization successful. Version: %s, Package: %s, Base: 0x%lx",
                 g_appInfo.versionName.c_str(), g_appInfo.packageName.c_str(), il2cpp_base);
        // Short delay before applying modifications, might help timing issues
        std::this_thread::sleep_for(std::chrono::milliseconds(500));

        ApplyMemoryPatches(); // Apply direct memory modifications
        InstallHooks();       // Install function hooks using Dobby

        LOGDEBUG("Initialization thread finished applying patches and hooks.");
    } else {
        LOGE("Core initialization failed. Patches and hooks were skipped.");
    }

    LOGDEBUG("Initialization thread finished execution.");
    if (attached) {
        vm->DetachCurrentThread(); // Detach from JVM if we attached it
    }
    return nullptr; // Thread finished
}


// --- JNI_OnLoad ---
// This function is called by the Android runtime when the native library is loaded.
extern "C" JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, [[maybe_unused]] void* reserved) {
    g_JavaVM = vm; // Store JavaVM globally
    JNIEnv* env;
    __android_log_print(ANDROID_LOG_INFO, LOG_TAG_CUSTOM, "JNI_OnLoad called. Library loading...");

    // Get JNIEnv for the current thread
    if (vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6) != JNI_OK) {
        __android_log_print(ANDROID_LOG_ERROR, LOG_TAG_CUSTOM, "JNI_OnLoad: Failed to get JNIEnv. Cannot proceed.");
        return JNI_ERR; // Return error code
    }

    // Create a detached background thread to perform initialization and hooking.
    // This avoids blocking the main thread.
    pthread_t ptid = 0;
    int ret = pthread_create(&ptid, nullptr, hack_thread, (void*)vm); // Pass the JavaVM pointer to the thread
    if (ret != 0) {
        __android_log_print(ANDROID_LOG_ERROR, LOG_TAG_CUSTOM, "Failed to create initialization thread! Error: %s (%d)", strerror(ret), ret);
        // Mod might not function, but we let the app continue loading.
    } else {
        // Detach the thread so its resources are automatically released upon completion.
        pthread_detach(ptid);
        __android_log_print(ANDROID_LOG_INFO, LOG_TAG_CUSTOM, "Initialization thread created and detached successfully (ID: %lu).", (unsigned long)ptid);
    }

    // Return the JNI version this library supports.
    return JNI_VERSION_1_6;
}

// --- Library Unload Function ---
// This function is marked with __attribute__((destructor)) and is called when the library is unloaded.
__attribute__((destructor))
void lib_unload() {
    LOGDEBUG("Library destructor (lib_unload) called. Cleaning up...");

    // --- Cleanup Resources ---
    // 1. Reset global pointers/state
    current_offsets.reset(); // Release the unique_ptr for offsets
    il2cpp_base = 0;         // Reset base address
    Original_UIRoot_Awake = nullptr; // Reset original function pointers
    Original_LobbyItem_get_IsExists = nullptr;
    g_JavaVM = nullptr;      // Clear global JavaVM pointer

    // 2. Close the log file safely
    {
        std::lock_guard<std::mutex> lock(log_mutex); // Lock before accessing shared resource
        if (log_file) {
            fprintf(log_file, "--- Log Session End ---\n"); // Add footer to log
            fflush(log_file); // Ensure footer is written
            fclose(log_file);
            log_file = nullptr; // Set pointer to null after closing
            __android_log_print(ANDROID_LOG_INFO, LOG_TAG_CUSTOM, "Log file closed.");
        }
    } // Mutex lock released here

    // 3. TODO: Optional Dobby cleanup.
    // Dobby *should* handle cleanup automatically when the library unloads.
    // Explicitly calling DobbyDestroy here might be problematic if addresses are invalid.
    // If issues arise, investigate manual unhooking.
    // Example: if (Original_UIRoot_Awake) DobbyDestroy((void*)(il2cpp_base + current_offsets->UIRoot_Awake));


    __android_log_print(ANDROID_LOG_INFO, LOG_TAG_CUSTOM, "Library cleanup finished.");
}

#pragma clang diagnostic pop