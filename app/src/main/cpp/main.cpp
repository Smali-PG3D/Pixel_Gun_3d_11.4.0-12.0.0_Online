#include <jni.h>
#include <pthread.h>
#include <cstring>
#include <vector>
#include <cstdint>
#include <dlfcn.h>
#include <cstdio> // For FILE, fopen, fclose
#include <cstdlib>
#include <thread>
#include <chrono>
#include <string>
#include <memory>  // For std::unique_ptr
#include <fstream> // For /proc/self/maps parsing
#include <sstream> // For string manipulation
#include <dobby.h>
#include "KittyMemory/MemoryPatch.hpp" // Assumed available

#pragma clang diagnostic push
#pragma ide diagnostic ignored "ConstantConditionsOC"
#pragma ide diagnostic ignored "ConstantFunctionResult" // Ignore specific IDE warnings

// --- JNI Globals ---
[[maybe_unused]] static JavaVM* g_JavaVM = nullptr; // Global JavaVM pointer

// --- App Info Struct ---
struct AppInfo {
    std::string versionName = "unknown";
    std::string packageName = "unknown";
    bool success = false; // Indicates if info retrieval succeeded
};

// --- IL2CPP Type Declarations ---
// Basic IL2CPP type definitions.
typedef struct Il2CppDomain Il2CppDomain;
typedef struct Il2CppAssembly Il2CppAssembly;
typedef struct Il2CppImage Il2CppImage;
typedef struct Il2CppClass Il2CppClass;
typedef struct Il2CppObject Il2CppObject;
typedef struct Il2CppString Il2CppString;
typedef struct MethodInfo MethodInfo;
typedef struct FieldInfo FieldInfo;
// Removed unused optional types: Il2CppException, Il2CppType

// --- IL2CPP API Function Pointers ---
// Pointers to core IL2CPP functions resolved dynamically.
static Il2CppDomain* (*il2cpp_domain_get)() = nullptr;
static Il2CppAssembly* (*il2cpp_domain_assembly_open)(Il2CppDomain* domain, const char* name) = nullptr;
static Il2CppImage* (*il2cpp_assembly_get_image)(Il2CppAssembly* assembly) = nullptr;
static Il2CppClass* (*il2cpp_class_from_name)(Il2CppImage* image, const char* namespaze, const char* name) = nullptr;
static MethodInfo* (*il2cpp_class_get_method_from_name)(Il2CppClass* klass, const char* name, int argsCount) = nullptr;
static Il2CppString* (*il2cpp_string_new)(const char* str) = nullptr;
static Il2CppObject* (*il2cpp_runtime_invoke)(MethodInfo* method, void* obj, void** params, Il2CppObject** exc) = nullptr;
static FieldInfo* (*il2cpp_class_get_field_from_name)(Il2CppClass* klass, const char* name) = nullptr;
static void (*il2cpp_field_static_get_value)(FieldInfo* field, void* value) = nullptr;
static void (*il2cpp_field_set_value)(Il2CppObject* obj, FieldInfo* field, void* value) = nullptr;
static void* (*il2cpp_object_unbox)(Il2CppObject* obj) = nullptr;
// Removed unused optional API pointers

// --- Global Variables ---
const char* FALLBACK_APP_PACKAGE_NAME = "com.pg12a.gun3d"; // Fallback package name
const char* IL2CPP_SO_NAME = "libil2cpp.so"; // Target library name
const char* TARGET_ASSEMBLY_NAME = "Assembly-CSharp.dll"; // Main game assembly
const char* FIRSTPASS_ASSEMBLY_NAME = "Assembly-CSharp-firstpass.dll"; // First pass assembly
const char* UNITYENGINE_ASSEMBLY_NAME = "UnityEngine.dll"; // Assembly containing Application class
static uintptr_t il2cpp_base = 0; // Base address of libil2cpp.so
static AppInfo g_appInfo;         // Store detected app info globally

// --- Constants for Modifications ---
// Photon related constants
const char* PHOTON_NAMESPACE = "";
const char* PHOTON_CLASS_NAME = "PhotonNetwork";
const char* PHOTON_SETTINGS_STATIC_FIELD_NAME = "PhotonServerSettings";
const char* SERVER_SETTINGS_CLASS_NAME = "ServerSettings";
const char* SERVERSETTINGS_APPID_FIELD_NAME = "AppID";
const char* SERVERSETTINGS_REGION_FIELD_NAME = "PreferredRegion";
const char* SERVERSETTINGS_HOSTTYPE_FIELD_NAME = "HostType";

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
const char* NEW_PHOTON_APP_ID = "your appid"; // Your Photon App ID
const int NEW_PHOTON_HOST_TYPE = 1; // ServerSettings.HostingOption.PhotonCloud
const int NEW_PHOTON_REGION = 0;    // CloudRegionCode.eu
const int ACCRUAL_TYPE_DEFAULT = 0; // Default accrual type
const int EXPERIENCE_TO_SET = 1000000;
const int TICKETS_TO_ADD = 999999999;
const int COINS_TO_ADD = 999999999;
const int GEMS_TO_ADD = 999999999;
const int LEVEL_KEY_VALUE_TO_SET = 1;
const int TARGET_FRAMERATE = 360; // Target frame rate

// Application related constants
const char* UNITYENGINE_NAMESPACE = "UnityEngine";
const char* APPLICATION_CLASS_NAME = "Application";
const char* SET_TARGETFRAMERATE_METHOD_NAME = "set_targetFrameRate";

// --- Base Offsets Structure ---
// Defines common RVAs (Relative Virtual Addresses) for different game versions.
struct BaseOffsets {
    virtual ~BaseOffsets() = default;
    uintptr_t UIRoot_Awake = 0;
    uintptr_t CraftHack = 0; // RVA for LobbyItem.get_IsExists or similar
    uintptr_t cheatDetectedBanner = 0;
    uintptr_t clearProgress = 0;
    uintptr_t showClearProgress = 0;
    uintptr_t awakeCheat = 0;
    uintptr_t updateCheat = 0;
    uintptr_t get_cheaterConfig = 0;
    uintptr_t set_cheaterConfig = 0;
    uintptr_t get_CheckSignatureTampering = 0;
    uintptr_t get_coinThreshold = 0;
    uintptr_t get_gemThreshold = 0;
};

// --- Specific Offset Structures ---
// Version/architecture specific RVAs.
struct Offsets_12_0_0_x86 : BaseOffsets {
    Offsets_12_0_0_x86() {
        UIRoot_Awake = 0xCBF798; CraftHack = 0xF247BC; cheatDetectedBanner = 0xF61FFC;
        clearProgress = 0xF620BB; showClearProgress = 0xF6202B; awakeCheat = 0xF6237E;
        updateCheat = 0xF62680; get_cheaterConfig = 0x138443F; set_cheaterConfig = 0x1386BE3;
        get_CheckSignatureTampering = 0xCF94C0; get_coinThreshold = 0xCF94D1; get_gemThreshold = 0xCF94E1;
    }
};

struct Offsets_12_0_0_armv7 : BaseOffsets {
    Offsets_12_0_0_armv7() {
        UIRoot_Awake = 0xDFBA60; CraftHack = 0x10BE904; cheatDetectedBanner = 0x1103220;
        clearProgress = 0x11032F0; showClearProgress = 0x1103228; awakeCheat = 0x1103654;
        updateCheat = 0x11039B4; get_cheaterConfig = 0x15ADA68; set_cheaterConfig = 0x15B09D4;
        get_CheckSignatureTampering = 0xE3F020; get_coinThreshold = 0xE3F028; get_gemThreshold = 0xE3F030;
    }
};

struct Offsets_11_4_0_x86 : BaseOffsets {
    Offsets_11_4_0_x86() {
        UIRoot_Awake = 0xBBA111; CraftHack = 0; // No crafts in 11.4.0
        cheatDetectedBanner = 0xF1C667; clearProgress = 0xF1C726; showClearProgress = 0xF1C696;
        awakeCheat = 0xF1C9E9; updateCheat = 0xF1CD07; get_cheaterConfig = 0xF2EF53;
        set_cheaterConfig = 0xF315DA; get_CheckSignatureTampering = 0x126F0FC;
        get_coinThreshold = 0x126F10D; get_gemThreshold = 0x126F11D;
    }
};

struct Offsets_11_4_0_armv7 : BaseOffsets {
    Offsets_11_4_0_armv7() {
        UIRoot_Awake = 0xCD1A08; CraftHack = 0; // No crafts in 11.4.0
        cheatDetectedBanner = 0x10B4F5C; clearProgress = 0x10B502C; showClearProgress = 0x10B4F64;
        awakeCheat = 0x10B5390; updateCheat = 0x10B5714; get_cheaterConfig = 0x10CB664;
        set_cheaterConfig = 0x10CE44C; get_CheckSignatureTampering = 0x147E64C;
        get_coinThreshold = 0x147E654; get_gemThreshold = 0x147E65C;
    }
};

// Global pointer to the current offsets.
static std::unique_ptr<BaseOffsets> current_offsets = nullptr;

// --- Utility Functions ---

// Helper to create an Il2CppString. Returns nullptr on failure.
inline Il2CppString* CreateIl2cppString(const char* str) {
    if (!il2cpp_string_new || !str) return nullptr;
    return il2cpp_string_new(str);
}

// Get the application's files directory path. Uses fallback if detection failed.
std::string get_files_dir() {
    const std::string& packageNameToUse = g_appInfo.success ? g_appInfo.packageName : FALLBACK_APP_PACKAGE_NAME;
    return "/data/data/" + packageNameToUse + "/files";
}

// Finds the base address of a loaded library by parsing /proc/self/maps.
uintptr_t findLibraryBaseAddress(const char* libraryName) {
    std::ifstream maps_file("/proc/self/maps");
    std::string line;
    uintptr_t base_addr = 0;
    if (!maps_file.is_open()) return 0;
    while (getline(maps_file, line)) {
        // Find library name and read-execute-private permissions
        if (line.find(libraryName) != std::string::npos && line.find("r-xp") != std::string::npos) {
            try {
                base_addr = std::stoull(line.substr(0, line.find('-')), nullptr, 16);
                break; // Found the first r-xp segment
            } catch (...) {
                base_addr = 0; // Reset on error
            }
        }
    }
    maps_file.close();
    return base_addr;
}

// --- JNI Helper: Get App Version and Package Name ---
// Retrieves app info using JNI via AppGlobals (non-SDK interface).
AppInfo get_app_info(JNIEnv* env) {
    AppInfo result;
    if (!env) return result;

    jclass appGlobalsClass = env->FindClass("android/app/AppGlobals");
    jobject application = nullptr;
    if (appGlobalsClass) {
        jmethodID getInitialApplicationMethod = env->GetStaticMethodID(appGlobalsClass, "getInitialApplication", "()Landroid/app/Application;");
        if (getInitialApplicationMethod) {
            application = env->CallStaticObjectMethod(appGlobalsClass, getInitialApplicationMethod);
        }
        env->DeleteLocalRef(appGlobalsClass);
    }
    if (!application) return result; // Cannot proceed without application context

    jclass contextClass = env->FindClass("android/content/Context");
    if (!contextClass) { env->DeleteLocalRef(application); return result; }

    // Get Package Name
    jmethodID getPackageNameMethod = env->GetMethodID(contextClass, "getPackageName", "()Ljava/lang/String;");
    jstring packageNameJString = nullptr;
    if (getPackageNameMethod) {
        packageNameJString = (jstring)env->CallObjectMethod(application, getPackageNameMethod);
        if (packageNameJString) {
            const char* packageNameCStr = env->GetStringUTFChars(packageNameJString, nullptr);
            if (packageNameCStr) {
                result.packageName = packageNameCStr;
                env->ReleaseStringUTFChars(packageNameJString, packageNameCStr);
            }
        }
    }
    if (result.packageName == "unknown") { // Abort if package name failed
        env->DeleteLocalRef(contextClass); env->DeleteLocalRef(application);
        if(packageNameJString) env->DeleteLocalRef(packageNameJString);
        return result;
    }

    // Get Version Name
    jmethodID getPackageManagerMethod = env->GetMethodID(contextClass, "getPackageManager", "()Landroid/content/pm/PackageManager;");
    jobject packageManager = nullptr;
    jclass packageManagerClass = nullptr;
    jmethodID getPackageInfoMethod = nullptr;
    jobject packageInfo = nullptr;
    jclass packageInfoClass = nullptr;
    jfieldID versionNameField = nullptr;
    jstring versionNameJString = nullptr;

    if (getPackageManagerMethod) packageManager = env->CallObjectMethod(application, getPackageManagerMethod);
    if (packageManager) packageManagerClass = env->GetObjectClass(packageManager);
    if (packageManagerClass) getPackageInfoMethod = env->GetMethodID(packageManagerClass, "getPackageInfo", "(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;");
    if (getPackageInfoMethod) packageInfo = env->CallObjectMethod(packageManager, getPackageInfoMethod, packageNameJString, 0);
    if (packageInfo) packageInfoClass = env->GetObjectClass(packageInfo);
    if (packageInfoClass) versionNameField = env->GetFieldID(packageInfoClass, "versionName", "Ljava/lang/String;");
    if (versionNameField) versionNameJString = (jstring)env->GetObjectField(packageInfo, versionNameField);

    if (versionNameJString) {
        const char* versionNameCStr = env->GetStringUTFChars(versionNameJString, nullptr);
        if (versionNameCStr) {
            result.versionName = versionNameCStr;
            env->ReleaseStringUTFChars(versionNameJString, versionNameCStr);
        }
        env->DeleteLocalRef(versionNameJString);
    }

    // Cleanup JNI Local References
    if (packageInfoClass) env->DeleteLocalRef(packageInfoClass);
    if (packageInfo) env->DeleteLocalRef(packageInfo);
    if (packageManagerClass) env->DeleteLocalRef(packageManagerClass);
    if (packageManager) env->DeleteLocalRef(packageManager);
    env->DeleteLocalRef(packageNameJString);
    env->DeleteLocalRef(contextClass);
    env->DeleteLocalRef(application);

    // Set success flag if both were retrieved
    if (result.packageName != "unknown" && result.versionName != "unknown") {
        result.success = true;
    }

    return result;
}


// --- IL2CPP API Resolution Function ---
// Resolves pointers to necessary IL2CPP functions using dlsym.
bool resolve_il2cpp_api() {
    void* handle = dlopen(IL2CPP_SO_NAME, RTLD_LAZY);
    if (!handle) handle = RTLD_DEFAULT; // Fallback
    if (!handle) return false; // Cannot resolve if no handle

    bool success = true;
    // Macro to resolve a function pointer and update success flag
#define RESOLVE_API(name) *(void**)(&name) = dlsym(handle, #name); if (!name) success = false;

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

#undef RESOLVE_API
    // Do not dlclose(handle) if it might be RTLD_DEFAULT or needed later.
    return success;
}


// --- Hook for UIRoot.Awake ---
// This function replaces the original UIRoot.Awake method and applies modifications.
void (*Original_UIRoot_Awake)(void* instance) = nullptr; // Pointer to the original function

void UIRoot_Awake_Hook(void* instance) {
    static bool one_time_actions_done = false; // Flag for one-time actions

    // Call the original UIRoot.Awake function first
    if (Original_UIRoot_Awake) {
        Original_UIRoot_Awake(instance);
    }

    // Check if essential IL2CPP API functions are available
    if (!il2cpp_domain_get || !il2cpp_domain_assembly_open || !il2cpp_assembly_get_image ||
        !il2cpp_class_from_name || !il2cpp_class_get_method_from_name || !il2cpp_runtime_invoke ||
        !il2cpp_string_new || !il2cpp_class_get_field_from_name || !il2cpp_field_set_value ||
        !il2cpp_field_static_get_value)
    {
        return; // Cannot proceed without essential APIs
    }

    Il2CppDomain* domain = il2cpp_domain_get();
    Il2CppAssembly* mainAssembly = il2cpp_domain_assembly_open(domain, TARGET_ASSEMBLY_NAME);
    Il2CppAssembly* firstpassAssembly = il2cpp_domain_assembly_open(domain, FIRSTPASS_ASSEMBLY_NAME);
    Il2CppAssembly* unityAssembly = il2cpp_domain_assembly_open(domain, UNITYENGINE_ASSEMBLY_NAME);

    const Il2CppImage* mainImage = mainAssembly ? il2cpp_assembly_get_image(mainAssembly) : nullptr;
    const Il2CppImage* firstpassImage = firstpassAssembly ? il2cpp_assembly_get_image(firstpassAssembly) : nullptr;
    const Il2CppImage* unityImage = unityAssembly ? il2cpp_assembly_get_image(unityAssembly) : nullptr;

    // Ensure required assembly images were loaded
    if (!mainImage || !firstpassImage || !unityImage) {
        return; // Cannot proceed without core images
    }

    // --- Modifications ---

    // 1. Modify Photon Settings via Static Field (EXECUTED EVERY CALL)
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
                    if (newAppIdStr) il2cpp_field_set_value(serverSettingsInstance, appIdField, newAppIdStr);
                }
                // Set HostType
                if (hostTypeField) {
                    int hostTypeValue = NEW_PHOTON_HOST_TYPE;
                    il2cpp_field_set_value(serverSettingsInstance, hostTypeField, &hostTypeValue);
                }
                // Set PreferredRegion
                if (regionField) {
                    int regionValue = NEW_PHOTON_REGION;
                    il2cpp_field_set_value(serverSettingsInstance, regionField, &regionValue);
                }
            }
        }
    }

    // 2. Add Currency/Tickets (One-time action using a flag file)
    if (!one_time_actions_done) {
        std::string flag_path_curr = get_files_dir() + "/currency_added.flag";
        FILE* flag_file_curr = fopen(flag_path_curr.c_str(), "r");
        if (flag_file_curr) {
            fclose(flag_file_curr); // Flag exists, already added
        } else {
            // Flag doesn't exist, attempt to add currency
            Il2CppClass* bankControllerClass = il2cpp_class_from_name((Il2CppImage*)mainImage, "", BANKCONTROLLER_CLASS_NAME);
            if (bankControllerClass) {
                bool item_added = false;
                MethodInfo* addCoinsMethod = il2cpp_class_get_method_from_name(bankControllerClass, ADD_COINS_METHOD_NAME, 3);
                MethodInfo* addGemsMethod = il2cpp_class_get_method_from_name(bankControllerClass, ADD_GEMS_METHOD_NAME, 3);
                MethodInfo* addTicketsMethod = il2cpp_class_get_method_from_name(bankControllerClass, ADD_TICKETS_METHOD_NAME, 3);
                Il2CppObject* ex = nullptr;
                int v; bool i=true; int a=ACCRUAL_TYPE_DEFAULT; void* args[]={&v,&i,&a};

                if (addCoinsMethod) { v=COINS_TO_ADD; ex=nullptr; il2cpp_runtime_invoke(addCoinsMethod, nullptr, args, &ex); if(!ex) item_added=true; }
                if (addGemsMethod) { v=GEMS_TO_ADD; ex=nullptr; il2cpp_runtime_invoke(addGemsMethod, nullptr, args, &ex); if(!ex) item_added=true; }
                if (addTicketsMethod) { v=TICKETS_TO_ADD; ex=nullptr; il2cpp_runtime_invoke(addTicketsMethod, nullptr, args, &ex); if(!ex) item_added=true; }

                if (item_added) { // Create flag file on success
                    FILE* f = fopen(flag_path_curr.c_str(), "w");
                    if (f) fclose(f);
                }
            }
        }
    }

    // 3. Set Level Key and Experience (EXECUTED EVERY CALL)
    Il2CppClass* storagerClass = il2cpp_class_from_name((Il2CppImage*)mainImage, "", STORAGER_CLASS_NAME);
    if (storagerClass) {
        MethodInfo* setIntMethod = il2cpp_class_get_method_from_name(storagerClass, STORAGER_SETINT_METHOD_NAME, 2);
        if (setIntMethod) {
            Il2CppObject* ex = nullptr;
            const char* levelKey = nullptr;

            // Determine level key based on game version
            if (g_appInfo.versionName == "11.4.0") levelKey = "currentLevel31";
            else levelKey = "currentLevel36"; // Default/Fallback for 12.0.0 or unknown

            // Set Level Key
            if (levelKey) {
                int levelValue = LEVEL_KEY_VALUE_TO_SET;
                Il2CppString* levelKeyStr = CreateIl2cppString(levelKey);
                if (levelKeyStr) { void* args[] = {levelKeyStr, &levelValue}; ex = nullptr; il2cpp_runtime_invoke(setIntMethod, nullptr, args, &ex); }
            }

            // Set Experience
            const char* expKey = "currentExperience";
            int expValue = EXPERIENCE_TO_SET;
            Il2CppString* expKeyStr = CreateIl2cppString(expKey);
            if (expKeyStr) { void* args[] = {expKeyStr, &expValue}; ex = nullptr; il2cpp_runtime_invoke(setIntMethod, nullptr, args, &ex); }
        }
    }

    // 4. Check/Set Training Flag (One-time action)
    if (!one_time_actions_done && storagerClass) { // Also ensure storagerClass is valid here
        Il2CppString* trainingKeyStr = nullptr;
        Il2CppClass* defsClass = il2cpp_class_from_name((Il2CppImage*)firstpassImage, "", DEFS_CLASS_NAME);
        if (defsClass) {
            MethodInfo* getKeyMethod = il2cpp_class_get_method_from_name(defsClass, TRAINING_KEY_GETTER_METHOD_NAME, 0);
            if (getKeyMethod) {
                Il2CppObject* keyRes=nullptr; Il2CppObject* getKeyEx=nullptr;
                keyRes=il2cpp_runtime_invoke(getKeyMethod, nullptr, nullptr, &getKeyEx);
                if(!getKeyEx && keyRes) trainingKeyStr=(Il2CppString*)keyRes;
            }
        }

        if (trainingKeyStr) {
            MethodInfo* getIntMethod = il2cpp_class_get_method_from_name(storagerClass, STORAGER_GETINT_METHOD_NAME, 1);
            if (getIntMethod) {
                void* getArgs[] = {trainingKeyStr}; Il2CppObject* getRes=nullptr; Il2CppObject* getEx=nullptr;
                getRes=il2cpp_runtime_invoke(getIntMethod, nullptr, getArgs, &getEx);
                if (!getEx && getRes && il2cpp_object_unbox) {
                    int currentVal = *(static_cast<int*>(il2cpp_object_unbox(getRes)));
                    if (currentVal == 0) { // Only set if currently 0
                        MethodInfo* setIntMethod = il2cpp_class_get_method_from_name(storagerClass, STORAGER_SETINT_METHOD_NAME, 2);
                        if (setIntMethod) {
                            int newVal=1; void* setArgs[]={trainingKeyStr, &newVal}; Il2CppObject* setEx=nullptr;
                            il2cpp_runtime_invoke(setIntMethod, nullptr, setArgs, &setEx);
                            // No error check needed here unless crucial
                        }
                    }
                }
            }
        }
    }

    // 5. Set Target Frame Rate (EXECUTED EVERY CALL)
    Il2CppClass* appClass = il2cpp_class_from_name((Il2CppImage*)unityImage, UNITYENGINE_NAMESPACE, APPLICATION_CLASS_NAME);
    if (appClass) {
        MethodInfo* setTargetFrameRateMethod = il2cpp_class_get_method_from_name(appClass, SET_TARGETFRAMERATE_METHOD_NAME, 1);
        if (setTargetFrameRateMethod) {
            int frameRate = TARGET_FRAMERATE; void* args[] = {&frameRate}; Il2CppObject* ex = nullptr;
            il2cpp_runtime_invoke(setTargetFrameRateMethod, nullptr, args, &ex); // Static method
        }
    }

    // Mark one-time actions as completed
    if (!one_time_actions_done) {
        one_time_actions_done = true;
    }
}


// --- Hook for LobbyItem.get_IsExists (Craft Hack) ---
// Always returns true to bypass crafting checks (if applicable).
bool (*Original_LobbyItem_get_IsExists)(void* instance) = nullptr;
bool CraftHack_Hook([[maybe_unused]] void* instance) {
    // No logging needed, just return true
    return true;
}

// --- Memory Patching Function ---
// Applies NOP/RET patches to disable specific functions.
void ApplyMemoryPatches() {
    if (!current_offsets || il2cpp_base == 0) return; // Cannot patch without offsets or base address

    const char* patchHex = nullptr;
#if defined(__arm__)
    patchHex = "1E FF 2F E1"; // BX LR (ARM Thumb)
#elif defined(__i386__)
    patchHex = "C3"; // RET (x86)
#else
    return; // Unsupported architecture
#endif
    if (!patchHex) return;

    // Lambda helper to apply a patch
    auto applyMemPatch = [&](uintptr_t rva) {
        if (rva == 0) return; // Skip if RVA is 0
        uintptr_t addr = il2cpp_base + rva;
        if (addr <= il2cpp_base) return; // Invalid address protection
        MemoryPatch patch = MemoryPatch::createWithHex(addr, patchHex);
        if (patch.isValid()) patch.Modify(); // Apply patch if valid
    };

    // Apply patches using the loaded offsets
    applyMemPatch(current_offsets->cheatDetectedBanner);
    applyMemPatch(current_offsets->clearProgress);
    applyMemPatch(current_offsets->showClearProgress);
    applyMemPatch(current_offsets->awakeCheat);
    applyMemPatch(current_offsets->updateCheat);
    applyMemPatch(current_offsets->get_cheaterConfig);
    applyMemPatch(current_offsets->set_cheaterConfig);
    applyMemPatch(current_offsets->get_CheckSignatureTampering);
    applyMemPatch(current_offsets->get_coinThreshold);
    applyMemPatch(current_offsets->get_gemThreshold);
}

// --- Hook Installation Function ---
// Installs function hooks using Dobby.
void InstallHooks() {
    if (!current_offsets || il2cpp_base == 0) return; // Cannot hook without offsets or base address

    // Lambda helper to install a hook
    auto installHook = [&](uintptr_t rva, void* hook_func, void** orig_func_ptr) {
        if (rva == 0) return; // Skip if RVA is 0
        uintptr_t addr = il2cpp_base + rva;
        if (addr <= il2cpp_base) { *orig_func_ptr = nullptr; return; } // Invalid address
        int status = DobbyHook((void*)addr, hook_func, orig_func_ptr);
        if (status != RT_SUCCESS) *orig_func_ptr = nullptr; // Ensure original pointer is null on failure
    };

    // Install hooks using the loaded offsets
    installHook(current_offsets->UIRoot_Awake, (void*)UIRoot_Awake_Hook, (void**)&Original_UIRoot_Awake);
    installHook(current_offsets->CraftHack, (void*)CraftHack_Hook, (void**)&Original_LobbyItem_get_IsExists);
}


// --- Core Initialization Function ---
// Gets app info, selects offsets, finds library base, resolves API.
bool PerformInitialization(JNIEnv* env) {
    // 1. Get App Version and Package Name
    g_appInfo = get_app_info(env);
    if (!g_appInfo.success) return false;

    // 2. Select Offsets based on Version and Architecture
    if (g_appInfo.versionName == "12.0.0") {
#if defined(__i386__)
        current_offsets = std::make_unique<Offsets_12_0_0_x86>();
#elif defined(__arm__)
        current_offsets = std::make_unique<Offsets_12_0_0_armv7>();
        #else
            return false; // Unsupported architecture
#endif
    } else if (g_appInfo.versionName == "11.4.0") {
#if defined(__i386__)
        current_offsets = std::make_unique<Offsets_11_4_0_x86>();
#elif defined(__arm__)
        current_offsets = std::make_unique<Offsets_11_4_0_armv7>();
        #else
            return false; // Unsupported architecture
#endif
    } else {
        return false; // Unsupported version
    }
    if (!current_offsets) return false; // Failed to create offsets

    // 3. Find libil2cpp.so base address (if not already found)
    if (il2cpp_base == 0) {
        il2cpp_base = findLibraryBaseAddress(IL2CPP_SO_NAME);
        if (il2cpp_base == 0) { current_offsets.reset(); return false; }
    }

    // 4. Resolve IL2CPP API functions (if not already resolved)
    if (!il2cpp_domain_get) { // Check one critical function
        if (!resolve_il2cpp_api()) { current_offsets.reset(); return false; }
    }

    return true; // Initialization successful
}

// --- Background Thread Function ---
// Waits for the target library, performs initialization, and applies patches/hooks.
void *hack_thread(void* vm_ptr) {
    JavaVM* vm = (JavaVM*)vm_ptr;
    JNIEnv* env = nullptr;
    bool attached = false;

    // Attach current thread to JVM to get JNIEnv
    jint attachResult = vm->GetEnv((void**)&env, JNI_VERSION_1_6);
    if (attachResult == JNI_EDETACHED) {
        if (vm->AttachCurrentThread(&env, nullptr) == JNI_OK) attached = true;
        else return nullptr; // Attach failed
    } else if (attachResult != JNI_OK) {
        return nullptr; // GetEnv failed
    }

    // Wait for the target library (libil2cpp.so) to be loaded
    const int max_wait_seconds = 120; // 2 minutes timeout
    bool library_found = false;
    for (int wait_seconds = 0; wait_seconds < max_wait_seconds; ++wait_seconds) {
        void* libHandle = dlopen(IL2CPP_SO_NAME, RTLD_NOLOAD | RTLD_LAZY);
        if (libHandle) {
            dlclose(libHandle);
            library_found = true;
            break;
        }
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }

    if (!library_found) {
        if (attached) vm->DetachCurrentThread();
        return nullptr; // Library not found, abort
    }

    // Perform core initialization
    bool init_success = PerformInitialization(env);

    // Apply Patches and Hooks only if Initialization Succeeded
    if (init_success) {
        // Short delay might help timing issues on some devices
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
        ApplyMemoryPatches();
        InstallHooks();
    } else {
        // Cleanup offsets if initialization failed after they were allocated
        current_offsets.reset();
    }

    if (attached) {
        vm->DetachCurrentThread(); // Detach from JVM if attached
    }
    return nullptr; // Thread finished
}


// --- JNI_OnLoad ---
// Called by the Android runtime when the native library is loaded.
extern "C" JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, [[maybe_unused]] void* reserved) {
    g_JavaVM = vm; // Store JavaVM globally
    JNIEnv* env;
    if (vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6) != JNI_OK) {
        return JNI_ERR; // Failed to get JNIEnv
    }

    // Create a detached background thread for initialization and hooking.
    pthread_t ptid = 0;
    if (pthread_create(&ptid, nullptr, hack_thread, (void*)vm) == 0) {
        pthread_detach(ptid); // Detach thread for automatic resource release
    } // If thread creation fails, the mod won't load, but the app continues.

    return JNI_VERSION_1_6; // Return supported JNI version
}

// No explicit unload function needed anymore as logging cleanup is removed.
// Dobby/OS should handle resource cleanup on library unload.

#pragma clang diagnostic pop // Restore diagnostics state