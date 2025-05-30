#include <jni.h>
#include <pthread.h>
#include <cstring>
#include <vector>
#include <cstdint>
#include <dlfcn.h>
#include <cstdio>
#include <cstdlib>
#include <thread>
#include <chrono>
#include <string>
#include <memory>
#include <fstream>
#include <sstream>
#include <dobby.h>
#include "KittyMemory/MemoryPatch.hpp" // Assumed available
#include <android/log.h> // For Android Logcat (general mod logging) - Retained for potential future use, but calls are removed

#pragma clang diagnostic push
#pragma ide diagnostic ignored "ConstantConditionsOC"
#pragma ide diagnostic ignored "ConstantFunctionResult"

// --- JNI Globals ---
[[maybe_unused]] static JavaVM* g_JavaVM = nullptr;

// --- App Info Struct ---
struct AppInfo {
    std::string versionName = "unknown";
    std::string packageName = "unknown";
    bool success = false;
};

// --- IL2CPP Type Declarations ---
typedef struct Il2CppDomain Il2CppDomain;
typedef struct Il2CppAssembly Il2CppAssembly;
typedef struct Il2CppImage Il2CppImage;
typedef struct Il2CppClass Il2CppClass;
typedef struct Il2CppObject Il2CppObject;
typedef struct Il2CppString Il2CppString;
typedef struct MethodInfo MethodInfo;
typedef struct FieldInfo FieldInfo;

// --- IL2CPP API Function Pointers ---
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

// --- Global Variables ---
const char* FALLBACK_APP_PACKAGE_NAME = "com.pg12a.gun3d";
const char* IL2CPP_SO_NAME = "libil2cpp.so";
const char* TARGET_ASSEMBLY_NAME = "Assembly-CSharp.dll";
const char* FIRSTPASS_ASSEMBLY_NAME = "Assembly-CSharp-firstpass.dll";
const char* UNITYENGINE_ASSEMBLY_NAME = "UnityEngine.dll";
static uintptr_t il2cpp_base = 0;
static AppInfo g_appInfo;

// --- Constants for Modifications ---
const char* PHOTON_NAMESPACE = "";
const char* PHOTON_CLASS_NAME = "PhotonNetwork";
const char* PHOTON_SETTINGS_STATIC_FIELD_NAME = "PhotonServerSettings";
const char* SERVER_SETTINGS_CLASS_NAME = "ServerSettings";
const char* SERVERSETTINGS_APPID_FIELD_NAME = "AppID";
const char* SERVERSETTINGS_REGION_FIELD_NAME = "PreferredRegion";
const char* SERVERSETTINGS_HOSTTYPE_FIELD_NAME = "HostType";
const char* BANKCONTROLLER_CLASS_NAME = "BankController";
const char* ADD_COINS_METHOD_NAME = "AddCoins";
const char* ADD_GEMS_METHOD_NAME = "AddGems";
const char* ADD_TICKETS_METHOD_NAME = "AddTickets";
const char* DEFS_CLASS_NAME = "Defs";
const char* TRAINING_KEY_GETTER_METHOD_NAME = "get_TrainingCompleted_4_4_Sett";
const char* STORAGER_CLASS_NAME = "Storager";
const char* STORAGER_GETINT_METHOD_NAME = "getInt";
const char* STORAGER_SETINT_METHOD_NAME = "setInt";
const char* NEW_PHOTON_APP_ID = "your appid";
const int NEW_PHOTON_HOST_TYPE = 1;
const int NEW_PHOTON_REGION = 0;
const int ACCRUAL_TYPE_DEFAULT = 0;
const int EXPERIENCE_TO_SET = 1000000;
const int TICKETS_TO_ADD = 999999999;
const int COINS_TO_ADD = 999999999;
const int GEMS_TO_ADD = 999999999;
const int LEVEL_KEY_VALUE_TO_SET = 1;
const int TARGET_FRAMERATE = 360;
const char* UNITYENGINE_NAMESPACE = "UnityEngine";
const char* APPLICATION_CLASS_NAME = "Application";
const char* SET_TARGETFRAMERATE_METHOD_NAME = "set_targetFrameRate";

// --- Base Offsets Structure ---
struct BaseOffsets {
    virtual ~BaseOffsets() = default;
    uintptr_t UIRoot_Awake = 0; uintptr_t CraftHack = 0; uintptr_t cheatDetectedBanner = 0;
    uintptr_t clearProgress = 0; uintptr_t showClearProgress = 0; uintptr_t awakeCheat = 0;
    uintptr_t updateCheat = 0; uintptr_t get_cheaterConfig = 0; uintptr_t set_cheaterConfig = 0;
    uintptr_t get_CheckSignatureTampering = 0; uintptr_t get_coinThreshold = 0; uintptr_t get_gemThreshold = 0;
    uintptr_t CleanUpAndDoAction_Start = 0; uintptr_t CleanUpAndDoAction_OnGUI = 0; uintptr_t ClosingScript_Start = 0;
    uintptr_t AppsMenu_Start = 0; uintptr_t AppsMenu_GetAbuseKey_53232de5 = 0;
    uintptr_t AppsMenu_GetAbuseKey_21493d18 = 0; uintptr_t AppsMenu_GetTerminalSceneName_4de1 = 0;
    uintptr_t AppsMenu_SafeGetSdkLevel = 0; uintptr_t AppsMenu_HandleNotification = 0;
};

// --- Specific Offset Structures ---
struct Offsets_12_0_0_x86 : BaseOffsets {
    Offsets_12_0_0_x86() {
        UIRoot_Awake = 0xCBF798; CraftHack = 0xF247BC; cheatDetectedBanner = 0xF61FFC; clearProgress = 0xF620BB;
        showClearProgress = 0xF6202B; awakeCheat = 0xF6237E; updateCheat = 0xF62680; get_cheaterConfig = 0x138443F;
        set_cheaterConfig = 0x1386BE3; get_CheckSignatureTampering = 0xCF94C0; get_coinThreshold = 0xCF94D1;
        get_gemThreshold = 0xCF94E1; CleanUpAndDoAction_Start = 0xBCAA76; CleanUpAndDoAction_OnGUI = 0xBCAB08;
        ClosingScript_Start = 0xBCB478; AppsMenu_Start = 0x130B4E1;
        AppsMenu_GetAbuseKey_53232de5 = 0x130A344; AppsMenu_GetAbuseKey_21493d18 = 0x130A3EC;
        AppsMenu_GetTerminalSceneName_4de1 = 0x130A494; AppsMenu_SafeGetSdkLevel = 0x130C0F3;
        AppsMenu_HandleNotification = 0x130C82C;
    }
};
struct Offsets_12_0_0_armv7 : BaseOffsets {
    Offsets_12_0_0_armv7() {
        UIRoot_Awake = 0xDFBA60; CraftHack = 0x10BE904; cheatDetectedBanner = 0x1103220; clearProgress = 0x11032F0;
        showClearProgress = 0x1103228; awakeCheat = 0x1103654; updateCheat = 0x11039B4; get_cheaterConfig = 0x15ADA68;
        set_cheaterConfig = 0x15B09D4; get_CheckSignatureTampering = 0xE3F020; get_coinThreshold = 0xE3F028;
        get_gemThreshold = 0xE3F030; CleanUpAndDoAction_Start = 0xCE0B2C; CleanUpAndDoAction_OnGUI = 0xCE0BC0;
        ClosingScript_Start = 0xCE1620; AppsMenu_Start = 0x1523BF8;
        AppsMenu_GetAbuseKey_53232de5 = 0x1522438; AppsMenu_GetAbuseKey_21493d18 = 0x1522548;
        AppsMenu_GetTerminalSceneName_4de1 = 0x1522658; AppsMenu_SafeGetSdkLevel = 0x15249F4;
        AppsMenu_HandleNotification = 0x15253B4;
    }
};
struct Offsets_11_4_0_x86 : BaseOffsets {
    Offsets_11_4_0_x86() {
        UIRoot_Awake = 0xBBA111; CraftHack = 0; cheatDetectedBanner = 0xF1C667; clearProgress = 0xF1C726;
        showClearProgress = 0xF1C696; awakeCheat = 0xF1C9E9; updateCheat = 0xF1CD07; get_cheaterConfig = 0xF2EF53;
        set_cheaterConfig = 0xF315DA; get_CheckSignatureTampering = 0x126F0FC; get_coinThreshold = 0x126F10D;
        get_gemThreshold = 0x126F11D; CleanUpAndDoAction_Start = 0x900228; CleanUpAndDoAction_OnGUI = 0x9002BA;
        ClosingScript_Start = 0x900C46; AppsMenu_Start = 0x125B8C9;
        AppsMenu_GetAbuseKey_53232de5 = 0x125AA7A; AppsMenu_GetAbuseKey_21493d18 = 0x125AB22;
        AppsMenu_GetTerminalSceneName_4de1 = 0x125ABCA; AppsMenu_SafeGetSdkLevel = 0;
        AppsMenu_HandleNotification = 0x125C08D;
    }
};
struct Offsets_11_4_0_armv7 : BaseOffsets {
    Offsets_11_4_0_armv7() {
        UIRoot_Awake = 0xCD1A08; CraftHack = 0; cheatDetectedBanner = 0x10B4F5C; clearProgress = 0x10B502C;
        showClearProgress = 0x10B4F64; awakeCheat = 0x10B5390; updateCheat = 0x10B5714; get_cheaterConfig = 0x10CB664;
        set_cheaterConfig = 0x10CE44C; get_CheckSignatureTampering = 0x147E64C; get_coinThreshold = 0x147E654;
        get_gemThreshold = 0x147E65C; CleanUpAndDoAction_Start = 0x9D58D4; CleanUpAndDoAction_OnGUI = 0x9D5968;
        ClosingScript_Start = 0x9D63D8; AppsMenu_Start = 0x14676B0;
        AppsMenu_GetAbuseKey_53232de5 = 0x1466388; AppsMenu_GetAbuseKey_21493d18 = 0x1466498;
        AppsMenu_GetTerminalSceneName_4de1 = 0x14665A8; AppsMenu_SafeGetSdkLevel = 0;
        AppsMenu_HandleNotification = 0x14680D8;
    }
};
static std::unique_ptr<BaseOffsets> current_offsets = nullptr;

// --- Utility Functions ---
inline Il2CppString* CreateIl2cppString(const char* str) {
    if (!il2cpp_string_new || !str) return nullptr;
    return il2cpp_string_new(str);
}

// Used for currency flag
std::string get_files_dir() {
    const std::string& packageNameToUse = g_appInfo.success && !g_appInfo.packageName.empty() ? g_appInfo.packageName : FALLBACK_APP_PACKAGE_NAME;
    return "/data/data/" + packageNameToUse + "/files";
}

uintptr_t findLibraryBaseAddress(const char* libraryName) {
    std::ifstream maps_file("/proc/self/maps"); std::string line; uintptr_t base_addr = 0;
    if (!maps_file.is_open()) return 0;
    while (getline(maps_file, line)) {
        if (line.find(libraryName) != std::string::npos && line.find("r-xp") != std::string::npos) {
            try { base_addr = std::stoull(line.substr(0, line.find('-')), nullptr, 16); break; } catch (...) { base_addr = 0; }
        }
    }
    maps_file.close(); return base_addr;
}

// --- JNI Helper: Get App Version and Package Name ---
AppInfo get_app_info(JNIEnv* env) {
    AppInfo result; if (!env) return result;
    jclass appGlobalsClass = env->FindClass("android/app/AppGlobals"); jobject application = nullptr;
    if (appGlobalsClass) {
        jmethodID getInitialApplicationMethod = env->GetStaticMethodID(appGlobalsClass, "getInitialApplication", "()Landroid/app/Application;");
        if (getInitialApplicationMethod) application = env->CallStaticObjectMethod(appGlobalsClass, getInitialApplicationMethod);
        env->DeleteLocalRef(appGlobalsClass);
    }
    if (!application) return result;
    jclass contextClass = env->FindClass("android/content/Context");
    if (!contextClass) { env->DeleteLocalRef(application); return result; }
    jmethodID getPackageNameMethod = env->GetMethodID(contextClass, "getPackageName", "()Ljava/lang/String;");
    jstring packageNameJString = nullptr;
    if (getPackageNameMethod) {
        packageNameJString = (jstring)env->CallObjectMethod(application, getPackageNameMethod);
        if (packageNameJString) {
            const char* packageNameCStr = env->GetStringUTFChars(packageNameJString, nullptr);
            if (packageNameCStr) { result.packageName = packageNameCStr; env->ReleaseStringUTFChars(packageNameJString, packageNameCStr); }
        }
    }
    if (result.packageName == "unknown" || result.packageName.empty()) result.packageName = FALLBACK_APP_PACKAGE_NAME;
    jmethodID getPackageManagerMethod = env->GetMethodID(contextClass, "getPackageManager", "()Landroid/content/pm/PackageManager;");
    jobject packageManager = nullptr; jclass packageManagerClass = nullptr; jmethodID getPackageInfoMethod = nullptr;
    jobject packageInfo = nullptr; jclass packageInfoClass = nullptr; jfieldID versionNameField = nullptr;
    jstring versionNameJString = nullptr;
    if (getPackageManagerMethod) packageManager = env->CallObjectMethod(application, getPackageManagerMethod);
    if (packageManager) packageManagerClass = env->GetObjectClass(packageManager);
    if (packageManagerClass) {
        getPackageInfoMethod = env->GetMethodID(packageManagerClass, "getPackageInfo", "(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;");
        if (getPackageInfoMethod) {
            jstring currentPackageNameJString = nullptr;
            if (packageNameJString) currentPackageNameJString = packageNameJString;
            else if (!result.packageName.empty()) currentPackageNameJString = env->NewStringUTF(result.packageName.c_str());
            if (currentPackageNameJString) {
                packageInfo = env->CallObjectMethod(packageManager, getPackageInfoMethod, currentPackageNameJString, 0);
                if (currentPackageNameJString != packageNameJString) env->DeleteLocalRef(currentPackageNameJString);
            }
        }
    }
    if (packageInfo) packageInfoClass = env->GetObjectClass(packageInfo);
    if (packageInfoClass) versionNameField = env->GetFieldID(packageInfoClass, "versionName", "Ljava/lang/String;");
    if (versionNameField) versionNameJString = (jstring)env->GetObjectField(packageInfo, versionNameField);
    if (versionNameJString) {
        const char* versionNameCStr = env->GetStringUTFChars(versionNameJString, nullptr);
        if (versionNameCStr) { result.versionName = versionNameCStr; env->ReleaseStringUTFChars(versionNameJString, versionNameCStr); }
        env->DeleteLocalRef(versionNameJString);
    }
    if (packageInfoClass) env->DeleteLocalRef(packageInfoClass); if (packageInfo) env->DeleteLocalRef(packageInfo);
    if (packageManagerClass) env->DeleteLocalRef(packageManagerClass); if (packageManager) env->DeleteLocalRef(packageManager);
    if (packageNameJString) env->DeleteLocalRef(packageNameJString); env->DeleteLocalRef(contextClass); env->DeleteLocalRef(application);
    result.success = (result.packageName != FALLBACK_APP_PACKAGE_NAME && result.versionName != "unknown" && !result.versionName.empty());
    return result;
}

// --- IL2CPP API Resolution Function ---
bool resolve_il2cpp_api() {
    void* handle = dlopen(IL2CPP_SO_NAME, RTLD_LAZY); if (!handle) handle = RTLD_DEFAULT; if (!handle) return false;
    bool success = true;
#define RESOLVE_API(name) *(void**)(&name) = dlsym(handle, #name); if (!name) success = false
    RESOLVE_API(il2cpp_domain_get); RESOLVE_API(il2cpp_domain_assembly_open); RESOLVE_API(il2cpp_assembly_get_image);
    RESOLVE_API(il2cpp_class_from_name); RESOLVE_API(il2cpp_class_get_method_from_name); RESOLVE_API(il2cpp_string_new);
    RESOLVE_API(il2cpp_runtime_invoke); RESOLVE_API(il2cpp_class_get_field_from_name); RESOLVE_API(il2cpp_field_static_get_value);
    RESOLVE_API(il2cpp_field_set_value); RESOLVE_API(il2cpp_object_unbox);
#undef RESOLVE_API
    return success;
}

// --- Hook for UIRoot.Awake ---
void (*Original_UIRoot_Awake)(void* instance) = nullptr;
void UIRoot_Awake_Hook(void* instance) {
    static bool one_time_actions_done = false;
    if (Original_UIRoot_Awake) Original_UIRoot_Awake(instance);
    if (!il2cpp_domain_get || !il2cpp_domain_assembly_open || !il2cpp_assembly_get_image ||
        !il2cpp_class_from_name || !il2cpp_class_get_method_from_name || !il2cpp_runtime_invoke ||
        !il2cpp_string_new || !il2cpp_class_get_field_from_name || !il2cpp_field_set_value ||
        !il2cpp_field_static_get_value || !il2cpp_object_unbox) return;
    Il2CppDomain* domain = il2cpp_domain_get(); if (!domain) return;
    Il2CppAssembly* mainAssembly = il2cpp_domain_assembly_open(domain, TARGET_ASSEMBLY_NAME);
    Il2CppAssembly* firstpassAssembly = il2cpp_domain_assembly_open(domain, FIRSTPASS_ASSEMBLY_NAME);
    Il2CppAssembly* unityAssembly = il2cpp_domain_assembly_open(domain, UNITYENGINE_ASSEMBLY_NAME);
    const Il2CppImage* mainImage = mainAssembly ? il2cpp_assembly_get_image(mainAssembly) : nullptr;
    const Il2CppImage* firstpassImage = firstpassAssembly ? il2cpp_assembly_get_image(firstpassAssembly) : nullptr;
    const Il2CppImage* unityImage = unityAssembly ? il2cpp_assembly_get_image(unityAssembly) : nullptr;
    if (!mainImage || !firstpassImage || !unityImage) return;

    Il2CppClass* photonNetworkClass = il2cpp_class_from_name((Il2CppImage*)mainImage, PHOTON_NAMESPACE, PHOTON_CLASS_NAME);
    Il2CppClass* serverSettingsClass = il2cpp_class_from_name((Il2CppImage*)mainImage, PHOTON_NAMESPACE, SERVER_SETTINGS_CLASS_NAME);
    if (photonNetworkClass && serverSettingsClass) {
        FieldInfo* settingsStaticField = il2cpp_class_get_field_from_name(photonNetworkClass, PHOTON_SETTINGS_STATIC_FIELD_NAME);
        if (settingsStaticField) {
            Il2CppObject* serverSettingsInstance = nullptr; il2cpp_field_static_get_value(settingsStaticField, &serverSettingsInstance);
            if (serverSettingsInstance) {
                FieldInfo* appIdField = il2cpp_class_get_field_from_name(serverSettingsClass, SERVERSETTINGS_APPID_FIELD_NAME);
                FieldInfo* hostTypeField = il2cpp_class_get_field_from_name(serverSettingsClass, SERVERSETTINGS_HOSTTYPE_FIELD_NAME);
                FieldInfo* regionField = il2cpp_class_get_field_from_name(serverSettingsClass, SERVERSETTINGS_REGION_FIELD_NAME);
                if (appIdField) { Il2CppString* newAppIdStr = CreateIl2cppString(NEW_PHOTON_APP_ID); if (newAppIdStr) il2cpp_field_set_value(serverSettingsInstance, appIdField, newAppIdStr); }
                if (hostTypeField) { int hostTypeValue = NEW_PHOTON_HOST_TYPE; il2cpp_field_set_value(serverSettingsInstance, hostTypeField, &hostTypeValue); }
                if (regionField) { int regionValue = NEW_PHOTON_REGION; il2cpp_field_set_value(serverSettingsInstance, regionField, &regionValue); }
            }
        }
    }
    if (!one_time_actions_done) {
        std::string files_dir_for_flag = get_files_dir(); std::string flag_path_curr = files_dir_for_flag + "/currency_added.flag";
        FILE* flag_file_curr = fopen(flag_path_curr.c_str(), "r");
        if (flag_file_curr) fclose(flag_file_curr);
        else {
            Il2CppClass* bankControllerClass = il2cpp_class_from_name((Il2CppImage*)mainImage, "", BANKCONTROLLER_CLASS_NAME);
            if (bankControllerClass) {
                bool item_added = false;
                MethodInfo* addCoinsMethod = il2cpp_class_get_method_from_name(bankControllerClass, ADD_COINS_METHOD_NAME, 3);
                MethodInfo* addGemsMethod = il2cpp_class_get_method_from_name(bankControllerClass, ADD_GEMS_METHOD_NAME, 3);
                MethodInfo* addTicketsMethod = il2cpp_class_get_method_from_name(bankControllerClass, ADD_TICKETS_METHOD_NAME, 3);
                Il2CppObject* ex = nullptr; int v_val; bool i_val=true; int a_val=ACCRUAL_TYPE_DEFAULT; void* args[]={&v_val,&i_val,&a_val};
                if (addCoinsMethod) { v_val=COINS_TO_ADD; ex=nullptr; il2cpp_runtime_invoke(addCoinsMethod, nullptr, args, &ex); if(!ex) item_added=true; }
                if (addGemsMethod) { v_val=GEMS_TO_ADD; ex=nullptr; il2cpp_runtime_invoke(addGemsMethod, nullptr, args, &ex); if(!ex) item_added=true; }
                if (addTicketsMethod) { v_val=TICKETS_TO_ADD; ex=nullptr; il2cpp_runtime_invoke(addTicketsMethod, nullptr, args, &ex); if(!ex) item_added=true; }
                if (item_added) { FILE* f = fopen(flag_path_curr.c_str(), "w"); if (f) fclose(f); }
            }
        }
    }
    Il2CppClass* storagerClass = il2cpp_class_from_name((Il2CppImage*)mainImage, "", STORAGER_CLASS_NAME);
    if (storagerClass) {
        MethodInfo* setIntMethod = il2cpp_class_get_method_from_name(storagerClass, STORAGER_SETINT_METHOD_NAME, 2);
        if (setIntMethod) {
            Il2CppObject* ex = nullptr; const char* levelKey = (g_appInfo.versionName == "11.4.0") ? "currentLevel31" : "currentLevel36";
            if (levelKey) { int levelValue = LEVEL_KEY_VALUE_TO_SET; Il2CppString* levelKeyStr = CreateIl2cppString(levelKey); if (levelKeyStr) { void* args[] = {levelKeyStr, &levelValue}; ex = nullptr; il2cpp_runtime_invoke(setIntMethod, nullptr, args, &ex); } }
            const char* expKey = "currentExperience"; int expValue = EXPERIENCE_TO_SET; Il2CppString* expKeyStr = CreateIl2cppString(expKey);
            if (expKeyStr) { void* args[] = {expKeyStr, &expValue}; ex = nullptr; il2cpp_runtime_invoke(setIntMethod, nullptr, args, &ex); }
        }
    }
    if (!one_time_actions_done && storagerClass) {
        Il2CppString* trainingKeyStr = nullptr;
        Il2CppClass* defsClass = il2cpp_class_from_name((Il2CppImage*)firstpassImage, "", DEFS_CLASS_NAME);
        if (defsClass) {
            MethodInfo* getKeyMethod = il2cpp_class_get_method_from_name(defsClass, TRAINING_KEY_GETTER_METHOD_NAME, 0);
            if (getKeyMethod) { Il2CppObject* keyRes=nullptr; Il2CppObject* getKeyEx=nullptr; keyRes=il2cpp_runtime_invoke(getKeyMethod, nullptr, nullptr, &getKeyEx); if(!getKeyEx && keyRes) trainingKeyStr=(Il2CppString*)keyRes; }
        }
        if (trainingKeyStr) {
            MethodInfo* getIntMethod = il2cpp_class_get_method_from_name(storagerClass, STORAGER_GETINT_METHOD_NAME, 1);
            if (getIntMethod) {
                void* getArgs[] = {trainingKeyStr}; Il2CppObject* getRes=nullptr; Il2CppObject* getEx=nullptr; getRes=il2cpp_runtime_invoke(getIntMethod, nullptr, getArgs, &getEx);
                if (!getEx && getRes && il2cpp_object_unbox) {
                    int currentVal = *(static_cast<int*>(il2cpp_object_unbox(getRes)));
                    if (currentVal == 0) {
                        MethodInfo* setIntMethod = il2cpp_class_get_method_from_name(storagerClass, STORAGER_SETINT_METHOD_NAME, 2);
                        if (setIntMethod) { int newVal=1; void* setArgs[]={trainingKeyStr, &newVal}; Il2CppObject* setEx=nullptr; il2cpp_runtime_invoke(setIntMethod, nullptr, setArgs, &setEx); }
                    }
                }
            }
        }
    }
    Il2CppClass* appClass = il2cpp_class_from_name((Il2CppImage*)unityImage, UNITYENGINE_NAMESPACE, APPLICATION_CLASS_NAME);
    if (appClass) {
        MethodInfo* setTargetFrameRateMethod = il2cpp_class_get_method_from_name(appClass, SET_TARGETFRAMERATE_METHOD_NAME, 1);
        if (setTargetFrameRateMethod) { int frameRate = TARGET_FRAMERATE; void* args[] = {&frameRate}; Il2CppObject* ex = nullptr; il2cpp_runtime_invoke(setTargetFrameRateMethod, nullptr, args, &ex); }
    }
    if (!one_time_actions_done) one_time_actions_done = true;
}

// --- Hook for LobbyItem.get_IsExists (Craft Hack) ---
bool (*Original_LobbyItem_get_IsExists)(void* instance) = nullptr;
bool CraftHack_Hook([[maybe_unused]] void* instance) { return true; }

// --- Memory Patching Function ---
void ApplyMemoryPatches() {
    if (!current_offsets || il2cpp_base == 0) return;
    const char* patchHex = nullptr;
#if defined(__arm__)
    patchHex = "1E FF 2F E1"; // BX LR
#elif defined(__i386__)
    patchHex = "C3"; // RET
#else
    return;
#endif
    if (!patchHex) return;
    auto applyMemPatch = [&](uintptr_t rva) {
        if (rva == 0) return; uintptr_t addr = il2cpp_base + rva; if (addr <= il2cpp_base) return;
        MemoryPatch patch = MemoryPatch::createWithHex(addr, patchHex); if (patch.isValid()) patch.Modify();
    };
    applyMemPatch(current_offsets->cheatDetectedBanner); applyMemPatch(current_offsets->clearProgress);
    applyMemPatch(current_offsets->showClearProgress); applyMemPatch(current_offsets->awakeCheat);
    applyMemPatch(current_offsets->updateCheat); applyMemPatch(current_offsets->get_cheaterConfig);
    applyMemPatch(current_offsets->set_cheaterConfig); applyMemPatch(current_offsets->get_CheckSignatureTampering);
    applyMemPatch(current_offsets->get_coinThreshold); applyMemPatch(current_offsets->get_gemThreshold);
    applyMemPatch(current_offsets->CleanUpAndDoAction_Start); applyMemPatch(current_offsets->CleanUpAndDoAction_OnGUI);
    applyMemPatch(current_offsets->ClosingScript_Start); applyMemPatch(current_offsets->AppsMenu_Start);
    applyMemPatch(current_offsets->AppsMenu_GetAbuseKey_53232de5);
    applyMemPatch(current_offsets->AppsMenu_GetAbuseKey_21493d18); applyMemPatch(current_offsets->AppsMenu_GetTerminalSceneName_4de1);
    applyMemPatch(current_offsets->AppsMenu_SafeGetSdkLevel); applyMemPatch(current_offsets->AppsMenu_HandleNotification);
}

// --- Hook Installation Function ---
void InstallHooks() {
    if (!current_offsets || il2cpp_base == 0) return;
    auto installHook = [&](uintptr_t rva, void* hook_func, void** orig_func_ptr) {
        if (rva == 0) { if (orig_func_ptr) *orig_func_ptr = nullptr; return; }
        uintptr_t addr = il2cpp_base + rva; if (addr <= il2cpp_base) { if (orig_func_ptr) *orig_func_ptr = nullptr; return; }
        int status = DobbyHook((void*)addr, hook_func, orig_func_ptr);
        if (status != RT_SUCCESS) { if (orig_func_ptr) *orig_func_ptr = nullptr; }
    };
    installHook(current_offsets->UIRoot_Awake, (void*)UIRoot_Awake_Hook, (void**)&Original_UIRoot_Awake);
    installHook(current_offsets->CraftHack, (void*)CraftHack_Hook, (void**)&Original_LobbyItem_get_IsExists);
}

// --- Core Initialization Function ---
bool PerformInitialization(JNIEnv* env) {
    g_appInfo = get_app_info(env);
    if (g_appInfo.versionName == "12.0.0") {
#if defined(__i386__)
        current_offsets = std::make_unique<Offsets_12_0_0_x86>();
#elif defined(__arm__)
        current_offsets = std::make_unique<Offsets_12_0_0_armv7>();
#else
        return false;
#endif
    } else if (g_appInfo.versionName == "11.4.0") {
#if defined(__i386__)
        current_offsets = std::make_unique<Offsets_11_4_0_x86>();
#elif defined(__arm__)
        current_offsets = std::make_unique<Offsets_11_4_0_armv7>();
#else
        return false;
#endif
    } else return false;
    if (!current_offsets) return false;
    if (il2cpp_base == 0) { il2cpp_base = findLibraryBaseAddress(IL2CPP_SO_NAME); if (il2cpp_base == 0) { current_offsets.reset(); return false; } }
    if (!il2cpp_domain_get) { if (!resolve_il2cpp_api()) { current_offsets.reset(); il2cpp_base = 0; return false; } }
    return true;
}

// --- Background Thread Function ---
void *hack_thread(void* vm_ptr) {
    JavaVM* vm = (JavaVM*)vm_ptr; JNIEnv* env = nullptr; bool attached = false;
    jint attachResult = vm->GetEnv((void**)&env, JNI_VERSION_1_6);
    if (attachResult == JNI_EDETACHED) { if (vm->AttachCurrentThread(&env, nullptr) == JNI_OK) attached = true; else return nullptr; }
    else if (attachResult != JNI_OK) return nullptr;
    const int max_wait_seconds = 120; bool library_found = false;
    for (int wait_seconds = 0; wait_seconds < max_wait_seconds; ++wait_seconds) {
        void* libHandle = dlopen(IL2CPP_SO_NAME, RTLD_NOLOAD | RTLD_LAZY);
        if (libHandle) { dlclose(libHandle); library_found = true; break; }
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
    if (!library_found) { if (attached) vm->DetachCurrentThread(); return nullptr; }
    bool init_success = PerformInitialization(env);
    if (init_success) {
        std::this_thread::sleep_for(std::chrono::milliseconds(800));
        ApplyMemoryPatches(); InstallHooks();
    } else current_offsets.reset();
    if (attached) vm->DetachCurrentThread();
    return nullptr;
}

// --- JNI_OnLoad ---
extern "C" JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, [[maybe_unused]] void* reserved) {
    g_JavaVM = vm; JNIEnv* env;
    if (vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6) != JNI_OK) return JNI_ERR;
    pthread_t ptid = 0;
    if (pthread_create(&ptid, nullptr, hack_thread, (void*)vm) == 0) pthread_detach(ptid);
    return JNI_VERSION_1_6;
}
#pragma clang diagnostic pop