#ifndef _SYSCALL_H_
#define _SYSCALL_H_

#include <winternl.h>
#include <windows.h>
#include "native.h"

#define SYSCALL_SSN_DIST  0x4
#define SYSCALL_INST_DIST 0x12

typedef struct _LDR_DATA_TABLE_ENTRY_CUSTOM {               // define custom structure for loaded module
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} LDR_DATA_TABLE_ENTRY_CUSTOM, *PLDR_DATA_TABLE_ENTRY_CUSTOM;

DWORD GetSsn(DWORD api_hash, PVOID* addr);                  // export GetSSn function prototype
extern NTSTATUS Syscall(int api_hash, int n_args, ...);     // import Syscall function prototype

#endif