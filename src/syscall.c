#include "syscall.h"

DWORD djb2_hash(const char* str) {
    DWORD hash = 5381;
    int c;
    while ((c = *str++)) {
        hash = ((hash << 5) + hash) + c;
    }
    return hash;
}

PVOID get_module_base_by_hash(DWORD module_hash) {

    PPEB peb;                               // pointer to PEB
    PPEB_LDR_DATA pldr;                     // pointer to PEB_LDR_DATA
    PLIST_ENTRY mod_list;                   // pointer to module list
    PLDR_DATA_TABLE_ENTRY_CUSTOM pentry;    // pointer to module entry
    PLIST_ENTRY pnextentry;                 // pointer to next entry
    DWORD mod_hash;                         // hash of module name

    //peb = (PPEB)__readgsqword(0x60); // PEB access on x64
    peb = NtCurrentTeb()->ProcessEnvironmentBlock;
    pldr = peb->Ldr;
    mod_list = &pldr->InMemoryOrderModuleList;
    pnextentry = mod_list->Flink;

    while (pnextentry != mod_list) {
        pentry = (PLDR_DATA_TABLE_ENTRY_CUSTOM)((PBYTE)pnextentry - sizeof(LIST_ENTRY));
        if (pentry->BaseDllName.Buffer != NULL) {
            mod_hash = djb2_hash((char*)pentry->BaseDllName.Buffer);

            if (mod_hash == module_hash) {
                return pentry->DllBase;
            }
        }
        pnextentry = pnextentry->Flink;
    }
    return NULL;
}

FARPROC get_api_by_hash(HMODULE hModule, DWORD api_hash) {

    PBYTE pbyte = (PBYTE)hModule;       // pointer to byte (for arithmetic)
    PIMAGE_DOS_HEADER pdos;             // pointer to DOS header
    PIMAGE_NT_HEADERS pnth;             // pointer to NT header
    IMAGE_DATA_DIRECTORY dir;           // export directory data
    PIMAGE_EXPORT_DIRECTORY expdir;     // pointer to export directory
    PDWORD aonames;                     // array of function names
    PWORD aoordinals;                   // array of function ordinals
    PDWORD aofunctions;                 // array of function addresses


    pdos = (PIMAGE_DOS_HEADER)pbyte;
    if (pdos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;

    pnth = (PIMAGE_NT_HEADERS)(pbyte + pdos->e_lfanew);
    if (pnth->Signature != IMAGE_NT_SIGNATURE) return NULL;

    // get EAT address
    dir = pnth->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (dir.Size == 0) return NULL;

    expdir = (PIMAGE_EXPORT_DIRECTORY)(pbyte + dir.VirtualAddress);

    aonames = (PDWORD)(pbyte + expdir->AddressOfNames);
    aoordinals = (PWORD)(pbyte + expdir->AddressOfNameOrdinals);
    aofunctions = (PDWORD)(pbyte + expdir->AddressOfFunctions);

    for (DWORD i = 0; i < expdir->NumberOfNames; i++) {
        char* func_name = (char*)(pbyte + aonames[i]);        
        DWORD func_hash = djb2_hash(func_name);

        if (func_hash == api_hash) {
            WORD ordinal = aoordinals[i];
            FARPROC func_addr = (FARPROC)(pbyte + aofunctions[ordinal]);
            return func_addr;
        }
    }

    return NULL;
}

DWORD GetSsn(DWORD api_hash, PVOID* addr) {

    PVOID ntdll_addr;
    PVOID func_addr;
    PVOID ssn_addr;
    DWORD ssn;

    ntdll_addr = get_module_base_by_hash(NTDLL_HASH);
    func_addr = get_api_by_hash(ntdll_addr, api_hash);
    ssn = *(DWORD*)((BYTE*)func_addr + SYSCALL_SSN_DIST);

    if (func_addr != NULL) {
        *addr = (PVOID)((DWORD_PTR)func_addr + SYSCALL_INST_DIST);
    }

    return ssn;

}