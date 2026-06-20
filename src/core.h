#ifndef CORE_H
#define CORE_H

#include <windows.h>

char* download_payload(SIZE_T* payload_size);
BOOL execute_payload(char* payload, SIZE_T payload_size);

#endif