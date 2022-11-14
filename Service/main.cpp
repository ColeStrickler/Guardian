#include <Windows.h>
#include <tchar.h>
#include <string>
#include <cstdio>
#include "Service.h"

int main() {
    printf("[START]\n\n");

    Service ServiceStart;
    if (ServiceStart.hFile == INVALID_HANDLE_VALUE) {
        printf("Could not obtain handle when starting service");
        return GetLastError();
    }


    while (true)
    {






        Sleep(10000);
    }

    // OutputDebugString(_T("My Sample Service: ServiceWorkerThread: Exit"));

    return ERROR_SUCCESS;
}
