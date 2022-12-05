#include "Manager.h"
#include <string>


BYTE* CopyToInputBuf(void* Parameter, SIZE_T ParameterSize, BYTE* buf) {
    memcpy(buf, Parameter, ParameterSize);
    buf += ParameterSize;
    memset(buf, 0x3b, 3);
    buf += 3;
    return buf;
}

struct CreateFileWParameters {
    DWORD FileNameSize;
    DWORD dwDesiredAccess;
    DWORD dwShareMode;
    LPSECURITY_ATTRIBUTES lpSecurityAttributes;
    DWORD dwCreationDisposition;
    DWORD dwFlagsAndAttributes;
    HANDLE hTemplateFile;
};


HANDLE(__stdcall* TrampolineCreateFileW)(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);

HANDLE __stdcall HookedCreateFileW(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile) 
{
    ApiMon* IrpStruct;
    std::wstring File(lpFileName);

    DWORD allocSize = sizeof(ApiMon);
    allocSize = sizeof(CreateFileWParameters);
    allocSize += File.size() * 2;
   
    BYTE* buf = RAII::NewBuffer(allocSize).Get();
    if (!buf) {
        return TrampolineCreateFileW(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
    }


    IrpStruct = (ApiMon*)buf;
    IrpStruct->EventType = ApiEvent::CreateFileW;
    IrpStruct->pid = GetCurrentProcessId();
    buf += sizeof(ApiMon);


    CreateFileWParameters* Params = (CreateFileWParameters*)buf;
    Params->FileNameSize = File.size() * 2;
    Params->dwDesiredAccess = dwDesiredAccess;
    Params->dwShareMode = dwShareMode;
    Params->lpSecurityAttributes = lpSecurityAttributes;
    Params->dwCreationDisposition = dwCreationDisposition;
    Params->dwFlagsAndAttributes = dwFlagsAndAttributes;
    Params->hTemplateFile = hTemplateFile;

    DWORD retBytes;
    bool check = DeviceIoControl(
        g_GlobalDriverHandle,
        IOCTL_API_EVENT,
        0,
        0,
        buf,
        allocSize,
        &retBytes,
        0
    );
    
    return TrampolineCreateFileW(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
}


struct OpenProcessParams {
    DWORD dwDesiredAccess;
    BOOL bInheritHandle;
    DWORD dwProcessId;
};

HANDLE(__stdcall* TrampolineOpenProcess)(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId);

HANDLE __stdcall HookedOpenProcess(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId) 
{
    ApiMon* IrpStruct;

    DWORD allocSize = sizeof(ApiMon);
    allocSize += sizeof(OpenProcessParams);

    BYTE* buf = RAII::NewBuffer(allocSize).Get();
    if (!buf) {
        return TrampolineOpenProcess(dwDesiredAccess, bInheritHandle, dwProcessId);
    }
    
    IrpStruct = (ApiMon*)buf;
    IrpStruct->EventType = ApiEvent::OpenProcess;
    IrpStruct->pid = GetCurrentProcessId();
    buf += sizeof(ApiMon);

    OpenProcessParams* Params = (OpenProcessParams*)buf;
    Params->dwDesiredAccess = dwDesiredAccess;
    Params->bInheritHandle = bInheritHandle;
    Params->dwProcessId = dwProcessId;

    DWORD retBytes;
    bool check = DeviceIoControl(
        g_GlobalDriverHandle,
        IOCTL_API_EVENT,
        0,
        0,
        buf,
        allocSize,
        &retBytes,
        0
    );

    return TrampolineOpenProcess(dwDesiredAccess, bInheritHandle, dwProcessId);
}


struct ReadFileParams {
    HANDLE hFile;
    LPVOID lpBuffer;
    DWORD nNumberOfBytesToRead;
    LPDWORD lpNumberOfBytesRead;
    LPOVERLAPPED lpOverlapped;
};

BOOL(__stdcall* TrampolineReadFile)(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped);

BOOL __stdcall HookedReadFile(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped) 
{
    ApiMon* IrpStruct;

    DWORD allocSize = sizeof(ApiMon);
    allocSize += sizeof(ReadFileParams);

    BYTE* buf = RAII::NewBuffer(allocSize).Get();
    if (!buf) {
        return TrampolineReadFile(hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped);
    }

    IrpStruct = (ApiMon*)buf;
    IrpStruct->EventType = ApiEvent::ReadFile;
    IrpStruct->pid = GetCurrentProcessId();
    buf += sizeof(IrpStruct);

    ReadFileParams* Params = (ReadFileParams*)buf;
    Params->hFile = hFile;
    Params->lpBuffer = lpBuffer;
    Params->nNumberOfBytesToRead = nNumberOfBytesToRead;
    Params->lpNumberOfBytesRead = lpNumberOfBytesRead;
    Params->lpOverlapped = lpOverlapped;

    DWORD retBytes;
    bool check = DeviceIoControl(
        g_GlobalDriverHandle,
        IOCTL_API_EVENT,
        0,
        0,
        buf,
        allocSize,
        &retBytes,
        0
    );

    return TrampolineReadFile(hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped);
}

struct WriteFileParams {
    HANDLE hFile;
    DWORD nNumberOfBytesToWrite;
    LPDWORD lpNumberOfBytesWritten;
    LPOVERLAPPED lpOverlapped;
};

BOOL(__stdcall* TrampolineWriteFile)(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped);

BOOL __stdcall HookedWriteFile(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped)
{
    ApiMon* IrpStruct;

    DWORD allocSize = sizeof(ApiMon);
    allocSize += sizeof(WriteFileParams);
    DWORD numCopyBytes = nNumberOfBytesToWrite < 512 ? nNumberOfBytesToWrite : 512;
    allocSize += numCopyBytes;

    BYTE* buf = RAII::NewBuffer(allocSize).Get();
    if (!buf) {
        return TrampolineWriteFile(hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped);
    }

    IrpStruct = (ApiMon*)buf;
    IrpStruct->EventType = ApiEvent::WriteFile;
    IrpStruct->pid = GetCurrentProcessId();
    buf += sizeof(ApiMon);

    WriteFileParams* Params = (WriteFileParams*)buf;
    Params->hFile = hFile;
    Params->nNumberOfBytesToWrite = nNumberOfBytesToWrite;
    Params->lpNumberOfBytesWritten = lpNumberOfBytesWritten;
    Params->lpOverlapped = lpOverlapped;
    buf += sizeof(WriteFileParams);

    memcpy(buf, lpBuffer, numCopyBytes);

    DWORD retBytes;
    bool check = DeviceIoControl(
        g_GlobalDriverHandle,
        IOCTL_API_EVENT,
        0,
        0,
        buf,
        allocSize,
        &retBytes,
        0
    );
   
    return TrampolineWriteFile(hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped);
}

std::vector<HookFuncs> InitHooks = {
    {(void*)&TrampolineCreateFileW, (void*)HookedCreateFileW, "Kernel32.dll", "CreateFileW"},
    {(void*)&TrampolineOpenProcess, (void*)HookedOpenProcess, "Kernel32.dll", "OpenProcess"},
    {(void*)&TrampolineReadFile, (void*)HookedReadFile, "Kernel32.dll", "ReadFile"},
    {(void*)&TrampolineWriteFile, (void*)HookedWriteFile, "Kernel32.dll", "WriteFile"}
};


SLIST_HEADER g_ApiEvents;
HANDLE g_GlobalDriverHandle;


int MainThread(HMODULE hModule) {

#ifdef _WIN64
    Manager<Hook::x64> Manager(InitHooks, g_ApiEvents, g_GlobalDriverHandle);
#else
    Manager<Hook::x86> Manager(InitHooks, g_ApiEvents, g_GlobalDriverHandle);
#endif
    
    if (!Manager.StartupSuccess) {
        FreeLibraryAndExitThread(hModule, 0);
    }

    while (true) {
        if (Manager.ExitVar) {
            FreeLibraryAndExitThread(hModule, 0);
        }




    }




    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
)
{

    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    {


        CloseHandle(CreateThread(0, 0, (LPTHREAD_START_ROUTINE)MainThread, hModule, 0, 0));
    }
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}