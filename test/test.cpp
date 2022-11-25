#include <filesystem>
#include <iostream>
#include <string>
#include <chrono>
#include "test.h"
#include <sddl.h>

RAII::Handle::Handle(HANDLE hHandle)
{
    _hHandle = hHandle;
}

void RAII::Handle::Update(HANDLE hHandle)
{
    _hHandle = hHandle;
}
HANDLE RAII::Handle::Get()
{
    return _hHandle;
}

BOOL RAII::Handle::Empty()
{
    if (_hHandle == NULL)
    {
        return TRUE;
    }
    else
    {
        return FALSE;
    }
}

BOOL RAII::Handle::Close()
{
    if (CloseHandle(_hHandle))
    {
        return TRUE;
    }
    else
    {
        return FALSE;
    }
}
RAII::Handle::~Handle()
{
    if (_hHandle) CloseHandle(_hHandle);
}



RAII::HeapBuffer::HeapBuffer(size_t size) {
    buf = (BYTE*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size);
}

BYTE* RAII::HeapBuffer::Get() {
    return buf;
}
RAII::HeapBuffer::~HeapBuffer() {
    if (buf != nullptr) {
        HeapFree(GetProcessHeap(), NULL, buf);
    }
}

std::string ConcatString(std::string String1, std::string String2) {
    int size = 1;
    int String1Size = String1.size();
    int String2Size = String2.size();
    size += String1Size + String2Size;
    BYTE* buf = new BYTE[size];
    memset(buf, 0, size);
    for (int i = 0; i < String2Size; i++) {
        buf[i] = String1.data()[i];
    }
    for (int i = 0; i < String2Size; i++) {
        buf[String1Size + i] = String2.data()[i];
    }
    std::string ret = std::string((char*)buf);
    free(buf);
    return ret;
}


std::string GetCurrentSid() {
    HANDLE hProc;
    HANDLE hToken;
    PTOKEN_USER TokenUserInfo;
    std::string ret;
    LPSTR strPtr = nullptr;
    DWORD retBytes;

    hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, GetCurrentProcessId());
    if (!hProc) {
        ret = "0";
        return ret;
    }


    if (!OpenProcessToken(hProc, TOKEN_READ, &hToken)) {
        ret = "0";
        return ret;
    }
    if (!GetTokenInformation(hToken, TokenUser, NULL, 0, &retBytes) && ERROR_INSUFFICIENT_BUFFER != GetLastError()) {
        ret = "0";
        return ret;
    }

    BYTE* buf = new BYTE[retBytes];
    if (buf == nullptr) {
        ret = "0";
        return ret;
    }


    TokenUserInfo = (PTOKEN_USER)buf;
    if (!GetTokenInformation(hToken, TokenUser, TokenUserInfo, retBytes, &retBytes)) {
        ret = "0";
        return ret;
    }



    bool success = ConvertSidToStringSidA(TokenUserInfo->User.Sid, &strPtr);
    if (success) {
        ret = std::string(strPtr);
        return ret;

    }
    else {
        ret = "0";
        return ret;
    }

}




int main() {
    std::string UserRegistryKey = "HKEY_CLASSES_ROOT\\.3gp";
    const char* prepath = "\\REGISTRY\\MACHINE\\SOFTWARE\\Classes\\";
    std::string s1 = std::string(prepath);
    std::string s2 = std::string((char*)((BYTE*)UserRegistryKey.data() + 18));
    std::string ret = s1 + s2;
    std::cout << s1 << std::endl;
    std::cout << s2 << std::endl;
    std::cout << ret << std::endl;
}


