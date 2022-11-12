#include "RAII.h"



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



