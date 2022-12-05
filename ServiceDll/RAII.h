#pragma once
#include <Windows.h>

namespace RAII
{
    class Handle
    {
    public:
        Handle(HANDLE hHandle);
        ~Handle();
        void Update(HANDLE hHandle);
        HANDLE Get();
        BOOL Empty();
        BOOL Close();
    private:
        HANDLE _hHandle;
    };


    class HeapBuffer
    {
    public:
        HeapBuffer(size_t size);
        BYTE* Get();
        ~HeapBuffer();
    private:
        BYTE* buf;
    };


    class NewBuffer
    {
    public:
        NewBuffer(size_t size);
        NewBuffer(BYTE* buffer);
        BYTE* Get();
        ~NewBuffer();
    private:
        BYTE* buf;
    };

}
