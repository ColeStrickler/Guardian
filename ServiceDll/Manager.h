#pragma once
#include "Hook.h"
#include "RAII.h"

#define IOCTL_READ_COMAPI CTL_CODE(0x8000, 0x806, METHOD_NEITHER, FILE_ANY_ACCESS)
#define IOCTL_API_EVENT CTL_CODE(0x8000, 0x807, METHOD_IN_DIRECT, FILE_ANY_ACCESS)



#define COMMAND_EJECT ULONG(1)

enum class ApiEvent : short {
	OpenProcess,
	CreateFileW,
	ReadFile,
	WriteFile
};



template<typename T>
struct WorkItem {
	SLIST_ENTRY Entry;
	T Data;
};


struct ApiMon {
	ApiEvent EventType;
	ULONG pid;
	ULONG size;
};



struct CreateFileWParameters {
	DWORD FileNameSize;
	DWORD dwDesiredAccess;
	DWORD dwShareMode;
	LPSECURITY_ATTRIBUTES lpSecurityAttributes;
	DWORD dwCreationDisposition;
	DWORD dwFlagsAndAttributes;
	HANDLE hTemplateFile;
};

struct OpenProcessParams {
	DWORD dwDesiredAccess;
	BOOL bInheritHandle;
	DWORD dwProcessId;
};


struct ReadFileParams {
	HANDLE hFile;
	LPVOID lpBuffer;
	DWORD nNumberOfBytesToRead;
	LPDWORD lpNumberOfBytesRead;
	LPOVERLAPPED lpOverlapped;
};


struct WriteFileParams { 
	HANDLE hFile;
	DWORD nNumberOfBytesToWrite;
	LPDWORD lpNumberOfBytesWritten;
	LPOVERLAPPED lpOverlapped;
	DWORD numCopyBytes;
};




 
class Manager
{
public:
	Manager(std::vector<HookFuncs>& InitStuct, SLIST_HEADER& GlobalLinkedList, HANDLE& GlobalDriverHandle);
	~Manager();

private:
	static void GetDriverCommands();


public:
	bool StartupSuccess;
	static bool ExitVar;
	SLIST_HEADER ApiEventSLL;
	Hook::x64 HookEngine64;
	Hook::x86 HookEngine86;
	HANDLE hCommandThread;
	static HANDLE hDriverFile;
	BOOL wow64;

};

