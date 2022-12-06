#pragma once
#include <ntifs.h>

// moved CTL_CODEs to driver.h
#define DWORD ULONG
#define BOOL bool
#define LPDWORD PULONG
#define LPVOID void*
#define LPSECURITY_ATTRIBUTES void*
#define LPOVERLAPPED void*

template<typename T>
struct WorkItem {
	LIST_ENTRY Entry;
	T Data;
};



enum class TaskType : short {
	ScanProcess,
	ScanFile,
	SystemScan,
	StartApiMonitor
};


enum class SystemScanType : short {
	FullScan,
	NonMicrosoft
};


struct TaskHeader {
	TaskType Type;
	ULONG Size;
};


// WE WILL USE THESE STRUCTS TO READ IN JOBS FROM THE DRIVER
struct ScanProcessHeaderJob : TaskHeader {
	ULONG ProcessId;
};

struct ScanFileHeaderJob : TaskHeader {
	ULONG FilePathLength;
	ULONG FilePathOffset;
};

struct SystemScanHeaderJob : TaskHeader {
	SystemScanType ScanType;
};

struct ApiMonitorJob : TaskHeader {
	ULONG Command;
	ULONG PID;
};


enum class ApiEvent : short {
	OpenProcess,
	CreateFileW,
	ReadFile,
	WriteFile
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

