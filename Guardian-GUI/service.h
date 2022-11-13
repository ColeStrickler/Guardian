#pragma once
#include <Windows.h>
#define IOCTL_WRITE_WORKITEM CTL_CODE(0x8000, 0x803, METHOD_IN_DIRECT, FILE_ANY_ACCESS)



template<typename T>
struct WorkItem {
	LIST_ENTRY Entry;
	T Data;
};



enum class TaskType : short {
	ScanProcess,
	ScanFile,
	SystemScan,
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
