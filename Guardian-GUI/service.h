#pragma once
#include <Windows.h>
#define IOCTL_WRITE_WORKITEM CTL_CODE(0x8000, 0x803, METHOD_IN_DIRECT, FILE_ANY_ACCESS)




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
