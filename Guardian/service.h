#pragma once
#include <ntifs.h>

// moved CTL_CODEs to driver.h


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
	size_t FilePathLength;
	ULONG FilePathOffset;
};

struct SystemScanHeaderJob : TaskHeader {
	SystemScanType ScanType;
};
