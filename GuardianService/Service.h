#pragma once
#include <Windows.h>
#include <vector>
#include <string>
#include "RAII.h"
#include "YaraAgent.h"

// TEMP
#include <iostream>


#ifdef DEBUG
# define DEBUG_PRINT(x) printf(x)
#else
# define DEBUG_PRINT(x) do {} while (0)
#endif


#define IOCTL_READ_WORKITEMS CTL_CODE(0x8000, 0x801, METHOD_OUT_DIRECT, FILE_ANY_ACCESS)
#define IOCTL_WRITE_ALERT CTL_CODE(0x8000, 0x802, METHOD_IN_DIRECT, FILE_ANY_ACCESS)


template<typename T>
struct WorkItem {
	SLIST_ENTRY Entry;
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



// WE WILL FILL OUT THESE STRUCTS WITH INFORMATION AS THE JOBS ARE COMPLETED
struct ScanProcessHeaderFull : ScanProcessHeaderJob {
	std::vector<std::string> YaraDetections;			// Store Name of yara rules here
};

struct ScanFileHeaderFull : ScanFileHeaderJob {
	std::wstring FilePathServiceUse;
	std::vector<std::string> YaraDetections;
};

struct SystemScanHeaderFull : SystemScanHeaderJob {
	std::vector<std::string> Detections;				// STORE FILE PATHS OF DETECTIONS HERE
};






class Service
{
// PUBLIC FUNCTIONS
public:
	Service();
	~Service();



// PUBLIC VARIABLES
public:
	static std::string YaraConfFilePath;
	static Yara::Scanner* Scanner;


// PRIVATE FUNCTIONS
private:
	static void StartWorkerThread();
	static void StartApiMonitorThread();
	static void StartNotificationThread();
	static void StartDriverReadThread();


// PRIVATE VARIABLES
private:
	static HANDLE hFile;							// THIS IS THE HANDLE TO THE DRIVER'S SYMBOLIC LINK
	static HANDLE hWorkerThread;					// THIS IS WHERE WE PERFORM SCANNING
	static HANDLE hApiMonitorThread;				// THIS IS WHERE WE DETECT MALICIOUS API SEQUENCES
	static HANDLE hNotificationThread;				// THIS IS WHERE WE WRITE DETECTIONS BACK TO DRIVER
	static HANDLE hDriverReadThread;				// THIS IS WHERE WE WILL CONTINUALLY GET WORK ITEMS
	static PSLIST_HEADER workItemsHead;
	static int workItemsCount;
};

