#pragma once
#include <Windows.h>
#include <vector>
#include <string>
#include "RAII.h"
#include "YaraAgent.h"
#include <unordered_set>
#include <iostream>
// TEMP
#include <iostream>

#define SERVICE_DLL_64 "C:\\Program Files\\Guardian\\utils\\service64.dll"
#define SERVICE_DLL_32 "C:\\Program Files\\Guardian\\utils\\service32.dll"


#define IOCTL_READ_WORKITEMS CTL_CODE(0x8000, 0x801, METHOD_OUT_DIRECT, FILE_ANY_ACCESS)
#define IOCTL_WRITE_ALERT CTL_CODE(0x8000, 0x802, METHOD_IN_DIRECT, FILE_ANY_ACCESS)


enum class ItemType : short {
	None,
	ProcessCreate,
	ProcessExit,
	ThreadCreate,
	ThreadExit,
	RemoteThreadCreate,
	ImageLoad,
	BlockedExecutionPath,
	YaraScanFile,
	YaraScanProcess,
	YaraScanSystem
};


struct Header {
	ItemType Type;
	USHORT Size;
	LARGE_INTEGER Time;
};

struct RemoteThreadAlert : Header {
	ULONG ThreadId;
	ULONG ProcessId;
	ULONG CreatorProcess;
};

struct BlockedPathAlert : Header {
	ULONG ImageNameLength;
	ULONG ImageNameOffset;
};


struct YaraScanFileAlert : Header {
	ULONG FilePathOffset;
	ULONG FilePathLength;
	ULONG MatchedRulesOffset;
	ULONG MatchedRuleCount;
};


struct YaraScanProcessAlert : Header {
	ULONG processId;
	ULONG MatchedRulesOffset;
	ULONG MatchedRuleCount;
};





template<typename T>
struct WorkItem {
	SLIST_ENTRY Entry;
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




// WE WILL FILL OUT THESE STRUCTS WITH INFORMATION AS THE JOBS ARE COMPLETED
struct ScanProcessHeaderFull : ScanProcessHeaderJob {
	std::vector<std::string> YaraDetections;			// Store Name of yara rules here
};

struct ScanFileHeaderFull : ScanFileHeaderJob {
	std::vector<std::string> YaraDetections;
};

struct SystemScanHeaderFull : SystemScanHeaderJob {
	std::vector<std::string> Detections;				// STORE FILE PATHS OF DETECTIONS HERE
};


namespace Injector {

	class DllThreadInjector {
	public:
		DllThreadInjector();
		~DllThreadInjector();
		bool InjectDll(DWORD procId, const char* DllPath);
	};


}



class Service
{
// PUBLIC FUNCTIONS
public:
	Service();
	~Service();



// PUBLIC VARIABLES
public:
	static inline std::string YaraConfFilePath;
	static inline Yara::Scanner* Scanner;
	static inline HANDLE hFile;							// THIS IS THE HANDLE TO THE DRIVER'S SYMBOLIC LINK
	static inline HANDLE hWorkerThread;					// THIS IS WHERE WE PERFORM SCANNING
	static inline HANDLE hApiMonitorThread;				// THIS IS WHERE WE DETECT MALICIOUS API SEQUENCES
	static inline HANDLE hNotificationThread;			// THIS IS WHERE WE WRITE DETECTIONS BACK TO DRIVER
	static inline HANDLE hDriverReadThread;				// THIS IS WHERE WE WILL CONTINUALLY GET WORK ITEMS
	static inline SLIST_HEADER workItemsHead;
	static inline int workItemsCount;


// PRIVATE FUNCTIONS
private:
	static void StartWorkerThread();
	static void StartApiMonitorThread();
	static void StartNotificationThread();
	static void StartDriverReadThread();


// PRIVATE VARIABLES
private:
	static Injector::DllThreadInjector Injector;

};

