#pragma once
#include <ntddk.h>

#define DRIVER_TAG 'grdn'
#define IOCTL_ADDFILE_BLACKLIST CTL_CODE(0x8000, 0x800, METHOD_NEITHER, FILE_ANY_ACCESS)
#define IOCTL_READ_WORKITEMS CTL_CODE(0x8000, 0x801, METHOD_OUT_DIRECT, FILE_ANY_ACCESS)
#define IOCTL_WRITE_ALERT CTL_CODE(0x8000, 0x802, METHOD_IN_DIRECT, FILE_ANY_ACCESS)			// This is where the service writes back detections
#define IOCTL_WRITE_WORKITEM CTL_CODE(0x8000, 0x803, METHOD_IN_DIRECT, FILE_ANY_ACCESS)			// This is where GUI manager writes in new work items

// DEFINE CONFIG FILES HERE
#define BLOCKED_PATH_CONFIG L"\\??\\C:\\Program Files\\Guardian\\conf\\paths.conf"



struct Config {
	LIST_ENTRY hashRuleHead;
	int hashRuleCount;
	LIST_ENTRY filePathExclusionHead;
	int filePathExclusionCount;
	LIST_ENTRY yaraRuleHead;
	int yaraRuleCount;
	LIST_ENTRY alerts;
	int alertCount;
	bool notifyRemoteThreadCreation;
};

struct Global {
	Config currentconfig;
//	FastMutex Mutex;
};
template<typename T>
struct Alert {
	LIST_ENTRY Entry;
	T Data;
};


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

// make blocked path alert
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


typedef struct REGIONINFO
{
	ULONG64 pBase;
	ULONG64 pAllocation;
	DWORD32 dwRegion;
	DWORD32 dwProtect;
	DWORD32 dwState;
	DWORD32 dwType;
} RegionInfo, * PRegionInfo;

struct YaraScanProcessAlert : Header {
	ULONG processId;
	ULONG MatchedRulesOffset;
	ULONG MatchedRuleCount;
};




