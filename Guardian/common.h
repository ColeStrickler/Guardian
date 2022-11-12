#pragma once
#include <ntddk.h>

#define DRIVER_TAG 'grdn'
#define IOCTL_ADDFILE_BLACKLIST CTL_CODE(0x8000, 0x800, METHOD_NEITHER, FILE_ANY_ACCESS)
#define IOCTL_READ_WORKITEMS CTL_CODE(0x8000, 0x801, METHOD_NEITHER, FILE_ANY_ACCESS)
#define IOCTL_WRITE_ALERT CTL_CODE(0x8000, 0x802, METHOD_NEITHER, FILE_ANY_ACCESS)

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
	BlockedExecutionPath
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




