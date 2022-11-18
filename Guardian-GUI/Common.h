#pragma once
#include <Windows.h>

#define DRIVER_TAG 'grdn'
#define IOCTL_ADDFILE_BLACKLIST CTL_CODE(0x8000, 0x800, METHOD_NEITHER, FILE_ANY_ACCESS)



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


typedef struct REGIONINFO
{
	LPVOID pBase;
	LPVOID pAllocation;
	DWORD dwRegion;
	DWORD dwProtect;
	DWORD dwState;
	DWORD dwType;
} RegionInfo, * PRegionInfo;

struct YaraScanProcessAlert : Header {
	ULONG processId;
	ULONG MatchedRulesOffset;
	ULONG MatchedRuleCount;
};