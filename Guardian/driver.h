#pragma once
#include <ntifs.h>
#include "primitives.h"
#include "common.h"
#include "service.h"




#define DRIVER_PREFIX "GUARDIAN: "


typedef NTSTATUS(*QUERY_INFO_PROCESS) (
	__in HANDLE ProcessHandle,
	__in PROCESSINFOCLASS ProcessInformationClass,
	__out_bcount(ProcessInformationLength) PVOID ProcessInformation,
	__in ULONG ProcessInformationLength,
	__out_opt PULONG ReturnLength
	);

QUERY_INFO_PROCESS ZwQueryInformationProcess;


struct ConfigFiles {
	wchar_t* BlockedPathConfigFile = BLOCKED_PATH_CONFIG;
};


struct BlockedPathNode {
	LIST_ENTRY Entry;
	UNICODE_STRING Path;
};