#pragma once
#include <ntifs.h>
#include "primitives.h"
#include "common.h"
#include "service.h"




#define DRIVER_PREFIX "GUARDIAN: "
#define PROCESS_TERMINATE 1


#define TIME_ABSOLUTE(wait) (wait)
#define TIME_RELATIVE(wait) (-(wait))
#define TIME_NANOSECONDS(nanos) (((signed __int64)(nanos)) / 100L)
#define TIME_MICROSECONDS(micros) (((signed __int64)(micros)) * TIME_NANOSECONDS(1000L))
#define TIME_MILLISECONDS(milli) (((signed __int64)(milli)) * TIME_MICROSECONDS(1000L))
#define TIME_SECONDS(seconds) (((signed __int64)(seconds)) * TIME_MILLISECONDS(1000L))


typedef NTSTATUS(*QUERY_INFO_PROCESS)(
	__in HANDLE                                      ProcessHandle,
	__in PROCESSINFOCLASS                            ProcessInformationClass,
	__out_bcount_opt(ProcessInformationLength) PVOID ProcessInformation,
	__in UINT32                                      ProcessInformationLength,
	__out_opt PUINT32                                ReturnLength
	);








// WE WILL USE THIS STRUCT FOR LOCKED REGISTRY KEYS AS WELL
struct BlockedPathNode {
	LIST_ENTRY Entry;
	UNICODE_STRING Path;
};