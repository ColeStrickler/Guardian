#pragma once
#include <ntddk.h>
#include "common.h"



struct procBasicInfo {
	procBasicInfo();
	~procBasicInfo();
	PROCESS_BASIC_INFORMATION* pBasic;
};