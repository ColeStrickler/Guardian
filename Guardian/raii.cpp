#include "raii.h"



procBasicInfo::procBasicInfo() {
	pBasic = (PROCESS_BASIC_INFORMATION*)ExAllocatePoolWithTag(NonPagedPool, sizeof(PROCESS_BASIC_INFORMATION), DRIVER_TAG);
}

procBasicInfo::~procBasicInfo() {
	ExFreePool(pBasic);
}