#include "Service.h"



Service::Service() {
	InitializeSListHead(workItemsHead);



}

Service::~Service() {

}

void Service::StartWorkerThread() {

	while (true) {
		if (workItemsCount == 0) {
			Sleep(50);
			continue;
		}

		PSLIST_ENTRY currEntry = InterlockedPopEntrySList(workItemsHead);
		TaskType EntryType = *(TaskType*)((uintptr_t)currEntry + sizeof(SLIST_ENTRY));


		switch (EntryType) {

			case TaskType::ScanFile:
			{
				
		
			}
			case TaskType::ScanProcess:
			{


			}
			case TaskType::SystemScan:
			{


			}

		}
		





	}

}


void Service::StartApiMonitorThread() {

}


void Service::StartNotificationThread() {

}


void Service::StartDriverReadThread() {
	while (true) {
		BYTE* buffer = (BYTE*)RAII::HeapBuffer(1 << 16).Get();
		if (buffer == nullptr) {
			continue;
		}
		DWORD retBytes;
		BOOL success = DeviceIoControl(
			hFile,
			IOCTL_READ_WORKITEMS,
			nullptr,
			0,
			&buffer,
			sizeof(buffer),
			&retBytes,
			nullptr         // lpOverlapped
		);
		if (!success) {
			DEBUG_PRINT("DeviceIO failed in DriverReadThread");
			continue;
		}

		while (retBytes > 0) {
			auto header = (TaskHeader*)buffer;

			switch (header->Type) {					// FROM HERE WE, WE REALLOCATE THESE OBJECTS AND PLACE THEM IN THE WORKER THREAD
				case TaskType::ScanFile:
				{
					auto ScanFileTask = (ScanFileHeaderJob*)buffer;
					auto NewScanFileTask = new WorkItem<ScanFileHeaderFull>();


					NewScanFileTask->Data.FilePathServiceUse = std::wstring(ScanFileTask->FilePath, ScanFileTask->FilePathLength);
					NewScanFileTask->Data.FilePath = (wchar_t*)NewScanFileTask->Data.FilePathServiceUse.c_str();
					NewScanFileTask->Data.FilePathLength = NewScanFileTask->Data.FilePathServiceUse.size();
					NewScanFileTask->Data.Size = 0;			// We will ignore this field in User mode
					NewScanFileTask->Data.Type = TaskType::ScanFile;


					InterlockedPushEntrySList(workItemsHead, &NewScanFileTask->Entry);
					workItemsCount++;
					break;
				}
				case TaskType::ScanProcess:
				{
					auto ScanProcessTask = (ScanProcessHeaderJob*)buffer;
					auto NewScanProcessTask = new WorkItem<ScanProcessHeaderFull>();
					

					NewScanProcessTask->Data.ProcessId = ScanProcessTask->ProcessId;
					NewScanProcessTask->Data.Size = 0;		// We will ignore this field in User mode
					NewScanProcessTask->Data.Type = TaskType::ScanProcess;


					InterlockedPushEntrySList(workItemsHead, &NewScanProcessTask->Entry);
					workItemsCount++;
					break;
				}
				case TaskType::SystemScan:
				{
					auto SystemScanTask = (SystemScanHeaderJob*)buffer;
					auto NewSystemScanTask = new WorkItem<SystemScanHeaderFull>();


					NewSystemScanTask->Data.Type = TaskType::SystemScan;
					NewSystemScanTask->Data.ScanType = SystemScanTask->ScanType;
					NewSystemScanTask->Data.Size = 0;		// We will ignore this field in User mode


					InterlockedPushEntrySList(workItemsHead, &NewSystemScanTask->Entry);
					workItemsCount++;
					break;
				}
				default:
				{
					break;
				}
			}

			buffer += header->Size;
			retBytes -= header->Size;

		}

		
	}
	
}