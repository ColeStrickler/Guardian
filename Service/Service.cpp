#include "Service.h"



Service::Service() {
	printf("HERE!\n");
	hFile = CreateFile(L"\\\\.\\guardian", GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
	if (hFile == INVALID_HANDLE_VALUE) {
		printf("INVALID HANDLE VALUE!\n");
	//	return;
	}


	InitializeSListHead(&workItemsHead);
	printf("WorkItemsHead initialized\n");
	YaraConfFilePath = std::string("C:\\Program Files\\Guardian\\conf\\Yara");
	Scanner = new Yara::Scanner(YaraConfFilePath);
	printf("Yara scanner initialized!\n");
	if (Scanner == nullptr) {
		printf("Could not initialize YaraScanner. ERROR: %d\n", GetLastError());
		return;
	}
	if (!Scanner->bSetup) {
		printf("Could not initialzie YaraScanner. ERROR: %d\n", GetLastError());
		return;
	}

	hDriverReadThread = CreateThread(0, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(StartDriverReadThread), this, 0, 0);
	if (hDriverReadThread == NULL) {
		printf("Could not start StartDriverReadThread(). ERROR: %d\n", GetLastError());
		return;
	}

	hWorkerThread = CreateThread(0, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(StartWorkerThread), this, 0, 0);
	if (hDriverReadThread == NULL) {
		printf("Could not start StartWorkerThread(). ERROR: %d\n", GetLastError());
		return;
	}

}

Service::~Service() {

}

void Service::StartWorkerThread() {

	while (true) {
		if (workItemsCount == 0) {
			Sleep(50);
			continue;
		}
		printf("Found new work item in Worker Thread!\n");

		PSLIST_ENTRY currEntry = InterlockedPopEntrySList(&workItemsHead);
		workItemsCount--;
		TaskType EntryType = *(TaskType*)((uintptr_t)currEntry + sizeof(SLIST_ENTRY));
		
		printf("New work item type: %d\n", EntryType);
		switch (EntryType) {

			case TaskType::ScanFile:
			{
				
				auto ScanFileJob = CONTAINING_RECORD(currEntry, WorkItem<ScanFileHeaderFull>, Entry);
				std::wstring wFilePath((wchar_t*)((BYTE*)ScanFileJob + ScanFileJob->Data.FilePathOffset), ScanFileJob->Data.Size);
				std::string FilePath = WstringToString(wFilePath);
				YaraInfo yaraInfo = Scanner->ScanFile(FilePath);
				if (yaraInfo.FilePath[0] == '0') {
					// No matches, break.
					break;
				}


				DWORD filePathlen = FilePath.size();
				DWORD allocSize = sizeof(YaraScanFileAlert) + filePathlen;
				DWORD matchRuleCount = 0;

				for (auto& rule : yaraInfo.matched_rules) {
					allocSize += rule.size() + 1;
					matchRuleCount += 1;
				}

				BYTE* writeBackBuffer = RAII::HeapBuffer(allocSize).Get();
				YaraScanFileAlert writeBackStruct;

				writeBackStruct.FilePathLength = filePathlen;
				writeBackStruct.FilePathOffset = sizeof(YaraScanFileAlert);
				writeBackStruct.MatchedRuleCount = matchRuleCount;
				writeBackStruct.MatchedRulesOffset = sizeof(YaraScanFileAlert) + filePathlen;
				writeBackStruct.Size = allocSize;
				writeBackStruct.Type = ItemType::YaraScanFile;
				// We dont fill out the time, we will do this in the Kernel

				memcpy(writeBackBuffer, &writeBackStruct, sizeof(YaraScanFileAlert));
				memcpy(writeBackBuffer + sizeof(YaraScanFileAlert), FilePath.data(), filePathlen);

				BYTE* writePtr = writeBackBuffer + writeBackStruct.MatchedRulesOffset;
				for (auto& rule : yaraInfo.matched_rules) {
					memcpy(writePtr, rule.data(), rule.size());
					writePtr += rule.size();
					memset(writePtr, 0x99, 1);
					writePtr += 1;
				}
				// [YaraScanFile]
				// [FilePathChars]
				// [MatchedRuleChars]


				// FOR METHOD_IN_DIRECT WE USE THE SECOND BUFFER
				DWORD retBytes;
				BOOL success = DeviceIoControl
				(
					hFile,
					IOCTL_WRITE_ALERT,
					0,
					0,
					writeBackBuffer,
					allocSize,
					&retBytes,
					0
				);
				if (!success) {
					printf("IOCTL ERROR ON ALERT WRITEBACK. ERROR: %d\n", GetLastError());
				}

				break;
			}
			case TaskType::ScanProcess:
			{
				auto ScanProcessJob = CONTAINING_RECORD(currEntry, WorkItem<ScanProcessHeaderFull>, Entry);
				DWORD procId = (DWORD)ScanProcessJob->Data.ProcessId;


				std::vector<YaraInfo> yaraInfo;
				yaraInfo = Scanner->ScanProcess(procId);


				break;
			}
			case TaskType::SystemScan:
			{
				auto ScanSystemJob = CONTAINING_RECORD(currEntry, WorkItem<SystemScanHeaderFull>, Entry);
				std::vector<YaraInfo> yaraInfo;

				yaraInfo = Scanner->ScanSystem();


				break;
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
		//BYTE* buffer = (BYTE*)RAII::HeapBuffer(DWORD(1 << 16)).Get();
		BYTE arr[1 << 16];
		BYTE* buffer = arr;
		if (buffer == nullptr) {
			continue;
		}
		DWORD retBytes;
		BOOL success = DeviceIoControl(
			hFile,
			IOCTL_READ_WORKITEMS,
			0,
			0,
			buffer,
			DWORD(1 << 16),
			&retBytes,
			nullptr         // lpOverlapped
		);
		if (!success) {
			printf("DeviceIO failed in DriverReadThread: %d\n", GetLastError());
			continue;
		}
		if (retBytes > 0) {
			printf("GOT TASK!\n");
		}
		while (retBytes > 0) {
			auto header = (TaskHeader*)buffer;

			switch (header->Type) {					// FROM HERE WE, WE REALLOCATE THESE OBJECTS AND PLACE THEM IN THE WORKER THREAD
				case TaskType::ScanFile:
				{
					auto ScanFileTask = (ScanFileHeaderJob*)buffer;
					DWORD allocSize = sizeof(WorkItem<ScanFileHeaderFull>) + ScanFileTask->FilePathLength;
					auto NewScanFileTask = (WorkItem<ScanFileHeaderFull>*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, allocSize);


					NewScanFileTask->Data.FilePathOffset = sizeof(WorkItem<ScanFileHeaderFull>);
					memcpy((BYTE*)NewScanFileTask + sizeof(WorkItem<ScanFileHeaderFull>), buffer + ScanFileTask->FilePathOffset, ScanFileTask->FilePathLength);
					NewScanFileTask->Data.FilePathLength = ScanFileTask->FilePathLength;
					NewScanFileTask->Data.Size = allocSize;			// We will ignore this field in User mode
					NewScanFileTask->Data.Type = TaskType::ScanFile;


					InterlockedPushEntrySList(&workItemsHead, &NewScanFileTask->Entry);
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


					InterlockedPushEntrySList(&workItemsHead, &NewScanProcessTask->Entry);
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


					InterlockedPushEntrySList(&workItemsHead, &NewSystemScanTask->Entry);
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
		Sleep(1500);
	}
	
}