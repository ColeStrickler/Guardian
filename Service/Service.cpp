#include "Service.h"
Injector::DllThreadInjector* Service::Inject;



Service::Service() {
	hFile = INVALID_HANDLE_VALUE;			// WE DO THIS LOOP HERE, BECAUSE WE WANT THE SERVICE TO RUNNING WHILE THE DRIVER ADDS ITS PID TO ITS PROTECTION ARRAY
	while (hFile == INVALID_HANDLE_VALUE) {	
		hFile = CreateFile(L"\\\\.\\guardian", GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
		if (hFile == INVALID_HANDLE_VALUE) {
			printf("INVALID HANDLE VALUE!\n");
			Sleep(100);
		}
	}
	


	InitializeSListHead(&workItemsHead);
	printf("WorkItemsHead initialized\n");

	Inject = new Injector::DllThreadInjector();

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
	free(Inject);
	printf("Last Error --> %d", GetLastError());
}
// FOR SOME REASON THIS FAILS ON LONG FILE PATHS
void Service::StartWorkerThread() {

	while (true) {
		if (workItemsCount == 0) {
			Sleep(50);
			continue;
		}
		printf("Found new work item in Worker Thread!\n");

		PSLIST_ENTRY currEntry = InterlockedPopEntrySList(&workItemsHead);
		workItemsCount -= 1;
		TaskType EntryType = *(TaskType*)((uintptr_t)currEntry + sizeof(SLIST_ENTRY));
		
		printf("New work item type: %d\n", EntryType);
		switch (EntryType) {

			case TaskType::ScanFile:
			{
				
				auto ScanFileJob = CONTAINING_RECORD(currEntry, WorkItem<ScanFileHeaderFull>, Entry);
				std::wstring wFilePath((wchar_t*)((BYTE*)ScanFileJob + ScanFileJob->Data.FilePathOffset), ScanFileJob->Data.Size);
				std::string FilePath = WstringToString(wFilePath);
				bool heapfreeCheck = HeapFree(GetProcessHeap(), NULL, (void*)ScanFileJob);
				printf("HeapFree check: %d\n", heapfreeCheck);
				std::cout << FilePath << std::endl;
				YaraInfo yaraInfo = Scanner->ScanFile(FilePath);
				if (yaraInfo.FilePath[0] == '0') {
					// No matches, break.
					printf("No matches, break!\n");
					break;
				}


				DWORD filePathlen = FilePath.size();
				DWORD allocSize = sizeof(YaraScanFileAlert) + filePathlen;
				DWORD matchRuleCount = 0;

				for (auto& rule : yaraInfo.matched_rules) {
					allocSize += rule.size() + 1;
					matchRuleCount += 1;
				}

				RAII::NewBuffer writeBackBuf(allocSize);
				BYTE* writeBackBuffer = writeBackBuf.Get();
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
					writePtr += rule.size() + 1;
				}
				// [YaraScanFileAlert]
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
				break;
				
			}
			case TaskType::ScanProcess:
			{
				auto ScanProcessJob = CONTAINING_RECORD(currEntry, WorkItem<ScanProcessHeaderFull>, Entry);
				DWORD procId = (DWORD)ScanProcessJob->Data.ProcessId;
				if (!ProcIdExists(procId)) {// check this twice to make sure there has been no change	
					printf("[Scan Process]: PID does not exist!\n");
					break;
				} 
				printf("pid: %d, procName: %s\n", procId, GetProcnameFromId(procId).c_str());


				std::vector<YaraInfo> yaraInfo;
				yaraInfo = Scanner->ScanProcess(procId);
				DWORD allocSize = sizeof(YaraScanProcessAlert);
				DWORD ruleCount = 0;
				
				std::unordered_set<std::string> set;
				for (auto& yr : yaraInfo) {
					for (auto& s : yr.matched_rules) {
						if (set.count(s)) {
							continue;
						}
						allocSize += s.size() + 1;
						ruleCount += 1;
						set.insert(s);
					}
				}
				auto writeBackBuffer = RAII::NewBuffer(allocSize).Get();
				YaraScanProcessAlert writeBackStruct;

				writeBackStruct.Size = allocSize;
				writeBackStruct.Type = ItemType::YaraScanProcess;
				writeBackStruct.MatchedRulesOffset = sizeof(YaraScanProcessAlert);
				writeBackStruct.MatchedRuleCount = ruleCount;
				writeBackStruct.processId = procId;

				memcpy(writeBackBuffer, &writeBackStruct, sizeof(YaraScanProcessAlert));
				BYTE* writePtr = writeBackBuffer + sizeof(YaraScanProcessAlert);
				for (auto& s : set) {
					memcpy(writePtr, s.data(), s.size());
					writePtr += s.size() + 1;
				}
				// [YaraScanProcessAlert]
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


				break;
			}
			case TaskType::SystemScan:
			{
				auto ScanSystemJob = CONTAINING_RECORD(currEntry, WorkItem<SystemScanHeaderFull>, Entry);
				std::vector<YaraInfo> yaraInfo;

				yaraInfo = Scanner->ScanSystem();


				break;
			}
			case TaskType::StartApiMonitor:
			{
				auto StartApiMonJob = CONTAINING_RECORD(currEntry, WorkItem<ApiMonitorJob>, Entry);
				auto pid = StartApiMonJob->Data.PID;
				if (!ProcIdExists((DWORD)pid)) {
					printf("Pid %d does not exist\n", pid);
					break;
				}
				
				// DETERMINE ARCHITECTURE OF PROCESS
				HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, (DWORD)pid);
				if (!hProc) {
					printf("Could not open Pid: %d\n", pid);
					break;
				}
				BOOL check;
				BOOL success = IsWow64Process(hProc, &check);
				if (!success) {
					if (hProc) {
						CloseHandle(hProc);
					}
					break;
				}

				// ATTEMPT TO INJECT DLL INTO TARGET PROCESS
				if (check) {
					printf("Found 32 bit process --> Pid: %d\n", pid);
					bool success = Inject->InjectDll((DWORD)pid, SERVICE_DLL_32);
					if (success) {
						printf("Successful injection!");
					}
				}
				else {
					printf("Found 64 bit process --> Pid: %d\n", pid);
					bool success = Inject->InjectDll((DWORD)pid, SERVICE_DLL_64);
					if (success) {
						printf("Successful injection!");
					}
				}
				break;
			}
			default:
				printf("default\n");
				break;

		}
		continue;

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
					printf("[SCAN FILE TYPE]\n");
					WorkItem<ScanFileHeaderFull>* NewScanFileTask;
					auto ScanFileTask = (ScanFileHeaderJob*)buffer;
					DWORD allocSize = sizeof(WorkItem<ScanFileHeaderFull>) + ScanFileTask->FilePathLength;
					
					HANDLE heap = GetProcessHeap();
					if (!heap) {
						printf("Could not get heap. ERROR: %d\n", GetLastError());
						continue;
					}
					try {
						NewScanFileTask = (WorkItem<ScanFileHeaderFull>*)HeapAlloc(heap, HEAP_ZERO_MEMORY, allocSize);
					}
					catch (...) {
						printf("ERROR ALLOCATING HEAP --> %d\tCONTINUING...\n");
						continue;
					}
					
					printf("Allocated heap\n");

					NewScanFileTask->Data.FilePathOffset = sizeof(WorkItem<ScanFileHeaderFull>);
					memcpy((BYTE*)NewScanFileTask + sizeof(WorkItem<ScanFileHeaderFull>), buffer + ScanFileTask->FilePathOffset, ScanFileTask->FilePathLength);
					printf("Copied over file path to end of struct\n");
					NewScanFileTask->Data.FilePathLength = ScanFileTask->FilePathLength;
					NewScanFileTask->Data.Size = allocSize;			// We will ignore this field in User mode
					NewScanFileTask->Data.Type = TaskType::ScanFile;

					printf("Attempting to push to entry list\n");
					InterlockedPushEntrySList(&workItemsHead, &NewScanFileTask->Entry);
					printf("Pushed scan file task.\n");
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
				case TaskType::StartApiMonitor:
				{
					auto ApiMonitorTask = (ApiMonitorJob*)buffer;
					auto NewApiMonitorTask = new WorkItem<ApiMonitorJob>();

					printf("New api task --> pid: %d\n", ApiMonitorTask->PID);
					printf("New api task --> pid: %d\n", ApiMonitorTask->Command);
					NewApiMonitorTask->Data.Command = ApiMonitorTask->Command;
					NewApiMonitorTask->Data.PID = ApiMonitorTask->PID;
					NewApiMonitorTask->Data.Size = ApiMonitorTask->Size;
					NewApiMonitorTask->Data.Type = ApiMonitorTask->Type;


					InterlockedPushEntrySList(&workItemsHead, &NewApiMonitorTask->Entry);
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