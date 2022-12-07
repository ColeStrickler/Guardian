#include "driver.h"
#include <stdlib.h>
#pragma warning(disable: 4100)
#pragma warning(disable: 4996)


// OUR FUNCTIONS
DRIVER_UNLOAD Unload;
DRIVER_DISPATCH CreateClose, Read, Write, IoControl;
void OnProcessNotify(PEPROCESS Process, HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO CreateInfo);
void OnThreadNotify(HANDLE ProcessId, HANDLE ThreadId, BOOLEAN Create);
void OnImageLoadNotify(PUNICODE_STRING FullImageName, HANDLE ProcessId, PIMAGE_INFO ImageInfo);
NTSTATUS OnRegistryNotify(PVOID context, PVOID arg1, PVOID arg2);

// SYSTEM FUNCTIONS
static QUERY_INFO_PROCESS ZwQueryInformationProcess;


struct Globals {
	// ALERT NOTIFICATIONS SLL
	LIST_ENTRY AlertsHead{0};
	int AlertCount{0};
	FastMutex AlertsHeadMutex;

	// BLOCKED PATH CONFIG SLL
	LIST_ENTRY BlockedPathsHead{0};
	int BlockedPathsCount{0};
	FastMutex BlockedPathsMutex;

	// LOCKED REG CONFIG SLL
	LIST_ENTRY LockedRegHead{0};
	int LockedRegCount{0};
	FastMutex LockedRegMutex;

	// SERVICE WORK ITEMS SLL
	LIST_ENTRY ServiceWorkItemsHead{0};
	int ServiceWorkItemsCount{0};
	FastMutex ServiceWorkItemsMutex;

	// API MONITOR COMMANDS SLL
	LIST_ENTRY ApiMonitorCommandHead{0};
	int ApiMonitorCommandCount{0};
	FastMutex ApiMonitorCommandMutex;

	// API EVENT SLL
	LIST_ENTRY ApiEventHead{0};
	int ApiEventCount{0};
	FastMutex ApiEventMutex;

	
	// OTHER GLOBAL CONFIG
	RTL_OSVERSIONINFOW versionInfo{0};
	ULONGLONG ServicePID{0};
	PVOID ServiceRegHandle{0};
	LARGE_INTEGER RegCookie;
	HANDLE MainThreadHandle{0};
	bool CloseMainThreadSwitch{0};
};
Globals g_Struct;



NTSTATUS CompleteIrp(PIRP Irp, NTSTATUS status = STATUS_SUCCESS, ULONG_PTR info = 0) {
	Irp->IoStatus.Status = status;
	Irp->IoStatus.Information = info;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return status;
}




void charToUnicodeString(char* text, UNICODE_STRING& outstring)
{
	KdPrint(("In string: %s\n", text));
	size_t size = (strlen(text) + 1) * sizeof(wchar_t);
	KdPrint(("Size: %d\n", size));
	wchar_t* wText = (wchar_t*)ExAllocatePoolWithTag(NonPagedPool, size, 'grdn');
	memset(wText, 0, size);
	mbstowcs(wText, text, (strlen(text)));
	KdPrint(("wText: %ws\n", wText));
	RtlInitUnicodeString(&outstring, wText);
	KdPrint(("Generated outstring %wZ\n", outstring));
	ExFreePool(wText);
}

void PushItem(LIST_ENTRY* entry, LIST_ENTRY* ListHead, FastMutex& Mutex, int& count) {
	AutoLock<FastMutex> lock(Mutex);

	// too many items, remove oldest
	if (count > 1024) {
		auto head = RemoveHeadList(ListHead);
		count--;
		auto item = CONTAINING_RECORD(head, Alert<Header>, Entry);
		


		ExFreePool(item);
	}
	InsertTailList(ListHead, entry);
	count++;
}

NTSTATUS InitLockedRegistryKeys()
{
	OBJECT_ATTRIBUTES objAttr;
	UNICODE_STRING fileName = RTL_CONSTANT_STRING(L"\\??\\C:\\Program Files\\Guardian\\conf\\reg.conf");
	IO_STATUS_BLOCK statusBlock;
	HANDLE hFile;
	NTSTATUS status = STATUS_SUCCESS;

	if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
		return STATUS_INVALID_DEVICE_STATE;
	}

	InitializeObjectAttributes(&objAttr, &fileName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);


	LARGE_INTEGER byteOffset{ 0 };

	int swag = 0;
	swag += 1;


	status = ZwCreateFile(&hFile,
		GENERIC_READ,
		&objAttr, &statusBlock,
		NULL,
		FILE_ATTRIBUTE_NORMAL,
		FILE_SHARE_READ,
		FILE_OPEN_IF,
		FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE,
		NULL, 0);

	if (!NT_SUCCESS(status)) {
		KdPrint(("ZwCreateFileFailed\n"));
		return status;
	}

	FILE_STANDARD_INFORMATION fileInfo = { 0 };
	status = ZwQueryInformationFile(hFile, &statusBlock, &fileInfo, sizeof(FILE_STANDARD_INFORMATION), FileStandardInformation);
	if (!NT_SUCCESS(status)) {
		if (hFile) {
			ZwClose(hFile);
		}
		return STATUS_FAILED_DRIVER_ENTRY;
	}
	KdPrint(("Read file: lockedRegKeyFile size : %d\n", (int)fileInfo.EndOfFile.QuadPart));

	char* buf = (char*)ExAllocatePoolWithTag(NonPagedPool, fileInfo.EndOfFile.QuadPart, DRIVER_TAG);

	byteOffset.LowPart = byteOffset.HighPart = 0;
	status = ZwReadFile(hFile, NULL, NULL, NULL, &statusBlock, buf, (ULONG)fileInfo.EndOfFile.QuadPart, &byteOffset, NULL);
	if (!NT_SUCCESS(status)) {
		if (hFile) {
			ZwClose(hFile);
		}
		if (buf != nullptr) {
			ExFreePool(buf);
		}
		return STATUS_FAILED_DRIVER_ENTRY;
	}
	if (buf == nullptr) {
		if (hFile) {
			ZwClose(hFile);
		}
		return STATUS_FAILED_DRIVER_ENTRY;
	}


	int startFileIndex = 0;
	int endFileIndex = 0;

	for (unsigned int i = 0; i < fileInfo.EndOfFile.QuadPart; i++) {
		if (buf[i] == 0x3b && buf[i + 1] == 0x3b && buf[i + 2] == 0x3b) { // we are storing paths in the config file separated by ;;;
			endFileIndex = i;
			char* regKeyName = (char*)ExAllocatePoolWithTag(NonPagedPool, endFileIndex - startFileIndex, DRIVER_TAG);
			memset(regKeyName, 0, endFileIndex - startFileIndex + 1);
			memcpy(regKeyName, buf + startFileIndex, endFileIndex - startFileIndex);
			startFileIndex = i + 3;
			KdPrint(("Found key: %s\n", regKeyName));
			BlockedPathNode* NewEntry = (BlockedPathNode*)ExAllocatePoolWithTag(NonPagedPool, sizeof(BlockedPathNode), DRIVER_TAG);
			charToUnicodeString(regKeyName, NewEntry->Path);
			PushItem(&NewEntry->Entry, &g_Struct.LockedRegHead, g_Struct.LockedRegMutex, g_Struct.LockedRegCount);
			KdPrint(("Added key %wZ to block list!\n", &NewEntry->Path));
			i += 2;
			ExFreePool(regKeyName);
		}

	}


	if (!NT_SUCCESS(status)) {
		ZwClose(hFile);
	}


	ExFreePool(buf);
	ZwClose(hFile);
	return status;
}

NTSTATUS InitBlockedExecutionPaths() 
{
	OBJECT_ATTRIBUTES objAttr;
	UNICODE_STRING fileName = RTL_CONSTANT_STRING(L"\\??\\C:\\Program Files\\Guardian\\conf\\paths.conf");
	IO_STATUS_BLOCK statusBlock;
	HANDLE hFile;
	NTSTATUS status = STATUS_SUCCESS;
	
	if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
		return STATUS_INVALID_DEVICE_STATE;
	}
	InitializeObjectAttributes(&objAttr, &fileName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);


	LARGE_INTEGER byteOffset{0};

	int swag = 0;
	swag += 1;

	
	status = ZwCreateFile(&hFile,
		GENERIC_READ,
		&objAttr, &statusBlock,
		NULL,
		FILE_ATTRIBUTE_NORMAL,
		FILE_SHARE_READ,
		FILE_OPEN_IF,
		FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE,
		NULL, 0);

	if (!NT_SUCCESS(status)) {
		KdPrint(("ZwCreateFileFailed\n"));
		return status;
	}

	FILE_STANDARD_INFORMATION fileInfo = { 0 };
	status = ZwQueryInformationFile(hFile, &statusBlock, &fileInfo, sizeof(FILE_STANDARD_INFORMATION), FileStandardInformation);
	if (!NT_SUCCESS(status)) {
		if (hFile) {
			ZwClose(hFile);
		}
		return STATUS_FAILED_DRIVER_ENTRY;
	}
	KdPrint(("Read file: blockConfigFile size : %d\n", (int)fileInfo.EndOfFile.QuadPart));

	char* buf = (char*)ExAllocatePoolWithTag(NonPagedPool, fileInfo.EndOfFile.QuadPart, DRIVER_TAG);
	
	byteOffset.LowPart = byteOffset.HighPart = 0;
	status = ZwReadFile(hFile, NULL, NULL, NULL, &statusBlock, buf, (ULONG)fileInfo.EndOfFile.QuadPart, &byteOffset, NULL);
	if (!NT_SUCCESS(status)) {
		if (hFile) {
			ZwClose(hFile);
		}
		if (buf != nullptr) {
			ExFreePool(buf);
		}
		return STATUS_FAILED_DRIVER_ENTRY;
	}
	if (buf == nullptr) {
		if (hFile) {
			ZwClose(hFile);
		}
		return STATUS_FAILED_DRIVER_ENTRY;
	}

	int startFileIndex = 0;
	int endFileIndex = 0;
	char filePathName[260] = {0}; // MAX_PATH

	for (unsigned int i = 0; i < fileInfo.EndOfFile.QuadPart; i++) {
		if (buf[i] == 0x3b && buf[i + 1] == 0x3b && buf[i+2] == 0x3b) { // we are storing paths in the config file separated by ;;;
			endFileIndex = i;
			memcpy(filePathName, buf + startFileIndex, endFileIndex - startFileIndex);
			startFileIndex = i + 3;
			KdPrint(("Found path: %s\n", filePathName));
			BlockedPathNode* NewEntry = (BlockedPathNode*)ExAllocatePoolWithTag(NonPagedPool, sizeof(BlockedPathNode), DRIVER_TAG);
			charToUnicodeString(filePathName, NewEntry->Path);
			PushItem(&NewEntry->Entry, &g_Struct.BlockedPathsHead, g_Struct.BlockedPathsMutex, g_Struct.BlockedPathsCount);
			KdPrint(("Added path %wZ to block list!\n", &NewEntry->Path));
			memset(filePathName, 0, 260); // set back to 0
			i += 2;
		}

	}



	if (!NT_SUCCESS(status)) {
		ZwClose(hFile);
	}

	ExFreePool(buf);
	ZwClose(hFile);
	return status;
}


WorkItem<ApiMonitorJob>* CheckApiMonitorCommands(LIST_ENTRY* ApiCommandHead, ULONG Pid)
{
	AutoLock<FastMutex> lock(g_Struct.ApiMonitorCommandMutex);

	if (IsListEmpty(&g_Struct.ApiMonitorCommandHead)) {
		return nullptr;
	}

	auto curr = CONTAINING_RECORD(ApiCommandHead, WorkItem<ApiMonitorJob>, Entry);
	while ((uintptr_t)curr != (uintptr_t)&g_Struct.ApiMonitorCommandHead) {
		if (Pid == curr->Data.PID) {
			RemoveEntryList(&curr->Entry);
			return curr;
		}
		curr = CONTAINING_RECORD(curr->Entry.Flink, WorkItem<ApiMonitorJob>, Entry);
	}

	return nullptr;
}


OB_PREOP_CALLBACK_STATUS PreOpenServiceProcess(PVOID, POB_PRE_OPERATION_INFORMATION Info) {
	if (Info->KernelHandle) {
		return OB_PREOP_SUCCESS;
	}

	auto process = (PEPROCESS)Info->Object;
	auto pid = HandleToUlong(PsGetProcessId(process));


	if (pid == g_Struct.ServicePID) {
		Info->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_TERMINATE;
	}


	return OB_PREOP_SUCCESS;
}


void mainThread() {
	while (true) {
		
		LARGE_INTEGER WaitTime;
		WaitTime.QuadPart = TIME_RELATIVE(TIME_SECONDS(1));
		KeDelayExecutionThread(KernelMode, FALSE, &WaitTime);

		if (g_Struct.CloseMainThreadSwitch) {
			break;
		}
	}
	PsTerminateSystemThread(STATUS_SUCCESS);
}


extern "C" NTSTATUS
DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING) {
	auto status = STATUS_SUCCESS;
	

	PDEVICE_OBJECT DeviceObject = nullptr;
	UNICODE_STRING symLink = RTL_CONSTANT_STRING(L"\\??\\guardian");
	UNICODE_STRING devName = RTL_CONSTANT_STRING(L"\\device\\guardian");
	bool symLinkCreated = false; 
	bool processCallbacks = false, threadCallbacks = false, imageLoadCallbacks = false;

	// STORE ALL OF OUR OBJECT OPERATION CALLBACK FUNCTIONS HERE
	OB_OPERATION_REGISTRATION callbackOperations[] = {
		{
			PsProcessType,
			OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE,
			PreOpenServiceProcess,
		}
	};

	OB_CALLBACK_REGISTRATION registration = {
		OB_FLT_REGISTRATION_VERSION,
		sizeof(callbackOperations) / sizeof(OB_OPERATION_REGISTRATION),			// OPERATION COUNT
		RTL_CONSTANT_STRING(L"12345.6789"),										// ALTITUDE
		nullptr,																// CONTEXT
		callbackOperations														// CALLBACK OPERATIONS ARRAY
	};

	// WE WILL DYNAMICALLY RESOLVE SYSTEM FUNCTIONS HERE
	UNICODE_STRING routineName;
	RtlInitUnicodeString(&routineName, L"ZwQueryInformationProcess");
	ZwQueryInformationProcess = reinterpret_cast<QUERY_INFO_PROCESS>(MmGetSystemRoutineAddress(&routineName));
	if (ZwQueryInformationProcess == NULL) {
		KdPrint(("Cannot resolve address for ZwQueryInformationProcess"));
		return STATUS_UNSUCCESSFUL;
	}

	// Initialize Linked lists
	InitializeListHead(&g_Struct.AlertsHead);
	InitializeListHead(&g_Struct.BlockedPathsHead);
	InitializeListHead(&g_Struct.ServiceWorkItemsHead);
	InitializeListHead(&g_Struct.LockedRegHead);
	InitializeListHead(&g_Struct.ApiMonitorCommandHead);
	InitializeListHead(&g_Struct.ApiEventHead);

	// Initialize Mutexes
	g_Struct.AlertsHeadMutex.Init();
	g_Struct.BlockedPathsMutex.Init();
	g_Struct.ServiceWorkItemsMutex.Init();
	g_Struct.LockedRegMutex.Init();
	g_Struct.ApiMonitorCommandMutex.Init();
	g_Struct.ApiEventMutex.Init();

	// Get Version
	RtlGetVersion(&g_Struct.versionInfo);
	KdPrint(("Version %d.%d.%d found!\n", g_Struct.versionInfo.dwMajorVersion, g_Struct.versionInfo.dwMinorVersion, g_Struct.versionInfo.dwBuildNumber));
	
	do {
		status = IoCreateDevice(DriverObject, 0, &devName, FILE_DEVICE_UNKNOWN, 0, FALSE, &DeviceObject);
		if (!NT_SUCCESS(status)) {
			KdPrint((DRIVER_PREFIX "failed to create device (0x%08X)\n", status));
			break;
		}
		// use DIRECT IO because we will be passing in large buffers and want to avoid copies
		DeviceObject->Flags |= DO_DIRECT_IO;

		status = IoCreateSymbolicLink(&symLink, &devName);
		if (!NT_SUCCESS(status)) {
			KdPrint((DRIVER_PREFIX "failed to create sym link (0x%08X)\n", status));
			break;
		}
		symLinkCreated = true;


		status = PsCreateSystemThread(&g_Struct.MainThreadHandle, THREAD_ALL_ACCESS, NULL, NULL, NULL, (PKSTART_ROUTINE)mainThread, NULL);
		if (!NT_SUCCESS(status)) {
			KdPrint((DRIVER_PREFIX "failed to create MainThread()\n", status));

		}

		status = ObRegisterCallbacks(&registration, &g_Struct.ServiceRegHandle);
		if (!NT_SUCCESS(status)) {
			KdPrint((DRIVER_PREFIX "failed to register object callbacks (0x%08X)\n", status));
				
		}

		status = InitBlockedExecutionPaths();
		if (!NT_SUCCESS(status)) {
			KdPrint((DRIVER_PREFIX "failed to get blocked execution paths!\n"));
			break;
		}
		KdPrint((DRIVER_PREFIX "successfully fetched blocked execution paths!\n"));

		status = InitLockedRegistryKeys();
		if (!NT_SUCCESS(status)) {
			KdPrint((DRIVER_PREFIX "failed to get locked registry!\n"));
			break;
		}
		KdPrint((DRIVER_PREFIX "successfully fetched locked registry keys!\n"));

		UNICODE_STRING altitude = RTL_CONSTANT_STRING(L"12345.6789");
		status = CmRegisterCallbackEx(OnRegistryNotify, &altitude, DriverObject, nullptr, &g_Struct.RegCookie, nullptr);
		if (!NT_SUCCESS(status)) {
			KdPrint((DRIVER_PREFIX "failed to register for registry notifications!\n"));
			break;
		}

		status = PsSetCreateProcessNotifyRoutineEx(OnProcessNotify, FALSE);
		if (!NT_SUCCESS(status)) {
			KdPrint((DRIVER_PREFIX "failed to register process callback (0x%08X)\n", status));
			break;
		}
		processCallbacks = true;

		status = PsSetCreateThreadNotifyRoutine(OnThreadNotify);
		if (!NT_SUCCESS(status)) {
			KdPrint((DRIVER_PREFIX "failed to set thread callback (status=%08X)\n", status));
			break;
		}
		threadCallbacks = true;

		status = PsSetLoadImageNotifyRoutine(OnImageLoadNotify);
		if (!NT_SUCCESS(status)) {
			KdPrint((DRIVER_PREFIX "failed to set image load callback (status=%08X)\n", status));
			break;
		}
		imageLoadCallbacks = true;
	} while (false);

	if (!NT_SUCCESS(status)) {
		if (threadCallbacks)
			PsRemoveCreateThreadNotifyRoutine(OnThreadNotify);
		if (processCallbacks)
			PsSetCreateProcessNotifyRoutineEx(OnProcessNotify, TRUE);
		if (symLinkCreated)
			IoDeleteSymbolicLink(&symLink);
		if (DeviceObject)
			IoDeleteDevice(DeviceObject);
		if (imageLoadCallbacks)
			PsRemoveLoadImageNotifyRoutine(OnImageLoadNotify);
	}
	DriverObject->DriverUnload = Unload;
	DriverObject->MajorFunction[IRP_MJ_CREATE] = DriverObject->MajorFunction[IRP_MJ_CLOSE] = CreateClose;
	DriverObject->MajorFunction[IRP_MJ_READ] = Read;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = IoControl;
	//DriverObject->MajorFunction[IRP_MJ_WRITE] = Write;

	KdPrint(("GUARDIAN LOADED"));
	return status;
}


NTSTATUS Read(PDEVICE_OBJECT, PIRP Irp) {
	auto stack = IoGetCurrentIrpStackLocation(Irp);
	auto len = stack->Parameters.Read.Length;
	auto status = STATUS_SUCCESS;
	auto count = 0;

	// ENSURE THIS EXISTS BECAUSE WERE USING DIRECT IO
	NT_ASSERT(Irp->MdlAddress);

	auto buffer = (UCHAR*)MmGetSystemAddressForMdlSafe(Irp->MdlAddress, NormalPagePriority);
	if (!buffer) {
		status = STATUS_INSUFFICIENT_RESOURCES;
	}
	else {
		AutoLock<FastMutex> lock(g_Struct.AlertsHeadMutex); // RAII mutex
		while (true) {
			if (IsListEmpty(&g_Struct.AlertsHead)) {
				break;
			}

			auto entry = RemoveHeadList(&g_Struct.AlertsHead);
			auto info = CONTAINING_RECORD(entry, Alert<Header>, Entry);
			auto size = info->Data.Size;
			if (len < size) {
				// user buffer is full, put it back
				InsertHeadList(&g_Struct.AlertsHead, entry);
				break;
			}
			g_Struct.AlertCount--;
			memcpy(buffer, &info->Data, size); // this size will change depending on what was set when the item was created
			len -= size;
			buffer += size; // adjust write position
			count += size;
			// free data after copy
			ExFreePool(info); // will free the entire allocated structure because of CONTAINING_RECORD macro
		}
	}
	Irp->IoStatus.Status = status;
	Irp->IoStatus.Information = count;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return status;
}








void Unload(PDRIVER_OBJECT DriverObject) {
	PsRemoveLoadImageNotifyRoutine(OnImageLoadNotify);
	PsRemoveCreateThreadNotifyRoutine(OnThreadNotify);
	PsSetCreateProcessNotifyRoutineEx(OnProcessNotify, TRUE);

	UNICODE_STRING symLink = RTL_CONSTANT_STRING(L"\\??\\guardian");
	IoDeleteSymbolicLink(&symLink);
	IoDeleteDevice(DriverObject->DeviceObject);
	ObUnRegisterCallbacks(g_Struct.ServiceRegHandle);
	CmUnRegisterCallback(g_Struct.RegCookie);

	if (g_Struct.MainThreadHandle) {
		g_Struct.CloseMainThreadSwitch = TRUE;
		PETHREAD threadObject;
		ObReferenceObjectByHandle(g_Struct.MainThreadHandle, THREAD_ALL_ACCESS, *PsThreadType, KernelMode, (PVOID*)&threadObject, NULL);
		KeWaitForSingleObject(threadObject, Executive, KernelMode, TRUE, nullptr);
		KdPrint(("MainThread() ended.. Closing handle!\n"));
		ZwClose(g_Struct.MainThreadHandle);
	}


	while (!IsListEmpty(&g_Struct.AlertsHead)) {
		auto entry = RemoveHeadList(&g_Struct.AlertsHead);
		short type = *(short*)((UINT64)entry + sizeof(LIST_ENTRY));


		switch (type) {
			case (short)ItemType::RemoteThreadCreate: 
			{
				ExFreePool(CONTAINING_RECORD(entry, Alert<RemoteThreadAlert>, Entry));
				break;
			}

			case (short)ItemType::BlockedExecutionPath:
			{
				ExFreePool(CONTAINING_RECORD(entry, Alert<BlockedPathAlert>, Entry));
				break;
			}
			
			case (short)ItemType::YaraScanFile:
			{
				ExFreePool(CONTAINING_RECORD(entry, Alert<YaraScanFileAlert>, Entry));
				break;
			}
		}	
	}

	while (!IsListEmpty(&g_Struct.BlockedPathsHead)) {
		auto entry = RemoveHeadList(&g_Struct.BlockedPathsHead);
		ExFreePool(CONTAINING_RECORD(entry, BlockedPathNode, Entry));
	}

	while (!IsListEmpty(&g_Struct.LockedRegHead)) {
		auto entry = RemoveHeadList(&g_Struct.LockedRegHead);
		ExFreePool(CONTAINING_RECORD(entry, BlockedPathNode, Entry));
	}


	while (!IsListEmpty(&g_Struct.ServiceWorkItemsHead)) {
		auto entry = RemoveHeadList(&g_Struct.ServiceWorkItemsHead);
		short type = *(short*)((UINT64)entry + sizeof(LIST_ENTRY));
		

		switch (type) {
			case (short)TaskType::ScanFile:
			{
				ExFreePool(CONTAINING_RECORD(entry, WorkItem<ScanFileHeaderJob>, Entry));
				break;
			}

			case (short)TaskType::ScanProcess:
			{
				ExFreePool(CONTAINING_RECORD(entry, WorkItem<ScanProcessHeaderJob>, Entry));
				break;
			}

			case (short)TaskType::SystemScan:
			{
				ExFreePool(CONTAINING_RECORD(entry, WorkItem<SystemScanHeaderJob>, Entry));
				break;
			}
		}
	}
	KdPrint(("[UNLOADED]\n"));
}


// We will edit this so only the user mode client can access
NTSTATUS CreateClose(PDEVICE_OBJECT, PIRP Irp) {
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, 0);
	return STATUS_SUCCESS;
}

// FOR SOME REASON THIS IS CHANGING THE RULES LMAO
bool CheckBlockedPath(LIST_ENTRY* BlockedPathListHead, PCUNICODE_STRING ImageFileName) {
	AutoLock<FastMutex> lock(g_Struct.BlockedPathsMutex);
	if (IsListEmpty(&g_Struct.BlockedPathsHead)) {
		return false;
	}


	BlockedPathNode* entry = CONTAINING_RECORD(BlockedPathListHead, BlockedPathNode, Entry);
	//KdPrint(("Entry Path-->%wZ", entry->Path));
	//auto head = entry;
	auto entrySize = entry->Path.Length;
	WCHAR buffer[260];
	memset(buffer, 0, 260);
	//KdPrint(("Entry Path-->%wZ", entry->Path));
	memcpy(buffer, ImageFileName->Buffer, entrySize);
	KdPrint(("Entry Path-->%wZ\n", entry->Path));
	UNICODE_STRING uni;
	RtlInitUnicodeString(&uni, (PCWSTR)buffer);
	KdPrint(("Checking if path %wZ is blocked by block rule --> %wZ\n", &uni, &entry->Path));
	
	if (RtlCompareUnicodeString(&entry->Path, &uni, TRUE) == 0) {
		KdPrint(("BLOCKING EXECUTION OF %wZ\n", ImageFileName));
		return true;
	}
	auto entry2 = CONTAINING_RECORD(entry->Entry.Flink, BlockedPathNode, Entry);
	//KdPrint(("Entry2 Path-->%wZ", &entry2->Path));
	while (&entry2->Entry != &g_Struct.BlockedPathsHead) {
		auto entrySize2 = entry2->Path.Length; // messing up somewhere here
		//KdPrint(("Entry2 Path-->%wZ", &entry2->Path));
		WCHAR buffer2[260];
		//KdPrint(("Entry2 Path-->%wZ", &entry2->Path));
		memset(buffer2, 0, entrySize2 + 5);
		memcpy(buffer2, ImageFileName->Buffer, entrySize2);
		UNICODE_STRING check;
		KdPrint(("Entry2 Path-->%wZ\n", &entry2->Path));
		RtlInitUnicodeString(&check, (PCWSTR)buffer2);
		KdPrint(("Checking if path %wZ is blocked by block rule --> %wZ\n", &check , &entry2->Path));

		if (RtlCompareUnicodeString(&entry2->Path, &check, TRUE) == 0) {
			KdPrint(("BLOCKING EXECUTION OF %wZ\n", ImageFileName));
			return true;
		}
		entry2 = CONTAINING_RECORD(entry2->Entry.Flink, BlockedPathNode, Entry);
	}
	return false;
}


void OnProcessNotify(PEPROCESS Process, HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO CreateInfo) {
	UNREFERENCED_PARAMETER(Process);
	UNREFERENCED_PARAMETER(ProcessId);
	if (CreateInfo) {
		if (CreateInfo->FileOpenNameAvailable) {
			KdPrint(("###############################\n"));
			KdPrint(("IMAGE FILE NAME: %wZ\n", CreateInfo->ImageFileName));
			
			if (g_Struct.ServicePID == 0) {
				KdPrint(("Checking to initialize ServicePID\n"));
				UNICODE_STRING serviceProcName = RTL_CONSTANT_STRING(SERVICE_PROCIMAGE_NAME);

				if (!RtlCompareUnicodeString(&serviceProcName, CreateInfo->ImageFileName, TRUE)) {
					KdPrint(("GOT SERVICE PID!"));
					g_Struct.ServicePID = (ULONGLONG)ProcessId;
					return;
				}
			}
			
			if (CheckBlockedPath(g_Struct.BlockedPathsHead.Flink, CreateInfo->ImageFileName)) {

				USHORT ImageNameLength = 0;
				if (CreateInfo->ImageFileName) {
					ImageNameLength = CreateInfo->ImageFileName->Length;
				}
					
				CreateInfo->CreationStatus = STATUS_ACCESS_DENIED;
				USHORT allocSize = sizeof(Alert<BlockedPathAlert>);
				allocSize += ImageNameLength;
				auto info = (Alert<BlockedPathAlert>*)ExAllocatePoolWithTag(PagedPool, allocSize, DRIVER_TAG);
				if (info == nullptr) {
					KdPrint((DRIVER_PREFIX "Unable to allocate space for BlockedPathAlert!\n"));
					return;
				}

				auto& item = info->Data;
				KeQuerySystemTime(&item.Time);
				item.Type = ItemType::BlockedExecutionPath;
				item.Size = sizeof(item) + ImageNameLength + 1;
				item.ImageNameLength = ImageNameLength;

				if (ImageNameLength > 0) {
					memcpy((UCHAR*)&item + sizeof(item), CreateInfo->ImageFileName->Buffer, ImageNameLength);
					item.ImageNameOffset = sizeof(item);
				}
				else {
					item.ImageNameOffset = 0;
					item.ImageNameLength = 0;
				}

				PushItem(&info->Entry, &g_Struct.AlertsHead, g_Struct.AlertsHeadMutex, g_Struct.AlertCount);
				return;
			}
			KdPrint(("###############################\n"));
		}
		
	}


	return;

}







void OnThreadNotify(HANDLE ProcessId, HANDLE ThreadId, BOOLEAN Create) {
	if (Create) {
		HANDLE caller = PsGetCurrentProcessId();
		ULONG callerId = HandleToUlong(caller);
		ULONG targetId = HandleToUlong(ProcessId);
		PEPROCESS pEprocess = NULL;
		//RTL_OSVERSIONINFOW versionInfo{0};
		int ActiveThreadsOffset = 0;

		ULONG MajorVersion = g_Struct.versionInfo.dwMajorVersion;
		ULONG MinorVersion = g_Struct.versionInfo.dwMinorVersion;
		ULONG Build = g_Struct.versionInfo.dwBuildNumber;


		// check version number so we know where EPROCESS offsets are

		// 10.0.19043
		if (MajorVersion == 10 && MinorVersion == 0 && Build == 19043) {
			ActiveThreadsOffset = 0x5F0;
		}
		// 10.0.17763
		else if (MajorVersion == 10 && MinorVersion == 0 && Build == 17763) {
			ActiveThreadsOffset = 0x498;
		}
		else {
			KdPrint(("Version %d.%d.%d not supported", MajorVersion, MinorVersion, Build));
			return;
		}


		if (callerId != targetId && callerId != 4) {
			PsLookupProcessByProcessId(caller, &pEprocess);

			UINT16 numThreads = *(UINT16*)((DWORD64)pEprocess + ActiveThreadsOffset);
			
			if (numThreads != 1) {
				USHORT allocSize = sizeof(Alert<RemoteThreadAlert>);
				KdPrint(("REMOTE THREAD CREATION! %d --> %d", callerId, targetId));
				auto info = (Alert<RemoteThreadAlert>*)ExAllocatePoolWithTag(PagedPool, allocSize, DRIVER_TAG);
				if (info == nullptr) {
					KdPrint((DRIVER_PREFIX "failed allocation\n"));
					return;
				}
				auto& item = info->Data;
				KeQuerySystemTime(&item.Time);
				item.Type = ItemType::RemoteThreadCreate;
				item.Size = sizeof(RemoteThreadAlert);
				item.ProcessId = targetId;
				item.CreatorProcess = callerId;
				item.ThreadId = HandleToUlong(ThreadId);
				PushItem(&info->Entry, &g_Struct.AlertsHead, g_Struct.AlertsHeadMutex, g_Struct.AlertCount);
			}
			
		}
	 
	}
}


NTSTATUS IoControl(PDEVICE_OBJECT, PIRP Irp) {
	if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
		return STATUS_INVALID_DEVICE_STATE;
	}


	NTSTATUS status = STATUS_SUCCESS;
	auto stack = IoGetCurrentIrpStackLocation(Irp);
	auto count = 0;

	KdPrint(("Control Code: 0x%8X\n", stack->Parameters.DeviceIoControl.IoControlCode));
	KdPrint(("IOCTL_API_EVENT: 0x%8X\n", IOCTL_API_EVENT));
	switch (stack->Parameters.DeviceIoControl.IoControlCode)
	{

		// ADD A FILE PATH TO THE BLACKLIST
		// NEED TO MAKE THIS ON A PER USER BASIS IN THE FUTURE
	case IOCTL_ADDFILE_BLACKLIST:
	{
		auto len = stack->Parameters.DeviceIoControl.InputBufferLength;
		if (len <= 0 || len > 260) { // check path size
			status = STATUS_INVALID_PARAMETER;
			break;
		}
		
		unsigned char* inBuffer = (unsigned char*)stack->Parameters.DeviceIoControl.Type3InputBuffer;
		bool foundDelimeter = false;
		for (unsigned short i = 0; i < len; i++) { // This is just another sanity check, we go ahead and zero the ; to make it easier to add to our global linked list
			if (inBuffer[i] == 0x3b) { 
				inBuffer[i] = 0x00;
				foundDelimeter = true;
			}
		}
		if (!foundDelimeter) {
			status = STATUS_INVALID_PARAMETER;
			break;
		}
		auto NewBlockedPathNode = (BlockedPathNode*)ExAllocatePoolWithTag(NonPagedPool, sizeof(BlockedPathNode), DRIVER_TAG);
		if (NewBlockedPathNode == nullptr) {
			status = STATUS_INSUFFICIENT_RESOURCES;
			break;
		}

		charToUnicodeString((char*)inBuffer, NewBlockedPathNode->Path);
		KdPrint(("NEW BLOCKED PATH --> %wZ", NewBlockedPathNode->Path));
		if (NewBlockedPathNode->Path.Length != 0) {
			KdPrint(("Successfully added user given path to new entry!\n"));
			PushItem(&NewBlockedPathNode->Entry, &g_Struct.BlockedPathsHead, g_Struct.BlockedPathsMutex, g_Struct.BlockedPathsCount);
		}
		else {
			KdPrint(("Unable to add user given path to new entry!\n"));
			status = STATUS_ABANDONED;
			ExFreePool(NewBlockedPathNode);
			break;
		}
		break;
	}

	case IOCTL_LOCKDOWN_REGKEY:
	{
		auto len = stack->Parameters.DeviceIoControl.InputBufferLength;
		if (len <= 0) { // check key size
			status = STATUS_INVALID_PARAMETER;
			break;
		}
		unsigned char* inBuffer = (unsigned char*)stack->Parameters.DeviceIoControl.Type3InputBuffer;
		bool foundDelimeter = false;
		for (unsigned short i = 0; i < len; i++) { // This is just another sanity check, we go ahead and zero the ; to make it easier to add to our global linked list
			if (inBuffer[i] == 0x3b) {
				inBuffer[i] = 0x00;
				foundDelimeter = true;
			}
		}

		if (!foundDelimeter) {
			status = STATUS_INVALID_PARAMETER;
			break;
		}

		auto NewBlockedPathNode = (BlockedPathNode*)ExAllocatePoolWithTag(NonPagedPool, sizeof(BlockedPathNode), DRIVER_TAG);
		if (NewBlockedPathNode == nullptr) {
			status = STATUS_INSUFFICIENT_RESOURCES;
			break;
		}

		charToUnicodeString((char*)inBuffer, NewBlockedPathNode->Path);
		KdPrint(("NEW BLOCKED PATH --> %wZ", NewBlockedPathNode->Path));
		if (NewBlockedPathNode->Path.Length != 0) {
			KdPrint(("Successfully added user given path to new entry!\n"));
			PushItem(&NewBlockedPathNode->Entry, &g_Struct.LockedRegHead, g_Struct.LockedRegMutex, g_Struct.LockedRegCount);
		}
		else {
			KdPrint(("Unable to add user given path to new entry!\n"));
			status = STATUS_ABANDONED;
			ExFreePool(NewBlockedPathNode);
			break;
		}
		break;

	}

	// FROM HERE, THE GUI MANAGER WILL WRITE IN NEW WORK ITEMS
	case IOCTL_WRITE_WORKITEM:
	{
		// DIRECT IO BECAUSE THIS COULD BE A LARGE BUFFER
		NT_ASSERT(Irp->MdlAddress);
		KdPrint(("Irp->MdlAddress: 0x%8x\n", (ULONGLONG)Irp->MdlAddress));

		auto buffer = (UCHAR*)MmGetSystemAddressForMdlSafe(Irp->MdlAddress, NormalPagePriority);
		if (!buffer) {
			KdPrint(("Could not get MdlAddress!\n"));
			status = STATUS_INSUFFICIENT_RESOURCES;
			break;
		}
		auto type = ((TaskHeader*)(buffer))->Type;
		KdPrint((DRIVER_PREFIX "IOCTL_WRITE_ITEM-->TYPE: %d\n", type));

		switch (type) {
			case TaskType::ScanFile:
			{
				ULONG allocSize = sizeof(WorkItem<ScanFileHeaderJob>);
				auto ReadInFileJob = (ScanFileHeaderJob*)buffer;
				ULONG filePathLen = ReadInFileJob->FilePathLength;
				allocSize += filePathLen;

				auto NewScanFileJob = (WorkItem<ScanFileHeaderJob>*)ExAllocatePoolWithTag(NonPagedPool, allocSize, DRIVER_TAG);
				if (NewScanFileJob == nullptr) {
					KdPrint((DRIVER_PREFIX "[IOCTL_WRITE_ITEM] Unable to allocate pool."));
					status = STATUS_INSUFFICIENT_RESOURCES;
				}

				NewScanFileJob->Data.Size = allocSize;
				NewScanFileJob->Data.Type = TaskType::ScanFile;
				NewScanFileJob->Data.FilePathLength = filePathLen;
				NewScanFileJob->Data.FilePathOffset = sizeof(ScanFileHeaderJob);
				KdPrint(("Reading file path: %ws\n", (wchar_t*)((UCHAR*)buffer + ReadInFileJob->FilePathOffset)));
				memcpy((UCHAR*)NewScanFileJob + sizeof(WorkItem<ScanFileHeaderJob>), buffer + ReadInFileJob->FilePathOffset, filePathLen);
				
				KdPrint(("Allocated new WorkItem<ScanFileHeaderJob>\n"));
				PushItem(&NewScanFileJob->Entry, &g_Struct.ServiceWorkItemsHead, g_Struct.ServiceWorkItemsMutex, g_Struct.ServiceWorkItemsCount);
				break;
			}
			
			case TaskType::ScanProcess:
			{
				ULONG allocSize = sizeof(WorkItem<ScanProcessHeaderJob>);
				auto ReadInProcessJob = (ScanProcessHeaderJob*)buffer;

				auto NewScanProcessJob = (WorkItem<ScanProcessHeaderJob>*)ExAllocatePoolWithTag(NonPagedPool, allocSize, DRIVER_TAG);
				if (NewScanProcessJob == nullptr) {
					KdPrint((DRIVER_PREFIX "[IOCTL_WRITE_ITEM] Unable to allocate pool."));
					status = STATUS_INSUFFICIENT_RESOURCES;
				}

				NewScanProcessJob->Data.Size = sizeof(WorkItem<ScanProcessHeaderJob>);
				NewScanProcessJob->Data.ProcessId = ReadInProcessJob->ProcessId;
				NewScanProcessJob->Data.Type = TaskType::ScanProcess;

				KdPrint(("Allocated new WorkItem<ScanProcessHeaderJob>\n"));
				PushItem(&NewScanProcessJob->Entry, &g_Struct.ServiceWorkItemsHead, g_Struct.ServiceWorkItemsMutex, g_Struct.ServiceWorkItemsCount);
				break;
			}

			case TaskType::SystemScan:
			{
				ULONG allocSize = sizeof(WorkItem<SystemScanHeaderJob>);
				auto ReadInProcessJob = (SystemScanHeaderJob*)buffer;

				auto NewSystemScanJob = (WorkItem<SystemScanHeaderJob>*)ExAllocatePoolWithTag(NonPagedPool, allocSize, DRIVER_TAG);
				if (NewSystemScanJob == nullptr) {
					KdPrint((DRIVER_PREFIX "[IOCTL_WRITE_ITEM] Unable to allocate pool."));
					status = STATUS_INSUFFICIENT_RESOURCES;
				}

				NewSystemScanJob->Data.ScanType = ReadInProcessJob->ScanType;
				NewSystemScanJob->Data.Size = sizeof(WorkItem<SystemScanHeaderJob>);
				NewSystemScanJob->Data.Type = TaskType::SystemScan;
				
				KdPrint(("Allocated new WorkItem<SystemScanHeaderJob>\n"));
				PushItem(&NewSystemScanJob->Entry, &g_Struct.ServiceWorkItemsHead, g_Struct.ServiceWorkItemsMutex, g_Struct.ServiceWorkItemsCount);
				break;
			}

			default:
				status = STATUS_INVALID_DEVICE_REQUEST;
				break;
		}
		break;
	}


	// FROM HERE, THE SERVICE COMPONENT WILL READ WORK ITEMS FROM THE DRIVER
	case IOCTL_READ_WORKITEMS:
	{
		KdPrint((DRIVER_PREFIX "[IOCTL_READ_WORKITEMS]\n"));
		// DIRECT IO BECAUSE THIS COULD BE A LARGE BUFFER
		NT_ASSERT(Irp->MdlAddress);
		auto len = stack->Parameters.DeviceIoControl.OutputBufferLength;
		auto buffer = (UCHAR*)MmGetSystemAddressForMdlSafe(Irp->MdlAddress, NormalPagePriority);
		if (!buffer) {
			KdPrint(("Could not get MdlAddress.\n"));
			status = STATUS_INSUFFICIENT_RESOURCES;
			break;
		}

		
		AutoLock<FastMutex> lock(g_Struct.ServiceWorkItemsMutex);
		while (true) {
			if (IsListEmpty(&g_Struct.ServiceWorkItemsHead)) {
				break;
			}
			auto entry = RemoveHeadList(&g_Struct.ServiceWorkItemsHead);
			TaskType type = *(TaskType*)((uintptr_t)entry + sizeof(LIST_ENTRY));
			KdPrint(("\nReading TaskType: %d\n", type));

			switch (type) {
				case TaskType::ScanFile:
				{
					auto info = CONTAINING_RECORD(entry, WorkItem<ScanFileHeaderJob>, Entry);
					auto size = info->Data.Size;

					if (len < size) {
						InsertHeadList(&g_Struct.ServiceWorkItemsHead, entry);
						KdPrint(("Not enough space. Putting back item.\n"));
						break;
					}

					g_Struct.ServiceWorkItemsCount--;
					memcpy(buffer, &info->Data, size);
					len -= size;
					buffer += size;
					count += size;

					ExFreePool(info);
					break;
				}

				case TaskType::ScanProcess:
				{
					auto info = CONTAINING_RECORD(entry, WorkItem<ScanProcessHeaderJob>, Entry);
					auto size = info->Data.Size;

					if (len < size) {
						InsertHeadList(&g_Struct.ServiceWorkItemsHead, entry);
						break;
					}

					g_Struct.ServiceWorkItemsCount--;
					memcpy(buffer, &info->Data, size);
					len -= size;
					buffer += size;
					count += size;

					ExFreePool(info);
					break;

				}

				case TaskType::SystemScan:
				{
					auto info = CONTAINING_RECORD(entry, WorkItem<SystemScanHeaderJob>, Entry);
					auto size = info->Data.Size;

					if (len < size) {
						InsertHeadList(&g_Struct.ServiceWorkItemsHead, entry);
						break;
					}

					g_Struct.ServiceWorkItemsCount--;
					memcpy(buffer, &info->Data, size);
					len -= size;
					buffer += size;
					count += size;

					ExFreePool(info);
					break;
				}

				case TaskType::StartApiMonitor:
				{
					auto info = CONTAINING_RECORD(entry, WorkItem<ApiMonitorJob>, Entry);
					auto size = info->Data.Size;

					if (len < size) {
						InsertHeadList(&g_Struct.ServiceWorkItemsHead, entry);
						break;
					}

					g_Struct.ServiceWorkItemsCount--;
					memcpy(buffer, &info->Data, size);
					len -= size;
					buffer += size;
					count += size;

					ExFreePool(info);
					break;
				}

				default:
					KdPrint(("Invalid type found when reading Task items to service\n"));
					break;
			}
		}
		break;
	}


	case IOCTL_WRITE_ALERT:
	{
		KdPrint((DRIVER_PREFIX "[IOCTL_WRITE_ALERT]\n"));
		// DIRECT IO BECAUSE THIS COULD BE A LARGE BUFFER
		NT_ASSERT(Irp->MdlAddress);
		//auto len = stack->Parameters.DeviceIoControl.OutputBufferLength;
		auto buffer = (UCHAR*)MmGetSystemAddressForMdlSafe(Irp->MdlAddress, NormalPagePriority);
		if (!buffer) {
			KdPrint(("Could not get MdlAddress.\n"));
			status = STATUS_INSUFFICIENT_RESOURCES;
			break;
		}

		auto type = ((Header*)buffer)->Type;
		switch (type) {
			case ItemType::YaraScanFile:
			{
				YaraScanFileAlert* readAlert = (YaraScanFileAlert*)buffer;
				ULONG allocSize = readAlert->Size - sizeof(YaraScanFileAlert);
				allocSize += sizeof(Alert<YaraScanFileAlert>);

				auto newAlert = (Alert<YaraScanFileAlert>*)ExAllocatePoolWithTag(NonPagedPool, allocSize, DRIVER_TAG);
				memcpy(&newAlert->Data, buffer, readAlert->Size);

				PushItem(&newAlert->Entry, &g_Struct.AlertsHead, g_Struct.AlertsHeadMutex, g_Struct.AlertCount);
				break;
			}

			case ItemType::YaraScanProcess:
			{
				YaraScanProcessAlert* readAlert = (YaraScanProcessAlert*)buffer;
				ULONG allocSize = readAlert->Size - sizeof(YaraScanProcessAlert);
				allocSize += sizeof(Alert<YaraScanProcessAlert>);

				auto newAlert = (Alert<YaraScanFileAlert>*)ExAllocatePoolWithTag(NonPagedPool, allocSize, DRIVER_TAG);
				memcpy(&newAlert->Data, buffer, readAlert->Size);

				PushItem(&newAlert->Entry, &g_Struct.AlertsHead, g_Struct.AlertsHeadMutex, g_Struct.AlertCount);
				break;
			}

			case ItemType::YaraScanSystem:
			{
				break;
			}


			default:
				break; 
		}




		break;
	}

	case IOCTL_READ_COMAPI:
	{
		ULONG Pid = (ULONG)HandleToUlong(PsGetCurrentProcessId());
		if (!Pid) {
			break;
		}
		auto len = stack->Parameters.DeviceIoControl.OutputBufferLength;

		if (len < sizeof(ULONG) || len > sizeof(ULONG)) {	// check command size
			status = STATUS_INVALID_PARAMETER;
			break;
		}

		ULONG* outBuffer = (ULONG*)Irp->UserBuffer;			// METHOD_NEITHER
		if (!outBuffer) {
			status = STATUS_INVALID_PARAMETER;
			break;
		}


		if (g_Struct.ApiMonitorCommandCount == 0) {
			break;
		}

		WorkItem<ApiMonitorJob>* Command = CheckApiMonitorCommands(g_Struct.ApiMonitorCommandHead.Flink, Pid);
		if (!Command) {
			break;
		}

		KdPrint(("Reading ApiMonitor Command %d to PID: %d\n", Command->Data.Command, Pid));
		memcpy(outBuffer, &Command->Data.Command, sizeof(ULONG));
		ExFreePool(Command);

		break;
	}


	case IOCTL_WRITE_COMAPI:
	{
		auto len = stack->Parameters.DeviceIoControl.InputBufferLength;
		if (len != sizeof(ApiMonitorJob)) {
			status = STATUS_INVALID_PARAMETER;
			break;
		}

		auto entry = (WorkItem<ApiMonitorJob>*)ExAllocatePoolWithTag(NonPagedPool, sizeof(WorkItem<ApiMonitorJob>), DRIVER_TAG);
		if (!entry) {
			status = STATUS_INSUFFICIENT_RESOURCES;
			break;
		}

		memcpy(&entry->Data, stack->Parameters.DeviceIoControl.Type3InputBuffer, sizeof(ApiMonitorJob));
		if (entry->Data.Command == COMMAND_START) {
			PushItem(&entry->Entry, &g_Struct.ServiceWorkItemsHead, g_Struct.ServiceWorkItemsMutex, g_Struct.ServiceWorkItemsCount);
		}
		else if (entry->Data.Command == COMMAND_EJECT) {
			PushItem(&entry->Entry, &g_Struct.ApiMonitorCommandHead, g_Struct.ApiMonitorCommandMutex, g_Struct.ApiMonitorCommandCount);
		}
		else {
			ExFreePool(entry);
		}
		
		break;
	}

	case IOCTL_READ_APIEVENT:
	{
		


		break;
	}

	case IOCTL_API_EVENT:
	{
		KdPrint(("API EVENT\n"));
		NT_ASSERT(Irp->MdlAddress);
		//auto len = stack->Parameters.DeviceIoControl.OutputBufferLength;
		auto buffer = (UCHAR*)MmGetSystemAddressForMdlSafe(Irp->MdlAddress, NormalPagePriority);
		if (!buffer) {
			KdPrint(("Could not get MdlAddress.\n"));
			status = STATUS_INSUFFICIENT_RESOURCES;
			break;
		}

		ApiMon* mon = (ApiMon*)buffer;

		switch (mon->EventType) {
			case ApiEvent::CreateFileW:
			{
				ULONG allocSize = 0;
				allocSize += sizeof(WorkItem<ApiMon>);
				allocSize += sizeof(CreateFileWParameters);

				auto buf = (UCHAR*)ExAllocatePoolWithTag(NonPagedPool, allocSize, DRIVER_TAG);
				if (!buf) {
					break;
				}

				auto apimon = (WorkItem<ApiMon>*)buf;
				apimon->Data.size = sizeof(ApiMon) + sizeof(CreateFileWParameters);				// data only
				apimon->Data.pid = mon->pid;
				apimon->Data.EventType = ApiEvent::CreateFileW;
				memcpy(buf + sizeof(WorkItem<ApiMon>), buffer + sizeof(ApiMon), sizeof(CreateFileWParameters));


				PushItem(&apimon->Entry, &g_Struct.ApiEventHead, g_Struct.ApiEventMutex, g_Struct.ApiEventCount);
				break;
			}

			case ApiEvent::OpenProcess:
			{
				ULONG allocSize = 0;
				allocSize += sizeof(WorkItem<ApiMon>);
				allocSize += sizeof(OpenProcessParams);

				auto buf = (UCHAR*)ExAllocatePoolWithTag(NonPagedPool, allocSize, DRIVER_TAG);
				if (!buf) {
					break;
				}

				auto apimon = (WorkItem<ApiMon>*)buf;
				apimon->Data.size = sizeof(ApiMon) + sizeof(OpenProcessParams);					// data only
				apimon->Data.pid = mon->pid;
				apimon->Data.EventType = ApiEvent::OpenProcess;
				memcpy(buf + sizeof(WorkItem<ApiMon>), buffer + sizeof(ApiMon), sizeof(OpenProcessParams));


				PushItem(&apimon->Entry, &g_Struct.ApiEventHead, g_Struct.ApiEventMutex, g_Struct.ApiEventCount);
				break;
			}

			case ApiEvent::ReadFile:
			{
				ULONG allocSize = 0;
				allocSize += sizeof(WorkItem<ApiMon>);
				allocSize += sizeof(ReadFileParams);
				auto buf = (UCHAR*)ExAllocatePoolWithTag(NonPagedPool, allocSize, DRIVER_TAG);
				if (!buf) {
					break;
				}

				auto apimon = (WorkItem<ApiMon>*)buf;
				apimon->Data.size = sizeof(ApiMon) + sizeof(ReadFileParams);					// data only
				apimon->Data.pid = mon->pid;
				apimon->Data.EventType = ApiEvent::ReadFile;
				memcpy(buf + sizeof(WorkItem<ApiMon>), buffer + sizeof(ApiMon), sizeof(ReadFileParams));

				PushItem(&apimon->Entry, &g_Struct.ApiEventHead, g_Struct.ApiEventMutex, g_Struct.ApiEventCount);
				break;
			}

			case ApiEvent::WriteFile:
			{
				ULONG allocSize = 0;

				auto WriteFile = (WriteFileParams*)(buffer + sizeof(ApiMon));
				allocSize += sizeof(WorkItem<ApiMon>);
				allocSize += sizeof(OpenProcessParams);
				allocSize += WriteFile->numCopyBytes;
				auto buf = (UCHAR*)ExAllocatePoolWithTag(NonPagedPool, allocSize, DRIVER_TAG);
				if (!buf) {
					break;
				}

				auto apimon = (WorkItem<ApiMon>*)buf;
				apimon->Data.size = sizeof(ApiMon) + sizeof(WriteFileParams) + WriteFile->numCopyBytes;					// data only
				apimon->Data.pid = mon->pid;
				apimon->Data.EventType = ApiEvent::WriteFile;
				memcpy(buf + sizeof(WorkItem<ApiMon>), buffer + sizeof(ApiMon), sizeof(ReadFileParams));
				memcpy(buf + sizeof(WorkItem<ApiMon>) + sizeof(WriteFileParams), buffer + sizeof(ApiMon) + sizeof(WriteFileParams), WriteFile->numCopyBytes);

				PushItem(&apimon->Entry, &g_Struct.ApiEventHead, g_Struct.ApiEventMutex, g_Struct.ApiEventCount);
				break;
			}

			default:
				break;
		}

		break;
	}


	default:
		status = STATUS_INVALID_DEVICE_REQUEST;
		break;
	}

	CompleteIrp(Irp, status, count);
	return status;
}


void OnImageLoadNotify(PUNICODE_STRING FullImageName, HANDLE ProcessId, PIMAGE_INFO ImageInfo)
{
	return;
}

// RETURN TRUE IF A MATCH IS FOUND
bool CheckLockedRegistryKey(LIST_ENTRY* LockedKeysListHead, PCUNICODE_STRING KeyName) {
	AutoLock<FastMutex> lock(g_Struct.LockedRegMutex);

	if (IsListEmpty(&g_Struct.LockedRegHead)) {
		return false;
	}

	BlockedPathNode* entry = CONTAINING_RECORD(LockedKeysListHead, BlockedPathNode, Entry);
	BlockedPathNode* head = entry;
	
	if (!RtlCompareUnicodeString(&head->Path, KeyName, TRUE)) {
		return true;
	}
	
	BlockedPathNode* curr = CONTAINING_RECORD(head->Entry.Flink, BlockedPathNode, Entry);
	while ((uintptr_t)curr != (uintptr_t)&g_Struct.LockedRegHead) {
		KdPrint(("Checking if %ws is blocked by rule --> %ws\n", KeyName->Buffer, curr->Path.Buffer));
		if (!RtlCompareUnicodeString(&curr->Path, KeyName, TRUE)) {
			return true;
		}

		curr = CONTAINING_RECORD(curr->Entry.Flink, BlockedPathNode, Entry);
	}

	return false;
}




NTSTATUS OnRegistryNotify(PVOID context, PVOID arg1, PVOID arg2)
{
	UNREFERENCED_PARAMETER(context);
	NTSTATUS status = STATUS_SUCCESS;


	// REGISTRY TRANSLATIONS FROM USER MODE SPEAK TO DRIVER SPEAK
	// HKEY_CLASSES_ROOT	-->		\REGISTRY\MACHINE\SOFTWARE\Classes\
	// HKEY_CURRENT_USER	-->		\REGISTRY\USER\SID
	// HKEY_LOCAL_MACHINE	-->		\REGISTRY\MACHINE\
	// HKEY_USERS			-->		\REGISTRY\USER\
	// HKEY_CURRENT_CONFIG  -->		\REGISTRY\MACHINE\SYSTEM\ControlSet001\Hardware Profiles\0001\


	static const WCHAR hKeyClasses[] =				L"\\REGISTRY\\MACHINE\\SOFTWARE\\Classes\\";
	static const WCHAR hKeyCurrentUser[] =			L"\\REGISTRY\\USER\\SID";
	static const WCHAR hKeyLocalMachine[] =			L"\\REGISTRY\\MACHINE\\";
	static const WCHAR hKeyUsers[] =				L"\\REGISTRY\\USER\\";
	static const WCHAR hKeyCurrConfig[] =			L"\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet001\\Hardware Profiles\\0001\\";
	



	switch ((REG_NOTIFY_CLASS)(ULONG_PTR)arg1) 
	{
		case RegNtPreSetValueKey:
		{
			auto args = static_cast<REG_SET_VALUE_KEY_INFORMATION*> (arg2);

			PCUNICODE_STRING name;
			// WE WILL TRANSLATE EACH DRIVER REGISTRY PATH TO A USERMODE PATH AND THEN COMPARE TO THE PROTECTED KEYS
			if (NT_SUCCESS(CmCallbackGetKeyObjectIDEx(&g_Struct.RegCookie, args->Object, nullptr, &name, 0))) {
				// filter out none-HKLM writes
				KdPrint(("Registry Key set value: %wZ\n", name));
				bool check = false;
				check = CheckLockedRegistryKey(g_Struct.LockedRegHead.Flink, name);
				if (check) {
					status = STATUS_ACCESS_DENIED;
				}


				CmCallbackReleaseKeyObjectIDEx(name);
				break;

			}
		}
			
	}

	return status;
}

	
