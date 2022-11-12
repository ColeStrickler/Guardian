#include "driver.h"
#include <stdlib.h>
#pragma warning(disable: 4100)
#pragma warning(disable: 4996)



DRIVER_UNLOAD Unload;
DRIVER_DISPATCH CreateClose, Read, Write, IoControl;
void OnProcessNotify(PEPROCESS Process, HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO CreateInfo);
void OnThreadNotify(HANDLE ProcessId, HANDLE ThreadId, BOOLEAN Create);
void OnImageLoadNotify(PUNICODE_STRING FullImageName, HANDLE ProcessId, PIMAGE_INFO ImageInfo);



struct Globals {
	LIST_ENTRY AlertsHead{0};
	int AlertCount{0};
	FastMutex AlertsHeadMutex;
	RTL_OSVERSIONINFOW versionInfo{0};
	ConfigFiles ConfigurationFiles{0};
	LIST_ENTRY BlockedPathsHead{0};
	int BlockedPathsCount{0};
	FastMutex BlockedPathsMutex;
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
	KdPrint(("In string: %s", text));
	size_t size = (strlen(text) + 1) * sizeof(wchar_t);
	KdPrint(("Size: %d", size));
	wchar_t* wText = (wchar_t*)ExAllocatePoolWithTag(NonPagedPool, size, 'grdn');
	memset(wText, 0, size);
	mbstowcs(wText, text, (strlen(text)));
	KdPrint(("wText: %ws", wText));
	RtlInitUnicodeString(&outstring, wText);
	KdPrint(("Generated outstring %wZ", outstring));
	ExFreePool(wText);
}

void PushItem(LIST_ENTRY* entry, LIST_ENTRY* ListHead, FastMutex& Mutex, int& count) {
	AutoLock<FastMutex> lock(Mutex);

	// too many items, remove oldest
	if (g_Struct.AlertCount > 1024) {
		auto head = RemoveHeadList(ListHead);
		g_Struct.AlertCount--;
		auto item = CONTAINING_RECORD(head, Alert<Header>, Entry);
		ExFreePool(item);
	}
	InsertTailList(ListHead, entry);
	count++;
}

NTSTATUS InitBlockedExecutionPaths() {
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
		KdPrint(("ZwCreateFileFailed"));
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
	KdPrint(("Read file: blockConfigFile size : %d", (int)fileInfo.EndOfFile.QuadPart));

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
			KdPrint(("Found path: %s", filePathName));
			BlockedPathNode* NewEntry = (BlockedPathNode*)ExAllocatePoolWithTag(NonPagedPool, sizeof(BlockedPathNode), DRIVER_TAG);
			charToUnicodeString(filePathName, NewEntry->Path);
			PushItem(&NewEntry->Entry, &g_Struct.BlockedPathsHead, g_Struct.BlockedPathsMutex, g_Struct.BlockedPathsCount);
			KdPrint(("Added path %wZ to block list!", &NewEntry->Path));
			memset(filePathName, 0, 260); // set back to 0
			i += 2;
		}

	}



	if (!NT_SUCCESS(status)) {
		ZwClose(hFile);
	}


	ZwClose(hFile);
	return status;
}


extern "C" NTSTATUS
DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING) {
	auto status = STATUS_SUCCESS;
	
	PDEVICE_OBJECT DeviceObject = nullptr;
	UNICODE_STRING symLink = RTL_CONSTANT_STRING(L"\\??\\guardian");
	UNICODE_STRING devName = RTL_CONSTANT_STRING(L"\\device\\guardian");
	bool symLinkCreated = false; 
	bool processCallbacks = false, threadCallbacks = false, imageLoadCallbacks = false;

	InitializeListHead(&g_Struct.AlertsHead);
	InitializeListHead(&g_Struct.BlockedPathsHead);
	g_Struct.AlertsHeadMutex.Init();
	g_Struct.BlockedPathsMutex.Init();
	RtlGetVersion(&g_Struct.versionInfo);
	KdPrint(("Version %d.%d.%d found!", g_Struct.versionInfo.dwMajorVersion, g_Struct.versionInfo.dwMinorVersion, g_Struct.versionInfo.dwBuildNumber));
	
	do {
		status = IoCreateDevice(DriverObject, 0, &devName, FILE_DEVICE_UNKNOWN, 0, TRUE, &DeviceObject);
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


		status = InitBlockedExecutionPaths();
		if (!NT_SUCCESS(status)) {
			KdPrint((DRIVER_PREFIX "failed to get blocked execution paths!"));
			break;
		}
		KdPrint((DRIVER_PREFIX "successfully fetched blocked execution paths!"));


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

		}	
	}



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
	NTSTATUS status = STATUS_SUCCESS;
	auto stack = IoGetCurrentIrpStackLocation(Irp);
	auto len = stack->Parameters.DeviceIoControl.InputBufferLength;
	KdPrint(("Control Code: 0x%8X", stack->Parameters.DeviceIoControl.IoControlCode));
	switch (stack->Parameters.DeviceIoControl.IoControlCode)
	{
	case IOCTL_ADDFILE_BLACKLIST:
	{
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
			ExFreePool(NewBlockedPathNode);
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
	default:
		status = STATUS_INVALID_DEVICE_REQUEST;
		break;
	}

	CompleteIrp(Irp, status);
	return status;
}


void OnImageLoadNotify(PUNICODE_STRING FullImageName, HANDLE ProcessId, PIMAGE_INFO ImageInfo) {
	return;
}