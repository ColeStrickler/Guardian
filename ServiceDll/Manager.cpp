#include "Manager.h"




Manager<Hook::x64>::Manager(std::vector<HookFuncs>& InitStruct, SLIST_HEADER& GlobalLinkedList, HANDLE& GlobalDriverHandle) : HookEngine(InitStruct), ApiEventSLL(GlobalLinkedList)
{
	StartupSuccess = TRUE;
	ExitVar = FALSE;

	GlobalDriverHandle = CreateFile(L"\\\\.\\guardian", GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
	hDriverFile = GlobalDriverHandle;
	if (!hDriverFile) {
		StartupSuccess = FALSE;
		return;
	}

	hCommandThread = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)GetDriverCommands, 0, 0, 0);
	if (!hCommandThread) {
		StartupSuccess = FALSE;
		return;
	}

};


Manager<Hook::x64>::~Manager()
{
	
	if (hCommandThread) {
		BOOL threadExitCheck = TerminateThread(hCommandThread, 0);
	}
	
	if (hDriverFile) {
		BOOL closeHandleCheck = CloseHandle(hDriverFile);
	}

};



Manager<Hook::x86>::Manager(std::vector<HookFuncs>& InitStruct, SLIST_HEADER& GlobalLinkedList, HANDLE& GlobalDriverHandle) : HookEngine(InitStruct), ApiEventSLL(GlobalLinkedList)
{

	StartupSuccess = TRUE;
	ExitVar = FALSE;

	GlobalDriverHandle = CreateFile(L"\\\\.\\guardian", GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
	hDriverFile = GlobalDriverHandle;
	if (!hDriverFile) {
		StartupSuccess = FALSE;
		return;
	}

	hCommandThread = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)GetDriverCommands, 0, 0, 0);
	if (!hCommandThread) {
		StartupSuccess = FALSE;
		return;
	}
}


Manager<Hook::x86>::~Manager()
{
	if (hCommandThread) {
		BOOL threadExitCheck = TerminateThread(hCommandThread, 0);
	}

	if (hDriverFile) {
		BOOL closeHandleCheck = CloseHandle(hDriverFile);
	}
};










// FUNCTIONS THAT ARE THE SAME ARE DOWN HERE

void Manager<Hook::x64>::GetDriverCommands()
{
	while (true) {
		DWORD bytes;
		ULONG CommandCode;

		DeviceIoControl(
			hDriverFile,
			IOCTL_READ_COMAPI,
			0,
			0,
			&CommandCode,
			sizeof(ULONG),
			&bytes,
			nullptr
		);

		if (bytes > 0) {
			if (CommandCode == COMMAND_EJECT) {
				ExitVar = TRUE;
			}
		}
		Sleep(200);
	}
}

void Manager<Hook::x86>::GetDriverCommands()
{
	while (true) {
		DWORD bytes;
		ULONG CommandCode;

		DeviceIoControl(
			hDriverFile,
			IOCTL_READ_COMAPI,
			0,
			0,
			&CommandCode,
			sizeof(ULONG),
			&bytes,
			nullptr
		);

		if (bytes > 0) {
			if (CommandCode == COMMAND_EJECT) {
				ExitVar = TRUE;
			}
		}
		Sleep(200);
	}
}
