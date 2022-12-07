#include "Manager.h"

HANDLE Manager::hDriverFile;
bool Manager::ExitVar;

Manager::Manager(std::vector<HookFuncs>& InitStruct, SLIST_HEADER& GlobalLinkedList, HANDLE& GlobalDriverHandle) : ApiEventSLL(GlobalLinkedList)
{
	StartupSuccess = TRUE;
	ExitVar = FALSE;
	GlobalDriverHandle = CreateFile(L"\\\\.\\guardian", GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
	hDriverFile = GlobalDriverHandle;
	if (!hDriverFile) {
		StartupSuccess = FALSE;
		printf("could not get handle to driver file\n");
		return;
	}
	printf("Got Handle to driver symlink\n");
	
	IsWow64Process(GetCurrentProcess(), &wow64);
	if (wow64) {
		printf("32bit\n");
		HookEngine86.InitHooks(InitStruct);
	}
	else {
		printf("64bit\n");
		HookEngine64.InitHooks(InitStruct);
	}



	hCommandThread = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)GetDriverCommands, 0, 0, 0);
	if (!hCommandThread) {
		StartupSuccess = FALSE;
		printf("Could not start command thread\n");
		return;
	}

	printf("Created thread!\n");
};




Manager::~Manager()
{
	if (hCommandThread) {
		BOOL threadExitCheck = TerminateThread(hCommandThread, 0);
	}

	if (hDriverFile) {
		BOOL closeHandleCheck = CloseHandle(hDriverFile);
	}

	if (wow64) {
		HookEngine86.RemoveHooks();
	}
	else {
		HookEngine64.RemoveHooks();
	}
};



void Manager::GetDriverCommands()
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
		Sleep(4000);
	}
}
