#include "DllThreadInjector.h"




Injector::DllThreadInjector::DllThreadInjector()
{

}

Injector::DllThreadInjector::~DllThreadInjector()
{

}

bool Injector::DllThreadInjector::InjectDll(DWORD procId, const char* dllPath)
{

	HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, 0, procId);
	if (hProc && hProc != INVALID_HANDLE_VALUE) {
		void* WriteLocation = VirtualAllocEx(hProc, 0, MAX_PATH, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		bool write = WriteProcessMemory(hProc, WriteLocation, dllPath, strlen(dllPath) + 1, 0);
		if (!write) {
			return false;
		}

		HANDLE hThread = CreateRemoteThread(hProc, 0, 0, (LPTHREAD_START_ROUTINE)LoadLibraryA, WriteLocation, 0, 0);
		if (hThread) {
			CloseHandle(hThread);
			if (hProc) {
				CloseHandle(hProc);
			}
			return TRUE;
		}

	}

	if (hProc) {
		CloseHandle(hProc);
	}

	return FALSE;
}