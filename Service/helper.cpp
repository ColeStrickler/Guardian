#include "helper.h"



std::string ConvToLowerA(std::string a)
{
	std::transform(a.begin(), a.end(), a.begin(), ::tolower);
	return a;
}

BOOL VectorContainsStringA(std::vector<std::string> haystack, std::string needle)
{
	for (std::string& hay : haystack)
	{
		if (ConvToLowerA(hay) == ConvToLowerA(needle))
		{
			return TRUE;
		}
	}
	return FALSE;
}


std::string WstringToString(std::wstring wstr) {
	DWORD len = wcslen(wstr.data()) + 1;
	RAII::HeapBuffer strbuffer(len);
	sprintf_s((char*)strbuffer.Get(), len, "%ws", wstr.data());
	std::string ret = std::string((char*)strbuffer.Get());
	return ret;
}


std::string ReadFileToStringA(std::string path)
{
	std::ifstream t(path);
	std::string str((std::istreambuf_iterator<char>(t)), std::istreambuf_iterator<char>());
	return str;
}


BOOL ProcIdExists(DWORD procId)
{
	BOOL ret = false;
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if (hSnap != INVALID_HANDLE_VALUE)
	{
		PROCESSENTRY32 procEntry;
		procEntry.dwSize = sizeof(procEntry);

		if (Process32First(hSnap, &procEntry))
		{
			do
			{
				if (procEntry.th32ProcessID == procId)
				{
					procId = true;
					break;
				}
			} while (Process32Next(hSnap, &procEntry));
		}
	}
	CloseHandle(hSnap);
	return procId;
}


std::string GetProcnameFromId(DWORD procId)
{
	std::string ret;
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if (hSnap != INVALID_HANDLE_VALUE)
	{
		PROCESSENTRY32 procEntry;
		procEntry.dwSize = sizeof(procEntry);

		if (Process32First(hSnap, &procEntry))
		{
			do
			{
				if (procEntry.th32ProcessID == procId)
				{
					ret = std::string(procEntry.szExeFile);
					break;
				}
			} while (Process32Next(hSnap, &procEntry));
		}
	}
	CloseHandle(hSnap);
	return ret;
}