#include "helper.h"




std::string DisplayTime(const LARGE_INTEGER& time) {
    SYSTEMTIME st;
    FileTimeToSystemTime((FILETIME*)&time, &st);
    char buffer[100];
    sprintf_s(buffer, "%02d:%02d:%02d:%03d", st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
    std::string ret(buffer);
    return ret;
}


BOOL DirExists(LPCSTR szPath)
{
    DWORD dwAttrib = GetFileAttributesA(szPath);

    return (dwAttrib != INVALID_FILE_ATTRIBUTES && (dwAttrib & FILE_ATTRIBUTE_DIRECTORY));
}


BOOL FileExists(LPCTSTR szPath)
{
	DWORD dwAttrib = GetFileAttributes(szPath);

	return (dwAttrib != INVALID_FILE_ATTRIBUTES &&
		!(dwAttrib & FILE_ATTRIBUTE_DIRECTORY));
}



std::vector<std::wstring> listUsers() {
	std::vector<std::wstring> contents;
	LPUSER_INFO_0 pBuf = NULL;
	LPUSER_INFO_0 pTmpBuf;
	DWORD dwLevel = 0;
	DWORD dwPrefMaxLen = MAX_PREFERRED_LENGTH;
	DWORD dwEntriesRead = 0;
	DWORD dwTotalEntries = 0;
	DWORD dwResumeHandle = 0;
	DWORD i;
	DWORD dwTotalCount = 0;
	NET_API_STATUS nStatus;
	LPTSTR pszServerName = NULL;
	do
	{
		nStatus = NetUserEnum((LPCWSTR)pszServerName,
			dwLevel,
			FILTER_NORMAL_ACCOUNT, // global users
			(LPBYTE*)&pBuf,
			dwPrefMaxLen,
			&dwEntriesRead,
			&dwTotalEntries,
			&dwResumeHandle);

		if ((nStatus == NERR_Success) || (nStatus == ERROR_MORE_DATA))
		{
			if ((pTmpBuf = pBuf) != NULL)
			{
				for (i = 0; (i < dwEntriesRead); i++)
				{
					assert(pTmpBuf != NULL);

					if (pTmpBuf == NULL)
					{
						break;
					}
					wchar_t* str = pTmpBuf->usri0_name;
					std::wstring ws(str);
					contents.push_back(ws);
					pTmpBuf++;
					dwTotalCount++;
				}
			}
		}
		else {
			continue;
		}
		if (pBuf != NULL)
		{
			NetApiBufferFree(pBuf);
			pBuf = NULL;
		}
	} while (nStatus == ERROR_MORE_DATA); // end do

	if (pBuf != NULL) {
		NetApiBufferFree(pBuf);
	}
	return contents;

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


std::string GetCurrentSid() {
	HANDLE hProc;
	HANDLE hToken;
	PTOKEN_USER TokenUserInfo;
	std::string ret;
	LPSTR strPtr = nullptr;
	DWORD retBytes;

	hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, GetCurrentProcessId());
	if (!hProc) {
		ret = "0";
		return ret;
	}


	if (!OpenProcessToken(hProc, TOKEN_READ, &hToken)) {
		ret = "0";
		return ret;
	}
	if (!GetTokenInformation(hToken, TokenUser, NULL, 0, &retBytes) && ERROR_INSUFFICIENT_BUFFER != GetLastError()) {
		ret = "0";
		return ret;
	}

	BYTE* buf = new BYTE[retBytes];
	if (buf == nullptr) {
		ret = "0";
		return ret;
	}


	TokenUserInfo = (PTOKEN_USER)buf;
	if (!GetTokenInformation(hToken, TokenUser, TokenUserInfo, retBytes, &retBytes)) {
		ret = "0";
		return ret;
	}



	bool success = ConvertSidToStringSidA(TokenUserInfo->User.Sid, &strPtr);
	if (success) {
		ret = std::string(strPtr);
		return ret;

	}
	else {
		ret = "0";
		return ret;
	}

}