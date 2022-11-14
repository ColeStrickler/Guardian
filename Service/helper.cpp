#include "helper.h"



std::string ConvToLowerA(std::string a)
{
	std::transform(a.begin(), a.end(), a.begin(), ::tolower);
	return a;
}
BOOL VectorContainsStringA(std::vector<std::string> haystack, std::string
	needle)
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
