#include "helper.h"



inline std::string ConvToLowerA(std::string a)
{
	std::transform(a.begin(), a.end(), a.begin(), ::tolower);
	return a;
}
inline BOOL VectorContainsStringA(std::vector<std::string> haystack, std::string
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
