#pragma once
#include <Windows.h>
#include <string>
#include <vector>
#include <algorithm>
#include "RAII.h"

std::string ConvToLowerA(std::string a);


BOOL VectorContainsStringA(std::vector<std::string> haystack, std::string needle);


std::string WstringToString(std::wstring wstr);