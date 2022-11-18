#pragma once
#include <Windows.h>
#include <string>
#include <vector>
#include <algorithm>
#include <filesystem>
#include <fstream>
#include <TlHelp32.h>
#include "RAII.h"


#define Process32First Process32First
#define Process32Next Process32Next
#define PROCESSENTRY32 PROCESSENTRY32
std::string ConvToLowerA(std::string a);


BOOL VectorContainsStringA(std::vector<std::string> haystack, std::string needle);


std::string WstringToString(std::wstring wstr);


std::string ReadFileToStringA(std::string path);

BOOL ProcIdExists(DWORD procId);

std::string GetProcnameFromId(DWORD procId);