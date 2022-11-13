#pragma once
#include <Windows.h>
#include <lm.h>
#include <string>
#include <cassert>
#include <vector>
#include "RAII.h"



std::string DisplayTime(const LARGE_INTEGER& time);
BOOL DirExists(LPCSTR szPath);
BOOL FileExists(LPCTSTR szPath);
std::vector<std::wstring> listUsers();