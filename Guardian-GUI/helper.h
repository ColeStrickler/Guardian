#pragma once
#include <Windows.h>
#include <lm.h>
#include <string>
#include <cassert>
#include <vector>
#include <TlHelp32.h>
#include "RAII.h"

#define Process32First Process32First
#define Process32Next Process32Next
#define PROCESSENTRY32 PROCESSENTRY32

std::string DisplayTime(const LARGE_INTEGER& time);
BOOL DirExists(LPCSTR szPath);
BOOL FileExists(LPCTSTR szPath);
std::vector<std::wstring> listUsers();
BOOL ProcIdExists(DWORD procId);
std::string GetProcnameFromId(DWORD procId);