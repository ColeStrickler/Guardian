#pragma once
#include "Hook.h"
#include "RAII.h"

#define IOCTL_STOP_APIMON CTL_CODE(0x8000, 0x806, METHOD_NEITHER, FILE_ANY_ACCESS)
#define IOCTL_API_EVENT CTL_CODE(0x8000, 0x807, METHOD_IN_DIRECT, FILE_ANY_ACCESS)
#define IOCTL_READ_COMAPI CTL_CODE(0x8000, 0x808, METHOD_NEITHER, FILE_ANY_ACCESS)


#define COMMAND_EJECT ULONG(1)

enum class ApiEvent : short {
	OpenProcess,
	CreateFileW,
	ReadFile,
	WriteFile
};



template<typename T>
struct WorkItem {
	SLIST_ENTRY Entry;
	T Data;
};


struct ApiMon {
	ApiEvent EventType;
	ULONG pid;
};





template<class T>
struct HookDriver {
	HookDriver(std::vector<HookFuncs>& InitStruct) : HookClassType(HookClass) {
		HookClassType.InitHooks(InitStruct);
	}

	~HookDriver() {
		HookClassType.RemoveHooks();
	}

private:
	T& HookClassType;
};

template<class T>
class Manager
{
public:
	Manager<Hook::x64>(std::vector<HookFuncs>& InitStuct, SLIST_HEADER& GlobalLinkedList, HANDLE& GlobalDriverHandle);
	Manager<Hook::x86>(std::vector<HookFuncs>& InitStuct, SLIST_HEADER& GlobalLinkedList, HANDLE& GlobalDriverHandle);
	~Manager();

private:
	static void GetDriverCommands();


public:
	static bool StartupSuccess;
	static bool ExitVar;

private:
	SLIST_HEADER ApiEventSLL;
	HookDriver<T> HookEngine;
	static HANDLE hCommandThread;
	static HANDLE hDriverFile;
	



};

