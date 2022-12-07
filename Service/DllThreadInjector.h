#pragma once
#include <Windows.h>
namespace Injector {

	class DllThreadInjector {
	public:
		DllThreadInjector();
		~DllThreadInjector();
		bool InjectDll(DWORD procId, const char* DllPath);
	};


}

