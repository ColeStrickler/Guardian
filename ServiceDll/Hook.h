#pragma once
#include <Windows.h>
#include <TlHelp32.h>
#include <map>
#include <vector>
// Must include the actual folder in the additional include settings
#include "capstone/capstone.h"





struct X64Instructions
{
	cs_insn* instructions;
	cs_insn* nonModifyInstructions;
	uint32_t numInstructions;
	uint32_t numBytes;
};

struct X86Instructions
{
	cs_insn* instructions;
	BYTE* OriginalInstructions;
	uint32_t numInstructions;
	uint32_t numBytes;
};


struct HookInfo64 {
	X64Instructions StolenBytes;
	uintptr_t HookedFunctionAddress;
	DWORD TrampolineSize;
};

struct HookInfo86 {
	X86Instructions StolenBytes;
	DWORD HookedFunctionAddress;
	DWORD PageAddress;
};

struct HookFuncs {
	void* TrampolineFunc;
	void* HookFunction;
	const char* dllName;
	const char* funcName;
};



// HELPER FUNCTIONS X64
template<class T> T GetDisplacement(cs_insn* inst, uint8_t offset);
bool IsRelativeCall(cs_insn& inst);
bool IsRelativeJump(cs_insn& inst);
bool IsRIPRelativeInstr(cs_insn& inst);

namespace Hook {

	class x64 {
	public:
		x64();
		x64(std::vector<HookFuncs>& hookFuncs);
		~x64();
		void InstallHook(void* func2hook, void* payloadFunc, void** trampolinePtr);
		uintptr_t GetBaseAddress(wchar_t* modName);
		uintptr_t GetFuncAddress(LPCSTR ModuleName, LPCSTR FunctionName);
		X64Instructions StealBytes(void* TgtFunc);
		uint32_t BuildTrampoline(void* func2hook, void* dstMemForTrampoline);
		void InitHooks(std::vector<HookFuncs>& hookFuncs);
		void RemoveHooks();
	private:
		void* AllocatePageNearAddress(void* targetAddr);
		void WriteAbsoluteJump64(void* absJumpMemory, void* addrToJumpTo);
		void RelocateInstruction(cs_insn* inst, void* dstLocation);
		uint32_t AddJmpToAbsTable(cs_insn& jmp, uint8_t* absTableMem);
		uint32_t AddCallToAbsTable(cs_insn& call, uint8_t* absTableMem, uint8_t* jumpBackToHookedFunc);
		void RewriteStolenCallInstruction(cs_insn* instr, uint8_t* instrPtr, uint8_t* absTableEntry);
		void RewriteStolenJumpInstruction(cs_insn* instr, uint8_t* instrPtr, uint8_t* absTableEntry);
	public:
		std::vector<HookInfo64> Hooks;
		BYTE* PageAddress;
	};

	class x86 {
	public:
		x86();
		~x86();
		void InstallHook(void* func2hook, void* payloadFunc, void** trampolinePtr);
		DWORD GetBaseAddress(wchar_t* modName);
		DWORD GetFuncAddress(LPCSTR ModuleName, LPCSTR FunctionName);
		void InitHooks(std::vector<HookFuncs>& hookFuncs);
		void RemoveHooks();
	private:
		X86Instructions StealBytes(void* TgtFunc);
		void WriteTrampoline(void* TgtFunc, void* TrampolineMemory, X86Instructions& StolenInstructions);
		DWORD CalculateRelativeJmp(void* Src, void* Dst);
		void* FixupAndWriteStolenInstructions(void* TgtFunc, void* JmpSrc, X86Instructions& Instructions);
	public:
		std::vector<HookInfo86> Hooks;
	};

}