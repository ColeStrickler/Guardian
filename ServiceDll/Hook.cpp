#include "Hook.h"



Hook::x86::x86()
{

}

Hook::x86::~x86()
{

}

DWORD Hook::x86::GetBaseAddress(wchar_t* modName) {
	DWORD modBase = 0;
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, GetCurrentProcessId());
	if (hSnap && hSnap != INVALID_HANDLE_VALUE) {
		MODULEENTRY32 modEntry;
		modEntry.dwSize = sizeof(MODULEENTRY32);
		if (Module32First(hSnap, &modEntry)) {
			do {
				if (!_wcsicmp(modEntry.szModule, modName)) {
					modBase = (DWORD)modEntry.modBaseAddr;
					break;
				}
			} while (Module32Next(hSnap, &modEntry));
		}
		CloseHandle(hSnap);
		return modBase;
	}
	else {
		return NULL;
	}
}


DWORD Hook::x86::GetFuncAddress(LPCSTR ModuleName, LPCSTR FunctionName)
{
	DWORD ret = 0;
	HMODULE hModule = GetModuleHandleA(ModuleName);
	if (!hModule) {
		return ret;
	}
	return (DWORD)GetProcAddress(hModule, FunctionName);
}


void Hook::x86::InitHooks(std::vector<HookFuncs>& hookFuncs)
{
	for (auto& hook : hookFuncs) {
		void* TgtFunc = (void*)GetFuncAddress(hook.dllName, hook.funcName);
		if (!TgtFunc) {
			//printf("Did not find address\n");
			continue;
		}
		//	printf("Installing hook for %s at address: 0x%lx, HookFunction: 0x%lx, Trampoline: 0x%lx\n", hook.funcName, TgtFunc, hook.HookFunction, *(void**)hook.TrampolineFunc);
		InstallHook(TgtFunc, hook.HookFunction, (void**)hook.TrampolineFunc);
		//	printf("Resulting hook for %s at address: 0x%lx, HookFunction: 0x%lx, Trampoline: 0x%lx\n", hook.funcName, TgtFunc, hook.HookFunction, *(void**)hook.TrampolineFunc);
	}

}


X86Instructions Hook::x86::StealBytes(void* TgtFunc)
{

	//Sleep(5000);
	// Disassemble stolen bytes
	csh handle;
	csh handle2;
	cs_open(CS_ARCH_X86, CS_MODE_32, &handle);
	cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON); // turn ON detail feature with CS_OPT_ON
	cs_open(CS_ARCH_X86, CS_MODE_32, &handle2);

	size_t count;
	size_t count2;
	cs_insn* disassembledInstructions; //allocated by cs_disasm, needs to be manually freed later
	cs_insn* nonModifyInstructions;
	count = cs_disasm(handle, (uint8_t*)TgtFunc, 20, (uint64_t)TgtFunc, 20, &disassembledInstructions);
	count2 = cs_disasm(handle2, (uint8_t*)TgtFunc, 20, (uint64_t)TgtFunc, 20, &nonModifyInstructions);


	//get the instructions covered by the first 5 bytes of the original function
	uint32_t byteCount = 0;
	uint32_t stolenInstrCount = 0;
	for (int32_t i = 0; i < count; ++i)
	{
		cs_insn& inst = disassembledInstructions[i];
		byteCount += inst.size;
		stolenInstrCount++;
		if (byteCount >= 5) break;
	}

	//replace stolen instructions in target func wtih NOPs, so that when we jump
	//back to the target function, we don't have to care about how many
	//bytes were stolen
	BYTE* OriginalInstructions = new BYTE[byteCount];
	memcpy(OriginalInstructions, TgtFunc, byteCount);

	memset(TgtFunc, 0x90, byteCount);
	cs_close(&handle);
	cs_close(&handle2);

	return { disassembledInstructions, OriginalInstructions, stolenInstrCount, byteCount };
}

DWORD Hook::x86::CalculateRelativeJmp(void* Src, void* Dst)
{
	return (DWORD)((DWORD)Dst - (DWORD)Src - 5);
}

void* Hook::x86::FixupAndWriteStolenInstructions(void* TgtFunc, void* JmpSrc, X86Instructions& Instructions)
{
	BYTE* Src = (BYTE*)JmpSrc;
	for (int i = 0; i < Instructions.numInstructions; i++) {
		auto& inst = Instructions.instructions[i];
		if (IsRelativeJump(inst)) {
			DWORD jmpOp;
			memcpy(&jmpOp, inst.bytes + 1, 4);
			DWORD OriginalDst = (DWORD)TgtFunc + CalculateRelativeJmp(TgtFunc, (void*)jmpOp);
			DWORD NewJmpOp = CalculateRelativeJmp(Src, (void*)OriginalDst);
			memcpy(inst.bytes, &NewJmpOp, 4);
		}
		memcpy(Src, inst.bytes, inst.size);
		Src += inst.size;
	}
	return (void*)Src;
}



void Hook::x86::WriteTrampoline(void* TgtFunc, void* TrampolineMemory, X86Instructions& StolenInstructions)
{
	TrampolineMemory = FixupAndWriteStolenInstructions(TgtFunc, TrampolineMemory, StolenInstructions);
	BYTE JmpBack[] = { 0xE9, 0x00, 0x00, 0x00, 0x00 };
	DWORD RelAddr = CalculateRelativeJmp(TrampolineMemory, (BYTE*)TgtFunc + 5);
	memcpy(JmpBack + 1, &RelAddr, 4);
	memcpy(TrampolineMemory, JmpBack, 5);
}


void Hook::x86::InstallHook(void* func2hook, void* payloadFunc, void** trampolinePtr) {
	HookInfo86 hook;
	DWORD oldProtect;

	VirtualProtect(func2hook, 512, PAGE_EXECUTE_READWRITE, &oldProtect);

	LPVOID trampolineMem;
	BYTE* check = new BYTE[5];
	memcpy(check, func2hook, 5);
	//for (int i = 0; i < 5; i++) {
	//	printf("%x,", check[i]);
	//}
	//Sleep(5000);
	X86Instructions Instructions = StealBytes(func2hook);
	trampolineMem = VirtualAlloc(0, 512, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!trampolineMem) {
		return;
	}
	hook.PageAddress = (DWORD)trampolineMem;
	//printf("trampoline before: %lx\n", *trampolinePtr);
	*trampolinePtr = trampolineMem;
	//printf("trampoline after: %lx\n", *trampolinePtr);
	WriteTrampoline(func2hook, trampolineMem, Instructions);

	BYTE HookJmp[] = { 0xE9, 0x00, 0x00, 0x00, 0x00 };
	DWORD RelAddr = CalculateRelativeJmp(func2hook, payloadFunc);
	memcpy(HookJmp + 1, &RelAddr, 4);
	memcpy(func2hook, HookJmp, 5);



	hook.HookedFunctionAddress = (DWORD)func2hook;
	hook.StolenBytes = Instructions;
	Hooks.push_back(hook);

	VirtualProtect(func2hook, 512, oldProtect, &oldProtect);
}


void Hook::x86::RemoveHooks()
{

	DWORD oldProtect;
	for (auto& hook : Hooks) {
		auto& inst = hook.StolenBytes;
		VirtualProtect((void*)hook.HookedFunctionAddress, 512, PAGE_EXECUTE_READWRITE, &oldProtect);
		//printf("\nCopying %d bytes back..\n", inst.numBytes);
		//for (int i = 0; i < inst.numBytes; i++) {
		//	printf("0x%x,", inst.OriginalInstructions[i]);
		//}
		memcpy((void*)hook.HookedFunctionAddress, inst.OriginalInstructions, inst.numBytes);
		free(inst.instructions);
		free(inst.OriginalInstructions);
		VirtualProtect((void*)hook.HookedFunctionAddress, 512, oldProtect, &oldProtect);
		VirtualFree((void*)hook.PageAddress, 512, MEM_DECOMMIT);
	}
	Hooks.clear();
}

Hook::x64::x64()
{
	PageAddress = nullptr;
}

Hook::x64::x64(std::vector<HookFuncs>& hookFuncs)
{
	PageAddress = nullptr;
	InitHooks(hookFuncs);
}

Hook::x64::~x64()
{
	RemoveHooks();
}

void Hook::x64::InstallHook(void* func2hook, void* payloadFunc, void** trampolinePtr)
{
	DWORD oldProtect;
	VirtualProtect(func2hook, 1024, PAGE_EXECUTE_READWRITE, &oldProtect);
	void* hookMemory = AllocatePageNearAddress(func2hook);


	uint32_t trampolineSize = BuildTrampoline(func2hook, hookMemory);
	*trampolinePtr = hookMemory;
	printf("Trampoline is built at %llx\n", *trampolinePtr);
	// Increase Global ptr
	PageAddress += trampolineSize += 0x30;

	//create the relay function
	void* relayFuncMemory = (char*)hookMemory + trampolineSize;
	WriteAbsoluteJump64(relayFuncMemory, payloadFunc); //write relay func instructions
	//printf("Absolute Jump is written\n");

	//install the hook
	uint8_t jmpInstruction[5] = { 0xE9, 0x0, 0x0, 0x0, 0x0 };
	const int32_t relAddr = (int32_t)relayFuncMemory - ((int32_t)func2hook + sizeof(jmpInstruction));
	memcpy(jmpInstruction + 1, &relAddr, 4);
	memcpy(func2hook, jmpInstruction, sizeof(jmpInstruction));
	//printf("finished installing hook!\n");
}

void Hook::x64::WriteAbsoluteJump64(void* absJumpMemory, void* addrToJumpTo)
{
	uint8_t absJumpInstructions[] = { 0x49, 0xBA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					  0x41, 0xFF, 0xE2 };

	uint64_t addrToJumpTo64 = (uint64_t)addrToJumpTo;
	memcpy(&absJumpInstructions[2], &addrToJumpTo64, sizeof(addrToJumpTo64));
	memcpy(absJumpMemory, absJumpInstructions, sizeof(absJumpInstructions));
}

uintptr_t Hook::x64::GetFuncAddress(LPCSTR ModuleName, LPCSTR FunctionName)
{
	uintptr_t ret = 0;
	HMODULE hModule = GetModuleHandleA(ModuleName);
	if (!hModule) {
		return ret;
	}
	return (uintptr_t)GetProcAddress(hModule, FunctionName);
}


uintptr_t Hook::x64::GetBaseAddress(wchar_t* modName) {
	uintptr_t modBase = 0;
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, GetCurrentProcessId());
	if (hSnap && hSnap != INVALID_HANDLE_VALUE) {
		MODULEENTRY32 modEntry;
		modEntry.dwSize = sizeof(MODULEENTRY32);
		if (Module32First(hSnap, &modEntry)) {
			do {
				if (!_wcsicmp(modEntry.szModule, modName)) {
					modBase = (uintptr_t)modEntry.modBaseAddr;
					break;
				}
			} while (Module32Next(hSnap, &modEntry));
		}
		CloseHandle(hSnap);
		return modBase;
	}
	else {
		return NULL;
	}
}

void* Hook::x64::AllocatePageNearAddress(void* targetAddr)
{
	SYSTEM_INFO sysInfo;
	GetSystemInfo(&sysInfo);
	const uint64_t PAGE_SIZE = sysInfo.dwPageSize;

	uint64_t startAddr = (uint64_t(targetAddr) & ~(PAGE_SIZE - 1)); //round down to nearest page boundary
	uint64_t minAddr = min(startAddr - 0x7FFFFF00, (uint64_t)sysInfo.lpMinimumApplicationAddress);
	uint64_t maxAddr = max(startAddr + 0x7FFFFF00, (uint64_t)sysInfo.lpMaximumApplicationAddress);

	uint64_t startPage = (startAddr - (startAddr % PAGE_SIZE));

	uint64_t pageOffset = 1;
	while (1)
	{
		uint64_t byteOffset = pageOffset * PAGE_SIZE;
		uint64_t highAddr = startPage + byteOffset;
		uint64_t lowAddr = (startPage > byteOffset) ? startPage - byteOffset : 0;

		bool needsExit = highAddr > maxAddr && lowAddr < minAddr;

		if (highAddr < maxAddr)
		{
			void* outAddr = VirtualAlloc((void*)highAddr, PAGE_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
			if (outAddr)
				return outAddr;
		}

		if (lowAddr > minAddr)
		{
			void* outAddr = VirtualAlloc((void*)lowAddr, PAGE_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
			if (outAddr != nullptr)
				return outAddr;
		}

		pageOffset++;

		if (needsExit)
		{
			break;
		}
	}

	return nullptr;
}

X64Instructions Hook::x64::StealBytes(void* TgtFunc)
{
	// Disassemble stolen bytes
	csh handle;
	cs_open(CS_ARCH_X86, CS_MODE_64, &handle);
	cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON); // turn ON detail feature with CS_OPT_ON

	size_t count;
	cs_insn* disassembledInstructions; //allocated by cs_disasm, needs to be manually freed later
	count = cs_disasm(handle, (uint8_t*)TgtFunc, 20, (uint64_t)TgtFunc, 20, &disassembledInstructions);
	cs_insn* nonModifyInstructions;
	size_t count2 = cs_disasm(handle, (uint8_t*)TgtFunc, 20, (uint64_t)TgtFunc, 20, &nonModifyInstructions);

	//get the instructions covered by the first 5 bytes of the original function
	uint32_t byteCount = 0;
	uint32_t stolenInstrCount = 0;
	for (int32_t i = 0; i < count; ++i)
	{
		cs_insn& inst = disassembledInstructions[i];
		byteCount += inst.size;
		stolenInstrCount++;
		if (byteCount >= 5) break;
	}

	//replace stolen instructions in target func wtih NOPs, so that when we jump
	//back to the target function, we don't have to care about how many
	//bytes were stolen
	memset(TgtFunc, 0x90, byteCount);

	cs_close(&handle);
	return { disassembledInstructions, nonModifyInstructions, stolenInstrCount, byteCount };
}

bool IsRelativeJump(cs_insn& inst)
{
	bool isAnyJumpInstruction = inst.id >= X86_INS_JAE && inst.id <= X86_INS_JS;
	bool isJmp = inst.id == X86_INS_JMP;
	bool startsWithEBorE9 = inst.bytes[0] == 0xEB || inst.bytes[0] == 0xE9;
	return isJmp ? startsWithEBorE9 : isAnyJumpInstruction;
}

bool IsRelativeCall(cs_insn& inst)
{
	bool isCall = inst.id == X86_INS_CALL;
	bool startsWithE8 = inst.bytes[0] == 0xE8;
	return isCall && startsWithE8;
}

bool IsRIPRelativeInstr(cs_insn& inst)
{
	cs_x86* x86 = &(inst.detail->x86);

	for (uint32_t i = 0; i < inst.detail->x86.op_count; i++)
	{
		cs_x86_op* op = &(x86->operands[i]);

		//mem type is rip relative, like lea rcx,[rip+0xbeef]
		if (op->type == X86_OP_MEM)
		{
			//if we're relative to rip
			return op->mem.base == X86_REG_RIP;
		}
	}

	return false;
}

template<class T>
T GetDisplacement(cs_insn* inst, uint8_t offset)
{
	T disp;
	memcpy(&disp, &inst->bytes[offset], sizeof(T));
	return disp;
}

//rewrite instruction bytes so that any RIP-relative displacement operands
//make sense with wherever we're relocating to
void Hook::x64::RelocateInstruction(cs_insn* inst, void* dstLocation)
{
	cs_x86* x86 = &(inst->detail->x86);
	uint8_t offset = x86->encoding.disp_offset;

	uint64_t displacement = inst->bytes[x86->encoding.disp_offset];
	switch (x86->encoding.disp_size)
	{
	case 1:
	{
		int8_t disp = GetDisplacement<uint8_t>(inst, offset);
		disp -= int8_t(uint64_t(dstLocation) - inst->address);
		memcpy(&inst->bytes[offset], &disp, 1);
	}break;

	case 2:
	{
		int16_t disp = GetDisplacement<uint16_t>(inst, offset);
		disp -= int16_t(uint64_t(dstLocation) - inst->address);
		memcpy(&inst->bytes[offset], &disp, 2);
	}break;

	case 4:
	{
		int32_t disp = GetDisplacement<int32_t>(inst, offset);
		disp -= int32_t(uint64_t(dstLocation) - inst->address);
		memcpy(&inst->bytes[offset], &disp, 4);
	}break;
	}
}


//relative jump instructions need to be rewritten so that they jump to the appropriate
//place in the Absolute Instruction Table. Since we want to preserve any conditional
//jump logic, this func rewrites the instruction's operand bytes only. 
void Hook::x64::RewriteStolenJumpInstruction(cs_insn* instr, uint8_t* instrPtr, uint8_t* absTableEntry)
{
	uint8_t distToJumpTable = uint8_t(absTableEntry - (instrPtr + instr->size));

	//jmp instructions can have a 1 or 2 byte opcode, and need a 1-4 byte operand
	//rewrite the operand for the jump to go to the jump table
	uint8_t instrByteSize = instr->bytes[0] == 0x0F ? 2 : 1;
	uint8_t operandSize = instr->size - instrByteSize;

	switch (operandSize)
	{
	case 1: instr->bytes[instrByteSize] = distToJumpTable; break;
	case 2: {uint16_t dist16 = distToJumpTable; memcpy(&instr->bytes[instrByteSize], &dist16, 2); } break;
	case 4: {uint32_t dist32 = distToJumpTable; memcpy(&instr->bytes[instrByteSize], &dist32, 4); } break;
	}
}

//relative call instructions need to be rewritten as jumps to the appropriate
//plaec in the Absolute Instruction Table. Since we want to preserve the length
//of the call instruction, we first replace all the instruction's bytes with 1 byte
//NOPs, before writing a 2 byte jump to the start
void Hook::x64::RewriteStolenCallInstruction(cs_insn* instr, uint8_t* instrPtr, uint8_t* absTableEntry)
{
	uint32_t numNOPs = instr->size - 2;
	uint8_t distToJumpTable = uint8_t(absTableEntry - (instrPtr + instr->size - numNOPs));

	//calls need to be rewritten as relative jumps to the abs table
	//but we want to preserve the length of the instruction, so pad with NOPs
	uint8_t jmpBytes[2] = { 0xEB, distToJumpTable };
	memset(instr->bytes, 0x90, instr->size);
	memcpy(instr->bytes, jmpBytes, sizeof(jmpBytes));
}

uint32_t Hook::x64::AddJmpToAbsTable(cs_insn& jmp, uint8_t* absTableMem)
{
	char* targetAddrStr = jmp.op_str; //where the instruction intended to go
	uint64_t targetAddr = _strtoui64(targetAddrStr, NULL, 0);
	WriteAbsoluteJump64(absTableMem, (void*)targetAddr);
	return 13;
}

uint32_t Hook::x64::AddCallToAbsTable(cs_insn& call, uint8_t* absTableMem, uint8_t* jumpBackToHookedFunc)
{
	char* targetAddrStr = call.op_str; //where the instruction intended to go
	uint64_t targetAddr = _strtoui64(targetAddrStr, NULL, 0);

	uint8_t* dstMem = absTableMem;

	uint8_t callAsmBytes[] =
	{
		0x49, 0xBA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, //movabs 64 bit value into r10
		0x41, 0xFF, 0xD2, //call r10
	};
	memcpy(&callAsmBytes[2], &targetAddr, sizeof(void*));
	memcpy(dstMem, &callAsmBytes, sizeof(callAsmBytes));
	dstMem += sizeof(callAsmBytes);

	//after the call, we need to add a second 2 byte jump, which will jump back to the 
		//final jump of the stolen bytes
	uint8_t jmpBytes[2] = { 0xEB, uint8_t(jumpBackToHookedFunc - (dstMem + sizeof(jmpBytes))) };
	memcpy(dstMem, jmpBytes, sizeof(jmpBytes));

	return sizeof(callAsmBytes) + sizeof(jmpBytes); //15
}


/*build a "jump - sandwich" style trampoline. This style of trampoline has three sections:
		|----------------------------|
		|Stolen Instructions         |
		|----------------------------|
		|Jummp back to target func   |
		|----------------------------|
		|Absolute Instruction Table  |
		|----------------------------|
Relative instructions in the stolen instructions section need to be rewritten as absolute
instructions which jump/call to the intended target address of those instructions (since they've
been relocated). Absolute versions of these instructions are added to the absolute instruction
table. The relative instruction in the stolen instructions section get rewritten to relative
jumps to the corresponding instructions in the absolute instruction table.
*/

uint32_t Hook::x64::BuildTrampoline(void* func2hook, void* dstMemForTrampoline)
{
	X64Instructions stolenInstrs = StealBytes(func2hook);

	uint8_t* stolenByteMem = (uint8_t*)dstMemForTrampoline;
	uint8_t* jumpBackMem = stolenByteMem + stolenInstrs.numBytes;
	uint8_t* absTableMem = jumpBackMem + 13; //13 is the size of a 64 bit mov/jmp instruction pair

	for (uint32_t i = 0; i < stolenInstrs.numInstructions; ++i)
	{
		cs_insn& inst = stolenInstrs.instructions[i];
		if (inst.id >= X86_INS_LOOP && inst.id <= X86_INS_LOOPNE)
		{
			//printf("loop");
			return 0; //bail out on loop instructions, I don't have a good way of handling them 
		}

		if (IsRelativeJump(inst))
		{
			uint32_t aitSize = AddJmpToAbsTable(inst, absTableMem);
			RewriteStolenJumpInstruction(&inst, stolenByteMem, absTableMem);
			absTableMem += aitSize;
		}
		else if (IsRelativeCall(inst))
		{
			uint32_t aitSize = AddCallToAbsTable(inst, absTableMem, jumpBackMem);
			RewriteStolenCallInstruction(&inst, stolenByteMem, absTableMem);
			absTableMem += aitSize;
		}
		else if (IsRIPRelativeInstr(inst))
		{
			RelocateInstruction(&inst, stolenByteMem);
		}
		//printf("Writing %d bytes to trampoline memory--> %llx\n", inst.size, stolenByteMem);
		memcpy(stolenByteMem, inst.bytes, inst.size);
		stolenByteMem += inst.size;
	}

	WriteAbsoluteJump64(jumpBackMem, (uint8_t*)func2hook + 5);
	//free(stolenInstrs.instructions);

	HookInfo64 HookInfo;
	HookInfo.HookedFunctionAddress = (uintptr_t)func2hook;
	HookInfo.StolenBytes = stolenInstrs;
	HookInfo.TrampolineSize = uint32_t((uint8_t*)absTableMem - (uint8_t*)dstMemForTrampoline);
	Hooks.push_back(HookInfo);

	return uint32_t((uint8_t*)absTableMem - (uint8_t*)dstMemForTrampoline);
}


void Hook::x64::RemoveHooks()
{

	SYSTEM_INFO sysInfo;
	GetSystemInfo(&sysInfo);
	const uint64_t PAGE_SIZE = sysInfo.dwPageSize;


	for (auto& hook : Hooks) {
		auto& inst = hook.StolenBytes;
		memcpy((void*)hook.HookedFunctionAddress, inst.nonModifyInstructions->bytes, inst.numBytes);
		free(inst.instructions);
		free(inst.nonModifyInstructions);

	}
	VirtualFree(PageAddress, PAGE_SIZE, MEM_RELEASE);
	Hooks.clear();
}


void Hook::x64::InitHooks(std::vector<HookFuncs>& hookFuncs)
{
	for (auto& hook : hookFuncs) {
		void* TgtFunc = (void*)GetFuncAddress(hook.dllName, hook.funcName);
		if (!TgtFunc) {
			printf("Did not find address for %s\n", hook.funcName);
			continue;
		}
		InstallHook(TgtFunc, hook.HookFunction, (void**)hook.TrampolineFunc);
		printf("Installed hook for %s at address: 0x%llx, HookFunction: 0x%llx, Trampoline: 0x%llx\n", hook.funcName, TgtFunc, hook.HookFunction, hook.TrampolineFunc);
		Sleep(2000);
	}

}
