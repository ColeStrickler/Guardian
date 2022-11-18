#include "YaraAgent.h"



Yara::Scanner::Scanner(std::string YaraConfFilePath) 
{
	int init = yr_initialize();

	if (init != ERROR_SUCCESS) {
		printf("Yara ProcessScanner initialize failed: %d\n", GetLastError());
		return;
	}

	if (CreateCompiler()) {
		bSetup = TRUE;
	}
	
	if (bSetup) {
		AddRulesFromDirectory(YaraConfFilePath, TRUE);
		int result = yr_compiler_get_rules(compiler, &rules);
		if (result != ERROR_SUCCESS) {
			printf("Yara ProcessScanner initialize failed during rule initialization: %d\n", GetLastError());
			bSetup = FALSE;
		}

	}
}


Yara::Scanner::~Scanner() 
{
	int end = yr_finalize();
	if (end != ERROR_SUCCESS) {
		printf("Yara ProcessScanner finalize failed: %d\n", GetLastError());
		return;
	}
}


BOOL Yara::Scanner::CreateCompiler() 
{
	int check = yr_compiler_create(&compiler);

	

	if (check == ERROR_SUCCESS) {
		return TRUE;
	}
	else {
		return FALSE;
	}
}


BOOL Yara::Scanner::LoadRule(std::string path, BOOL bVerbose)
{
	std::string rule = ReadFileToStringA(path);

	if (rule.empty())
	{
		return TRUE;
	}

	// Add the rule to the compiler
	int result = yr_compiler_add_string(compiler, rule.c_str(), nullptr);
	if (result != ERROR_SUCCESS)
	{
		if (bVerbose) printf("Failed to add rules from %s: %d\n", path.c_str(), GetLastError());
		return FALSE;
	}
	else
	{
		return TRUE;
	}
}



BOOL Yara::Scanner::AddRulesFromDirectory(std::string rule_directory, BOOL bVerbose)
{
	int file_count = 0;
	int succes_count = 0;

	for (const auto& dirEntry : std::filesystem::recursive_directory_iterator(rule_directory))
	{
		if (".yar" != dirEntry.path().extension())
		{
			continue;
		}
		if (LoadRule(dirEntry.path().string(), bVerbose))
		{
			succes_count++;
		}
		file_count++;
	}

	printf("\\_ Added %ld/%ld rules!\n", succes_count, file_count);

	// Check the rule was added
	int result = yr_compiler_get_rules(compiler, &rules);

	if (result != ERROR_SUCCESS)
	{
		printf("Failed to get rules from %s: %d\n", rule_directory.c_str(), GetLastError());
		return FALSE;
	}
	else
	{
		printf("\\_ Successfully verified rules!\n");
		return TRUE;
	}
}


BOOL Yara::Scanner::AddRuleFromFile(std::string file_name)
{
	FILE* rule_file = NULL;
	int result = fopen_s(&rule_file, file_name.c_str(), "r");
	if (result != ERROR_SUCCESS) {
		printf("Failed to add rule from %s --> ERROR: \n", file_name.c_str(), GetLastError());
		return FALSE;
	}
	printf("Opened the file!\n");
	result = yr_compiler_add_file(compiler, rule_file, NULL, file_name.c_str());
	printf("got here\n");
	if (result != ERROR_SUCCESS) {
		printf("Failed to compile rule from %s --> ERROR: \n", file_name.c_str(), GetLastError());
		return FALSE;
	}
	printf("Compiled the file!\n");
	result = yr_compiler_get_rules(compiler, &rules);
	if (result != ERROR_SUCCESS) {
		printf("Failed to compile rule from %s --> ERROR: \n", file_name.c_str(), GetLastError());
		return FALSE;
	}
	printf("Compiled got the rules!\n");
	return TRUE;
}

std::vector<RegionInfo> Yara::Scanner::GetProcessRegions(HANDLE hProcess) 
{
	std::vector<RegionInfo> regions;
	MEMORY_BASIC_INFORMATION memory_basic_info = {};
	LPVOID offset = 0;

	while (VirtualQueryEx(hProcess, offset, &memory_basic_info, sizeof(MEMORY_BASIC_INFORMATION))) {
		offset = (LPVOID)((DWORD_PTR)memory_basic_info.BaseAddress + memory_basic_info.RegionSize);

		RegionInfo regInfo;
		regInfo.pBase = memory_basic_info.BaseAddress;
		regInfo.pAllocation = memory_basic_info.AllocationBase;
		regInfo.dwProtect = memory_basic_info.Protect;
		regInfo.dwRegion = memory_basic_info.RegionSize;
		regInfo.dwState = memory_basic_info.State;
		regInfo.dwType = memory_basic_info.Type;
		regions.push_back(regInfo);
	}

	if (regions.size() == 0) {
		printf("Error while trying to querry virtual memory --> %d.\n", GetLastError());
	}

	return regions;
}


std::vector<std::byte> ReadFileToBuffer(HANDLE hFile)
{
	DWORD fileSize{ 0 };
	fileSize = GetFileSize(hFile, 0);



	std::vector<std::byte> buffer(fileSize);			// INITIALIZE THIS WITH THE SIZE OF THE FILE
	DWORD numRead;
	BOOL bRead = ReadFile(hFile, buffer.data(), fileSize, &numRead, 0);
	if (bRead == FALSE)
	{
		printf("Yara::Scanner::ReadFileToBuffer()-->ReadFile() failure! Error: %d", GetLastError());
	}

	return buffer;
}


std::vector<std::byte> ReadRegionToBuffer(RegionInfo regionInfo, HANDLE hProcess)
{
	if (regionInfo.dwProtect == PAGE_NOACCESS) {
		return std::vector<std::byte>{};
	}

	std::vector<std::byte> buffer(regionInfo.dwRegion);			// INITIALIZE THIS WITH THE SIZE OF THE REGION
	BOOL bRead = ReadProcessMemory(hProcess, (LPVOID)regionInfo.pBase, buffer.data(),regionInfo.dwRegion, NULL);
	if (bRead == FALSE)
	{
		printf("Yara::Scanner::ReadRegionToBuffer()-->ReadProcessMemory() failure! Error: %d", GetLastError());
	}

	return buffer;
}


int Yara::Scanner::GetYaraMatches(YR_SCAN_CONTEXT* context, int message, void* message_data, void* user_data)
{
	PYaraInfo yaraInfo = static_cast<PYaraInfo>(user_data);

	if (message == CALLBACK_MSG_RULE_MATCHING)
	{
		YR_RULE* rule = (YR_RULE*)message_data;
		YR_STRING* string;

		yr_rule_strings_foreach(rule, string)
		{
			std::string rule_name = rule->identifier;
			if (VectorContainsStringA(yaraInfo->matched_rules, rule_name) == FALSE)
			{
				printf("[MATCH] => %s\n", rule_name.c_str());
				yaraInfo->matched_rules.push_back(rule_name);
			}
		}
	}

	return CALLBACK_CONTINUE;
}






std::vector<YaraInfo> Yara::Scanner::ScanProcess(DWORD procId) 
{
	RAII::Handle hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, procId);
	std::vector<YaraInfo> retInfo;
	if (hProc.Empty()) {
		printf("Yara::Scanner::ScanProcess() unable to obtain handle to process --> %d\n", GetLastError());
		return retInfo;
	}
	std::vector<RegionInfo> ProcessMemoryRegions = GetProcessRegions(hProc.Get());
	

	for (auto& regInfo : ProcessMemoryRegions) {
		std::vector<std::byte> RegionBytes = ReadRegionToBuffer(regInfo, hProc.Get());
		if (RegionBytes.empty()) {
			continue;
		}

		BYTE* buffer = (BYTE*)RegionBytes.data();
		unsigned int bufferSize = RegionBytes.size();

		if (strlen((char*)buffer) == 0) {
			continue;
		}

		YaraInfo yaraInfo;
		// Scan													MAY NEED TO CHANGE THIS FLAG
		int result = yr_rules_scan_mem(rules, buffer, bufferSize, SCAN_FLAGS_NO_TRYCATCH, GetYaraMatches, &yaraInfo, 0);

		if (yaraInfo.matched_rules.size() > 0) {
			yaraInfo.infectedRegion = regInfo;
			retInfo.push_back(yaraInfo);
		}


	}
	return retInfo;;

}


YaraInfo Yara::Scanner::ScanFile(std::string FilePath)
{
	YaraInfo retInfo;

	RAII::Handle hFile = CreateFileA(FilePath.c_str(), GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, NULL, NULL);
	if (hFile.Get() == NULL) {
		printf("Could not obtain handle to file.\n");
		return retInfo;
	}
	std::vector<std::byte> FileMap = ReadFileToBuffer(hFile.Get());
	if (FileMap.empty()) {
		printf("Could not read file to buffer.\n");
		return retInfo;
	}

	BYTE* buffer = (BYTE*)FileMap.data();
	unsigned int bufferSize = FileMap.size();

	YaraInfo yaraInfo;
	int result = yr_rules_scan_mem(rules, buffer, bufferSize, SCAN_FLAGS_NO_TRYCATCH, GetYaraMatches, &yaraInfo, 0);

	if (yaraInfo.matched_rules.size() > 0) {
		yaraInfo.FilePath = FilePath;			// WE ONLY NEED THE MATCHING RULES FOR ScanFile SINCE THE PATH IS ALREADY KNOWN
	}											// AND WE WILL FILL OUT A NEW STRUCTURE TO SEND BACK TO THE DRIVER
	else {
		yaraInfo.FilePath = '0';
	}

	return yaraInfo;

}



std::vector<YaraInfo> Yara::Scanner::ScanSystem()
{
	std::string startPath("C:\\");

	std::vector<YaraInfo> retInfo;

	try {
		for (const auto& dirEntry : std::filesystem::recursive_directory_iterator(startPath, std::filesystem::directory_options::skip_permission_denied)) {
			YaraInfo found = ScanFile(dirEntry.path().string());
			if (*found.FilePath.data() != '0') {					// IN ScanFile WE SET THE FILEPATH TO '0' IF THERE ARE NO MATCHED RULES
				continue;
			}
			retInfo.push_back(found);
		}
	}
	catch (std::filesystem::filesystem_error e) {
		printf("Yara::Scanner::ScanSystem() error Traversing filesystem: %s\n", e.what());
	}


	return retInfo;
}


