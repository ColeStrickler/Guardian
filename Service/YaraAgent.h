#pragma once
#include <string>
#include <Windows.h>
#include <vector>
#include <yara.h>
#include <filesystem>
#include "helper.h"
#include "RAII.h"
#include <iostream>




typedef struct REGIONINFO
{
	LPVOID pBase;
	LPVOID pAllocation;
	DWORD dwRegion;
	DWORD dwProtect;
	DWORD dwState;
	DWORD dwType;
} RegionInfo, * PRegionInfo;


typedef struct YARAINFO
{
	std::vector<std::string> matched_rules;
	RegionInfo infectedRegion;
	std::string FilePath;
} YaraInfo, * PYaraInfo;



namespace Yara {


	class Scanner 
	{
	// PUBLIC FUNCTIONS
	public:
		Scanner(std::string YaraConfFilePath);
		~Scanner();
		std::vector<YaraInfo>		ScanProcess(DWORD procId);
		YaraInfo					ScanFile(std::string FilePath);
		std::vector<YaraInfo>		ScanSystem();

	// PUBLIC VARIABLES
	public:
		BOOL bSetup = FALSE;		// THIS WILL BE SET IF INITIALIZATION IS SUCCESSFUL

	// PRIVATE FUNCTIONS
	private:
		BOOL CreateCompiler();
		BOOL AddRuleFromFile(std::string file_name);
		BOOL LoadRule(std::string path, BOOL bVerbose);
		BOOL AddRulesFromDirectory(std::string rule_directory, BOOL bVerbose);
		std::vector<RegionInfo> GetProcessRegions(HANDLE hProcess);
		static int GetYaraMatches(YR_SCAN_CONTEXT* context, int message, void* message_data, void* user_data);


	// PRIVATE VARS
	private:
		YR_COMPILER* compiler = NULL;
		YR_RULES* rules = NULL;
		std::string YaraConfFilePath;
		int RuleCount = 0;
	};


}



