#pragma once
#include "wx/wx.h"
#include "Common.h"
#include <cstdio>
#include <winternl.h>
#include "helper.h"
#include "RAII.h"
#include "service.h"
#include "linkedlist.h"


template<typename T>
struct DataItem {
	lEntry Entry;
	T Data;
};

template<typename T>
struct ApiDataItem : DataItem<T> {
	DWORD pid;
};


// wxFrame is basically a form
class cMain : public wxFrame
{

public:
	cMain();
	~cMain();



// GUI ELEMENTS AND THEIR NEEDED DATA
public:
	wxButton* AddBlockedFileBtn = nullptr;
	int AddBlockedFileBtnId = 1;

	wxTextCtrl* AddBlockedFileTxtBox = nullptr;
	int AddBlockedFileTxtBoxId = 2;

	wxListBox* AlertFeed = nullptr;
	int AlertFeedId = 3;

	wxComboBox* userChoicesAddBlockedFile = nullptr;
	int userChoicesAddBlockedFileId = 4;
	std::vector<std::wstring> validUsers;

	wxListBox* ScanResults = nullptr;
	int ScanResultsId = 5;

	wxButton* YaraScanFileBtn = nullptr;
	int YaraScanFileBtnId = 6;

	wxTextCtrl* YaraScanFileTxtBox = nullptr;
	int YaraScanFileTxtBoxId = 7;

	wxButton* YaraScanProcessBtn = nullptr;
	int YaraScanProcessBtnId = 8;

	wxTextCtrl* YaraScanProcessTxtBox = nullptr;
	int YaraScanProcessTxtBoxId = 9;

	wxButton* AddBlockedRegistryKeyBtn = nullptr;
	int AddBlockedRegistryKeyBtnId = 10;

	wxTextCtrl* AddBlockedRegistryKeyTxtBox = nullptr;
	int AddBlockedRegistryKeyTxtBoxId = 11;

	wxButton* startApiMonitorBtn = nullptr;
	int startApiMonitorBtnId = 12;

	wxTextCtrl* startApiMonitorTxtBox = nullptr;
	int startApiMonitorTxtBoxId = 13;

	wxButton* stopApiMonitorBtn = nullptr;
	int stopApiMonitorBtnId = 14;

	wxTextCtrl* stopApiMonitorTxtBox = nullptr;
	int stopApiMonitorTxtBoxId = 15;

	wxListBox* apiEventFeed = nullptr;
	int apiEventFeedId = 16;


	wxGauge* m_statBar1 = nullptr;						// WE WILL USE THIS LATER TO GAUGE SCAN PROGRESS

	// must include this macro for events
	wxDECLARE_EVENT_TABLE();



// PUBLIC VARIABLES
public:
	HANDLE hFile = nullptr;				// HANDLE TO DRIVER SYMLINK
	HANDLE hEventThread = nullptr;		// HANDLE TO EVENT/ALERT THREAD
	


// PUBLIC FUNCTIONS
public:
	void AddBlockedFilePathBtnFunc(wxCommandEvent& evt);
	void AddLockedRegistryKey(wxCommandEvent& evt);
	void StartApiMonitor(wxCommandEvent& evt);
	void StopApiMonitor(wxCommandEvent& evt);
	void YaraScanFile(wxCommandEvent& evt);
	void YaraScanProcess(wxCommandEvent& evt);
	void DisplayInfo(BYTE* buffer, DWORD size);
	void FormatApiEvents(BYTE* buffer, DWORD size);
	


// PRIVATE FUNCTIONS
private:
	//THREADS
	static void displayEventThread(cMain* main);
	static void displayApiEventThread(cMain* main);


	// PRIVATE HELPER FUNCTIONS
	void initUserArray(std::vector<std::wstring> users);
	bool CheckValidUser();
	bool CheckValidRegistryKey(std::wstring RegKey);
	bool CheckExistingRegistryKey(HANDLE HandleLockedPathConfigFile, std::string RegKey);
	void PrintYaraScanFile(std::vector<std::string> matchedRules, std::string FilePath);
	void PrintYaraScanProcess(std::vector<std::string> matchedRules, std::string ProcName, DWORD processId);
	std::string UserRegistryToKernelRegistry(std::string UserRegistryKey);
	bool PidAlreadyMonitored(DWORD pid);
	void DisplayApiEvents();


// PRIVATE VARIABLES
private: 
	const wchar_t* BlockedFilePathConfig = L"C:\\Program Files\\Guardian\\conf\\paths.conf";
	const wchar_t* LockedRegistryPathConfig = L"C:\\Program Files\\Guardian\\conf\\reg.conf";
	PListHeader MonitoredProcs;
	PListHeader ApiEvents;
};

