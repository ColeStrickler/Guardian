#pragma once
#include "wx/wx.h"
#include "Common.h"
#include <cstdio>
#include "helper.h"
#include "RAII.h"
#include "service.h"



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

	wxButton* YaraScanFileBtn = nullptr;
	int YaraScanFileBtnId = 5;

	wxTextCtrl* YaraScanFileTxtBox = nullptr;
	int YaraScanFileTxtBoxId = 6;


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
	void YaraScanFile(wxCommandEvent& evt);
	void DisplayInfo(BYTE* buffer, DWORD size);
	


// PRIVATE FUNCTIONS
private:
	static void displayEventThread(cMain* main);
	void initUserArray(std::vector<std::wstring> users);
	bool CheckValidUser();



// PRIVATE VARIABLES
private: 
	const wchar_t* BlockedFilePathConfig = L"C:\\Program Files\\Guardian\\conf\\paths.conf";
};

