#include "cMain.h"

// takes name of class producing events, and the base class
wxBEGIN_EVENT_TABLE(cMain, wxFrame)
// link an id to a function
EVT_BUTTON(10001, AddBlockedFilePathBtnFunc)
EVT_BUTTON(10002, YaraScanFile)
EVT_BUTTON(10003, YaraScanProcess)
EVT_BUTTON(10004, AddLockedRegistryKey)

wxEND_EVENT_TABLE()


void cMain::PrintYaraScanProcess(std::vector<std::string> matchedRules, std::string ProcName, DWORD processId)
{
    // //////<<[YARA SCAN PROCESS FINISHED]>>\\\\\\
    // Scan Finish Time: 
    // Process Name:
    // Process Id: 
    // [|MATCHED RULE|]: 
    // [|MATCHED RULE|]:
    // [|MATCHED RULE|]:
    ScanResults->Clear();

    std::string Header("//////<<[YARA SCAN PROCESS FINISHED]>>\\\\\\\\\\\\");
    SYSTEMTIME st;
    GetSystemTime(&st);
    char buf[200];
    sprintf_s(buf, "Scan Finish Time: %02d:%02d:%02d:%03d", st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
    std::string ScanFinishTime = std::string(buf);

    char buf2[300];
    sprintf_s(buf2, "Process Name: %s", ProcName.c_str());
    std::string ProcessNameFormat(buf2);

    char buf3[300];
    sprintf_s(buf3, "Process Id: %d", processId);
    std::string PidFormat(buf3);

    std::vector<std::string> matchedRulesFormatted;
    for (auto& s : matchedRules) {
        char format[300];
        sprintf_s(format, "[MATCHED RULE]: %s", s.c_str());
        std::string sFormat(format);
        matchedRulesFormatted.push_back(sFormat);
    }


    ScanResults->AppendString(wxString(Header));
    ScanResults->AppendString(wxString(ScanFinishTime));
    ScanResults->AppendString(wxString(ProcessNameFormat));
    ScanResults->AppendString(wxString(PidFormat));
    for (auto& s : matchedRulesFormatted) {
        ScanResults->AppendString(wxString(s));
    }

    return;
}


void cMain::PrintYaraScanFile(std::vector<std::string> matchedRules, std::string FilePath) 
{
    // //////<<[YARA SCAN FILE FINISHED]>>\\\\\\
    // Scan Finish Time: 
    // File Path:
    // [|MATCHED RULE|]: 
    // [|MATCHED RULE|]:
    // [|MATCHED RULE|]:
    ScanResults->Clear();

    std::string Header("//////<<[YARA SCAN FILE FINISHED]>>\\\\\\\\\\\\");
    SYSTEMTIME st;
    GetSystemTime(&st);
    char buf[200];
    sprintf_s(buf, "Scan Finish Time: %02d:%02d:%02d:%03d", st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
    std::string ScanFinishTime = std::string(buf);


    char buf2[300];
    sprintf_s(buf2, "File Path: %s", FilePath.c_str());
    std::string FilePathFormat(buf2);

    std::vector<std::string> matchedRulesFormatted;
    for (auto& s : matchedRules) {
        char format[300];
        sprintf_s(format, "[MATCHED RULE]: %s", s.c_str());
        std::string sFormat(format);
        matchedRulesFormatted.push_back(sFormat);
    }

    ScanResults->AppendString(wxString(Header));
    ScanResults->AppendString(wxString(ScanFinishTime));
    ScanResults->AppendString(wxString(FilePathFormat));
    for (auto& s : matchedRulesFormatted) {
        ScanResults->AppendString(wxString(s));
    }

    return;
}




void cMain::DisplayInfo(BYTE* buffer, DWORD size) 
{
    auto count = size;
    while (count > 0) {
        auto header = (Header*)buffer;
       // if ((int)header->Type != 0) {
      //      m_list1->AppendString(wxString(std::to_string((DWORD)header->Type).c_str()));
       // }
       // else {
          //  m_list1->AppendString(wxString("Invalid header type"));
       // }
        
        switch (header->Type) {
            case ItemType::ProcessExit:
            {
                
                    std::string time = DisplayTime(header->Time);
                    // auto info = (ProcessExitInfo*)buffer;
                    // printf("[*] {PROCESS EXIT} |PID-->%d|\n", info->ProcessId);
                    break;
            }

            case ItemType::ProcessCreate:
            {
                // DisplayTime(header->Time);
                // auto info = (ProcessCreateInfo*)buffer;
               //  std::wstring commandLine((WCHAR*)(buffer + info->CommandLineOffset), info->CommandLineLength);
               //  std::wstring fileImage((WCHAR*)(buffer + info->ImageFileNameOffset), info->ImageFileNameLength);
              //   printf("offset: %d\n", info->ImageFileNameOffset);
                // printf("[*] {PROCESS CREATION} |PID-->%d|IMAGEFILE-->%ws|CMDLINE-->%ws|\n", info->ProcessId, fileImage.c_str(), commandLine.c_str());
                // break;
                break;
            }

            case ItemType::RemoteThreadCreate:
            {
               // m_list1->AppendString(wxString("RemoteThreadCreate"));
                std::string time = DisplayTime(header->Time);
                auto info = (RemoteThreadAlert*)buffer;
                auto targetId = info->ProcessId;
                auto threadId = info->ThreadId;
                auto creatorId = info->CreatorProcess;
                char buf[300];
                sprintf(buf, "%s ~ [RemoteThreadCreation]: %d --> %d.   ThreadId: %d\n", time.c_str(), creatorId, targetId, threadId);
                std::string ret(buf);
                wxString logString = wxString(ret.c_str());
                AlertFeed->AppendString(logString);
               // m_list1->AppendString(wxString("log"));
                break;
            }

            case ItemType::BlockedExecutionPath:
            {
                std::string time = DisplayTime(header->Time);
                auto info = (BlockedPathAlert*)buffer;
                std::wstring imageName((WCHAR*)(buffer + info->ImageNameOffset), info->ImageNameLength);

                char buf[300];
                sprintf(buf, "%s ~ [BlockedExecutionPath]:  Path: %ws\n", time.c_str(), imageName.c_str());
                std::string ret(buf);
                wxString logString = wxString(ret.c_str());
                AlertFeed->AppendString(logString);
                break;
            }
            // NEEDS DEBUGGED
            // NEEDS DEBUGGED
            case ItemType::YaraScanFile:
            {
                std::vector<std::string> matchedRules;
                std::string FilePath;
                int matchCount = 0;
                auto info = (YaraScanFileAlert*)buffer;
                

                ULONG filePathlen = info->FilePathLength;
                FilePath = std::string((char*)(buffer + info->FilePathOffset), filePathlen);
                matchCount = info->MatchedRuleCount;

                BYTE* currPtr = buffer + info->MatchedRulesOffset;
                while (matchCount > 0) {
                    std::string rule((char*)currPtr);
                    matchedRules.push_back(rule);
                    currPtr += rule.size() + 1;
                    matchCount--;
                }

                PrintYaraScanFile(matchedRules, FilePath);
                break;
            }

            case ItemType::YaraScanProcess:
            {
                std::vector<std::string> matchedRules;
                int matchCount = 0;
                auto info = (YaraScanProcessAlert*)buffer;


                matchCount = info->MatchedRuleCount;
                DWORD pid = info->processId;
                std::string procName;
                if (ProcIdExists(pid)) {
                    procName = GetProcnameFromId(pid);
                }

                BYTE* currPtr = buffer + info->MatchedRulesOffset;
                while (matchCount > 0) {
                    std::string rule((char*)currPtr);
                    matchedRules.push_back(rule);
                    currPtr += rule.size() + 1;
                    matchCount--;
                }


                PrintYaraScanProcess(matchedRules, procName, pid);
                break;
            }

            default:
                break;

        }
        buffer += header->Size;
        count -= header->Size;
    }
        
}



void cMain::displayEventThread(cMain* main) 
{

    while (true) {
        BYTE buffer[1 << 16];

        if (main->hFile == INVALID_HANDLE_VALUE) {
            main->AlertFeed->Append(wxString("Invalid file handle to driver"));
            continue;
        }
        DWORD bytes;
        if (!ReadFile(main->hFile, buffer, sizeof(buffer), &bytes, nullptr)) {
            main->AlertFeed->AppendString(wxString("Handle to driver file could not be read."));
            continue;
        }
        if (bytes != 0) {
            main->DisplayInfo(buffer, bytes);
        }

        Sleep(200);
    }
    
}


void cMain::initUserArray(std::vector<std::wstring> users) 
{
    int i = 0;
    for (auto& u : users) {
        userChoicesAddBlockedFile->Append(wxString(u));
        validUsers.push_back(u);
        i++;
    }
}


cMain::cMain() : wxFrame(nullptr, wxID_ANY, "Guardian", wxPoint(30, 30), wxSize(1200, 1800)) 
{

    hFile = CreateFile(L"\\\\.\\guardian", GENERIC_READ, 0, nullptr, OPEN_EXISTING, 0, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) {
  
        MessageBoxA(NULL, "Unable to obtain handle to Guardian Kernel mode component", "Could not start", MB_ICONERROR | MB_DEFBUTTON1);
      //  exit(-1);
    }

    
    // ADD BLOCKED FILE         wxPoint(410, 20), wxSize(200, 200), userChoices
    userChoicesAddBlockedFile = new wxComboBox(this, wxID_ANY, wxString("<select user>"), wxPoint(410, 20), wxSize(200, 20));
    initUserArray(listUsers());
    AddBlockedFileBtn = new wxButton(this, 10001, "Add new blocked file path", wxPoint(10, 20), wxSize(200, 20));
	AddBlockedFileTxtBox = new wxTextCtrl(this, wxID_ANY, "<file path>", wxPoint(210, 20), wxSize(200, 20));

    
    // YARA SCAN FILE BUTTON
    YaraScanFileBtn = new wxButton(this, 10002, "Yara scan file", wxPoint(10, 40), wxSize(200, 20));
    YaraScanFileTxtBox = new wxTextCtrl(this, wxID_ANY, "<file path>", wxPoint(210, 40), wxSize(200, 20));

    // YARA SCAN PROCESS BUTTON
    YaraScanProcessBtn = new wxButton(this, 10003, "Yara scan PID", wxPoint(10, 60), wxSize(200, 20));
    YaraScanProcessTxtBox = new wxTextCtrl(this, wxID_ANY, "<process id>", wxPoint(210, 60), wxSize(200, 20));

    // LOCK REGISTRY KEY BUTTON
    AddBlockedRegistryKeyBtn = new wxButton(this, 10004, "Add Blocked Registry Key", wxPoint(10, 80), wxSize(200, 20));
    AddBlockedRegistryKeyTxtBox = new wxTextCtrl(this, wxID_ANY, "<registry key>", wxPoint(210, 80), wxSize(200, 20));

    // EVENT/ALERT FEED
	AlertFeed = new wxListBox(this, wxID_ANY, wxPoint(10, 210), wxSize(500, 400));
    hEventThread = CreateThread(0, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(displayEventThread), this, 0, 0);

   


    // SCAN RESULTS TEXT BOX
    ScanResults = new wxListBox(this, wxID_ANY, wxPoint(510, 210), wxSize(500, 400));
    // --> Results will be written by the EventThread

}

cMain::~cMain() {
    CloseHandle(hFile);
}


int checkExistingBlockedFilePath(HANDLE HandleBlockedPathConfigFile, std::string FilePath, std::string& outString) 
{
    DWORD size{ 0 };
    size = GetFileSize(HandleBlockedPathConfigFile, NULL);
    BYTE* configFile = RAII::HeapBuffer(size).Get();
    if (configFile == nullptr) {
        HeapFree(GetProcessHeap(), NULL, configFile);
        MessageBoxA(NULL, "Could not allocate heap memory for file read.", "Error", MB_ICONERROR | MB_DEFBUTTON1);
        return 3;             
    }
    DWORD read;
    bool check = ReadFile(HandleBlockedPathConfigFile, configFile, size, &read, NULL);
    if (!check) {
        MessageBoxA(NULL, "Could not read from configuration file.", "Error", MB_ICONERROR | MB_DEFBUTTON1);
        return 3;
    }

    int relIndex = 0;
    bool match = true;
    char testBuf[MAX_PATH] = { 0 };
    const char* filePathchars = FilePath.c_str();
    for (unsigned int i = 0; i < size; i++) {
        
        if (configFile[i] == 0x3b && configFile[i + 1] == 0x3b && configFile[i + 2] == 0x3b) { 
            if (match == true) {
                std::string capture(testBuf);
                outString = capture;
                HeapFree(GetProcessHeap(), NULL, configFile);
                return true;
            }
            else {
                memset(testBuf, 0, MAX_PATH);
            }
            i += 2;
            relIndex = 0;
            match = true;
            continue;
        }

        if (filePathchars[relIndex] != configFile[i]) {
            match = false;
        }
        relIndex++;
    }
    HeapFree(GetProcessHeap(), NULL, configFile);
    return false;
}




void cMain::AddBlockedFilePathBtnFunc(wxCommandEvent& evt) 
{
    std::string filePath = std::string((AddBlockedFileTxtBox->GetValue()).mb_str());
    bool check = DirExists(filePath.c_str());
    if (!check) {
        MessageBoxA(NULL, "Path does not exist.", "Error", MB_ICONERROR | MB_DEFBUTTON1);
        evt.Skip();
        return;
    }


    std::wstring userSelection = userChoicesAddBlockedFile->GetStringSelection().wc_str();
    check = false;
    for (auto& s : validUsers) {
        if (!s.compare(userSelection)) {
            check = true;
        }
    }
    if (!check) {
        MessageBoxA(NULL, "Please use a valid user from the provided dropdown.", "Error", MB_ICONERROR | MB_DEFBUTTON1);
        evt.Skip();
        return;
    }

   
    RAII::Handle hConfig = CreateFileW(BlockedFilePathConfig, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hConfig.Get() == INVALID_HANDLE_VALUE) {
        MessageBoxA(NULL, "Could not open config file for write.", "Error", MB_ICONERROR | MB_DEFBUTTON1);
        evt.Skip();
        return;
    }

    std::string ExistingPathCheck;
    int existingMatchExists = checkExistingBlockedFilePath(hConfig.Get(), filePath, ExistingPathCheck);
    MessageBoxA(NULL, std::to_string(existingMatchExists).c_str(), "Error", MB_ICONERROR | MB_DEFBUTTON1);


    bool keepGoing = false;


    switch (existingMatchExists){
        case 0:
            {
                break;
            }
        case 1:
            {
                char buf[400];
                sprintf(buf, "Path already exists or a more specific path already includes the specific path: %s\n", ExistingPathCheck.c_str());
                MessageBoxA(NULL, buf, "Error", MB_ICONERROR | MB_DEFBUTTON1);
                evt.Skip();
                return;
            }
        case 3:
            {
                evt.Skip();
                return;
            }
    }

    // close our original handle, because now we must use CreateFileWith the append flag
    hConfig.Close(); 
    RAII::Handle hConfig2 = CreateFileW(BlockedFilePathConfig, FILE_APPEND_DATA, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hConfig2.Get() == INVALID_HANDLE_VALUE) {
        MessageBoxA(NULL, "Unable to obtain handle to write config file.", "Error", MB_ICONERROR | MB_DEFBUTTON1);
        evt.Skip();
        return;
    }
    DWORD size = filePath.length() + 3; // size of user given path + ;;;
    BYTE* writeBuffer = RAII::HeapBuffer(size).Get();
    memcpy(writeBuffer, filePath.c_str(), size - 3);
    memset((void*)((uintptr_t)writeBuffer + filePath.length()), 0x3b, 3); // set last 3 bytes to ;;;
    DWORD numWritten;
    BOOL writeSuccess = false;
    writeSuccess = WriteFile(hConfig2.Get(), writeBuffer, size, &numWritten, NULL);
    if (!writeSuccess) {
        MessageBoxA(NULL, "Unable to write file path to current configuration.", "Error", MB_ICONERROR | MB_DEFBUTTON1);
        evt.Skip();
        return;
    }
    
    ULONG64 outBuffer;
    DWORD retBytes;
    BOOL success = DeviceIoControl(
        hFile,
        IOCTL_ADDFILE_BLACKLIST,
        writeBuffer,
        size,
        &outBuffer,
        sizeof(ULONG64),
        &retBytes,
        nullptr         // lpOverlapped
    );
    if (!success) {
        MessageBoxA(NULL, "Blocked file path added to configuration file, but not added to current Guardian session.", "Error", MB_ICONERROR | MB_DEFBUTTON1);
    }
    else {
        wxString successText("OK!");
        AddBlockedFileTxtBox->Clear();
        AddBlockedFileTxtBox->AppendText(successText);
    }
	evt.Skip(); // call this to end the event
    return;
}


bool cMain::CheckValidRegistryKey(std::wstring RegKey) 
{
    wchar_t* stringData = RegKey.data();
    RAII::NewBuffer buffer(RegKey.size() * 2);
    BYTE* buf = buffer.Get();
    HKEY hk;
    LSTATUS status;

    

    if (stringData[5] == L'L') {             // HKEY_LOCAL_MACHINE

        memcpy(buf, RegKey.data() + 19, RegKey.size() * 2 - 19);
        status = RegOpenKeyExW(HKEY_LOCAL_MACHINE, (LPWSTR)buf, 0, KEY_READ | KEY_WOW64_64KEY, &hk);
        if (status != ERROR_SUCCESS) {
            return false;
        }
        return true;

    }
    else if (stringData[5] == L'U') {        // HKEY_USERS

        memcpy(buf, RegKey.data() + 11, RegKey.size() * 2 - 11);
        status = RegOpenKeyExW(HKEY_USERS, (LPWSTR)buf, 0, KEY_READ| KEY_WOW64_64KEY, &hk);
        if (status != ERROR_SUCCESS) {
            return false;
        }
        return true;

    }
    else if (stringData[5] == L'C') {         

        if (stringData[6] == L'L') {          // HKEY_CLASSES_ROOT

            memcpy(buf, RegKey.data() + 18, RegKey.size() * 2 - 18);
            status = RegOpenKeyExW(HKEY_CLASSES_ROOT, (LPWSTR)buf, 0, KEY_READ | KEY_WOW64_64KEY, &hk);
            if (status != ERROR_SUCCESS) {
                return false;
            }
            return true;

        }
        else if (stringData[13] == 'C') {   // HKEY_CURRENT_CONFIG

            memcpy(buf, RegKey.data() + 20, RegKey.size() * 2 - 20);
            status = RegOpenKeyExW(HKEY_CURRENT_CONFIG, (LPWSTR)buf, 0, KEY_READ | KEY_WOW64_64KEY, &hk);
            if (status != ERROR_SUCCESS) {
                return false;
            }
            return true;

        }
        else if (stringData[13] == 'U') {   // HKEY_CURRENT_USER

            memcpy(buf, RegKey.data() + 18, RegKey.size() * 2 - 18);
            status = RegOpenKeyExW(HKEY_CURRENT_USER, (LPWSTR)buf, 0, KEY_READ | KEY_WOW64_64KEY, &hk);
            if (status != ERROR_SUCCESS) {
                return false;
            }
            return true;

        }

        return false;
    }
    else {
        return false;
    }
}


bool cMain::CheckExistingRegistryKey(HANDLE HandleLockedRegistryKeyConfigFile, std::string RegKey)
{
    DWORD size{ 0 };
    size = GetFileSize(HandleLockedRegistryKeyConfigFile, 0);
    BYTE* configFile = RAII::NewBuffer(size).Get();
    if (configFile == nullptr) {
        MessageBoxA(NULL, "Could not allocate heap memory for file read.", "Error", MB_ICONERROR | MB_DEFBUTTON1);
        return false;
    }

    DWORD read;
    bool check = ReadFile(HandleLockedRegistryKeyConfigFile, configFile, size, &read, NULL);
    if (!check) {
        MessageBoxA(NULL, "Could not read from configuration file.", "Error", MB_ICONERROR | MB_DEFBUTTON1);
        return 3;
    }

    int relIndex = 0;
    bool match = true;
    const char* filePathchars = RegKey.c_str();
    for (unsigned int i = 0; i < size; i++) {

        if (configFile[i] == 0x3b && configFile[i + 1] == 0x3b && configFile[i + 2] == 0x3b) {
            if (match == true) {
                return true;
            }
            i += 2;
            relIndex = 0;
            match = true;
            continue;
        }

        if (filePathchars[relIndex] != configFile[i]) {
            match = false;
        }
        relIndex++;
    }

    return false;
}


std::string cMain::UserRegistryToKernelRegistry(std::string UserRegistryKey)
{
    // REGISTRY TRANSLATIONS FROM USER MODE SPEAK TO DRIVER SPEAK
    // HKEY_CLASSES_ROOT	-->		\REGISTRY\MACHINE\SOFTWARE\Classes\
	// HKEY_CURRENT_USER	-->		\REGISTRY\USER\SID
    // HKEY_LOCAL_MACHINE	-->		\REGISTRY\MACHINE\
	// HKEY_USERS			-->		\REGISTRY\USER\
	// HKEY_CURRENT_CONFIG  -->		\REGISTRY\MACHINE\SYSTEM\ControlSet001\Hardware Profiles\0001\

    if (UserRegistryKey.data()[5] == 'C') {

        if (UserRegistryKey.data()[6] == 'L') {                                                             // HKEY_CLASSES_ROOT
            const char* prepath = "\\REGISTRY\\MACHINE\\SOFTWARE\\Classes\\";
            std::string s1 = std::string(prepath);
            std::string s2 = std::string(UserRegistryKey.data() + 18);
            std::string ret = s1 + s2;
            return ret;


        }
        else if (UserRegistryKey.data()[13] == 'C') {                                                      // HKEY_CURRENT_CONFIG
            const char* prepath = "\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet001\\Hardware Profiles\\0001\\";  
            std::string s1 = std::string(prepath);
            std::string s2 = std::string(UserRegistryKey.data() + 20);
            std::string ret = s1 + s2;
            return ret;

        }
        else if (UserRegistryKey.data()[13] == 'U') {                                                       // HKEY_CURRENT_USER
            const char* prepath = "\\REGISTRY\\USER\\";  // need to add current sid after
            std::string s1 = std::string(prepath);
            std::string sid = GetCurrentSid();
            s1 = s1 + sid;
            std::string s2 = std::string(UserRegistryKey.data() + 18);
            std::string ret = s1 + s2;
            return ret;
        }
        else {
            return UserRegistryKey;
        }


    }
    else if (UserRegistryKey.data()[5] == 'L') {                                                            // HKEY_LOCAL_MACHINE
        const char* prepath = "\\REGISTRY\\MACHINE\\";
        std::string s1 = std::string(prepath);
        std::string s2 = std::string(UserRegistryKey.data() + 19);
        std::string ret = s1 + s2;
        return ret;

    }
    else if (UserRegistryKey.data()[5] == 'U') {
        const char* prepath = "\\REGISTRY\\USER\\";                                                         // HKEY_USERS   
        std::string s1 = std::string(prepath);
        std::string s2 = std::string(UserRegistryKey.data() + 11);
        std::string ret = s1 + s2;
        return ret;

    }
    else {
        return UserRegistryKey;
    }



}


void cMain::AddLockedRegistryKey(wxCommandEvent& evt)
{
    std::wstring RegKey = std::wstring(AddBlockedRegistryKeyTxtBox->GetValue().c_str());
    std::string RegKeyS = std::string(AddBlockedRegistryKeyTxtBox->GetValue().mb_str());
    if (!CheckValidRegistryKey(RegKey)) {
        char buf[200];
        sprintf_s(buf, "Registry Key does not exist. Error code: %d", GetLastError());
        MessageBoxA(NULL, buf, "Error", MB_ICONERROR | MB_DEFBUTTON1);
        evt.Skip();
        return;
    }

    RAII::Handle hConfig = CreateFileW(LockedRegistryPathConfig, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hConfig.Get() == INVALID_HANDLE_VALUE) {
        MessageBoxA(NULL, "Could not open config file for write.", "Error", MB_ICONERROR | MB_DEFBUTTON1);
        evt.Skip();
        return;
    }

    RegKeyS = UserRegistryToKernelRegistry(RegKeyS);
    MessageBoxA(NULL, RegKeyS.c_str(), "Error", MB_ICONERROR | MB_DEFBUTTON1);

    if (CheckExistingRegistryKey(hConfig.Get(), RegKeyS)) {         // Key exists
        MessageBoxA(NULL, "Registry key is already locked.", "Error", MB_ICONERROR | MB_DEFBUTTON1);
        evt.Skip();
        return;
    }
    
    // close our original handle, because now we must use CreateFileWith the append flag
    hConfig.Close();
    RAII::Handle hConfig2 = CreateFileW(LockedRegistryPathConfig, FILE_APPEND_DATA, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hConfig2.Get() == INVALID_HANDLE_VALUE) {
        MessageBoxA(NULL, "Unable to obtain handle to write config file.", "Error", MB_ICONERROR | MB_DEFBUTTON1);
        evt.Skip();
        return;
    }

    

    DWORD size = RegKeyS.length() + 3; // size of user given path + ;;;
    BYTE* writeBuffer = RAII::NewBuffer(size).Get();
    memcpy(writeBuffer, RegKeyS.c_str(), size - 3);
    memset((void*)((uintptr_t)writeBuffer + RegKeyS.length()), 0x3b, 3); // set last 3 bytes to ;;;

    DWORD numWritten;
    BOOL writeSuccess = false;
    writeSuccess = WriteFile(hConfig2.Get(), writeBuffer, size, &numWritten, NULL);
    if (!writeSuccess) {
        MessageBoxA(NULL, "Unable to write file path to current configuration.", "Error", MB_ICONERROR | MB_DEFBUTTON1);
        evt.Skip();
        return;
    }

    ULONG64 outBuffer;
    DWORD retBytes;
    BOOL success = DeviceIoControl(
        hFile,
        IOCTL_LOCKDOWN_REGKEY,
        writeBuffer,
        size,
        &outBuffer,
        sizeof(ULONG64),
        &retBytes,
        nullptr         // lpOverlapped
    );
    if (!success) {
        MessageBoxA(NULL, "Blocked file path added to configuration file, but not added to current Guardian session.", "Error", MB_ICONERROR | MB_DEFBUTTON1);
    }
    else {
        wxString successText("OK!");
        AddBlockedFileTxtBox->Clear();
        AddBlockedFileTxtBox->AppendText(successText);
    }
    evt.Skip(); // call this to end the event
    return;


}


void cMain::YaraScanFile(wxCommandEvent& evt) 
{
    std::wstring filePath = std::wstring((YaraScanFileTxtBox->GetValue()).wc_str());
    bool check = FileExists(filePath.c_str());
    if (!check) {
        MessageBoxA(NULL, "File does not exist.", "Error", MB_ICONERROR | MB_DEFBUTTON1);
        evt.Skip();
        return;
    }

    DWORD allocSize = sizeof(ScanFileHeaderJob) + filePath.size() * 2 + 1;
    auto buffer = RAII::HeapBuffer(allocSize).Get();
    if (buffer == nullptr) {
        MessageBoxA(NULL, "Unable to allocate heap for IO.", "Error", MB_ICONERROR | MB_DEFBUTTON1);
        evt.Skip();
        return;
    }

    ScanFileHeaderJob NewScanFileJob;
    NewScanFileJob.Type = TaskType::ScanFile;
    NewScanFileJob.FilePathOffset = sizeof(ScanFileHeaderJob);
    NewScanFileJob.FilePathLength = filePath.size() * 2;
    NewScanFileJob.Size = sizeof(ScanFileHeaderJob) + filePath.size() * 2;

    memcpy(buffer, &NewScanFileJob, sizeof(ScanFileHeaderJob));
    memcpy(buffer + sizeof(ScanFileHeaderJob), filePath.data(), filePath.size() * 2);

    DWORD retBytes;
    // https://stackoverflow.com/questions/26329328/pass-deviceiocontrol-input-buffer-with-directio
    // THERE ARE TWO INPUT BUFFERS WHEN DIRECT IO IS SPECIFIED, THE FIRST IS AVAILABLE TO THE DRIVER THROUGH THE SYSTEM BUFFER,
    // THE SECOND IS AVAILABLE THROUGH DIRECT IO
    check = DeviceIoControl(
        hFile,
        IOCTL_WRITE_WORKITEM,
        0,
        0,
        buffer,
        allocSize,
        &retBytes,
        0
    );




    if (check) {
       YaraScanFileTxtBox->Clear();
       YaraScanFileTxtBox->AppendText(wxString("Started scan successfully."));
    }
    else {
        YaraScanFileTxtBox->Clear();
        YaraScanFileTxtBox->AppendText(wxString("Unable to start scan."));
    }

    evt.Skip();
    return;
}


void cMain::YaraScanProcess(wxCommandEvent& evt)
{
    std::wstring filePath = std::wstring((YaraScanProcessTxtBox->GetValue()).wc_str());
    DWORD procId = atoi(YaraScanProcessTxtBox->GetValue().mb_str().data());

    char buf[40];
    sprintf(buf, "%d", procId);
    MessageBoxA(NULL, buf, "Error", MB_ICONERROR | MB_DEFBUTTON1);


    if (!ProcIdExists(procId)) {
        MessageBoxA(NULL, "Process Id does not exist.", "Error", MB_ICONERROR | MB_DEFBUTTON1);
        evt.Skip();
        return;
    }

    DWORD allocSize = sizeof(ScanProcessHeaderJob);
    auto buffer = RAII::NewBuffer(allocSize).Get();
    if (buffer == nullptr) {
        MessageBoxA(NULL, "Unable to allocate heap for IO.", "Error", MB_ICONERROR | MB_DEFBUTTON1);
        evt.Skip();
        return;
    }

    ScanProcessHeaderJob NewScanProcessJob;
    NewScanProcessJob.ProcessId = procId;
    NewScanProcessJob.Size = allocSize;
    NewScanProcessJob.Type = TaskType::ScanProcess;

    memcpy(buffer, &NewScanProcessJob, allocSize);

    DWORD retBytes;
    // https://stackoverflow.com/questions/26329328/pass-deviceiocontrol-input-buffer-with-directio
    // THERE ARE TWO INPUT BUFFERS WHEN DIRECT IO IS SPECIFIED, THE FIRST IS AVAILABLE TO THE DRIVER THROUGH THE SYSTEM BUFFER,
    // THE SECOND IS AVAILABLE THROUGH DIRECT IO
    BOOL check = DeviceIoControl(
        hFile,
        IOCTL_WRITE_WORKITEM,
        0,
        0,
        buffer,
        allocSize,
        &retBytes,
        0
    );

    if (check) {
        YaraScanProcessTxtBox->Clear();
        YaraScanProcessTxtBox->AppendText(wxString("Started scan successfully."));
    }
    else {
        YaraScanProcessTxtBox->Clear();
        YaraScanProcessTxtBox->AppendText(wxString("Unable to start scan."));
    }

    evt.Skip();
    return;

}