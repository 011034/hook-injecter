#include <Windows.h>
#include <TlHelp32.h>
#include <iostream>
#include <string>

// 获取当前执行文件的路径并构建 DLL 的完整路径
std::wstring GetDllPath()
{
    wchar_t buffer[MAX_PATH];
    GetModuleFileName(NULL, buffer, MAX_PATH);

    // 获取当前执行文件的目录
    std::wstring::size_type pos = std::wstring(buffer).find_last_of(L"\\/");
    std::wstring directory = std::wstring(buffer).substr(0, pos);

    // 构建 DLL 的完整路径
    return directory + L"\\hook.dll";
}

// 查找进程 ID
DWORD FindProcessId(const std::wstring& processName)
{
    PROCESSENTRY32 processInfo;
    processInfo.dwSize = sizeof(processInfo);

    HANDLE processesSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
    if (processesSnapshot == INVALID_HANDLE_VALUE) {
        return 0;
    }

    Process32First(processesSnapshot, &processInfo);
    if (!_wcsicmp(processInfo.szExeFile, processName.c_str()))
    {
        CloseHandle(processesSnapshot);
        return processInfo.th32ProcessID;
    }

    while (Process32Next(processesSnapshot, &processInfo))
    {
        if (!_wcsicmp(processInfo.szExeFile, processName.c_str()))
        {
            CloseHandle(processesSnapshot);
            return processInfo.th32ProcessID;
        }
    }

    CloseHandle(processesSnapshot);
    return 0;
}

// 进程注入函数
BOOL InjectDLL(DWORD processId, const std::wstring& dllPath)
{
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
    if (hProcess == NULL) {
        std::wcerr << L"Failed to open target process." << std::endl;
        return FALSE;
    }

    LPVOID pDllPath = VirtualAllocEx(hProcess, 0, dllPath.length() * sizeof(wchar_t), MEM_COMMIT, PAGE_READWRITE);
    WriteProcessMemory(hProcess, pDllPath, dllPath.c_str(), dllPath.length() * sizeof(wchar_t), NULL);

    HMODULE hKernel32 = GetModuleHandle(L"kernel32.dll");
    LPTHREAD_START_ROUTINE pLoadLibraryW = (LPTHREAD_START_ROUTINE)GetProcAddress(hKernel32, "LoadLibraryW");

    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, pLoadLibraryW, pDllPath, 0, NULL);
    if (hThread == NULL) {
        std::wcerr << L"Failed to create remote thread." << std::endl;
        CloseHandle(hProcess);
        return FALSE;
    }

    WaitForSingleObject(hThread, INFINITE);

    VirtualFreeEx(hProcess, pDllPath, 0, MEM_RELEASE);
    CloseHandle(hThread);
    CloseHandle(hProcess);

    return TRUE;
}

int main()
{
    std::wstring dllPath = GetDllPath(); // 获取根目录下的 DLL 路径

    DWORD processId = FindProcessId(L"explorer.exe");
    if (processId == 0)
    {
        std::wcerr << L"Failed to find explorer.exe process." << std::endl;
        return 1;
    }

    std::wcout << L"Explorer.exe process ID: " << processId << std::endl;

    if (InjectDLL(processId, dllPath))
    {
        std::wcout << L"DLL injected successfully into explorer.exe from: " << dllPath << std::endl;
    }
    else
    {
        std::wcerr << L"Failed to inject DLL into explorer.exe." << std::endl;
    }

    return 0;
}
