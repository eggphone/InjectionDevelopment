#include <string.h>
#include <stdio.h>
#include <windows.h>
#include <iostream>
#include <memoryapi.h>

#define TARGET_PROGRAM L"C:\\Windows\\system32\\cmd.exe"
#define PAGE_SIZE 0x1000


extern "C" {

typedef DWORD (WINAPI *__GetLastError)();
typedef UINT (WINAPI *__ExitProcess)(UINT uExitCode);


typedef struct _PL_ARGS
{
    DWORD_PTR lpArg;
    __GetLastError _GetLastError;
    __ExitProcess _ExitProcess;
} PL_ARGS;
}

#pragma code_seg("PAYLOAD")
DWORD WINAPI Payload(LPVOID lpArgs)
{
    PL_ARGS *pArgs = reinterpret_cast<PL_ARGS *>(lpArgs);
    //(*pArgs->_ExitProcess)(2);
    return 1;
}
#pragma code_seg("PAYLOAD")

DWORD GetSectionSize(const PCHAR pSectionName) {
    HMODULE hModule = GetModuleHandle(NULL);
    if (!hModule) {
        printf("Failed to get module handle\n");
        return 0;
    }

    PIMAGE_DOS_HEADER pDosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(hModule);
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        printf("Not a valid PE file\n");
        return 0;
    }

    PIMAGE_NT_HEADERS pNtHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<PBYTE>(hModule) + pDosHeader->e_lfanew);
    if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
        printf("Not a valid NT header\n");
        return 0;
    }

    PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);
    for (int i = 0; i < pNtHeaders->FileHeader.NumberOfSections; ++i) {
        if (strcmp((PCHAR)pSectionHeader[i].Name, pSectionName) == 0) {
            return pSectionHeader[i].Misc.VirtualSize;
        }
    }
    printf("Section %s not found\n", pSectionName);
    return 0;
}

BOOL WriteMemoryEx(LPPROCESS_INFORMATION lpProcessInformation, LPVOID lpPayloadAddr, LPVOID lpArgumentAddr, DWORD dwNumPages)
{

    if (lpPayloadAddr == NULL || lpArgumentAddr == NULL )
    {
        printf("Could not allocate memory in target process\n");
        return FALSE;
    }

    if ((ULONG_PTR)Payload % (ULONG_PTR)PAGE_SIZE)
    {
        printf("Payload not at begin of section... %p\n", Payload);
        return FALSE;
    }

    SIZE_T bytesWritten = 0;
    BOOL bMemWritten = WriteProcessMemory(lpProcessInformation->hProcess, lpPayloadAddr,
                                          reinterpret_cast<LPVOID>(Payload), PAGE_SIZE * dwNumPages, &bytesWritten);
    if (bMemWritten == 0)
    {
        printf("Failed writing memory\n");
        return FALSE;
    }

    PL_ARGS *pPayloadArgs = new PL_ARGS;
    memset(pPayloadArgs, 0, sizeof(PL_ARGS));

    pPayloadArgs->_GetLastError = (__GetLastError )GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "GetLastError");
    pPayloadArgs->_ExitProcess = (__ExitProcess)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "ExitProcess");

    if (pPayloadArgs->_GetLastError == NULL || pPayloadArgs->_ExitProcess == NULL )
    {
        printf("could not get kernel32 functions\n");
        delete pPayloadArgs;
        return FALSE;
    }

    bMemWritten = WriteProcessMemory(lpProcessInformation->hProcess, lpArgumentAddr,
                                     reinterpret_cast<LPCVOID>(pPayloadArgs), sizeof(PL_ARGS), &bytesWritten);

    if (bMemWritten == 0)
    {
        printf("Failed writing memory\n");
        delete pPayloadArgs;
        return FALSE;
    }
    delete pPayloadArgs;
    return TRUE;
}

BOOL RunThreadEx(LPPROCESS_INFORMATION lpProcessInfo, LPVOID lpPayloadAddr, LPVOID lpArgumentAddr)
{
    DWORD dwThreadId = 0;
    HANDLE hThread = CreateRemoteThreadEx(lpProcessInfo->hProcess, NULL, 0,
                                          reinterpret_cast<LPTHREAD_START_ROUTINE>(lpPayloadAddr), lpArgumentAddr,
                                          CREATE_SUSPENDED, NULL, &dwThreadId);

    if (hThread == NULL)
    {
        printf("Could not start remote thread\n");
        return FALSE;
    }

    DWORD dwResume = ResumeThread(hThread);
    if(!dwResume)
    {
        printf("Could not resume remote thread\n");
        VirtualFreeEx(lpProcessInfo->hProcess, lpPayloadAddr, 0, MEM_RELEASE );
        VirtualFreeEx(lpProcessInfo->hProcess, lpArgumentAddr, 0, MEM_RELEASE );
        CloseHandle(hThread);
        return FALSE;
    }

    WaitForSingleObject(hThread, INFINITE);
    DWORD dwExitCode = 0;
    if(!GetExitCodeThread(hThread, &dwExitCode))
    {
        printf("Could not get exit code\n");
    }
    else
    {
        printf("Thread finished with exit code 0x%08lx\n", dwExitCode);
    }

    VirtualFreeEx(lpProcessInfo->hProcess, lpPayloadAddr, 0, MEM_RELEASE );
    VirtualFreeEx(lpProcessInfo->hProcess, lpArgumentAddr, 0, MEM_RELEASE );
    CloseHandle(hThread);

    dwResume = ResumeThread(lpProcessInfo->hThread);
    if (dwResume == -1ul)
    {
        printf("Failed to resume thread\n");
    }
    else
    {
        WaitForSingleObject(lpProcessInfo->hThread, INFINITE);
    }

    if (!GetExitCodeThread(lpProcessInfo->hThread, &dwExitCode))
    {
        printf("Could not get exit code\n");
    }
    else
    {
        printf("Main thread of remote process finished with exit code 0x%08lx\n", dwExitCode);
    }
    return TRUE;
}

int main(int argc, char **argv)
{
    STARTUPINFOW *pStartupInfo = new STARTUPINFOW ;
    PROCESS_INFORMATION *pProcessInfo = new PROCESS_INFORMATION;

    memset(pStartupInfo, 0, sizeof(STARTUPINFOW));
    pStartupInfo->cb = sizeof(STARTUPINFOW);
    memset(pProcessInfo, 0, sizeof(PROCESS_INFORMATION));

    BOOL bPsCreate = CreateProcessW(TARGET_PROGRAM, NULL, NULL,
                                    NULL, TRUE, CREATE_NEW_CONSOLE | CREATE_SUSPENDED,
                                    NULL, NULL, pStartupInfo, pProcessInfo);
    if (bPsCreate == FALSE)
    {
        printf("Could not start process\n");
        return -1;
    }

    DWORD dwSecSize = GetSectionSize("PAYLOAD");
    if (dwSecSize == 0)
    {
        printf("Could get Payload Section\n");
        return -1;
    }

    DWORD dwNumPages  =  (dwSecSize / PAGE_SIZE) + 1;
    LPVOID lpPayloadAddr = VirtualAllocEx(pProcessInfo->hProcess, NULL,
                                          PAGE_SIZE * dwNumPages, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    LPVOID lpArgumentAddr = VirtualAllocEx(pProcessInfo->hProcess, NULL,
                                           PAGE_SIZE, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

    if (lpPayloadAddr == NULL || lpArgumentAddr == NULL)
    {
        CloseHandle(pProcessInfo->hThread);
        CloseHandle(pProcessInfo->hProcess);
        return -1;
    }

    BOOL bMemWrittenEx = WriteMemoryEx(pProcessInfo, lpPayloadAddr, lpArgumentAddr, dwNumPages);
    if (bMemWrittenEx == FALSE)
    {
        VirtualFreeEx(pProcessInfo->hProcess, lpPayloadAddr, 0, MEM_RELEASE );
        VirtualFreeEx(pProcessInfo->hProcess, lpArgumentAddr, 0, MEM_RELEASE );
        CloseHandle(pProcessInfo->hThread);
        CloseHandle(pProcessInfo->hProcess);
        return -1;
    }

    BOOL bThreadEx = RunThreadEx(pProcessInfo, lpPayloadAddr, lpArgumentAddr);

    if(bThreadEx == FALSE)
    {
        CloseHandle(pProcessInfo->hThread);
        CloseHandle(pProcessInfo->hProcess);
        return -1;
    }

    CloseHandle(pProcessInfo->hThread);
    CloseHandle(pProcessInfo->hProcess);
    return 0;
}
