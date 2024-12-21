// myTestFixer.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#define WIN32_LEAN_AND_MEAN  // Exclude rarely-used stuff from Windows headers
#include <windows.h>
//#include <conio.h>
#include <stdio.h>
#include <stdlib.h>
#include "..\inc\detours.h"
//#include "..\inc\test.h"

int main()
{
    printf("TestFixer: Hello! \n");

    /*BOOL DetourCreateProcessWithDllEx(
        _In_        LPCSTR lpDllName,
        _In_opt_    PDETOUR_CREATE_PROCESS_ROUTINEW pfCreateProcessW
    );*/

    CHAR szPath[MAX_PATH];
    CHAR szDrive[MAX_PATH];
    CHAR szDir[MAX_PATH];
    CHAR szFilename[MAX_PATH];
    CHAR szExt[MAX_PATH];
    CHAR szAppToFix[MAX_PATH];
    CHAR szAppExtenstionDll[MAX_PATH];
    GetModuleFileNameA(nullptr, szPath, MAX_PATH);
    _splitpath_s(szPath, szDrive, szDir, szFilename, szExt);
    sprintf_s(szAppToFix, "%s%s%s", szDrive, szDir, "TestApp.exe");
    sprintf_s(szAppExtenstionDll, "%s%s%s", szDrive, szDir, "myTestExtension64.dll");
    printf("TestFixer: AppToFix: %s \n", szAppToFix);
    printf("TestFixer: AppExtenstionDll: %s \n", szAppExtenstionDll);

    STARTUPINFOA si = { .cb = sizeof(si) };
    PROCESS_INFORMATION pi;
    if (!DetourCreateProcessWithDllExA(szAppToFix, nullptr, nullptr, nullptr, FALSE, 0, nullptr, nullptr, &si, &pi,
        szAppExtenstionDll, nullptr)) {
        printf("ERROR: myTestFixer: CreateProcess failed with %d \n", GetLastError());
    }

    //HANDLE h = CreateMutex(NULL, FALSE, L"TestApp_MyMutex");
    //if (NULL == h) {
    //    printf("ERROR: TestApp: CreateMutex failed with %d \n", GetLastError());
    //    return -1;
    //}
    //if (ERROR_ALREADY_EXISTS == GetLastError()) {
    //    printf("ERROR: TestApp: CreateMutex exited!!! \n");
    //    printf("TestApp: !!! only SINGLE running instance allowed !!! \n");
    //    return -1;
    //}

    //TestApi(L"TestApp calls TestApi");
    //printf("TestApp: press any key...");
    //_getch();
    //CloseHandle(h);
    return 0;
}
