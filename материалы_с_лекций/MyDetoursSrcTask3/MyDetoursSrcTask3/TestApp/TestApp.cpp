// TestApp.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#define WIN32_LEAN_AND_MEAN  // Exclude rarely-used stuff from Windows headers
#include <windows.h>
#include <conio.h>
#include <stdio.h>
#include "..\inc\test.h"

int main()
{
    HANDLE h = CreateMutex(NULL, FALSE, L"TestApp_MyMutex");
    if (NULL == h) {
        printf("ERROR: TestApp: CreateMutex failed with %d \n", GetLastError());
        return -1;
    }
    if (ERROR_ALREADY_EXISTS == GetLastError()) {
        printf("ERROR: TestApp: CreateMutex exited!!! \n");
        printf("TestApp: !!! only SINGLE running instance allowed !!! \n");
        return -1;
    }

    printf("TestApp: Hello! \n");
    TestApi(L"TestApp calls TestApi");
    printf("TestApp: press any key...");
    _getch();
    CloseHandle(h);
    return 0;
}

