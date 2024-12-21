// dllmain.cpp : Defines the entry point for the DLL application.
#define WIN32_LEAN_AND_MEAN             // Exclude rarely-used stuff from Windows headers
#include <windows.h>
#include "../inc/detours.h"
#include <stdio.h>
#include <type_traits>

#define DETOURS_PFN(func) auto *g_##func = &func
#define DETOURS_FN_CHECK(func) static_assert(std::is_same_v<decltype(&My##func), decltype(&func)>, "DETOURS_FN_CHECK: " #func " mistype")
#define DETOURS_XXTACH(func) reinterpret_cast<PVOID*>(&g_##func), reinterpret_cast<PVOID>(My##func)

static DETOURS_PFN(CreateMutexW);
HANDLE MyCreateMutexW(LPSECURITY_ATTRIBUTES lpMutexAttributes, BOOL bInitialOwner, LPCWSTR lpName)
{
    WCHAR szNameFix[MAX_PATH];
    swprintf_s(szNameFix, L"%ws_%X", lpName, GetCurrentProcessId());

    WCHAR szMsg[MAX_PATH];
    swprintf_s(szMsg, L"Fixed: %ws => %ws", lpName, szNameFix);
    MessageBox(nullptr, szMsg, L"myTestExtesnion: MyCreateMutexW", MB_OK);

    return g_CreateMutexW(lpMutexAttributes, bInitialOwner, szNameFix);
}
DETOURS_FN_CHECK(CreateMutexW);

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    if (DetourIsHelperProcess()) {
        return TRUE;
    }

    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        //MessageBox(nullptr, L"dll was attached!", L"TestDllExtension", MB_OK);
        DetourRestoreAfterWith();
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourAttach(DETOURS_XXTACH(CreateMutexW));
        DetourTransactionCommit();
        break;
    case DLL_PROCESS_DETACH:
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourDetach(DETOURS_XXTACH(CreateMutexW));
        DetourTransactionCommit();
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
        break;
    }
    return TRUE;
}

