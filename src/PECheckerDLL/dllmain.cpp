#include "pch.h"
#include <Windows.h>
#include <iostream>

extern "C" __declspec(dllexport) void myDllFunction()
{
    std::cerr << "PECheckerDLL function was called!" << std::endl;
    OutputDebugString(L"PECheckerDLL function was called!\n");
    MessageBox(NULL, L"PECheckerDLL function was called!", L"Debug Message", MB_OK);
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        OutputDebugString(L"PECheckerDLL.dll loaded: Process Attach\n");
        break;

    case DLL_PROCESS_DETACH:
        OutputDebugString(L"PECheckerDLL.dll unloaded: Process Detach\n");
        break;

    case DLL_THREAD_ATTACH:
        OutputDebugString(L"PECheckerDLL.dll loaded: Thread Attach\n");
        break;

    case DLL_THREAD_DETACH:
        OutputDebugString(L"PECheckerDLL.dll unloaded: Thread Detach\n");
        break;
    }
    return TRUE;
}

