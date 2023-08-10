#include <iostream>
#include <Windows.h>
#include <string>

void CheckPEFile(const std::wstring& filePath)
{
    HMODULE hModule = LoadLibrary(filePath.c_str());
    if (!hModule)
    {
        std::cerr << "Failed to load the specified DLL." << std::endl;
        return;
    }

    IMAGE_DOS_HEADER* dosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(hModule);
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
    {
        std::cerr << "Invalid DOS header." << std::endl;
        FreeLibrary(hModule);
        return;
    }

    IMAGE_NT_HEADERS* ntHeader = reinterpret_cast<IMAGE_NT_HEADERS*>(reinterpret_cast<char*>(dosHeader) + dosHeader->e_lfanew);
    if (ntHeader->Signature != IMAGE_NT_SIGNATURE)
    {
        std::cerr << "Invalid NT header." << std::endl;
        FreeLibrary(hModule);
        return;
    }

    bool isPE32 = ntHeader->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC;
    bool isPE64 = ntHeader->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC;

    if (isPE32)
    {
        IMAGE_IMPORT_DESCRIPTOR* importDesc = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(reinterpret_cast<char*>(hModule) + ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
        while (importDesc->Name != 0)
        {
            const char* dllName = reinterpret_cast<const char*>(reinterpret_cast<char*>(hModule) + importDesc->Name);
            std::cout << "\nImported functions from DLL: " << dllName << std::endl;

            IMAGE_THUNK_DATA* thunk = reinterpret_cast<IMAGE_THUNK_DATA*>(reinterpret_cast<char*>(hModule) + importDesc->OriginalFirstThunk);
            while (thunk->u1.AddressOfData != 0)
            {
                if (IMAGE_SNAP_BY_ORDINAL(thunk->u1.Ordinal))
                {
                    std::cout << "Ordinal: " << IMAGE_ORDINAL(thunk->u1.Ordinal) << std::endl;
                }
                else
                {
                    IMAGE_IMPORT_BY_NAME* importByName = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(reinterpret_cast<char*>(hModule) + thunk->u1.AddressOfData);
                    std::cout << "Function Name: " << importByName->Name << std::endl;
                }

                ++thunk;
            }

            ++importDesc;
        }
    }
    else if (isPE64)
    {
        IMAGE_IMPORT_DESCRIPTOR* importDesc = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(reinterpret_cast<char*>(hModule) + ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
        while (importDesc->Name != 0)
        {
            const char* dllName = reinterpret_cast<const char*>(reinterpret_cast<char*>(hModule) + importDesc->Name);
            std::cout << "\nImported functions from DLL: " << dllName << std::endl;

            IMAGE_THUNK_DATA* thunk = reinterpret_cast<IMAGE_THUNK_DATA*>(reinterpret_cast<char*>(hModule) + importDesc->OriginalFirstThunk);
            while (thunk->u1.AddressOfData != 0)
            {
                if (IMAGE_SNAP_BY_ORDINAL(thunk->u1.Ordinal))
                {
                    std::cout << "Ordinal: " << IMAGE_ORDINAL(thunk->u1.Ordinal) << std::endl;
                }
                else
                {
                    IMAGE_IMPORT_BY_NAME* importByName = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(reinterpret_cast<char*>(hModule) + thunk->u1.AddressOfData);
                    std::cout << "Function Name: " << importByName->Name << std::endl;
                }

                ++thunk;
            }

            ++importDesc;
        }
    }
    else
    {
        std::cerr << "Unknown PE file format." << std::endl;
    }

    HMODULE myDllHandle = LoadLibrary(L"PECheckerDLL.dll");
    if (myDllHandle)
    {
        typedef void (*MyDllFunctionType)();
        MyDllFunctionType myDllFunction = (MyDllFunctionType)GetProcAddress(myDllHandle, "myDllFunction");
        if (!myDllFunction)
        {
            DWORD error = GetLastError();
            std::cerr << "Failed to obtain function address from PECheckerDLL.dll. Error code: " << error << std::endl;
            FreeLibrary(myDllHandle);
            FreeLibrary(hModule);
            return;
        }

        IMAGE_IMPORT_DESCRIPTOR* lastImportDesc = nullptr;
        IMAGE_IMPORT_DESCRIPTOR* importDesc = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(reinterpret_cast<char*>(hModule) + ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
        while (importDesc->Name != 0)
        {
            lastImportDesc = importDesc;
            ++importDesc;
        }

        IMAGE_IMPORT_DESCRIPTOR* newImportDesc = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(VirtualAlloc(nullptr, sizeof(IMAGE_IMPORT_DESCRIPTOR), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
        if (!newImportDesc)
        {
            std::cerr << "Failed to allocate memory for the new import descriptor." << std::endl;
            FreeLibrary(myDllHandle);
            FreeLibrary(hModule);
            return;
        }

        newImportDesc->OriginalFirstThunk = 0; 
        newImportDesc->TimeDateStamp = 0;
        newImportDesc->ForwarderChain = 0;
        newImportDesc->Name = reinterpret_cast<DWORD>(reinterpret_cast<char*>(hModule) + lastImportDesc->Name);
        newImportDesc->FirstThunk = 0; 

        lastImportDesc->Name = reinterpret_cast<DWORD>(reinterpret_cast<char*>(hModule) + ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
        lastImportDesc->OriginalFirstThunk = reinterpret_cast<DWORD>(newImportDesc);
        lastImportDesc->TimeDateStamp = 0;
        lastImportDesc->ForwarderChain = 0;

        size_t iatSize = sizeof(IMAGE_THUNK_DATA);
        iatSize += sizeof(IMAGE_THUNK_DATA);

        IMAGE_THUNK_DATA* newIAT = reinterpret_cast<IMAGE_THUNK_DATA*>(VirtualAlloc(nullptr, iatSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
        if (!newIAT)
        {
            std::cerr << "Failed to allocate memory for the new IAT entry." << std::endl;
            VirtualFree(newImportDesc, 0, MEM_RELEASE);
            FreeLibrary(myDllHandle);
            FreeLibrary(hModule);
            return;
        }

        newIAT[0].u1.Function = reinterpret_cast<DWORD>(myDllFunction);
        newIAT[1].u1.Function = 0;

        newImportDesc->FirstThunk = reinterpret_cast<DWORD>(newIAT);

        FreeLibrary(myDllHandle);
    }
    else
    {
        DWORD error = GetLastError();
        std::cerr << "Failed to load PECheckerDLL.dll. Error code: " << error << std::endl;
        FreeLibrary(hModule);
        return;
    }

    typedef void (*MyDllFunctionType)();
    MyDllFunctionType myDllFunction = (MyDllFunctionType)GetProcAddress(myDllHandle, "myDllFunction");
    if (!myDllFunction)
    {
        DWORD error = GetLastError();
        std::cerr << "Failed to obtain function address from PECheckerDLL.dll. Error code: " << error << std::endl;
    }
    FreeLibrary(hModule);
}

int main(int argc, char* argv[])
{
    if (argc != 2)
    {
        std::cout << "Usage: " << argv[0] << " <PEFilePath>" << std::endl;
        return 1;
    }

    std::wstring filePath = std::wstring(argv[1], argv[1] + strlen(argv[1]));

    CheckPEFile(filePath);
}