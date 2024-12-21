// PeInfo.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include "windows.h"
#include "stdio.h"

PVOID MapPeFile(LPCWSTR filePath)
{
    HANDLE hFile = CreateFile(filePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (INVALID_HANDLE_VALUE == hFile) {
        printf("MapPeFile: CreateFile fails with %d \n", GetLastError());
        return NULL;
    }
    HANDLE hFileMapping = CreateFileMapping(hFile, NULL, PAGE_READONLY | SEC_IMAGE_NO_EXECUTE, 0, 0, NULL);
    if (NULL == hFileMapping) {
        printf("MapPeFile: CreateFileMapping fails with %d \n", GetLastError());
        return NULL;
    }
    PVOID p = MapViewOfFile(hFileMapping, FILE_MAP_READ, 0, 0, 0);
    if (NULL == hFileMapping) {
        printf("MapPeFile: MapViewOfFile fails with %d \n", GetLastError());
        return NULL;
    }
    return p;
}

int wmain(int argc, wchar_t* argv[])
{
    if (argc != 2) {
        printf("Usage: PeInfo PeFilePath \n");
    }

    PUCHAR pImageBase = (PUCHAR)MapPeFile(argv[1]);
    PUCHAR p = pImageBase;
    if (NULL == p) return -1;

    printf("MS-DOS Signature: %c%c \n", p[0], p[1]);
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)p;
    p += pDosHeader->e_lfanew;
    printf("PE Signature: %c%c %x%x \n", p[0], p[1], p[2], p[3]);
    PIMAGE_NT_HEADERS32 pTempPeHeader = (PIMAGE_NT_HEADERS32)p;
    WORD numSections = pTempPeHeader->FileHeader.NumberOfSections;
    WORD arch = pTempPeHeader->FileHeader.Machine;
    BOOL b64 = false;
    switch (arch) {
        case IMAGE_FILE_MACHINE_I386:
            printf("PE Architecture: x86 \n");
            break;
        case IMAGE_FILE_MACHINE_AMD64:
            printf("PE Architecture: x64 \n");
            b64 = true;
            break;
        default:
            printf("PE Architecture: unknown \n");
            return -1;
            break;
    }

    //correct but ugly and too much code
    //PIMAGE_NT_HEADERS32 pOptHdr32 = (PIMAGE_NT_HEADERS32)pOptHdr32;
    //PIMAGE_NT_HEADERS64 pOptHdr64 = (PIMAGE_NT_HEADERS64)pOptHdr64;
    //if (b64) {
    //} else {
    //}

    #define RVA(ofs) (pImageBase+(ofs))
    #define DECLARE_TYPE_P(TYPE, var) TYPE var = (TYPE)p

    //HACK! HACK! these fields are before first ULONGULONG so has fixed ofset even in optional header!
    printf("PE ImageBase : %p \n", pImageBase);
    printf("PE EntryPoint: %p \n", pImageBase + pTempPeHeader->OptionalHeader.AddressOfEntryPoint);

    //HACK! HACK! these fields are after first ULONGULONG so has fixed shift
    //!!! there is no shift becuase BaseOfData was omitted and incorporated into ImageBase
    //if (b64) pTempPeHeader = (PIMAGE_NT_HEADERS32)(((PUCHAR)pTempPeHeader) + sizeof(ULONG));
    printf("PE SectionAlignment (def=512) : %d\n", pTempPeHeader->OptionalHeader.SectionAlignment);
    printf("PE FileAlignment    (def=4096): %d\n", pTempPeHeader->OptionalHeader.FileAlignment);

    //HACK! HACK! these fields are after second ULONGULONGs so has fixed shift
    if (b64) pTempPeHeader = (PIMAGE_NT_HEADERS32)(((PUCHAR)pTempPeHeader) + 4*sizeof(ULONG));
    printf("PE NumberOfRvaAndSizes (16)  : %d\n", pTempPeHeader->OptionalHeader.NumberOfRvaAndSizes);
    printf("PE Imports at %p \n", pImageBase + pTempPeHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

    p += b64 ? sizeof(IMAGE_NT_HEADERS64) : sizeof(IMAGE_NT_HEADERS32);
#if 0
    PIMAGE_SECTION_HEADER pSection = (PIMAGE_SECTION_HEADER)p;
#else
    DECLARE_TYPE_P(PIMAGE_SECTION_HEADER, pSection);
#endif
    printf("\n");
    for (int i = 0; i < numSections; i++) {
        printf("PE Section #%d %.8s \n", i, pSection->Name);
        pSection++;
    }
}
