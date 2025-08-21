#ifndef PE_LOGIC
#define PE_LOGIC

#include	<ntifs.h>

#include "PE_parse.h"

typedef struct _PEB_LDR_DATA {
    CHAR       Reserved1[8];
    PVOID      Reserved2[3];
    LIST_ENTRY InMemoryOrderModuleList;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _PEB {
    CHAR                          Reserved1[2];
    CHAR                          BeingDebugged;
    CHAR                          Reserved2[1];
    PVOID                         Reserved3[2];
    PPEB_LDR_DATA                 Ldr;
} PEB, * PPEB;

typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    // ... 이하 생략
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

// Looking for the Dll and API Address from Target Process
NTSTATUS Dll_API_Address_Search(
	HANDLE Processid,

	PWCH Dll_Name, // Dll Name
	PCHAR Api_Name, // API Name

	PUCHAR* Dll_Base_VirtualAddress, // Dll Base Address
	PUCHAR* API_VirtualAddress // API Address in Dll Base Address
);

typedef struct ImageSectionInformation {

    CHAR SectionName[256]; // ".data", ".rdata" 같은 것들

    PUCHAR SectionBaseAddress;
    SIZE_T SectionSize;

    PUCHAR NextAddr;

}ImageSectionInformation, *PImageSectionInformation;

typedef struct ImageInformation {

    PUCHAR Image_BaseAddress;
    SIZE_T ImageSize;

    UNICODE_STRING ImageName;

    PImageSectionInformation SectionInfo_StartNode; // Section 정보

    PUCHAR NextAddr; // next node

}ImageInformation, *PImageInformation;

#define ImageInformationNode_TAG 'IINT' // ImageInofrmationNodeTag

NTSTATUS Get_ImageInformation_by_ProcessId(HANDLE ProcessId, PImageInformation* output);
VOID Release_ImageInformation(PImageInformation input);

#endif