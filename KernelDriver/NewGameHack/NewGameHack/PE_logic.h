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
    UCHAR InheritedAddressSpace;       // 0x000
    UCHAR ReadImageFileExecOptions;    // 0x001
    UCHAR BeingDebugged;               // 0x002
    UCHAR BitField;                    // 0x003
    CHAR  Padding0[4];                 // 0x004
    void* Mutant;                      // 0x008
    void* ImageBaseAddress;            // 0x010
    struct _PEB_LDR_DATA* Ldr;         // 0x018
    void* ProcessParameters;           // 0x020
    void* SubSystemData;               // 0x028
    void* ProcessHeap;                 // 0x030
    void* FastPebLock;                 // 0x038
    void* AtlThunkSListPtr;            // 0x040
    void* IFEOKey;                     // 0x048
    UINT32 CrossProcessFlags;          // 0x050
    CHAR  Padding1[4];                 // 0x054
    void* KernelCallbackTable;         // 0x058
    UINT32 SystemReserved;             // 0x060
    UINT32 AtlThunkSListPtr32;         // 0x064
    void* ApiSetMap;                   // 0x068
    UINT32 TlsExpansionCounter;        // 0x070
    CHAR  Padding2[4];                 // 0x074
    void* TlsBitmap;                   // 0x078
    UINT32 TlsBitmapBits[2];           // 0x080
    void* ReadOnlySharedMemoryBase;    // 0x088
    void* SharedData;                  // 0x090
    void** ReadOnlyStaticServerData;   // 0x098
    void* AnsiCodePageData;            // 0x0a0
    void* OemCodePageData;             // 0x0a8
    void* UnicodeCaseTableData;        // 0x0b0
    UINT32 NumberOfProcessors;         // 0x0b8
    UINT32 NtGlobalFlag;               // 0x0bc
    CHAR  CriticalSectionTimeout[8];   // 0x0c0
    UINT64 HeapSegmentReserve;         // 0x0c8
    UINT64 HeapSegmentCommit;          // 0x0d0
    UINT64 HeapDeCommitTotalFreeThreshold; // 0x0d8
    UINT64 HeapDeCommitFreeBlockThreshold; // 0x0e0
    UINT32 NumberOfHeaps;              // 0x0e8
    UINT32 MaximumNumberOfHeaps;       // 0x0ec
    void** ProcessHeaps;               // 0x0f0
    void* GdiSharedHandleTable;        // 0x0f8
    void* ProcessStarterHelper;        // 0x100
    UINT32 GdiDCAttributeList;         // 0x108
    CHAR  Padding3[4];                 // 0x10c
    void* LoaderLock;                  // 0x110
    UINT32 OSMajorVersion;             // 0x118
    UINT32 OSMinorVersion;             // 0x11c
    UINT16 OSBuildNumber;              // 0x120
    UINT16 OSCSDVersion;               // 0x122
    UINT32 OSPlatformId;               // 0x124
    UINT32 ImageSubsystem;             // 0x128
    UINT32 ImageSubsystemMajorVersion; // 0x12c
    UINT32 ImageSubsystemMinorVersion; // 0x130
    CHAR  Padding4[4];                 // 0x134
    UINT64 ActiveProcessAffinityMask;  // 0x138
    UINT32 GdiHandleBuffer[60];        // 0x140
    void* PostProcessInitRoutine;      // 0x230
    void* TlsExpansionBitmap;          // 0x238
    UINT32 TlsExpansionBitmapBits[32]; // 0x240
    UINT32 SessionId;                  // 0x2c0
    CHAR  Padding5[4];                 // 0x2c4
    CHAR  AppCompatFlags[8];           // 0x2c8
    CHAR  AppCompatFlagsUser[8];       // 0x2d0
    void* pShimData;                   // 0x2d8
    void* AppCompatInfo;               // 0x2e0
    CHAR  CSDVersion[16];              // 0x2e8
    void* ActivationContextData;       // 0x2f8
    void* ProcessAssemblyStorageMap;   // 0x300
    void* SystemDefaultActivationContextData; // 0x308
    void* SystemAssemblyStorageMap;    // 0x310
    UINT64 MinimumStackCommit;         // 0x318
    void* SparePointers[2];            // 0x320
    void* PatchLoaderData;             // 0x330
    void* ChpeV2ProcessInfo;           // 0x338
    UINT32 AppModelFeatureState;       // 0x340
    UINT32 SpareUlongs[2];             // 0x344
    UINT16 ActiveCodePage;             // 0x34c
    UINT16 OemCodePage;                // 0x34e
    UINT16 UseCaseMapping;             // 0x350
    UINT16 UnusedNlsField;             // 0x352
    void* WerRegistrationData;         // 0x358
    void* WerShipAssertPtr;            // 0x360
    void* EcCodeBitMap;                // 0x368
    void* pImageHeaderHash;            // 0x370
    UINT32 TracingFlags;               // 0x378
    CHAR  Padding6[4];                 // 0x37c
    UINT64 CsrServerReadOnlySharedMemoryBase; // 0x380
    UINT64 TppWorkerpListLock;         // 0x388
    CHAR  TppWorkerpList[16];          // 0x390
    void* WaitOnAddressHashTable[128]; // 0x3a0
    void* TelemetryCoverageHeader;     // 0x7a0
    UINT32 CloudFileFlags;             // 0x7a8
    UINT32 CloudFileDiagFlags;         // 0x7ac
    CHAR  PlaceholderCompatibilityMode; // 0x7b0
    CHAR  PlaceholderCompatibilityModeReserved[7]; // 0x7b1
    void* LeapSecondData;              // 0x7b8
    UINT32 LeapSecondFlags;            // 0x7c0
    UINT32 NtGlobalFlag2;              // 0x7c4
    UINT64 ExtendedFeatureDisableMask; // 0x7c8
} PEB, *PPEB;

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