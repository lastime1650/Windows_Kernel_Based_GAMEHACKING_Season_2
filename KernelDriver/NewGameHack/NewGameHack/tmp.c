#include <ntifs.h>
#include <wdm.h>
#include <ntstrsafe.h>

// --- 구조체 정의 ---

#define POOL_TAG 'nScP'

typedef struct ImageSectionInformation {
    CHAR SectionName[256];
    PUCHAR SectionBaseAddress;
    SIZE_T SectionSize;
    PUCHAR NextAddr;
} ImageSectionInformation, * PImageSectionInformation;

typedef struct ImageInformation {
    PUCHAR Image_BaseAddress;
    SIZE_T ImageSize;
    UNICODE_STRING ImageName;
    PImageSectionInformation SectionInfo_StartNode;
    PUCHAR NextAddr;
} ImageInformation, * PImageInformation;

#define MAX_DEPTH 7

// 포인터 경로 데이터
typedef struct _POINTER_PATH {
    WCHAR moduleName[260];
    ULONG_PTR baseAddressOffset;
    LONG_PTR offsets[MAX_DEPTH];
    int depth;
} POINTER_PATH, * PPOINTER_PATH;

// 결과를 저장할 연결 리스트 노드
typedef struct _POINTER_PATH_NODE {
    POINTER_PATH path;
    struct _POINTER_PATH_NODE* next;
} POINTER_PATH_NODE, * PPOINTER_PATH_NODE;


// --- 함수 선언 ---

VOID DriverUnload(_In_ PDRIVER_OBJECT DriverObject);
NTSTATUS StartPointerScan(HANDLE targetPid, ULONG_PTR targetAddress);
void PrintPointerPath(const POINTER_PATH* path, ULONG_PTR targetAddress);
void FinalRecursiveScanner_Kernel(ULONG_PTR current_base, PPOINTER_PATH path, int depth,
    ULONG_PTR targetAddress, PPOINTER_PATH_NODE* resultListHead,
    volatile LONG* foundCount);
void ScanModuleForPointers_Kernel(PImageInformation pModuleInfo, ULONG_PTR targetAddress,
    PPOINTER_PATH_NODE* resultListHead, volatile LONG* foundCount);

NTSTATUS GetUserProcessModules(PEPROCESS pProcess, PImageInformation* pOutModuleList);
VOID FreeUserProcessModules(PImageInformation moduleList);
VOID FreePointerPathList(PPOINTER_PATH_NODE listHead);


// --- 구현 ---

/**
 * @brief 찾은 포인터 경로 출력 (변경 없음)
 */
void PrintPointerPath(const POINTER_PATH* path, ULONG_PTR targetAddress) {
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[PointerScanner] Found: \"%ls\" + 0x%p", path->moduleName, (void*)path->baseAddressOffset);
    for (int i = 0; i < path->depth; ++i) {
        if (path->offsets[i] >= 0) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, " -> +0x%llX", (ULONGLONG)path->offsets[i]);
        }
        else {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, " -> -0x%llX", (ULONGLONG)-path->offsets[i]);
        }
    }
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, " (Value: 0x%p)\n", (void*)targetAddress);
}

/**
 * @brief 재귀적으로 포인터 체인 탐색 (결과를 연결 리스트에 추가)
 */
void FinalRecursiveScanner_Kernel(ULONG_PTR current_base, PPOINTER_PATH path, int depth,
    ULONG_PTR targetAddress, PPOINTER_PATH_NODE* resultListHead,
    volatile LONG* foundCount) {
    if (depth >= MAX_DEPTH) {
        return;
    }
    ULONG_PTR next_base = 0;
    __try {
        next_base = *(PULONG_PTR)current_base;
        if (next_base == 0 || next_base > (ULONG_PTR)MM_HIGHEST_USER_ADDRESS) {
            return;
        }
        LONG_PTR final_offset = (LONG_PTR)targetAddress - (LONG_PTR)next_base;
        if (abs(final_offset) < 0x2000) {

            // 결과를 저장할 새 노드 할당
            PPOINTER_PATH_NODE newNode = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(POINTER_PATH_NODE), POOL_TAG);
            if (newNode) {
                // 경로 정보 복사
                path->offsets[depth] = final_offset;
                path->depth = depth + 1;
                RtlCopyMemory(&newNode->path, path, sizeof(POINTER_PATH));

                // 스레드 안전하게 연결 리스트 헤드에 추가
                PPOINTER_PATH_NODE oldHead;
                do {
                    oldHead = *resultListHead;
                    newNode->next = oldHead;
                } while (InterlockedCompareExchangePointer((PVOID*)resultListHead, newNode, oldHead) != oldHead);

                InterlockedIncrement(foundCount);
                PrintPointerPath(&newNode->path, targetAddress);
            }
        }
        path->offsets[depth] = 0;
        FinalRecursiveScanner_Kernel(next_base, path, depth + 1,
            targetAddress, resultListHead, foundCount);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        // 메모리 접근 실패
    }
}

/**
 * @brief 특정 모듈의 데이터 섹션 스캔
 */
void ScanModuleForPointers_Kernel(PImageInformation pModuleInfo, ULONG_PTR targetAddress,
    PPOINTER_PATH_NODE* resultListHead, volatile LONG* foundCount) {
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "\n[+] Scanning module: %wZ (Base: 0x%p)\n", &pModuleInfo->ImageName, pModuleInfo->Image_BaseAddress);

    PImageSectionInformation currentSection = pModuleInfo->SectionInfo_StartNode;
    while (currentSection != NULL) {
        if (strcmp(currentSection->SectionName, ".data") == 0 ||
            strcmp(currentSection->SectionName, ".rdata") == 0) {

            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "  -> Scanning section %s (Base: 0x%p, Size: 0x%zX)\n",
                currentSection->SectionName, currentSection->SectionBaseAddress, currentSection->SectionSize);

            ULONG_PTR sectionStart = (ULONG_PTR)currentSection->SectionBaseAddress;
            SIZE_T sectionSize = currentSection->SectionSize;

            for (SIZE_T offset = 0; offset < sectionSize; offset += sizeof(ULONG_PTR)) {
                POINTER_PATH path; // 스택에 임시 경로 정보 생성
                RtlZeroMemory(&path, sizeof(POINTER_PATH));

                ULONG_PTR staticAddress = sectionStart + offset;

                RtlStringCbCopyW(path.moduleName, sizeof(path.moduleName), pModuleInfo->ImageName.Buffer);
                path.baseAddressOffset = staticAddress - (ULONG_PTR)pModuleInfo->Image_BaseAddress;

                FinalRecursiveScanner_Kernel(staticAddress, &path, 0,
                    targetAddress, resultListHead, foundCount);
            }
        }
        currentSection = (PImageSectionInformation)currentSection->NextAddr;
    }
}

/**
 * @brief 포인터 스캔을 시작하는 메인 함수
 */
NTSTATUS StartPointerScan(HANDLE targetPid, ULONG_PTR targetAddress) {
    NTSTATUS status;
    PEPROCESS targetProcess = NULL;
    KAPC_STATE kapcState;
    PImageInformation moduleList = NULL, currentModule = NULL;

    // --- 지역 변수로 스캔 상태 관리 ---
    PPOINTER_PATH_NODE resultListHead = NULL; // 연결 리스트 헤드
    volatile LONG foundCount = 0;
    // ---------------------------------

    status = PsLookupProcessByProcessId(targetPid, &targetProcess);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[PointerScanner] Could not find PID %lu. Status: 0x%X\n", (ULONG)(ULONG_PTR)targetPid, status);
        return status;
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[PointerScanner] Targeting PID: %lu\n", (ULONG)(ULONG_PTR)targetPid);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[PointerScanner] Searching for pointers to address: 0x%p\n", (void*)targetAddress);

    status = GetUserProcessModules(targetProcess, &moduleList);
    if (!NT_SUCCESS(status) || !moduleList) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[PointerScanner] Failed to get process modules.\n");
        ObDereferenceObject(targetProcess);
        return status;
    }

    KeStackAttachProcess(targetProcess, &kapcState);

    currentModule = moduleList;
    while (currentModule != NULL) {
        ScanModuleForPointers_Kernel(currentModule, targetAddress, &resultListHead, &foundCount);
        currentModule = (PImageInformation)currentModule->NextAddr;
    }

    KeStackDetachProcess(&kapcState);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "\n[PointerScanner] Scan finished. Found %ld pointer path(s).\n", foundCount);

    // --- 결과 처리 및 리소스 정리 ---
    // 찾은 결과를 출력하거나 다른 작업 수행 가능 (이미 실시간으로 출력했음)

    FreePointerPathList(resultListHead); // 결과 리스트 메모리 해제
    FreeUserProcessModules(moduleList);
    ObDereferenceObject(targetProcess);

    return STATUS_SUCCESS;
}


/**
 * @brief 드라이버 진입점
 */
NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(RegistryPath);
    DriverObject->DriverUnload = DriverUnload;
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[PointerScanner] Driver Loaded.\n");

    HANDLE pid = (HANDLE)5468;
    ULONG_PTR address = 0x161C15AAEE0;

    if (pid != 0 && address != 0) {
        StartPointerScan(pid, address);
    }
    return STATUS_SUCCESS;
}

/**
 * @brief 드라이버 언로드 루틴
 */
VOID DriverUnload(_In_ PDRIVER_OBJECT DriverObject) {
    UNREFERENCED_PARAMETER(DriverObject);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[PointerScanner] Driver Unloaded.\n");
}

/**
 * @brief 결과 연결 리스트 메모리 해제
 */
VOID FreePointerPathList(PPOINTER_PATH_NODE listHead) {
    PPOINTER_PATH_NODE currentNode = listHead;
    while (currentNode != NULL) {
        PPOINTER_PATH_NODE nextNode = currentNode->next;
        ExFreePoolWithTag(currentNode, POOL_TAG);
        currentNode = nextNode;
    }
}


// --- 사용자 구현 필요 함수 (예시, 변경 없음) ---
NTSTATUS GetUserProcessModules(PEPROCESS pProcess, PImageInformation* pOutModuleList) {
    UNREFERENCED_PARAMETER(pProcess);
    *pOutModuleList = NULL;
    return STATUS_NOT_IMPLEMENTED;
}
VOID FreeUserProcessModules(PImageInformation moduleList) {
    PImageInformation currentModule = moduleList;
    while (currentModule != NULL) {
        PImageInformation nextModule = (PImageInformation)currentModule->NextAddr;
        PImageSectionInformation currentSection = currentModule->SectionInfo_StartNode;
        while (currentSection != NULL) {
            PImageSectionInformation nextSection = (PImageSectionInformation)currentSection->NextAddr;
            ExFreePoolWithTag(currentSection, POOL_TAG);
            currentSection = nextSection;
        }
        if (currentModule->ImageName.Buffer) {
            ExFreePoolWithTag(currentModule->ImageName.Buffer, POOL_TAG);
        }
        ExFreePoolWithTag(currentModule, POOL_TAG);
        currentModule = nextModule;
    }
}