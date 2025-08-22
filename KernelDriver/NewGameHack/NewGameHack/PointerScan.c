#include "PointerScan.h"
#include "Process.h"
#include "PE_logic.h"
#include "VirtualMemory.h"
#include <ntstrsafe.h>
#include "API.h"

// Blacklist dll
const WCHAR* g_SystemModuleBlacklist[] = {
    L"ntdll.dll",
    L"kernel32.dll",
    L"kernelbase.dll",
    L"user32.dll",
    L"gdi32.dll",
    L"advapi32.dll",
    L"msvcrt.dll",
    L"rpcrt4.dll",
    L"sechost.dll",
    L"ucrtbase.dll"
    // 필요한 다른 시스템 DLL들을 여기에 추가할 수 있습니다.
};
const ULONG g_BlacklistCount = sizeof(g_SystemModuleBlacklist) / sizeof(g_SystemModuleBlacklist[0]);

// --- 설정값 ---
#define MAX_POINTER_DEPTH 7
#define MAX_POINTER_OFFSET 0xFF
#define NUM_THREADS 8 // 사용할 스레드 수 (CPU 코어 수에 맞게 조절)

// --- 전역 변수 (스레드 간 공유) ---

PUCHAR g_TargetAddress_Global = NULL; // TargetAddress를 전역으로 저장

// --- 포인터 맵 관련 정의 ---

typedef struct _PointerInfo {
    ULONG_PTR points_to;
    ULONG_PTR address;
} PointerInfo, * PPointerInfo;

typedef struct _PointerPathNode {
    WCHAR moduleName[260];
    PUCHAR ImageBaseAddress;
    ULONG_PTR baseAddressOffset;
    LONG_PTR* offsets; // [개선] 동적 할당된 오프셋 배열
    int depth;
    struct _PointerPathNode* next;
} PointerPathNode, * PPointerPathNode;

// 스캔 작업의 모든 상태를 담는 컨텍스트 구조체
typedef struct _SCAN_CONTEXT {
    // 입력 설정값
    UINT32 MaxDepth;
    LONG_PTR MaxBaseOffset;
    LONG_PTR MaxChainOffset;
    UINT32 MinPointersInPeek;
    UINT32 NumThreads;

    // 스캔 중 사용되는 데이터
    PVOID TargetAddress;
    PPointerInfo PointerMap;
    ULONG_PTR MapSize;

    PImageInformation AllModulesHead; // 전체 모듈 리스트의 헤드를 저장
    volatile PPointerPathNode ResultListHead;
} SCAN_CONTEXT, * PSCAN_CONTEXT;

// --- 멀티스레딩을 위한 파라미터 구조체 ---
typedef struct _THREAD_CONTEXT {
    PVOID Start;
    ULONG_PTR Count;
    PSCAN_CONTEXT ScanContext;
} THREAD_CONTEXT, * PTHREAD_CONTEXT;


// --- 헬퍼 함수 선언 ---
int ComparePointerInfo(const void* a, const void* b);
void SwapElements(char* a, char* b, size_t size, char* temp_buffer);
void Heapify(char* base, size_t num, size_t i, size_t size, int (*compare)(const void*, const void*), char* temp_buffer);
void HeapSort(void* base, size_t num, size_t size, int (*compare)(const void*, const void*));
PPointerInfo BinarySearch_LowerBound(PPointerInfo array, ULONG_PTR count, ULONG_PTR value);

// --- 헬퍼 함수 프로토타입 ---
BOOLEAN Backtrack(ULONG_PTR address_to_find, LONG_PTR* currentOffsets, int depth, PSCAN_CONTEXT scanContext, BOOLEAN use_max_offset);
VOID ReconstructPathsThreadRoutine(PVOID Context);
VOID CleanupScanContext(PSCAN_CONTEXT scanContext);
BOOLEAN IsModuleInBlacklist(PUNICODE_STRING ModuleName); // [추가] 블랙리스트 확인 함수

// --- 경로 재구성 함수 (반복 방식) ---
typedef struct _BacktrackNode {
    ULONG_PTR address;
    int depth;
} BacktrackNode;

#define MAX_BACKTRACK_STACK 100

BOOLEAN Backtrack(
    ULONG_PTR address_to_find,
    LONG_PTR* currentOffsets,
    int depth,
    PSCAN_CONTEXT scanContext,
    BOOLEAN use_max_offset
) {
    PImageInformation currentModule = scanContext->AllModulesHead;
    while (currentModule) {
        if (address_to_find >= (ULONG_PTR)currentModule->Image_BaseAddress &&
            address_to_find < (ULONG_PTR)currentModule->Image_BaseAddress + currentModule->ImageSize) {

            if (IsModuleInBlacklist(&currentModule->ImageName)) {
                return FALSE;
            }

            PPointerPathNode newNode = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(PointerPathNode), POINTER_PATH_TAG);
            if (!newNode) return FALSE;
            RtlZeroMemory(newNode, sizeof(PointerPathNode));

            newNode->offsets = (LONG_PTR*)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(LONG_PTR) * depth, OFFSETS_ARRAY_TAG);
            if (!newNode->offsets) {
                ExFreePoolWithTag(newNode, POINTER_PATH_TAG);
                return FALSE;
            }

            RtlCopyMemory(newNode->moduleName, currentModule->ImageName.Buffer, currentModule->ImageName.Length);
            newNode->moduleName[currentModule->ImageName.Length / sizeof(WCHAR)] = L'\0';

			newNode->ImageBaseAddress = currentModule->Image_BaseAddress;
            newNode->baseAddressOffset = address_to_find - (ULONG_PTR)currentModule->Image_BaseAddress;
            newNode->depth = depth;

            for (int i = 0; i < depth; ++i) {
                newNode->offsets[i] = currentOffsets[depth - 1 - i];
            }

            PPointerPathNode oldHead;
            do {
                oldHead = scanContext->ResultListHead;
                newNode->next = oldHead;
            } while (InterlockedCompareExchangePointer((PVOID*)&scanContext->ResultListHead, newNode, oldHead) != oldHead);

            return TRUE;
        }
        currentModule = (PImageInformation)currentModule->NextAddr;
    }

    if (depth >= (int)scanContext->MaxDepth) {
        return FALSE;
    }

    LONG_PTR current_offset = use_max_offset ? scanContext->MaxChainOffset : 0;
    ULONG_PTR search_min = (address_to_find > (ULONG_PTR)current_offset) ? address_to_find - current_offset : 0;
    ULONG_PTR search_max = address_to_find + current_offset;
    PPointerInfo it = BinarySearch_LowerBound(scanContext->PointerMap, scanContext->MapSize, search_min);
    BOOLEAN found_path = FALSE;

    for (; it != NULL && it < (scanContext->PointerMap + scanContext->MapSize) && it->points_to <= search_max; ++it) {
        currentOffsets[depth] = (LONG_PTR)address_to_find - (LONG_PTR)it->points_to;
        if (Backtrack(it->address, currentOffsets, depth + 1, scanContext, use_max_offset)) {
            found_path = TRUE;
            if (!use_max_offset) break;
        }
    }
    return found_path;
}


// [추가] 모듈 이름이 블랙리스트에 있는지 확인하는 함수
BOOLEAN IsModuleInBlacklist(PUNICODE_STRING ModuleName) {
    for (ULONG i = 0; i < g_BlacklistCount; ++i) {
        UNICODE_STRING unicodeBlacklistName;
        RtlInitUnicodeString(&unicodeBlacklistName, g_SystemModuleBlacklist[i]);

        if (RtlCompareUnicodeString(ModuleName, &unicodeBlacklistName, TRUE) == 0) { // TRUE = Case-Insensitive
            return TRUE; // 블랙리스트에서 일치하는 것을 찾으면 즉시 TRUE 반환
        }
    }
    return FALSE; // 루프가 끝날 때까지 찾지 못하면 FALSE 반환
}


void ReconstructPathsIterative(
    ULONG_PTR startAddress,
    LONG_PTR firstOffset, // ULONG_PTR -> LONG_PTR로 수정
    PImageInformation imageInfo,
    PPointerInfo pointerMap,
    ULONG_PTR mapSize,
    PPointerPathNode* resultListHead
);


// ======================================================================
//                            헬퍼 함수 구현
// ======================================================================

int ComparePointerInfo(const void* a, const void* b) {
    PPointerInfo pA = (PPointerInfo)a;
    PPointerInfo pB = (PPointerInfo)b;
    if (pA->points_to < pB->points_to) return -1;
    if (pA->points_to > pB->points_to) return 1;
    if (pA->address < pB->address) return -1;
    if (pA->address > pB->address) return 1;
    return 0;
}

void SwapElements(char* a, char* b, size_t size, char* temp_buffer) {
    RtlCopyMemory(temp_buffer, a, size);
    RtlCopyMemory(a, b, size);
    RtlCopyMemory(b, temp_buffer, size);
}

void Heapify(char* base, size_t num, size_t i, size_t size, int (*compare)(const void*, const void*), char* temp_buffer) {
    size_t largest = i;
    size_t left = 2 * i + 1;
    size_t right = 2 * i + 2;

    if (left < num && compare(base + left * size, base + largest * size) > 0) largest = left;
    if (right < num && compare(base + right * size, base + largest * size) > 0) largest = right;

    if (largest != i) {
        SwapElements(base + i * size, base + largest * size, size, temp_buffer);
        Heapify(base, num, largest, size, compare, temp_buffer);
    }
}

void HeapSort(void* base, size_t num, size_t size, int (*compare)(const void*, const void*)) {
    if (num <= 1) return;
    char* arr = (char*)base;
    char* temp_buffer = ExAllocatePool2(POOL_FLAG_NON_PAGED, size, TEMP_BUFFER_TAG);
    if (!temp_buffer) return;

    for (LONG_PTR i = num / 2 - 1; i >= 0; i--) {
        Heapify(arr, num, i, size, compare, temp_buffer);
    }
    for (LONG_PTR i = num - 1; i > 0; i--) {
        SwapElements(arr, arr + i * size, size, temp_buffer);
        Heapify(arr, i, 0, size, compare, temp_buffer);
    }
    ExFreePoolWithTag(temp_buffer, TEMP_BUFFER_TAG);
}

PPointerInfo BinarySearch_LowerBound(PPointerInfo array, ULONG_PTR count, ULONG_PTR value) {
    LONG_PTR first = 0;
    ULONG_PTR current_count = count;
    while (current_count > 0) {
        LONG_PTR step = current_count / 2;
        LONG_PTR mid = first + step;
        if (array[mid].points_to < value) {
            first = mid + 1;
            current_count -= (step + 1);
        }
        else {
            current_count = step;
        }
    }
    if (first >= (LONG_PTR)count) {
        return array + count;
    }
    return array + first;
}

void ReconstructPathsIterative(
    ULONG_PTR startAddress,
    LONG_PTR firstOffset, // 파라미터 타입이 LONG_PTR임을 다시 확인
    PImageInformation imageInfo,
    PPointerInfo pointerMap,
    ULONG_PTR mapSize,
    PPointerPathNode* resultListHead
) {
    BacktrackNode stack[MAX_BACKTRACK_STACK];
    LONG_PTR offsets[MAX_POINTER_DEPTH];
    int stack_top = -1;

    stack_top++;
    stack[stack_top].address = startAddress;
    stack[stack_top].depth = 1;
    offsets[0] = firstOffset;

    while (stack_top != -1) {
        BacktrackNode currentNode = stack[stack_top];
        stack_top--;

        PImageInformation currentImage = imageInfo;
        BOOLEAN found = FALSE;
        while (currentImage) {
            if (currentNode.address >= (ULONG_PTR)currentImage->Image_BaseAddress &&
                currentNode.address < (ULONG_PTR)currentImage->Image_BaseAddress + currentImage->ImageSize) {

                PPointerPathNode newNode = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(PointerPathNode), POINTER_PATH_TAG);
                if (newNode) {
                    RtlZeroMemory(newNode, sizeof(PointerPathNode));
                    RtlStringCbCopyW(newNode->moduleName, sizeof(newNode->moduleName), currentImage->ImageName.Buffer);

                    newNode->ImageBaseAddress = currentImage->Image_BaseAddress;
                    newNode->baseAddressOffset = currentNode.address - (ULONG_PTR)currentImage->Image_BaseAddress;
                    newNode->depth = currentNode.depth;

                    for (int i = 0; i < currentNode.depth; ++i) {
                        newNode->offsets[i] = offsets[currentNode.depth - 1 - i];
                    }
                    PPointerPathNode oldHead;
                    do {
                        oldHead = *resultListHead;
                        newNode->next = oldHead;
                    } while (InterlockedCompareExchangePointer((PVOID*)resultListHead, newNode, oldHead) != oldHead);
                }
                found = TRUE;
                break;
            }
            currentImage = (PImageInformation)currentImage->NextAddr;
        }

        if (found || currentNode.depth >= MAX_POINTER_DEPTH) {
            continue;
        }

        ULONG_PTR search_min = (currentNode.address > MAX_POINTER_OFFSET) ? currentNode.address - MAX_POINTER_OFFSET : 0;
        ULONG_PTR search_max = currentNode.address + MAX_POINTER_OFFSET;
        PPointerInfo it = BinarySearch_LowerBound(pointerMap, mapSize, search_min);

        for (; it != NULL && it < (pointerMap + mapSize) && it->points_to <= search_max; ++it) {
            if (stack_top + 1 < MAX_BACKTRACK_STACK) {
                stack_top++;
                stack[stack_top].address = it->address;
                stack[stack_top].depth = currentNode.depth + 1;
                // [!!! 핵심 버그 수정 !!!]
                // 뺄셈 전에 LONG_PTR로 명시적 캐스팅을 하여 signed 연산을 보장합니다.
                offsets[currentNode.depth] = (LONG_PTR)currentNode.address - (LONG_PTR)it->points_to;
            }
        }
    }
}

VOID ReconstructPathsThreadRoutine(PVOID Context) {
    PTHREAD_CONTEXT threadContext = (PTHREAD_CONTEXT)Context;
    PSCAN_CONTEXT scanContext = threadContext->ScanContext;
    PPointerInfo level1_start = (PPointerInfo)threadContext->Start;
    ULONG_PTR count = threadContext->Count;
    LONG_PTR* offsets = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(LONG_PTR) * scanContext->MaxDepth, OFFSETS_ARRAY_TAG);

    if (offsets) {
        for (ULONG_PTR i = 0; i < count; ++i) {
            PPointerInfo current_level1_ptr = level1_start + i;
            offsets[0] = (LONG_PTR)scanContext->TargetAddress - (LONG_PTR)current_level1_ptr->points_to;

            BOOLEAN found = Backtrack(current_level1_ptr->address, offsets, 1, scanContext, FALSE);
            if (!found) {
                Backtrack(current_level1_ptr->address, offsets, 1, scanContext, TRUE);
            }
        }
        ExFreePoolWithTag(offsets, OFFSETS_ARRAY_TAG);
    }
    PsTerminateSystemThread(STATUS_SUCCESS);
}

VOID CleanupScanContext(PSCAN_CONTEXT scanContext) {
    if (!scanContext) return;

    if (scanContext->PointerMap) {
        ExFreePoolWithTag(scanContext->PointerMap, POINTER_MAP_TAG);
    }

    PPointerPathNode current = scanContext->ResultListHead;
    while (current) {
        PPointerPathNode next = current->next;
        if (current->offsets) {
            ExFreePoolWithTag(current->offsets, OFFSETS_ARRAY_TAG);
        }
        ExFreePoolWithTag(current, POINTER_PATH_TAG);
        current = next;
    }

    // ExeModuleInfo는 ImageInfoStartNode의 일부이므로 별도 해제 불필요
}


// Print 함수
VOID PrintFinalResults(PPointerPathNode resultListHead) {
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "\n--- [PointerScanner] Printing Found Pointer Paths ---\n");
    PPointerPathNode currentNode = resultListHead;
    ULONG count = 0;

    while (currentNode) {
        char printBuffer[1024];
        char tempBuffer[64];
        UNICODE_STRING moduleNameString;

        RtlInitUnicodeString(&moduleNameString, currentNode->moduleName);

        RtlStringCbPrintfA(printBuffer, sizeof(printBuffer),
            "[Path %lu] Found: \"%wZ\" + 0x%p",
            count + 1,
            &moduleNameString,
            (PVOID)currentNode->baseAddressOffset
        );

        for (int i = 0; i < currentNode->depth; i++) {
            LONG_PTR offset = currentNode->offsets[i];
            if (offset >= 0) {
                RtlStringCbPrintfA(tempBuffer, sizeof(tempBuffer), " -> +0x%llX", (ULONGLONG)offset);
            }
            else {
                RtlStringCbPrintfA(tempBuffer, sizeof(tempBuffer), " -> -0x%llX", (ULONGLONG)-offset);
            }
            RtlStringCbCatA(printBuffer, sizeof(printBuffer), tempBuffer);
        }

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "%s\n", printBuffer);

        currentNode = currentNode->next;
        count++;
    }
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "--- [PointerScanner] Total %lu paths found ---\n\n", count);
}

// ======================================================================
//                            메인 스캔 함수
// ======================================================================

NTSTATUS PointerScanning(
    _In_ HANDLE RequesterPID,
    _In_ HANDLE TargetPID,
    _In_ PVOID TargetAddress,
    _In_ ULONG32 MaxDepth,
    _In_ UINT32 NumThreads,
    _In_ LONG_PTR MaxBaseOffset,
    _In_ LONG_PTR MaxChainOffset,
    _In_ UINT32 MinPointersInPeek,
    _Out_ PPointerScannedNode* output
) {
    NTSTATUS status = STATUS_SUCCESS;
    *output = NULL;

    PSCAN_CONTEXT scanContext = NULL;
    PProcess_info Requester__processInfo = NULL;
    PProcess_info Target__processInfo = NULL;
    PImageInformation ImageInfoStartNode = NULL;
    PUCHAR peekBuffer = NULL;

    HANDLE handles[64] = { 0 };
    PVOID objects[64] = { 0 };
    THREAD_CONTEXT contexts[64] = { 0 };
    ULONG successful_thread_count = 0;

    // --- Phase 0: 컨텍스트 및 파라미터 초기화 ---
    scanContext = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(SCAN_CONTEXT), SCAN_CONTEXT_TAG);
    if (!scanContext) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto CLEANUP;
    }
    RtlZeroMemory(scanContext, sizeof(SCAN_CONTEXT));

    scanContext->TargetAddress = TargetAddress;
    scanContext->MaxDepth = MaxDepth > 32 ? 32 : MaxDepth; // Max depth 32 to prevent stack issues
    scanContext->NumThreads = NumThreads > 0 && NumThreads <= 64 ? NumThreads : 1;
    scanContext->MaxBaseOffset = MaxBaseOffset;
    scanContext->MaxChainOffset = MaxChainOffset;
    scanContext->MinPointersInPeek = MinPointersInPeek > 0 ? MinPointersInPeek : 2;
    scanContext->ResultListHead = NULL;

    // --- 사전 작업: 프로세스 정보 및 EXE 모듈 정보 획득 ---
    status = GetProcessInfoByProcessId(TargetPID, &Target__processInfo);
    if (!NT_SUCCESS(status)) goto CLEANUP;

    status = Get_ImageInformation_by_ProcessId(TargetPID, &ImageInfoStartNode);
    if (!NT_SUCCESS(status)) goto CLEANUP;

    scanContext->AllModulesHead = ImageInfoStartNode;


    // --- Phase 1: 포인터 맵 생성 ---
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[PointerScanner] Phase 1: Building Pointer Map...\n");
    ULONG_PTR mapCapacity = 1000000;
    scanContext->PointerMap = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(PointerInfo) * mapCapacity, POINTER_MAP_TAG);
    if (!scanContext->PointerMap) { status = STATUS_INSUFFICIENT_RESOURCES; goto CLEANUP; }

    peekBuffer = ExAllocatePool2(POOL_FLAG_NON_PAGED, 256, TEMP_BUFFER_TAG);
    if (!peekBuffer) { status = STATUS_INSUFFICIENT_RESOURCES; goto CLEANUP; }

    KAPC_STATE attachState;
    KeStackAttachProcess(Target__processInfo->ProcessObject, &attachState);
    __try {
        MEMORY_BASIC_INFORMATION mbi;
        PVOID currentAddress = NULL;
        // [추가] MmCopyVirtualMemory를 위해 현재 프로세스 객체를 가져옵니다.
        PEPROCESS currentSystemProcess = IoGetCurrentProcess();

        while (NT_SUCCESS(ZwQueryVirtualMemory(NtCurrentProcess(), currentAddress, MemoryBasicInformation, &mbi, sizeof(mbi), NULL))) {
            if (mbi.State == MEM_COMMIT &&
                mbi.Protect != PAGE_NOACCESS && mbi.Protect != PAGE_GUARD &&
                (mbi.Type == MEM_PRIVATE || mbi.Type == MEM_MAPPED || mbi.Type == MEM_IMAGE)) {

                SIZE_T regionSize = mbi.RegionSize;
                for (SIZE_T offset = 0; offset <= regionSize - sizeof(ULONG_PTR); offset += sizeof(ULONG_PTR)) {
                    ULONG_PTR pointerValue = 0;
                    __try {
                        pointerValue = *(PULONG_PTR)((PUCHAR)mbi.BaseAddress + offset);
                    }
                    __except (EXCEPTION_EXECUTE_HANDLER) { continue; }

                    if (pointerValue > 0x10000 && pointerValue < (ULONG_PTR)MM_HIGHEST_USER_ADDRESS) {
                        SIZE_T peekBytesRead = 0;

                        // [수정] ZwReadVirtualMemory 대신 MmCopyVirtualMemory 사용
                        status = MmCopyVirtualMemory(
                            Target__processInfo->ProcessObject, // 소스: 타겟 프로세스
                            (PVOID)pointerValue,                // 소스 주소
                            currentSystemProcess,               // 목적지: 우리 커널 드라이버가 실행 중인 프로세스
                            peekBuffer,                         // 목적지 버퍼
                            256,                                // 복사할 크기
                            KernelMode,                         // 커널 모드에서 호출
                            &peekBytesRead                      // 실제 복사된 크기
                        );

                        if (NT_SUCCESS(status) && peekBytesRead > 0) {
                            int pointerCountInPeek = 0;
                            for (SIZE_T peekOffset = 0; peekOffset + sizeof(ULONG_PTR) <= peekBytesRead; peekOffset += sizeof(ULONG_PTR)) {
                                ULONG_PTR innerPtr = *(PULONG_PTR)((PUCHAR)peekBuffer + peekOffset);
                                if (innerPtr > 0x10000 && innerPtr < (ULONG_PTR)MM_HIGHEST_USER_ADDRESS) {
                                    pointerCountInPeek++;
                                }
                            }
                            if (pointerCountInPeek >= (int)scanContext->MinPointersInPeek) {
                                if (scanContext->MapSize >= mapCapacity) {
                                    ULONG_PTR newCapacity = mapCapacity * 2;
                                    PPointerInfo newMap = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(PointerInfo) * newCapacity, POINTER_MAP_TAG);
                                    if (!newMap) __leave; // __try 블록을 빠져나감
                                    RtlCopyMemory(newMap, scanContext->PointerMap, sizeof(PointerInfo) * mapCapacity);
                                    ExFreePoolWithTag(scanContext->PointerMap, POINTER_MAP_TAG);
                                    scanContext->PointerMap = newMap;
                                    mapCapacity = newCapacity;
                                }
                                scanContext->PointerMap[scanContext->MapSize].points_to = pointerValue;
                                scanContext->PointerMap[scanContext->MapSize].address = (ULONG_PTR)mbi.BaseAddress + offset;
                                scanContext->MapSize++;
                            }
                        }
                    }
                }
            }
            currentAddress = (PVOID)((ULONG_PTR)mbi.BaseAddress + mbi.RegionSize);
        }
    }
    __finally {
        KeUnstackDetachProcess(&attachState);
    }
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[PointerScanner] Map built with %llu pointers.\n", scanContext->MapSize);

    // --- Phase 2: 맵 정렬 ---
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[PointerScanner] Phase 2: Sorting map...\n");
    HeapSort(scanContext->PointerMap, scanContext->MapSize, sizeof(PointerInfo), ComparePointerInfo);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[PointerScanner] Map sorted.\n");

    // --- Phase 3: 경로 재구성 ---
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[PointerScanner] Phase 3: Reconstructing paths...\n");
    ULONG_PTR search_min = ((ULONG_PTR)scanContext->TargetAddress > (ULONG_PTR)scanContext->MaxBaseOffset) ? (ULONG_PTR)scanContext->TargetAddress - scanContext->MaxBaseOffset : 0;
    ULONG_PTR search_max = (ULONG_PTR)scanContext->TargetAddress + scanContext->MaxBaseOffset;
    PPointerInfo it = BinarySearch_LowerBound(scanContext->PointerMap, scanContext->MapSize, search_min);
    PPointerInfo start_it = it;
    ULONG_PTR level1_count = 0;
    for (; it < scanContext->PointerMap + scanContext->MapSize && it->points_to <= search_max; ++it) {
        level1_count++;
    }
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[PointerScanner] Found %llu Level 1 pointers.\n", level1_count);

    if (level1_count > 0) {
        ULONG_PTR count_per_thread = level1_count / scanContext->NumThreads;
        if (count_per_thread == 0 && level1_count > 0) count_per_thread = 1;

        for (UINT32 i = 0; i < scanContext->NumThreads; ++i) {
            ULONG_PTR start_index = i * count_per_thread;
            if (start_index >= level1_count) break;

            ULONG_PTR current_count = (i == scanContext->NumThreads - 1) ? (level1_count - start_index) : count_per_thread;
            if (start_index + current_count > level1_count) {
                current_count = level1_count - start_index;
            }

            contexts[i].Start = start_it + start_index;
            contexts[i].Count = current_count;
            contexts[i].ScanContext = scanContext;

            status = PsCreateSystemThread(&handles[i], THREAD_ALL_ACCESS, NULL, NULL, NULL, ReconstructPathsThreadRoutine, &contexts[i]);
            if (NT_SUCCESS(status)) {
                status = ObReferenceObjectByHandle(handles[i], THREAD_ALL_ACCESS, *PsThreadType, KernelMode, (PVOID*)&objects[i], NULL);
                if (NT_SUCCESS(status)) {
                    successful_thread_count++;
                }
                else {
                    ZwClose(handles[i]);
                    handles[i] = NULL;
                }
            }
        }

        // [수정] KeWaitForMultipleObjects 대신 KeWaitForSingleObject를 루프에서 사용
        if (successful_thread_count > 0) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[PointerScanner] Waiting for %lu threads to finish...\n", successful_thread_count);
            for (ULONG i = 0; i < successful_thread_count; i++) {
                if (objects[i]) {
                    KeWaitForSingleObject(
                        objects[i],
                        Executive,
                        KernelMode,
                        FALSE,
                        NULL
                    );
                }
            }
        }
    }
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[PointerScanner] Path reconstruction finished.\n");

    // --- Phase 4: 최종 결과를 요청자 메모리에 기록 ---
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[PointerScanner] Phase 4: Writing results to requester...\n");
    status = GetProcessInfoByProcessId(RequesterPID, &Requester__processInfo);
    if (!NT_SUCCESS(status)) goto CLEANUP;

    PPointerPathNode currentResult = scanContext->ResultListHead;
    PPointerScannedNode lastOutNode = NULL;
    PPointerScannedNode outListHead = NULL;

    KeStackAttachProcess(Requester__processInfo->ProcessObject, &attachState);
    __try {
        while (currentResult) {
            PPointerScannedNode newNode = NULL;
            PPointers pointerArray = NULL;

            status = VirtualAllocate(Requester__processInfo->ProcessHandle, sizeof(PointerScannedNode), (PUCHAR*)&newNode);
            if (!NT_SUCCESS(status) || !newNode) __leave;
            RtlZeroMemory(newNode, sizeof(PointerScannedNode));

            SIZE_T arraySize = sizeof(Pointers) * currentResult->depth;
            status = VirtualAllocate(Requester__processInfo->ProcessHandle, arraySize, (PUCHAR*)&pointerArray);
            if (!NT_SUCCESS(status) || !pointerArray) {
                // VirtualFree(Requester__processInfo->ProcessHandle, (PUCHAR)newNode);
                __leave;
            }
            RtlZeroMemory(pointerArray, arraySize);

            RtlStringCbCopyW(newNode->ImageName, sizeof(newNode->ImageName), currentResult->moduleName);
            newNode->ImageBaseAddress = currentResult->ImageBaseAddress;
			newNode->ImageBaseOffset = currentResult->baseAddressOffset;
            newNode->PointerDepth = currentResult->depth;
            newNode->NodeArray = pointerArray;

            for (int i = 0; i < currentResult->depth; ++i) {
                pointerArray[i].pointer = currentResult->offsets[i];
            }

            if (!outListHead) {
                outListHead = newNode;
            }
            else {
                lastOutNode->NextAddress = (PUCHAR)newNode;
            }
            lastOutNode = newNode;

            currentResult = currentResult->next;
        }
    }
    __finally {
        KeUnstackDetachProcess(&attachState);
    }
    *output = outListHead;

CLEANUP:
    for (ULONG i = 0; i < successful_thread_count; i++) {
        // ObReferenceObjectByHandle이 성공한 경우에만 objects[i]가 유효함
        if (objects[i]) {
            ObDereferenceObject(objects[i]);
        }
    }

    for (UINT32 i = 0; i < scanContext->NumThreads; i++) {
        if (handles[i]) {
            ZwClose(handles[i]);
        }
    }
    if (peekBuffer) ExFreePoolWithTag(peekBuffer, TEMP_BUFFER_TAG);
    if (scanContext) {
        CleanupScanContext(scanContext);
        ExFreePoolWithTag(scanContext, SCAN_CONTEXT_TAG);
    }
    if (ImageInfoStartNode) Release_ImageInformation(ImageInfoStartNode);
    if (Requester__processInfo) ReleaseProcessInfo(Requester__processInfo);
    if (Target__processInfo) ReleaseProcessInfo(Target__processInfo);

    return status;
}