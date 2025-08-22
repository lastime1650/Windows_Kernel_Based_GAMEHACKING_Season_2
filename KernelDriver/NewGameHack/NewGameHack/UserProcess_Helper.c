#include "UserProcess_Helper.h"
#include "API.h"
#include "PE_logic.h"
// ==============================================================================
// 1. 핵심 헬퍼 함수 구현 (수정됨)
// ==============================================================================

// 이 함수는 이전과 동일합니다.
NTSTATUS SafeReadPhysicalAddress(
    _In_ UINT64 TargetAddress,
    _Out_writes_bytes_(Size) PVOID lpBuffer,
    _In_ SIZE_T Size
)
{
    if (!lpBuffer || Size == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    PHYSICAL_ADDRESS PhysicalAddress;
    PhysicalAddress.QuadPart = TargetAddress;

    // 소스 주소를 물리 주소로 지정하기 위한 구조체
    MM_COPY_ADDRESS SourceAddress;
    SourceAddress.PhysicalAddress = PhysicalAddress;

    SIZE_T numberOfBytesCopied = 0;

    // MmCopyMemory를 사용하여 물리 주소에서 가상 주소(lpBuffer)로 복사
    // MM_COPY_MEMORY_PHYSICAL 플래그는 소스가 물리 주소임을 나타냅니다.
    NTSTATUS status = MmCopyMemory(
        lpBuffer,                   // 대상 (가상 주소)
        SourceAddress,              // 소스 (물리 주소)
        Size,                       // 복사할 크기
        MM_COPY_MEMORY_PHYSICAL,    // 플래그
        &numberOfBytesCopied        // 실제로 복사된 바이트 수
    );

    // 복사가 성공했는지, 그리고 요청한 크기만큼 정확히 복사되었는지 확인
    if (!NT_SUCCESS(status)) {
        // DbgPrint("[-] MmCopyMemory failed with status 0x%X for PA 0x%llX\n", status, TargetAddress);
        return status;
    }

    if (numberOfBytesCopied != Size) {
        // DbgPrint("[-] MmCopyMemory copied %zu bytes instead of %zu for PA 0x%llX\n", numberOfBytesCopied, Size, TargetAddress);
        return STATUS_PARTIAL_COPY;
    }

    return STATUS_SUCCESS;
}

// 이 함수도 이전과 동일합니다.
NTSTATUS GetPhysicalMemoryRanges(_Out_ PPHYSICAL_MEMORY_RANGE* OutMemoryRanges, _Out_ PULONG NumberOfRanges)
{
    *OutMemoryRanges = NULL;
    *NumberOfRanges = 0;
    PPHYSICAL_MEMORY_RANGE memoryRanges = MmGetPhysicalMemoryRanges();
    if (!memoryRanges) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    ULONG count = 0;
    for (count = 0; memoryRanges[count].BaseAddress.QuadPart != 0 || memoryRanges[count].NumberOfBytes.QuadPart != 0; ++count) {}
    *OutMemoryRanges = memoryRanges;
    *NumberOfRanges = count;
    return STATUS_SUCCESS;
}

// *** [수정된 헬퍼 함수] ***
// 주어진 물리 주소 '범위'가 유효한지 확인하는 함수
BOOLEAN IsValidPhysicalRange(
    _In_ UINT64 Address,
    _In_ SIZE_T Size,
    _In_ PPHYSICAL_MEMORY_RANGE MemoryRanges,
    _In_ ULONG NumberOfRanges
)
{
    // 오버플로우 방지
    if (Address + Size < Address) {
        return FALSE;
    }

    UINT64 endAddress = Address + Size;

    for (ULONG i = 0; i < NumberOfRanges; i++) {
        UINT64 runBase = MemoryRanges[i].BaseAddress.QuadPart;
        UINT64 runEnd = runBase + MemoryRanges[i].NumberOfBytes.QuadPart;
        // 시작 주소와 끝 주소가 '하나의' 유효한 범위 내에 완전히 포함되는지 확인
        if (Address >= runBase && endAddress <= runEnd) {
            return TRUE;
        }
    }
    return FALSE;
}

PVOID GetProcessBaseAddress(_In_ PEPROCESS Process)
{
    if (!Process) return NULL;
    return *(PVOID*)((PUCHAR)Process + SECTION_BASE_ADDRESS_OFFSET);
}

// ==============================================================================
// 2. 메인 브루트포스 함수 (디버그 출력 추가 및 검증 로직 수정)
// ==============================================================================

UINT64 Get_CR3_by_BruteForce( _In_ PEPROCESS Process)
{
    //DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[DBG] Entering Get_CR3_by_BruteForce for Process: %p\n", Process);
    if (!Process) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[-] Process is NULL.\n");
        return 0;
    }
    PVOID baseAddress = GetProcessBaseAddress(Process);
    //DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[DBG] Got baseAddress: %p\n", baseAddress);
    if (!baseAddress) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[-] Failed to get SectionBaseAddress.\n");
        return 0;
    }
    //DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[+] Landmark VA: 0x%p\n", baseAddress);
    VIRTUAL_ADDRESS virtualAddress;
    virtualAddress.Address = baseAddress;
    //DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[DBG] VirtualAddress: 0x%p\n", virtualAddress.Address);
    PPHYSICAL_MEMORY_RANGE memoryRanges = NULL;
    ULONG numberOfRanges = 0;
    NTSTATUS status = GetPhysicalMemoryRanges(&memoryRanges, &numberOfRanges);
    //DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[DBG] GetPhysicalMemoryRanges status: 0x%X, memoryRanges: %p, numberOfRanges: %lu\n", status, memoryRanges, numberOfRanges);
    if (!NT_SUCCESS(status) || !memoryRanges || numberOfRanges == 0) {
        //DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[-] Failed to get physical memory ranges.\n");
        if (memoryRanges) {
            //DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[DBG] Freeing memoryRanges: %p\n", memoryRanges);
            ExFreePool(memoryRanges);
        }
        return 0;
    }
    UINT64 highestPhysicalAddress = 0;
    for (ULONG i = 0; i < numberOfRanges; i++) {
        UINT64 runEnd = memoryRanges[i].BaseAddress.QuadPart + memoryRanges[i].NumberOfBytes.QuadPart;
        //DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[DBG] Range %lu: Base 0x%llX, End 0x%llX\n", i, memoryRanges[i].BaseAddress.QuadPart, runEnd);
        if (runEnd > highestPhysicalAddress) highestPhysicalAddress = runEnd;
    }
    UINT64 highestPfn = highestPhysicalAddress >> PAGE_SHIFT;
    //DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[+] Highest PFN: 0x%llX\n", highestPfn);
    UINT64 CR3 = 0;
    SIZE_T pteSize = sizeof(MMPTE_HARDWARE);
    //DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[DBG] pteSize: %zu\n", pteSize);
    for (ULONG i = 0; i < numberOfRanges; i++)
    {
        UINT64 runBase = memoryRanges[i].BaseAddress.QuadPart;
        UINT64 runEnd = runBase + memoryRanges[i].NumberOfBytes.QuadPart;
        //DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[DBG] Processing range %lu: Base 0x%llX to End 0x%llX\n", i, runBase, runEnd);
        for (UINT64 cr3_candidate = runBase; cr3_candidate < runEnd; cr3_candidate += PAGE_SIZE)
        {
            //DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[DBG] Testing cr3_candidate: 0x%llX\n", cr3_candidate);
            MMPTE_HARDWARE pml4e, pdpte, pde, pte;
            UINT64 physicalBase = 0;
            // --- PML4E ---
            UINT64 pml4e_addr = cr3_candidate + virtualAddress.BITS.Pml4Index * pteSize;
            //DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[DBG] PML4E addr: 0x%llX\n", pml4e_addr);
            if (!IsValidPhysicalRange(pml4e_addr, pteSize, memoryRanges, numberOfRanges)) {
                //DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[DBG] Invalid PML4E range.\n");
                continue;
            }
            status = SafeReadPhysicalAddress(pml4e_addr, &pml4e, pteSize);
            //DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[DBG] SafeRead PML4E status: 0x%X\n", status);
            if (!NT_SUCCESS(status)) continue;
            //DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[DBG] PML4E Valid: %llu, PFN: 0x%llX\n", pml4e.u.Bits.Valid, pml4e.u.Bits.PageFrameNumber);
            if (!pml4e.u.Bits.Valid || pml4e.u.Bits.PageFrameNumber >= highestPfn) continue;
            // --- PDPTE ---
            UINT64 pdpt_base = pml4e.u.Bits.PageFrameNumber << PAGE_SHIFT;
            UINT64 pdpte_addr = pdpt_base + virtualAddress.BITS.PdptIndex * pteSize;
            //DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[DBG] PDPTE addr: 0x%llX\n", pdpte_addr);
            if (!IsValidPhysicalRange(pdpte_addr, pteSize, memoryRanges, numberOfRanges)) {
                //DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[DBG] Invalid PDPTE range.\n");
                continue;
            }
            status = SafeReadPhysicalAddress(pdpte_addr, &pdpte, pteSize);
            //DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[DBG] SafeRead PDPTE status: 0x%X\n", status);
            if (!NT_SUCCESS(status)) continue;
            //DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[DBG] PDPTE Valid: %llu, PFN: 0x%llX, LargePage: %llu\n", pdpte.u.Bits.Valid, pdpte.u.Bits.PageFrameNumber, pdpte.u.Bits.LargePage);
            if (!pdpte.u.Bits.Valid || pdpte.u.Bits.PageFrameNumber >= highestPfn) continue;
            if (pdpte.u.Bits.LargePage) {
                physicalBase = (pdpte.u.Bits.PageFrameNumber << PAGE_SHIFT) + (virtualAddress.Value & 0x3FFFFFFF);
                //DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[DBG] Large PDPTE physicalBase: 0x%llX\n", physicalBase);
                goto FinalValidation;
            }
            // --- PDE ---
            UINT64 pd_base = pdpte.u.Bits.PageFrameNumber << PAGE_SHIFT;
            UINT64 pde_addr = pd_base + virtualAddress.BITS.PdIndex * pteSize;
            //DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[DBG] PDE addr: 0x%llX\n", pde_addr);
            if (!IsValidPhysicalRange(pde_addr, pteSize, memoryRanges, numberOfRanges)) {
                //DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[DBG] Invalid PDE range.\n");
                continue;
            }
            status = SafeReadPhysicalAddress(pde_addr, &pde, pteSize);
            //DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[DBG] SafeRead PDE status: 0x%X\n", status);
            if (!NT_SUCCESS(status)) continue;
            //DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[DBG] PDE Valid: %llu, PFN: 0x%llX, LargePage: %llu\n", pde.u.Bits.Valid, pde.u.Bits.PageFrameNumber, pde.u.Bits.LargePage);
            if (!pde.u.Bits.Valid || pde.u.Bits.PageFrameNumber >= highestPfn) continue;
            if (pde.u.Bits.LargePage) {
                physicalBase = (pde.u.Bits.PageFrameNumber << PAGE_SHIFT) + (virtualAddress.Value & 0x1FFFFF);
                //DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[DBG] Large PDE physicalBase: 0x%llX\n", physicalBase);
                goto FinalValidation;
            }
            // --- PTE ---
            UINT64 pt_base = pde.u.Bits.PageFrameNumber << PAGE_SHIFT;
            UINT64 pte_addr = pt_base + virtualAddress.BITS.PtIndex * pteSize;
            //DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[DBG] PTE addr: 0x%llX\n", pte_addr);
            if (!IsValidPhysicalRange(pte_addr, pteSize, memoryRanges, numberOfRanges)) {
                //DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[DBG] Invalid PTE range.\n");
                continue;
            }
            status = SafeReadPhysicalAddress(pte_addr, &pte, pteSize);
            //DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[DBG] SafeRead PTE status: 0x%X\n", status);
            if (!NT_SUCCESS(status)) continue;
            //DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[DBG] PTE Valid: %llu, PFN: 0x%llX\n", pte.u.Bits.Valid, pte.u.Bits.PageFrameNumber);
            if (!pte.u.Bits.Valid || pte.u.Bits.PageFrameNumber >= highestPfn) continue;
            physicalBase = (pte.u.Bits.PageFrameNumber << PAGE_SHIFT) + virtualAddress.BITS.Offset;
            //DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[DBG] PTE physicalBase: 0x%llX\n", physicalBase);
        FinalValidation:
            //DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[DBG] Entering FinalValidation, physicalBase: 0x%llX\n", physicalBase);
            if (physicalBase == 0) continue;
            if (!IsValidPhysicalRange(physicalBase, sizeof(IMAGE_DOS_HEADER__), memoryRanges, numberOfRanges)) {
                //DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[DBG] Invalid physicalBase range.\n");
                continue;
            }
            IMAGE_DOS_HEADER__ dosHeader;
            status = SafeReadPhysicalAddress(physicalBase, &dosHeader, sizeof(dosHeader));
            //DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[DBG] SafeRead DOS Header status: 0x%X\n", status);
            if(NT_SUCCESS(status) && dosHeader.e_magic == IMAGE_DOS_SIGNATURE) {
                //DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[DBG] DOS Header e_magic: 0x%X\n", dosHeader.e_magic);
                
                // 1단계 검증 통과: 'MZ' 시그니처를 찾았습니다.
                // 이제 2단계로, 이 CR3가 정말 대상 프로세스의 것인지 PEB를 통해 최종 확인합니다.

                PVOID targetPebVa = PsGetProcessPeb(Process);
                if (!targetPebVa) {
                    // PEB 주소를 얻을 수 없으면 검증이 불가능하므로, 오답으로 간주하고 다음 후보를 찾습니다.
                    continue;
                }

                // PEB의 가상 주소를 이 CR3 후보를 사용해 물리 주소로 변환합니다.
                UINT64 physicalPebAddress = 0;
                VIRTUAL_ADDRESS pebVirtualAddress;
                pebVirtualAddress.Address = targetPebVa;

                // --- PEB 주소 변환: PML4E ---
                MMPTE_HARDWARE peb_pml4e;
                UINT64 peb_pml4e_addr = cr3_candidate + pebVirtualAddress.BITS.Pml4Index * pteSize;
                if (!IsValidPhysicalRange(peb_pml4e_addr, pteSize, memoryRanges, numberOfRanges) ||
                    !NT_SUCCESS(SafeReadPhysicalAddress(peb_pml4e_addr, &peb_pml4e, pteSize)) ||
                    !peb_pml4e.u.Bits.Valid) {
                    // 변환 실패. 이 CR3는 오답입니다. 다음 후보로 넘어갑니다.
                    continue;
                }

                // --- PEB 주소 변환: PDPTE ---
                MMPTE_HARDWARE peb_pdpte;
                UINT64 peb_pdpt_base = peb_pml4e.u.Bits.PageFrameNumber << PAGE_SHIFT;
                UINT64 peb_pdpte_addr = peb_pdpt_base + pebVirtualAddress.BITS.PdptIndex * pteSize;
                if (!IsValidPhysicalRange(peb_pdpte_addr, pteSize, memoryRanges, numberOfRanges) ||
                    !NT_SUCCESS(SafeReadPhysicalAddress(peb_pdpte_addr, &peb_pdpte, pteSize)) ||
                    !peb_pdpte.u.Bits.Valid) {
                    continue; // 변환 실패. 다음 후보로.
                }

                // --- PEB 주소 변환: PDE ---
                MMPTE_HARDWARE peb_pde;
                UINT64 peb_pd_base = peb_pdpte.u.Bits.PageFrameNumber << PAGE_SHIFT;
                UINT64 peb_pde_addr = peb_pd_base + pebVirtualAddress.BITS.PdIndex * pteSize;
                if (!IsValidPhysicalRange(peb_pde_addr, pteSize, memoryRanges, numberOfRanges) ||
                    !NT_SUCCESS(SafeReadPhysicalAddress(peb_pde_addr, &peb_pde, pteSize)) ||
                    !peb_pde.u.Bits.Valid) {
                    continue; // 변환 실패. 다음 후보로.
                }

                // --- PEB 주소 변환: PTE ---
                MMPTE_HARDWARE peb_pte;
                UINT64 peb_pt_base = peb_pde.u.Bits.PageFrameNumber << PAGE_SHIFT;
                UINT64 peb_pte_addr = peb_pt_base + pebVirtualAddress.BITS.PtIndex * pteSize;
                if (!IsValidPhysicalRange(peb_pte_addr, pteSize, memoryRanges, numberOfRanges) ||
                    !NT_SUCCESS(SafeReadPhysicalAddress(peb_pte_addr, &peb_pte, pteSize)) ||
                    !peb_pte.u.Bits.Valid) {
                    continue; // 변환 실패. 다음 후보로.
                }

                // PEB의 최종 물리 주소를 계산합니다.
                physicalPebAddress = (peb_pte.u.Bits.PageFrameNumber << PAGE_SHIFT) + pebVirtualAddress.BITS.Offset;

                PEB targetPeb;
                if (!IsValidPhysicalRange(physicalPebAddress, sizeof(targetPeb), memoryRanges, numberOfRanges) ||
                    !NT_SUCCESS(SafeReadPhysicalAddress(physicalPebAddress, &targetPeb, sizeof(targetPeb)))) {
                    // PEB를 물리 메모리에서 읽지 못했습니다. 다음 후보로 넘어갑니다.
                    continue;
                }

                // [최종 검증] 읽어온 PEB의 ImageBaseAddress가 우리의 랜드마크 주소와 일치하는가?
                if (targetPeb.ImageBaseAddress == baseAddress) {
                    // ★★★ 모든 검증 통과! ★★★
                    // 이것이 우리가 찾던 진짜 CR3입니다.
                    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[+] Success! Verified CR3: 0x%llX (VA 0x%p -> PA 0x%llX)\n", cr3_candidate, baseAddress, physicalBase);
                    CR3 = cr3_candidate;
                    goto Cleanup; // 성공했으므로 루프를 완전히 종료합니다.
                }
                
            }
        }
    }
Cleanup:
    //DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[DBG] Entering Cleanup, cr3_found: 0x%llX\n", cr3_found);
    if (memoryRanges) {
       // DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[DBG] Freeing memoryRanges: %p\n", memoryRanges);
        ExFreePool(memoryRanges);
    }
    //DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[DBG] Exiting Get_CR3_by_BruteForce with CR3: 0x%llX\n", cr3_found);
    return CR3;
}


// PID 래퍼 함수는 이전과 동일
UINT64 FindProcessCr3ByPid(_In_ HANDLE ProcessId)
{
    PEPROCESS targetProcess = NULL;
    NTSTATUS status = PsLookupProcessByProcessId(ProcessId, &targetProcess);
    if (!NT_SUCCESS(status) || !targetProcess) {
        DbgPrint("[-] PsLookupProcessByProcessId failed for PID %p. Status: 0x%X\n", ProcessId, status);
        return 0;
    }
    UINT64 cr3Value = Get_CR3_by_BruteForce(targetProcess);
    ObDereferenceObject(targetProcess);
    return cr3Value;
}