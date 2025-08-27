#pragma once
#include "handlers.hpp"

namespace svm
{
    namespace handle
    {

        hook_info g_zw_create_file_hook;



        // 후킹을 활성화하는 함수 (실행 권한 제거)
        void enable_hook(hook_info* hook)
        {
            if (!hook || !hook->npt_entry) return;

            // NPT PD 엔트리의 복사본을 만듭니다.
            pd_entry_4kb_t new_entry;
            new_entry.value = hook->original_value;

            // 실행 금지(No-Execute) 비트를 1로 설정합니다.
            // (pd_entry_4kb_t 구조체 정의에 no_execute 필드가 있다고 가정)
            new_entry.fields.no_execute = 1;

            // 수정된 엔트리 값을 NPT에 원자적으로(atomically) 씁니다.
            // 다중 코어 환경에서 동기화를 위해 Interlocked 사용이 권장됩니다.
            InterlockedExchange64((PLONG64)&hook->npt_entry->value, new_entry.value);

            //debug_log("[HOOK] Hook enabled for GPA %llx. NPT value changed to %llx\n",hook->target_gpa, new_entry.value);
        }

        // 후킹을 비활성화하는 함수 (원래 권한 복구)
        void disable_hook(hook_info* hook)
        {
            if (!hook || !hook->npt_entry) return;

            // 백업해둔 원래 값으로 NPT 엔트리를 복구합니다.
            InterlockedExchange64((PLONG64)&hook->npt_entry->value, hook->original_value);
            //debug_log("[HOOK] Hook disabled for GPA %llx. NPT value restored to %llx\n", hook->target_gpa, hook->original_value);
        }

        bool initialize_hooks(pshared_vcpu_t shared_vcpu)
        {
            // --- STEP 1: GVA 찾고 HPA(이 경우 GPA와 동일)로 변환 ---
            UNICODE_STRING function_name;
            RtlInitUnicodeString(&function_name, L"PsGetCurrentProcessId");

            void* zw_create_file_gva = MmGetSystemRoutineAddress(&function_name);
            if (!zw_create_file_gva) { /* ... 오류 처리 ... */ return false; }

            PHYSICAL_ADDRESS pa_from_api = MmGetPhysicalAddress(zw_create_file_gva);
            if (pa_from_api.QuadPart == 0) { /* ... 오류 처리 ... */ return false; }

            uint64_t target_gpa = pa_from_api.QuadPart;
            debug_log("[HOOK] Target Function GPA (from API): %llx\n", target_gpa);

            // --- NPT 조회 및 검증 ---
            debug_log("------------------------------------------\n");
            debug_log("[VERIFY] Starting NPT cross-verification...\n");

            // 1. 대상 GPA가 몇 번째 2MB 페이지에 속하는지 계산
            uint64_t page_2mb_index = target_gpa / (2 * 1024 * 1024);

            // 2. 2MB 페이지 인덱스를 PDPT/PD 인덱스로 변환
            uint64_t pdpt_index = page_2mb_index / 512;
            uint64_t pd_index = page_2mb_index % 512;

            if (pdpt_index >= 512)
            {
                debug_log("[VERIFY] FAILED: Target GPA is out of NPT range (> 512GB).\n");
                return false;
            }

            // 3. NPT 테이블에서 해당 엔트리를 직접 조회
            pd_entry_4kb_t* npt_entry = &shared_vcpu->pd_entries[pdpt_index][pd_index];

            // 4. NPT 엔트리에 기록된 페이지 프레임 번호(PFN)를 가져옴
            uint64_t pfn_from_npt = npt_entry->fields.page_frame_nr;

            // 5. NPT의 PFN으로 HPA의 시작 주소를 계산
            //    (setup_npt에서 2MB 페이지로 설정했으므로 2MB를 곱함)
            uint64_t hpa_base_from_npt = pfn_from_npt * (2 * 1024 * 1024);

            // 6. 대상 GPA가 속한 페이지의 시작 주소 계산
            uint64_t gpa_page_base = target_gpa & ~((2 * 1024 * 1024) - 1);

            debug_log("[VERIFY] > Target GPA belongs to page starting at: %llx\n", gpa_page_base);
            debug_log("[VERIFY] > NPT entry points to HPA starting at : %llx\n", hpa_base_from_npt);


            // 7. 두 시작 주소가 일치하는지 최종 검증
            if (gpa_page_base == hpa_base_from_npt)
            {
                debug_log("[VERIFY] SUCCESS: NPT mapping is 1:1 as expected.\n");
            }
            else
            {
                debug_log("[VERIFY] FAILED: NPT mapping is NOT 1:1! GPA page base != HPA base from NPT.\n");
                debug_log("         This indicates a critical bug in setup_npt or GPA calculation.\n");
                // 심각한 오류이므로 후킹을 진행하면 안 됨
                return false;
            }
            debug_log("------------------------------------------\n");

            // --- 검증 성공 후, 후킹 설정 진행 ---
            g_zw_create_file_hook.target_gva = zw_create_file_gva;
            g_zw_create_file_hook.target_gpa = target_gpa;
            g_zw_create_file_hook.npt_entry = npt_entry;
            g_zw_create_file_hook.original_value = npt_entry->value;

            enable_hook(&g_zw_create_file_hook);

            debug_log("[HOOK] Hook initialization and activation successful.\n");
            return true;
        }

        // 이 핸들러는 vmexit::npf 케이스에서 호출됩니다.
        bool handle_npf_hook(pvcpu_t vcpu, pguest_registers_t guest_regs)
        {
            
            svm::NPF_EXITINFO1 ExitInfo = { .AsUInt64 = vcpu->guest_vmcb.control_area.exit_info1 };

            ULONG64 FailAddress_ = vcpu->guest_vmcb.control_area.exit_info2;

            PHYSICAL_ADDRESS FailAddresss;
            FailAddresss.QuadPart = FailAddress_;


            if (ExitInfo.Fields.Execute)
            {

                // ZwCreateFile 함수의 시작 GPA를 가져옵니다.
                uint64_t zw_create_file_start_gpa = g_zw_create_file_hook.target_gpa;

                // 검사할 범위를 정의합니다. (함수 시작점 기준 앞뒤 0xFF 바이트)
                const uint64_t GPA_TOLERANCE = 0xFF;

                // 범위의 시작과 끝을 계산합니다.
                // (시작 주소에서 오버플로우가 나지 않도록 주의)
                uint64_t range_start = (zw_create_file_start_gpa > GPA_TOLERANCE) ? (zw_create_file_start_gpa - GPA_TOLERANCE) : 0;
                uint64_t range_end = zw_create_file_start_gpa + GPA_TOLERANCE;

                
                if (PAGE_ALIGN(g_zw_create_file_hook.target_gva) == (PVOID)MmGetVirtualForPhysical(FailAddresss))
                {
                    debug_log("MATCHED1?\n");
                    __debugbreak();
                }
                else if (g_zw_create_file_hook.target_gva == (PVOID)MmGetVirtualForPhysical(FailAddresss))
                {
                    debug_log("MATCHED2?\n");
                    __debugbreak();
                }
                else if (FailAddress_ >= range_start && FailAddress_ <= range_end) {
                    debug_log("MATCHED3?\n");
                    __debugbreak();
                }

                
                // 목표 함수의 GPA가 속한 2MB 페이지의 시작 주소
                uint64_t target_gpa_page = g_zw_create_file_hook.target_gpa & ~((2 * 1024 * 1024) - 1);

                // 폴트가 발생한 GPA가 속한 2MB 페이지의 시작 주소
                uint64_t faulting_gpa_page = FailAddress_ & ~((2 * 1024 * 1024) - 1);

                if (target_gpa_page == faulting_gpa_page)
                {
                    if (vcpu->guest_vmcb.state_save_area.rip == (ULONG64)g_zw_create_file_hook.target_gva) {
                        debug_log("MATCHED6?\n");
                        __debugbreak();

                    }
                    
                }
                

            }


            // 싱글 스텝 준비
            // 후크된 페이지의 실행 권한을 "일시적으로" 해제합니다.
            disable_hook(&g_zw_create_file_hook);

            // 게스트가 딱 한 명령어만 실행하고 다시 VM-Exit을 하도록 Trap Flag를 설정합니다.
            vcpu->guest_vmcb.state_save_area.rflags |= (1 << 8); // Set Trap Flag
            

            return true;
        }

        void is_hook_matched(pvcpu_t vcpu, pguest_registers_t guest_regs, PVOID API_NAME)
        {

        }

        extern "C" bool __stdcall handle_vmexit(pvcpu_t vcpu, pguest_registers_t guest_registers)
        {
            guest_ctx_t guest_ctx;
            KIRQL old_irql;

            guest_ctx.vprocessor_registers = guest_registers;
            guest_ctx.should_exit = false;

            // load some of the host state which isn't loaded on vmexit
            __svm_vmload(vcpu->host_stack_layout.host_vmcb_pa);

            NT_ASSERT(vcpu->host_stack_layout.reserved1 == MAXUINT64);

            // not needed
            old_irql = KeGetCurrentIrql();
            if (old_irql < DISPATCH_LEVEL)
                KeRaiseIrqlToDpcLevel();

            // the guest's rax is overwritten by the hosts on vmexit 
            // and saved in the vmcb instead
            guest_registers->rax = vcpu->guest_vmcb.state_save_area.rax;

            // update the _KTRAP_FRAME struct values in hypervisor stack, 
            // so that windbg can reconstruct the guests stack frame
            vcpu->host_stack_layout.trap_frame.Rsp = vcpu->guest_vmcb.state_save_area.rsp;
            vcpu->host_stack_layout.trap_frame.Rip = vcpu->guest_vmcb.control_area.next_rip;

            // vmexit handling
            switch (vcpu->guest_vmcb.control_area.exit_code)
            {
            case 0x41:
            {
                // SINGLE STEP 확인
                if (vcpu->guest_vmcb.state_save_area.rflags & (1ULL << 8))
                {
                    //debug_log("RIP: %p  \n", vcpu->guest_vmcb.state_save_area.rip);
                    vcpu->guest_vmcb.state_save_area.rflags &= ~(1ULL << 8);
                    enable_hook(&g_zw_create_file_hook);
                    /*
                    dr7_t new_dr7;
                    new_dr7.value = vcpu->guest_vmcb.state_save_area.dr7;
                    new_dr7.fields.l0 = 1;
                    new_dr7.fields.rw0 = 0; // 실행
                    new_dr7.fields.len0 = 0;
                    vcpu->guest_vmcb.state_save_area.dr6 = 0xFFFF0FF0; // 
                    vcpu->guest_vmcb.state_save_area.dr7 = new_dr7.value;
                    */
                    //__debugbreak();
                }
                else {
                    /*
                    __debugbreak();
                    debug_log("[DR6] %llu\n", vcpu->guest_vmcb.state_save_area.dr6);

                    
                        Dr0 잡혔다고 가정하고..
                    
                    //ULONG64 targetAPI = vcpu->guest_vmcb.state_save_area.rip;
                    debug_log("RIP: %p \n", vcpu->guest_vmcb.state_save_area.rip);
                    // --- 레지스터에 담긴 인자 (1-4) ---
                    uint64_t pFileHandle = guest_ctx.vprocessor_registers->rcx;
                    uint32_t DesiredAccess = (uint32_t)guest_ctx.vprocessor_registers->rdx;
                    uint64_t pObjectAttributes = guest_ctx.vprocessor_registers->r8;
                    uint64_t pIoStatusBlock = guest_ctx.vprocessor_registers->r9;

                    debug_log("  - Args in Registers:\n");
                    debug_log("    FileHandle*: 0x%llX\n", pFileHandle);
                    debug_log("    DesiredAccess: 0x%X\n", DesiredAccess);
                    debug_log("    ObjectAttributes*: 0x%llX\n", pObjectAttributes);
                    debug_log("    IoStatusBlock*: 0x%llX\n", pIoStatusBlock);


                    // ... (무한 루프 방지를 위한 BP 임시 비활성화 및 TF 설정) ...
                    dr7_t temp_dr7;
                    temp_dr7.value = vcpu->guest_vmcb.state_save_area.dr7;
                    temp_dr7.fields.l0 = 0;
                    vcpu->guest_vmcb.state_save_area.dr7 = temp_dr7.value;
                    vcpu->guest_vmcb.state_save_area.rflags |= (1ULL << 8); // 싱글스텝 ( 다시 활성화를 위해 ) 


                    __debugbreak();

                    __writedr(6, __readdr(6) & ~(1ULL << 0)); // 흔적 삭제
                    */
                }


                
                break;
            }
            case vmexit::cpuid:
                handle::cpuid(vcpu, &guest_ctx);
                break;

            case vmexit::msr:
                handle::msr(vcpu, &guest_ctx);
                break;

            case vmexit::vmrun:
                util::general_protection_exeption(vcpu);
                break;

            case vmexit::vmload:
                util::general_protection_exeption(vcpu);
                break;

            case vmexit::vmsave:
                util::general_protection_exeption(vcpu);
                break;

            case vmexit::rdtsc:
                handle::rdtsc(vcpu, &guest_ctx);
                break;
            case vmexit::npf:
            {
                handle_npf_hook(vcpu, guest_registers);
                break;
            }
            case vmexit::intr:
            {
                break;
            }
            default:
                debug_log("ExitCODE: %llu \n", vcpu->guest_vmcb.control_area.exit_code);
                __debugbreak();
                KeBugCheck(0xB16B00B5UL);
            }

            if (old_irql < DISPATCH_LEVEL)
                KeLowerIrql(old_irql);

            // terminate hypervisor
            if (guest_ctx.should_exit)
            {
                //  RBX     : address to return
                //  RCX     : stack pointer to restore
                //  EDX:EAX : address of per processor data to be freed by the caller
                guest_ctx.vprocessor_registers->rax = reinterpret_cast<uint64_t>(vcpu) & MAXUINT;
                guest_ctx.vprocessor_registers->rbx = vcpu->guest_vmcb.control_area.next_rip;
                guest_ctx.vprocessor_registers->rcx = vcpu->guest_vmcb.state_save_area.rsp;
                guest_ctx.vprocessor_registers->rdx = reinterpret_cast<uint64_t>(vcpu) >> 32;

                // load guest state
                __svm_vmload(MmGetPhysicalAddress(&vcpu->guest_vmcb).QuadPart);

                // set the global interrupt flag (GIF), but still disable interrupts by
                // clearing IF. GIF must be set to return to the normal execution, but
                // interruptions are unwanted untill SVM is disabled as it would
                // execute random kernel-code in the host context.
                _disable();
                __svm_stgi();


                // disable svm and restore the guest rflags
                // this may enable interrupts
                __writemsr(IA32_MSR_EFER, 
                    __readmsr(IA32_MSR_EFER) & ~EFER_SVME);

                __writeeflags(vcpu->guest_vmcb.state_save_area.rflags);
                NT_ASSERT(vcpu->host_stack_layout.reserved1 == MAXUINT64);
                return guest_ctx.should_exit;
            }

            // update rax
            vcpu->guest_vmcb.state_save_area.rax = guest_ctx.vprocessor_registers->rax;
            NT_ASSERT(vcpu->host_stack_layout.reserved1 == MAXUINT64);
            return guest_ctx.should_exit;
        }
    }
}