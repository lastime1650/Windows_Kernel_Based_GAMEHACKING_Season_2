#include "handlers.hpp"
#include "../util/util.hpp"
#pragma warning (disable : 4293)
#pragma warning (disable : 26451)

namespace svm
{
    namespace handle
    {

        typedef struct HYPERVISOR_CONTEXT {
            
            PVOID context;

        }HYPERVISOR_CONTEXT, *PHYPERVISOR_CONTEXT;


        void cpuid(pvcpu_t vcpu, pguest_ctx_t guest_ctx)
        {
            int registers[4]; // eax ebx ecx edx
            int leaf, sub_leaf;
            segment_attributes_t attribute;

            // execute cpuid for request
            leaf = static_cast<int>(guest_ctx->vprocessor_registers->rax);
            sub_leaf = static_cast<int>(guest_ctx->vprocessor_registers->rcx);
            __cpuidex(registers, leaf, sub_leaf);

            switch (leaf)
            {
                //case static_cast<int>(cpuid::processor_feature_id):
                //    // specify hypervisor presence 
                //    registers[2] |= static_cast<int>(cpuid::hypervisor_present_ex);
                //    break;

            case static_cast<int>(cpuid::hypervisor_vendor_id):
                // this is used in util::is_hypervisor_vendor_installed()
                // to check if the hypervisor is running
                registers[0] = static_cast<int>(cpuid::hypervisor_vendor_id); // CPUID_HV_MAX
                registers[1] = ' mvs';
                registers[2] = '    ';
                registers[3] = '    ';
                break;

            case static_cast<int>(cpuid::hypervisor_interface):
                // specify that our hypervisor does not 
                // conform to the Microsoft hypervisor interface
                registers[0] = '0#vH';  // Hv#0
                registers[1] = registers[2] = registers[3] = 0;
                break;
            case 0x1655:
            {
                // ##### SYSCALL 후킹 성공! #####

                // 1. Guest의 스택 주소 가져오기
                //uint64_t guest_rsp = vcpu->guest_vmcb.state_save_area.rsp;
                /*
                // 2. 시스템 프로세스의 컨텍스트에 Attach
                //    (우리의 하이퍼바이저는 시스템 프로세스 컨텍스트에서 실행되는 것을 가정)
                //    (만약 다르다면, PsLookupProcessByProcessId 등으로 시스템 프로세스를 찾아야 함)
                PEPROCESS system_process;
                // 이 부분은 하이퍼바이저 초기화 시 System 프로세스 EPROCESS 포인터를 구해 저장해두는 것이 좋음
                PsLookupProcessByProcessId((HANDLE)4, &system_process);

                KAPC_STATE apc_state;
                KeStackAttachProcess(system_process, &apc_state);

                uint64_t syscall_number = 0;
                __try
                {
                    // 3. 이제 Guest의 커널 주소를 직접 읽을 수 있음!
                    //    AsmSyscallHookHandler에서 push rax를 했으므로 rsp가 가리키는 곳에 syscall number가 있음
                    syscall_number = *(uint64_t*)guest_rsp;

                    debug_log("[MyHypervisor] Syscall hooked! Number: 0x%llX\n", syscall_number);
                }
                __except (EXCEPTION_EXECUTE_HANDLER)
                {
                    debug_log("[MyHypervisor] Failed to read guest stack!\n");
                }

                // 4. 원래 프로세스 컨텍스트로 복귀
                KeUnstackDetachProcess(&apc_state);
                ObDereferenceObject(system_process);*/

                // 5. Guest가 원래 가려던 nt!KiSystemCall64로 RIP를 직접 설정
                vcpu->guest_vmcb.state_save_area.rip = svm::g_original_lstar;

                // 6. 어셈 핸들러에서 스택에 push 했으므로, RSP를 8만큼 증가시켜 스택을 정리
                vcpu->guest_vmcb.state_save_area.rsp += 8;
            }
            case 0x1650:
            {
                PHYPERVISOR_CONTEXT packet = (PHYPERVISOR_CONTEXT)guest_ctx->vprocessor_registers->rcx;
                debug_log("packet -> %p \n", packet);
                __debugbreak();

                PHYSICAL_ADDRESS packet_Physical = MmGetPhysicalAddress(packet);
                //PHYPERVISOR_CONTEXT Context = (PHYPERVISOR_CONTEXT)packet_Physical.QuadPart;

                debug_log("packet_Physical -> %p \n", packet_Physical.QuadPart);
                __debugbreak();

                // HW BP 걸기
                //ULONG32 Core = KeGetCurrentProcessorNumberEx(NULL);

                //ULONG32 Core = KeGetCurrentProcessorNumberEx(NULL);
                typedef ULONG(*PsGetProcessSessionIdEx_)(PEPROCESS);

                PEPROCESS eprocess = (PEPROCESS)packet;
                PsGetProcessSessionIdEx_ PsGetProcessSessionIdEx = (PsGetProcessSessionIdEx_)0xfffff801660b7010;
                ULONG test = PsGetProcessSessionIdEx(eprocess);

                debug_log("test -> %d \n", test);
                __debugbreak();

                /*
                UNICODE_STRING func_name;
                RtlInitUnicodeString(&func_name, L"ZwCreateFile");
                void* func_addr = MmGetSystemRoutineAddress(&func_name);
                debug_log("ZwCreateFile API: %p \n", func_addr);

                __writedr(0, (uint64_t)func_addr);

                // 3. VMCB의 DR7을 수정하여 BP 활성화
                dr7_t new_dr7;
                new_dr7.value = vcpu->guest_vmcb.state_save_area.dr7;
                new_dr7.fields.l0 = 1;
                new_dr7.fields.rw0 = 0; // 실행
                new_dr7.fields.len0 = 0;
                vcpu->guest_vmcb.state_save_area.dr6 = 0xFFFF0FF0; // 
                vcpu->guest_vmcb.state_save_area.dr7 = new_dr7.value;
                __writedr(7, new_dr7.value);
                */



                break;
            }



            case CPUID_UNLOAD:
                if (sub_leaf == CPUID_UNLOAD)
                {
                    // unload 
                    attribute.value = vcpu->guest_vmcb.state_save_area.ss.attribute.value;
                    if (attribute.fields.dpl == DPL_SYSTEM)
                        guest_ctx->should_exit = true;
                }
                break;

            default:
                break;
            }

            // update the guest's gpr's used by cpuid
            guest_ctx->vprocessor_registers->rax = registers[0];
            guest_ctx->vprocessor_registers->rbx = registers[1];
            guest_ctx->vprocessor_registers->rcx = registers[2];
            guest_ctx->vprocessor_registers->rdx = registers[3];

            next_instruction;
        }
    }
}