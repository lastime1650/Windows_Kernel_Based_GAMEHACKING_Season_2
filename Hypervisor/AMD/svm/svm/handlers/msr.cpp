#include "handlers.hpp"
#include "../util/util.hpp"
#pragma warning (disable : 4293)
#pragma warning (disable : 26451)



namespace svm
{
    ULONG64 g_original_lstar = 0;
    namespace handle
    {
        
        void msr(pvcpu_t vcpu, pguest_ctx_t guest_ctx)
        {
            ULARGE_INTEGER value;
            uint32_t msr;
            bool write_access;

            msr = guest_ctx->vprocessor_registers->rcx & MAXUINT;
            write_access = (vcpu->guest_vmcb.control_area.exit_info1 != 0);

            if (msr == IA32_MSR_EFER)
            {
                // vmexit on EFER access should only occur on write access.
                NT_ASSERT(write_access);

                value.LowPart = guest_ctx->vprocessor_registers->rax & MAXUINT;
                value.HighPart = guest_ctx->vprocessor_registers->rdx & MAXUINT;

                if ((value.QuadPart & EFER_SVME) == 0)
                    util::invalid_opcode_exception(vcpu); // protect EFER.SVME bit by causing exeption

                // otherwise return the physical address of the value
                vcpu->guest_vmcb.state_save_area.efer = value.QuadPart;
            }
            else if (msr == IA32_LSTAR)
            {
                // LSTAR 접근은 쓰기만 인터셉트했으므로, 항상 쓰기 접근이어야 합니다.
                NT_ASSERT(write_access);

                // 게스트가 LSTAR에 쓰려고 했던 값을 가져옵니다.
                value.LowPart = guest_ctx->vprocessor_registers->rax & MAXUINT;
                value.HighPart = guest_ctx->vprocessor_registers->rdx & MAXUINT;

                // 로그를 남겨 LSTAR에 쓰기 시도가 있었음을 알립니다.
                debug_log("[MSR] LSTAR write attempt detected! Value: %llx\n", value.QuadPart);
                __debugbreak();
                // << 나중 단계에서 이 부분에 후킹 로직이 들어갑니다. >>
                // 지금은 게스트의 요청을 그대로 허용하여 시스템이 정상 동작하도록 합니다.
                vcpu->guest_vmcb.state_save_area.lstar = value.QuadPart;
            }
            else
            {
                if (write_access)
                {
                    value.LowPart = guest_ctx->vprocessor_registers->rax & MAXUINT;
                    value.HighPart = guest_ctx->vprocessor_registers->rdx & MAXUINT;
                    __writemsr(msr, value.QuadPart);
                }
                else
                {
                    value.QuadPart = __readmsr(msr);
                    guest_ctx->vprocessor_registers->rax = value.LowPart;
                    guest_ctx->vprocessor_registers->rdx = value.HighPart;
                }
            }

            next_instruction;
        }
    }
}