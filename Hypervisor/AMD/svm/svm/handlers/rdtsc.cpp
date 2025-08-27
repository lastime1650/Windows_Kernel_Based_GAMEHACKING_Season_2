#include "handlers.hpp"
#include "../util/util.hpp"
#pragma warning (disable : 4293)
#pragma warning (disable : 26451)

namespace svm
{
    namespace handle
    {
        void rdtsc(pvcpu_t vcpu, pguest_ctx_t guest_ctx)
        {
            guest_ctx->vprocessor_registers->rax = static_cast<uint32_t>(__rdtsc());
            guest_ctx->vprocessor_registers->rdx = __rdtsc() >> 32;

            next_instruction;
        }
    }
}