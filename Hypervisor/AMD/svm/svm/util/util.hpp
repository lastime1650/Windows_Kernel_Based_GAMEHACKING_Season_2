#include "../def/cpu.hpp"
#include "../../common-includes.hpp"
#include "../def/descriptors-info.hpp"
#include "../def/vmcb.hpp"
#include "../def/vprocessor-data.hpp"
#include "../def/vmexit.hpp"



#pragma warning (disable : 4244)
#define IA32_MSR_LSTAR 0xC0000082
namespace svm
{
    extern ULONG64 g_original_lstar;
    namespace util
    {
       
        extern "C" void AsmSyscallHookHandler(void);



        typedef bool (*callback)(PVOID ctx);

        PVOID alloc_nonpaged_pool(size_t size);

        void free_nonpaged_pool(PVOID base);

        PVOID alloc_contiguous_memory(size_t size);

        void free_contiguous_memory(PVOID base);

        void setup_npt(pshared_vcpu_t shared_vprocessor_data);

        void setup_msr_permissions_bitmap(PVOID msr_permissions);

        uint16_t execute_on_each_processor(callback callback, PVOID ctx);

        bool is_hypervisor_vendor_installed();

        uint16_t get_segment_access_rights(uint16_t segment_selector, ULONG_PTR gdt_base);

        void general_protection_exeption(pvcpu_t vprocessor_data);

        void invalid_opcode_exception(pvcpu_t vprocessor_data);

        uintptr_t get_kernel_dir_base();

        uint64_t random(int min, int max);

        PPHYSICAL_MEMORY_DESCRIPTOR get_physical_memory_ranges_descriptor();
    }
}