#pragma once
#include <cstdint>
#include "../../common-includes.hpp"

#define SVM_MSR_PERMISSIONS_MAP_SIZE (PAGE_SIZE * 2)
#define SVM_MSR_VM_HSAVE_PA             0xC0010117

// extended feature enable register (EFER)
#define IA32_MSR_EFER                0xC0000080
#define IA32_MSR_EFER_SVME           (1UL << 12)   // this will set the 13 bit of EFER (if we're counting starting from 1),
#define IA32_MSR_PAT                 0x00000277
#define SVM_MSR_VM_CR                0xc0010114
#define SVM_MSR_VM_HSAVE_PA          0xc0010117

// long system target-address register (LSTAR)
#define IA32_LSTAR                   0xC0000082

#define POOL_NX_OPTIN   1
#define SVM_VM_CR_SVMDIS             (1UL << 4)
#define SVM_NP_ENABLE_NP_ENABLE      (1UL << 0)

#define EFER_SVME       (1UL << 12)

#define IA32_APIC_BASE  0x0000001b

namespace svm
{
    enum class cpuid : uint32_t
    {
        cpu_vendor_string = 0x00000000,
        processor_feature_id = 0x00000001,
        hypervisor_present_ex = 0x80000000,
        processor_feature_id_ex = 0x80000001,
        svm_features = 0x8000000a,
        svm_features_ex = 0x80000001,
        hypervisor_vendor_id = 0x40000000,
        hypervisor_interface = 0x40000001,

        cpu_ecx_svm = 0x4,
        cpu_edx_np = 0x1,
    };

    enum class msr : uint32_t
    {
        svm_vm_cr = 0xc0010114,
        svm_vm_cr_svmdis = 0x10,
    };

    typedef union _cr3
    {
        uint64_t flags;
        struct
        {
            uint64_t reserved1 : 3;
            uint64_t page_level_write_through : 1;
            uint64_t page_level_cache_disable : 1;
            uint64_t reserved2 : 7;
            uint64_t dirbase : 36;
            uint64_t reserved3 : 16;
        };
    } cr3;

    extern "C" void _sgdt(PVOID descriptor);
}