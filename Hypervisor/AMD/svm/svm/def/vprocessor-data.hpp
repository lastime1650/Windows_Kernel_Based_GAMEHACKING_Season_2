#pragma once
#include "../../common-includes.hpp"
#include "vmcb.hpp"
#include "virtual-memory.hpp"

namespace svm
{
    typedef struct
    {
        PVOID msr_permissions_map;
        DECLSPEC_ALIGN(PAGE_SIZE) pml4_entry_4kb_t pml4_entries[1]; // 512 gb
        DECLSPEC_ALIGN(PAGE_SIZE) pdp_entry_4kb_t pdp_entries[512];
        DECLSPEC_ALIGN(PAGE_SIZE) pd_entry_4kb_t pd_entries[512][512];
    } shared_vcpu_t, * pshared_vcpu_t;

    typedef struct _vprocessor_data
    {
        union
        {
            DECLSPEC_ALIGN(PAGE_SIZE) uint8_t host_stack_limit[KERNEL_STACK_SIZE];
            struct
            {
                uint8_t stack_contents[KERNEL_STACK_SIZE - (sizeof(PVOID) * 6) - sizeof(KTRAP_FRAME)];
                KTRAP_FRAME trap_frame;
                uint64_t guest_vmcb_pa; // host rsp
                uint64_t host_vmcb_pa;
                _vprocessor_data* self;
                pshared_vcpu_t shared_vcpu;
                uint64_t padding1;      // keep host rsp 16 bytes aligned
                uint64_t reserved1;
            } host_stack_layout;
        };


        DECLSPEC_ALIGN(PAGE_SIZE) vmcb_t guest_vmcb;
        DECLSPEC_ALIGN(PAGE_SIZE) vmcb_t host_vmcb;
        DECLSPEC_ALIGN(PAGE_SIZE) uint8_t host_state_area[PAGE_SIZE];
    } vcpu_t, * pvcpu_t;
    static_assert(sizeof(vcpu_t) == (KERNEL_STACK_SIZE + PAGE_SIZE * 3),
        "vcpu_t size mismatch");
}