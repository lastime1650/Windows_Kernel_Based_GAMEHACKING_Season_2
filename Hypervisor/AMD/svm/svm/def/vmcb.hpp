#pragma once
#include "../../common-includes.hpp"

namespace svm
{
    typedef union
    {
        uint16_t value;

        struct
        {
            uint16_t type : 4;
            uint16_t system : 1;
            uint16_t dpl : 2;
            uint16_t present : 1;
            uint16_t avl : 1;
            uint16_t longmode : 1;
            uint16_t default_bit : 1;
            uint16_t granularity : 1;
            uint16_t reserved : 4;
        };
    } segment_attribute_64_t, * psegment_attribute_64_t;
    static_assert(sizeof(segment_attribute_64_t) == 2,
        "segment_attribute_64 size mismatch");

    struct seg_register
    {
        uint16_t selector;
        segment_attribute_64_t attribute;
        uint32_t limit;
        uint64_t base;
    };
    static_assert(sizeof(seg_register) == 0x10,
        "seg_register size mismatch");

    // Table B-1. VMCB Layout, Control Area
    typedef struct
    {
        uint16_t intercept_cr_read;           // +0x000
        uint16_t intercept_cr_write;          // +0x002
        uint16_t intercept_dr_read;           // +0x004
        uint16_t intercept_dr_write;          // +0x006
        uint32_t intercept_exeption;          // +0x008
        uint32_t intercept_misc1;             // +0x00c
        uint32_t intercept_misc2;              // +0x010
        uint8_t reserved1[0x03c - 0x014];     // +0x014
        uint16_t pause_filter_threshhold;     // +0x03c
        uint16_t pause_filter_count;          // +0x03e
        uint64_t iopm_base_pa;                // +0x040
        uint64_t msrpm_base_pa;               // +0x048
        uint64_t tsc_offset;                  // +0x050
        uint32_t guest_asid;                  // +0x058
        uint32_t tlb_control;                 // +0x05c
        uint64_t vintr;                       // +0x060
        uint64_t interrupt_shadow;            // +0x068
        uint64_t exit_code;                   // +0x070
        uint64_t exit_info1;                  // +0x078
        uint64_t exit_info2;                  // +0x080
        uint64_t exit_int_info;               // +0x088
        uint64_t np_enable;                   // +0x090
        uint64_t avic_apic_bar;               // +0x098
        uint64_t guest_pa_of_ghcb;            // +0x0a0
        uint64_t event_inj;                   // +0x0a8
        uint64_t ncr3;                        // +0x0b0
        uint64_t lbr_virtualization_enable;   // +0x0b8
        uint64_t vmcb_clean;                  // +0x0c0
        uint64_t next_rip;                    // +0x0c8
        uint8_t num_of_bytes_fetched;         // +0x0d0
        uint8_t guest_instruction_bytes[15];  // +0x0d1
        uint64_t avic_apic_backing_page_ptr;  // +0x0e0
        uint64_t reserved2;                   // +0x0e8
        uint64_t avic_logical_table_ptr;      // +0x0f0
        uint64_t avic_physical_table_ptr;     // +0x0f8
        uint64_t reserved3;                   // +0x100
        uint64_t vmcb_save_state_ptr;         // +0x108
        uint8_t reserved4[0x400 - 0x110];     // +0x110
    } vmcb_ctrl_area_t, * pvmcb_ctrl_area_t;
    static_assert(sizeof(vmcb_ctrl_area_t) == 0x400,
        "vmcb_ctrl_area size mismatch");

    // Table B-2. VMCB Layout, State Save Area 
    typedef struct
    {
        seg_register es;                      // +0x000
        seg_register cs;                      // +0x010
        seg_register ss;                      // +0x020
        seg_register ds;                      // +0x030
        seg_register fs;                      // +0x040
        seg_register gs;                      // +0x050
        seg_register gdtr;                    // +0x060
        seg_register ldtr;                    // +0x070
        seg_register idtr;                    // +0x080
        seg_register tr;                      // +0x090
        uint8_t reserved1[0x0cb - 0x0a0];     // +0x0a0
        uint8_t cpl;                          // +0x0cb
        uint32_t reserved2;                   // +0x0cc
        uint64_t efer;                        // +0x0d0
        uint8_t reserved3[0x148 - 0x0d8];     // +0x0d8
        uint64_t cr4;                         // +0x148
        uint64_t cr3;                         // +0x150
        uint64_t cr0;                         // +0x158
        uint64_t dr7;                         // +0x160
        uint64_t dr6;                         // +0x168
        uint64_t rflags;                      // +0x170
        uint64_t rip;                         // +0x178
        uint8_t reserved4[0x1d8 - 0x180];     // +0x180
        uint64_t rsp;                         // +0x1d8
        uint8_t reserved5[0x1f8 - 0x1e0];     // +0x1e0
        uint64_t rax;                         // +0x1f8
        uint64_t star;                        // +0x200
        uint64_t lstar;                       // +0x208
        uint64_t cstar;                       // +0x210
        uint64_t sfmask;                      // +0x218
        uint64_t kernel_gs_base;              // +0x220
        uint64_t sysenter_cs;                 // +0x228
        uint64_t sysenter_esp;                // +0x230
        uint64_t sysenter_eip;                // +0x238
        uint64_t cr2;                         // +0x240
        uint8_t reserved6[0x268 - 0x248];     // +0x248
        uint64_t gpat;                        // +0x268
        uint64_t dbg_ctl;                     // +0x270
        uint64_t br_from;                     // +0x278
        uint64_t br_to;                       // +0x280
        uint64_t last_excep_from;             // +0x288
        uint64_t last_exep_to;                // +0x290
    } vmcb_state_save_area_t, * pvmcb_state_save_area_t;
    static_assert(sizeof(vmcb_state_save_area_t) == 0x298,
        "vmcb_state_save_area size mismatch");

    typedef struct
    {
        vmcb_ctrl_area_t control_area;
        vmcb_state_save_area_t state_save_area;
        uint8_t reserved1[0x1000 - sizeof(vmcb_ctrl_area_t) - sizeof(vmcb_state_save_area_t)];
    } vmcb_t, * pvmcb_t;
    static_assert(sizeof(vmcb_t) == 0x1000,
        "vmcb size mismatch");

    typedef struct
    {
        uint64_t r15;
        uint64_t r14;
        uint64_t r13;
        uint64_t r12;
        uint64_t r11;
        uint64_t r10;
        uint64_t r9;
        uint64_t r8;
        uint64_t rdi;
        uint64_t rsi;
        uint64_t rbp;
        uint64_t rsp;
        uint64_t rbx;
        uint64_t rdx;
        uint64_t rcx;
        uint64_t rax;
    } guest_registers_t, * pguest_registers_t;

    typedef struct
    {
        pguest_registers_t vprocessor_registers;
        bool should_exit;
    } guest_ctx_t, * pguest_ctx_t;

    struct NPF_EXITINFO1
    {
        union
        {
            UINT64 AsUInt64;
            struct
            {
                UINT64 Valid : 1;                   // [0]
                UINT64 Write : 1;                   // [1]
                UINT64 User : 1;                    // [2]
                UINT64 Reserved : 1;                // [3]
                UINT64 Execute : 1;                 // [4]
                UINT64 Reserved2 : 27;              // [5:31]
                UINT64 GuestPhysicalAddress : 1;    // [32]
                UINT64 GuestPageTables : 1;         // [33]
            } Fields;
        };
    };


}