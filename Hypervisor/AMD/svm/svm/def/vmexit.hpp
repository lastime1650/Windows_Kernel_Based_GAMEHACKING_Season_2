#pragma once
#pragma warning (disable : 4369)
#pragma warning (disable : 4309)

#define RPL_MASK        3
#define DPL_SYSTEM      0

#define CPUID_UNLOAD 0xB16D1C

// Table B-1. VMCB Layout, Control Area
enum misc1_intercept : uint32_t
{
    intercept_intr = (1UL << 0),
    intercept_nmi = (1UL << 1),
    intercept_smi = (1UL << 2),
    intercept_init = (1UL << 3),
    intercept_vintr = (1UL << 4),
    intercept_cr0_ = (1UL << 5),

    intercept_read_idtr = (1UL << 6),
    intercept_read_gdtr = (1UL << 7),
    intercept_read_ldtr = (1UL << 8),
    intercept_read_tr = (1UL << 9),

    intercept_write_idtr = (1UL << 10),
    intercept_write_gdtr = (1UL << 11),
    intercept_write_ldtr = (1UL << 12),
    intercept_write_tr = (1UL << 13),

    intercept_rdtsc = (1UL << 14),
    intercept_rdpmc = (1UL << 15),
    intercept_pushf = (1UL << 16),
    intercept_popf = (1UL << 17),
    intercept_cpuid = (1UL << 18),
    intercept_rsm = (1UL << 19),
    intercept_iret = (1UL << 20),
    intercept_intn = (1UL << 21),
    intercept_invd= (1UL << 22),
    intercept_pause = (1UL << 23),
    intercept_hlt = (1UL << 24),
    intercept_invldpg = (1UL << 25),
    intercept_invlpga = (1UL << 26),
    intercept_ioio_prot = (1UL << 27),
    intercept_msr_prot = (1UL << 28),
    intercept_task_switches = (1UL << 29),
    intercept_ferr_freeze = (1UL << 30),
    intercept_shutdown = (1UL << 31),
};

enum misc2_intercept : uint32_t
{
    intercept_vmrun = (1UL << 0),
    intercept_vmcall = (1UL << 1),
    intercept_vmload = (1UL << 2),
    intercept_vmsave = (1UL << 3),

    intercept_stgi = (1UL << 4),
    intercept_clgi = (1UL << 5),
    intercept_skinit = (1UL << 6),
    intercept_rdtscp = (1UL << 7),
    intercept_incebp = (1UL << 8),
    intercept_wbinvd = (1UL << 9),
    intercept_monitor = (1UL << 10),
    intercept_mwait = (1UL << 11),
    intercept_mwait_conditional = (1UL << 12),
    intercept_xsetbv = (1UL << 13),
    intercept_rdpru = (1UL << 14),
    intercept_efer = (1UL << 15),

    intercept_cr0 = (1UL << 16),
    intercept_cr1 = (1UL << 17),
    intercept_cr2 = (1UL << 18),
    intercept_cr3 = (1UL << 19),
    intercept_cr4 = (1UL << 20),
    intercept_cr5 = (1UL << 21),
    intercept_cr6 = (1UL << 22),
    intercept_cr7 = (1UL << 23),
    intercept_cr8 = (1UL << 24),
    intercept_cr9 = (1UL << 25),
    intercept_cr10 = (1UL << 26),
    intercept_cr11 = (1UL << 27),
    intercept_cr12 = (1UL << 28),
    intercept_cr13 = (1UL << 29),
    intercept_cr14 = (1UL << 30),
    intercept_cr15 = (1UL << 31),
};

enum exception_intercept : int16_t
{

};

typedef struct 
{
    union
    {
        uint64_t value;
        struct
        {
            uint64_t vector : 8;        
            uint64_t type : 3;          
            uint64_t error_code_valid : 1;  
            uint64_t reserved1 : 19;   
            uint64_t valid : 1;        
            uint64_t error_code : 32;      
        } fields;
    };
} event_inj_t, * pevent_inj_t;
static_assert(sizeof(event_inj_t) == 8,
    "event_inj size mismatch");

// Table C-1. SVM Intercept Codes
enum vmexit : int16_t
{
    cr0_read = 0x0,
    cr1_read = 0x1,
    cr2_read = 0x2,
    cr3_read = 0x3,
    cr4_read = 0x4,
    cr5_read = 0x5,
    cr6_read = 0x6,
    cr7_read = 0x7,
    cr8_read = 0x8,
    cr9_read = 0x9,
    cr10_read = 0xa,
    cr11_read = 0xb,
    cr12_read = 0xc,
    cr13_read = 0xd,
    cr14_read = 0xe,
    cr15_read = 0xf,

    cr0_write = 0x10,
    cr1_write = 0x11,
    cr2_write = 0x12,
    cr3_write = 0x13,
    cr4_write = 0x14,
    cr5_write = 0x15,
    cr6_write = 0x16,
    cr7_write = 0x17,
    cr8_write = 0x18,
    cr9_write = 0x19,
    cr10_write = 0x1a,
    cr11_write = 0x1b,
    cr12_write = 0x1c,
    cr13_write = 0x1d,
    cr14_write = 0x1e,
    cr15_write = 0x1f,

    dr0_read = 0x20,
    dr1_read = 0x21,
    dr2_read = 0x22,
    dr3_read = 0x23,
    dr4_read = 0x24,
    dr5_read = 0x25,
    dr6_read = 0x26,
    dr7_read = 0x27,
    dr8_read = 0x28,
    dr9_read = 0x29,
    dr10_read = 0x2a,
    dr11_read = 0x2b,
    dr12_read = 0x2c,
    dr13_read = 0x2d,
    dr14_read = 0x2e,
    dr15_read = 0x2f,

    dr0_write = 0x30,
    dr1_write = 0x31,
    dr2_write = 0x32,
    dr3_write = 0x33,
    dr4_write = 0x34,
    dr5_write = 0x35,
    dr6_write = 0x36,
    dr7_write = 0x37,
    dr8_write = 0x38,
    dr9_write = 0x39,
    dr10_write = 0x3a,
    dr11_write = 0x3b,
    dr12_write = 0x3c,
    dr13_write = 0x3d,
    dr14_write = 0x3e,
    dr15_write = 0x3f,

    excp0_write = 0x40,
    excp1_write = 0x41,
    excp2_write = 0x42,
    excp3_write = 0x43,
    excp4_write = 0x44,
    excp5_write = 0x45,
    excp6_write = 0x46,
    excp7_write = 0x47,
    excp8_write = 0x48,
    excp9_write = 0x49,
    excp10_write = 0x4a,
    excp11_write = 0x4b,
    excp12_write = 0x4c,
    excp13_write = 0x4d,
    excp14_write = 0x4e,
    excp15_write = 0x4f,
    excp16_write = 0x50,
    excp17_write = 0x51,
    excp18_write = 0x52,
    excp19write = 0x53,
    excp20_write = 0x54,
    excp21_write = 0x55,
    excp22_write = 0x56,
    excp23_write = 0x57,
    excp24_write = 0x58,
    excp25_write = 0x59,
    excp26_write = 0x5a,
    excp27_write = 0x5b,
    excp28_write = 0x5c,
    excp29_write = 0x5d,
    excp30_write = 0x5e,
    excp31_write = 0x5f,

    intr = 0x60,
    nmi = 0x61,
    smi = 0x62,
    init = 0x63,
    vintr = 0x64,
    cr0_sel_write = 0x65,     
    idtr_read = 0x66,
    gdtr_read = 0x67,
    ldtr_read = 0x68,
    tr_read = 0x69,
    idtr_write = 0x6A,
    gftr_write = 0x6B,
    ldtr_write = 0x6C,
    tr_write = 0x6D,
    rdtsc = 0x6E,
    rdpmc = 0x6F,
    pushf = 0x70,
    popf = 0x71,
    cpuid = 0x72,
    rsm = 0x73,
    iret = 0x74,
    swint = 0x75,             
    invd = 0x76,
    pause = 0x77,
    hlt = 0x78,
    invlpg = 0x79,
    invlpga = 0x7A,
    ioio = 0x7B,            
    msr = 0x7C,             
    task_switch = 0x7D,     
    ferr_freeze = 0x7E,     
    shutdown = 0x7F,
    vmrun = 0x80,
    vmcall = 0x81,
    vmload = 0x82,
    vmsave = 0x83,
    sigi = 0x84,
    clgi = 0x85,
    skinit = 0x86,
    rdtscp = 0x87,
    icebp = 0x88,
    wbinvd = 0x89,
    monitor = 0x8A,
    mwait = 0x8B,
    mwait_conditional = 0x8C,
    rdpru = 0x8D,
    xsetbv = 0x8E,
    efer_write_trap = 0x8F,   

    cr0_write_trap = 0x90,
    cr1_write_trap = 0x91,
    cr2_write_trap= 0x92,
    cr3_write_trap= 0x93,
    cr4_write_trap= 0x94,
    cr5_write_trap= 0x95,
    cr6_write_trap= 0x96,
    cr7_write_trap= 0x97,
    cr8_write_trap= 0x98,
    cr9_write_trap= 0x99,
    cr10_write_trap = 0x9a,
    cr11_write_trap = 0x9b,
    cr12_write_trap = 0x9c,
    cr13_write_trap = 0x9d,
    cr14_write_trap = 0x9e,
    cr15_write_trap = 0x9f,

    invlpgb = 0xA0,
    invlpgb_illegal = 0xA1,
    invpcid = 0xA2,
    mcommit = 0xA3,
    tlbsync = 0xA4,
    npf = 0x400,
    incomplete_ipi = 0x401,
    avic_noaccel = 0x402,      
    vmgexit = 0x403,
    invalid = -1,
    busy = -2
};