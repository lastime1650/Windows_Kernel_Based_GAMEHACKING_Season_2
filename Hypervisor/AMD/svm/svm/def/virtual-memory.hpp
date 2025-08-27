#pragma once
#include "../../common-includes.hpp"

namespace svm
{
    // // http://developer.amd.com/wordpress/media/2012/10/NPT-WP-1%201-final-TM.pdf
    typedef struct
    {
        union
        {
            UINT64 value;
            struct
            {
                UINT64 reserved1 : 8;         
                UINT64 bootstrap_processor : 1;
                UINT64 reserved2 : 1;         
                UINT64 enable_x2_apic_mode : 1;  
                UINT64 enable_x_api_global : 1; 
                UINT64 apic_base : 24;         
            } fields;
        };
    } apic_base_t, * papic_base_t;
    static_assert(sizeof(apic_base_t) == 8, "apic base size mismatch");

    typedef struct
    {
        union
        {
            UINT64 value;
            struct
            {
                UINT64 valid : 1;               
                UINT64 write : 1;               
                UINT64 user : 1;                
                UINT64 write_through : 1;        
                UINT64 cache_disable : 1;        
                UINT64 accessed : 1;            
                UINT64 dirty : 1;               
                UINT64 pat : 1;                 
                UINT64 global : 1;              
                UINT64 avl : 3;                 
                UINT64 page_frame_nr : 40;    
                UINT64 reserved1 : 11;          
                UINT64 no_execute : 1;           
            } fields;
        };
    } pt_entry_4kb_t, * ppt_entry_4kb_t;
    static_assert(sizeof(pt_entry_4kb_t) == 8, "page table enty 4kb size mismatch");

    typedef struct
    {
        union
        {
            uint64_t value;
            struct
            {
                uint64_t valid : 1;
                uint64_t write : 1;
                uint64_t user : 1;
                uint64_t write_through : 1;
                uint64_t cache_disable : 1;
                uint64_t accessed : 1;
                uint64_t reserved1 : 3;
                uint64_t avl : 3;
                uint64_t page_frame_nr : 40;
                uint64_t reserved2 : 11;
                uint64_t no_execute : 1;
            } fields;
        };
    } pml4_entry_4kb_t, * ppml4_entry_4kb_t,
        pdp_entry_4kb_t, * ppdp_entry_4kb_t;
    static_assert(sizeof(pml4_entry_4kb_t) == 8,
        "pml4 entry 4kb size mismatch");

    typedef struct
    {
        union
        {
            uint64_t value;
            struct
            {
                uint64_t valid : 1;
                uint64_t write : 1;
                uint64_t user : 1;
                uint64_t write_through : 1;
                uint64_t cache_disable : 1;
                uint64_t accessed : 1;
                uint64_t dirty : 1;
                uint64_t large_page : 1;
                uint64_t global : 1;
                uint64_t avl : 3;
                uint64_t pat : 1;
                uint64_t reserved1 : 8;
                uint64_t page_frame_nr : 31;
                uint64_t reserved2 : 11;
                uint64_t no_execute : 1;
            } fields;
        };
    } pd_entry_4kb_t, * ppd_entry_4kb_t;
    static_assert(sizeof(pd_entry_4kb_t) == 8,
        "pd entry 4kb size mismatch");

    typedef union 
    {
        PVOID value;
        struct
        {
            uint64_t offset : 12;
            uint64_t pt_index : 9;
            uint64_t pd_index : 9;
            uint64_t pdpt_index : 9;
            uint64_t pml4_index : 9;
            uint64_t reserved1 : 16;
        };
    } virtual_address_t, * pvirtual_address_t;
    static_assert(sizeof(virtual_address_t) == 8,
        "virtual address size mismatch");

    

}