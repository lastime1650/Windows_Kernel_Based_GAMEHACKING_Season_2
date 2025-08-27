#pragma once
#include <cstdarg>
#pragma pack(push, 1)

namespace svm
{
    typedef struct
    {
        uint16_t limit;
        uintptr_t base;
    } descriptor_table_register_t, * pdescriptor_table_register_t;
    static_assert(sizeof(descriptor_table_register_t) == 10,
        "descriptor_table_register size mismatch");

    typedef struct
    {
        union
        {
            uint64_t value;
            struct
            {
                uint16_t limit_low;
                uint16_t base_low;
                uint32_t base_middle : 8;
                uint32_t type : 4;
                uint32_t system : 1;
                uint32_t dpl : 2;
                uint32_t present : 1;
                uint32_t limit_high : 4;
                uint32_t avl : 1;
                uint32_t long_mode : 1;
                uint32_t default_bit : 1;
                uint32_t granularity : 1;
                uint32_t base_high : 8;
            } fields;
        };
    } segment_descriptor_t, * psegment_descriptor_t;
    static_assert(sizeof(segment_descriptor_t) == 8,
        "segment_descriptor size mismatch");

    typedef struct
    {
        union
        {
            uint16_t value;
            struct
            {
                uint16_t type : 4;
                uint16_t system : 1;
                uint16_t dpl : 2;
                uint16_t present : 1;
                uint16_t avl : 1;
                uint16_t long_mode : 1;
                uint16_t default_bit : 1;
                uint16_t granularity : 1;
                uint16_t reserved1 : 4;
            } fields;
        };
    } segment_attributes_t, * psegment_attributes_t;
    static_assert(sizeof(segment_attributes_t) == 2,
        "segment_attributes size mismatch");
}

#pragma pack (pop)