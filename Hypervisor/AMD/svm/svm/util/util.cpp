#include "util.hpp"

namespace svm
{
    namespace util
    {
        PVOID alloc_nonpaged_pool(size_t size)
        {
            PVOID memory;

            memory = ExAllocatePoolWithTag(NonPagedPool, size, 'vmm');

            if (memory)
            {
                NT_ASSERT(PAGE_ALIGN(memory) == memory);
                RtlZeroMemory(memory, size);
            }

            return memory;
        }

        void free_nonpaged_pool(PVOID base)
        {
            ExFreePoolWithTag(base, 'vmm');
        }

        PVOID alloc_contiguous_memory(size_t size)
        {
            PVOID memory;
            PHYSICAL_ADDRESS boundary, lowest, highest;

            boundary.QuadPart = lowest.QuadPart = 0;
            highest.QuadPart = -1;

            memory = MmAllocateContiguousMemorySpecifyCacheNode(size,
                lowest,
                highest,
                boundary,
                MmCached,
                MM_ANY_NODE_OK);

            if (memory)
                RtlZeroMemory(memory, size);

            return memory;
        }

        void free_contiguous_memory(PVOID base)
        {
            MmFreeContiguousMemory(base);
        }

        void setup_npt(pshared_vcpu_t shared_vprocessor_data)
        {
            uint64_t pdp_base_pa, pde_base_pa, translation_pa;

            // build one pml4 entry with subtables that control up to 512 gb of physical memory.
            // the pfn here points to a base physical address of the page directory pointer table
            pdp_base_pa = MmGetPhysicalAddress(&shared_vprocessor_data->pdp_entries).QuadPart;
            shared_vprocessor_data->pml4_entries[0].fields.page_frame_nr = pdp_base_pa >> PAGE_SHIFT;

            shared_vprocessor_data->pml4_entries[0].fields.valid = 1;
            shared_vprocessor_data->pml4_entries[0].fields.write = 1;
            shared_vprocessor_data->pml4_entries[0].fields.user = 1;

            // one pml4 entry controls 512 page directory pointer entries
            for (uint64_t i = 0; i < 512; i++)
            {
                // make the pfn point to the base physical address of the page directory table
                pde_base_pa = MmGetPhysicalAddress(&shared_vprocessor_data->pd_entries[i][0]).QuadPart;
                shared_vprocessor_data->pdp_entries[i].fields.page_frame_nr = pde_base_pa >> PAGE_SHIFT;
                shared_vprocessor_data->pdp_entries[i].fields.valid = 1;
                shared_vprocessor_data->pdp_entries[i].fields.write = 1;
                shared_vprocessor_data->pdp_entries[i].fields.user = 1;

                for (uint64_t j = 0; j < 512; j++)
                {
                    // the page frame number points to a base physical address of 
                    // the system phyiscal address to be translated froma a guest physical address
                    translation_pa = (i * 512) + j;
                    shared_vprocessor_data->pd_entries[i][j].fields.page_frame_nr = translation_pa;
                    shared_vprocessor_data->pd_entries[i][j].fields.valid = 1;
                    shared_vprocessor_data->pd_entries[i][j].fields.write = 1;
                    shared_vprocessor_data->pd_entries[i][j].fields.user = 1;
                    shared_vprocessor_data->pd_entries[i][j].fields.large_page = 1;
                }
            }
        }

        void setup_msr_permissions_bitmap(PVOID msr_permissions)
        {
            RTL_BITMAP msr_bitmap;
            constexpr uint16_t bits_per_msr = 2;
            constexpr uint32_t msr_range_base = 0xC0000000;
            constexpr uint16_t bitmap_vector_size = 0x800 * CHAR_BIT; // 0x4000

            // initialize bitmap & clear bits
            // the AMD MSR bitmap is made up of four seperate bit vectors, 
            // which are all 16 kbits (2 kbytes) or 0x4000 bytes in size
            RtlInitializeBitMap(&msr_bitmap,
                static_cast<PULONG>(msr_permissions),
                SVM_MSR_PERMISSIONS_MAP_SIZE * CHAR_BIT);
            RtlClearAllBits(&msr_bitmap);

            // write access interception for EFER MSR
            constexpr uint64_t offset_2nd_base = (IA32_MSR_EFER - msr_range_base) * bits_per_msr;
            constexpr uint64_t offset = offset_2nd_base + bitmap_vector_size;
            RtlSetBits(&msr_bitmap, offset + 1, 1);
        }

        typedef bool (*callback)(PVOID ctx);

        uint16_t execute_on_each_processor(callback callback, PVOID ctx)
        {
            NTSTATUS status;
            PROCESSOR_NUMBER processor_number;
            GROUP_AFFINITY affinity, previous_affinity;
            uint16_t i, processors;

            processors = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);

            for (i = 0; i < processors; i++)
            {
                // get processor(s)
                status = KeGetProcessorNumberFromIndex(i, &processor_number);
                if (!NT_SUCCESS(status))
                    return 0;

                // switch code execution from processor i 
                affinity.Group = processor_number.Group;
                affinity.Mask = 1ULL << processor_number.Number;
                affinity.Reserved[0] = affinity.Reserved[1] = affinity.Reserved[2] = 0;
                KeSetSystemGroupAffinityThread(&affinity, &previous_affinity);

                bool success = callback(ctx);

                // continue previously executed code
                KeRevertToUserGroupAffinityThread(&previous_affinity);

                if (!success)
                    return i;

            }

            return i;
        }

        bool is_hypervisor_vendor_installed()
        {
            int registers[4];   // eax ebx ecx edx
            char vedor_id[13];

            // when hypervisor is active, CPUID leaf 0x40000000
            // will return our own hypervisor vendor
            __cpuid(registers, static_cast<int>(cpuid::hypervisor_vendor_id));
            RtlCopyMemory(vedor_id + 0, &registers[1], sizeof(registers[1]));
            RtlCopyMemory(vedor_id + 4, &registers[2], sizeof(registers[2]));
            RtlCopyMemory(vedor_id + 8, &registers[3], sizeof(registers[3]));
            vedor_id[12] = ANSI_NULL;

            return (strcmp(vedor_id, "svm         ") == 0);
        }

        uint16_t get_segment_access_rights(uint16_t segment_selector, ULONG_PTR gdt_base)
        {
            psegment_descriptor_t descriptor;
            segment_attributes_t attribute;

            // get a corresponding segment desciptor to segment selector
            descriptor = reinterpret_cast<psegment_descriptor_t>(
                gdt_base + (segment_selector & ~RPL_MASK));

            // get all attribute fields in the segment descriptor
            attribute.fields.type = descriptor->fields.type;
            attribute.fields.system = descriptor->fields.system;
            attribute.fields.dpl = descriptor->fields.dpl;
            attribute.fields.present = descriptor->fields.present;
            attribute.fields.avl = descriptor->fields.avl;
            attribute.fields.long_mode = descriptor->fields.long_mode;
            attribute.fields.default_bit = descriptor->fields.default_bit;
            attribute.fields.granularity = descriptor->fields.granularity;
            attribute.fields.reserved1 = 0;

            return attribute.value;
        }

        // https://wiki.osdev.org/Exceptions
        void general_protection_exeption(pvcpu_t vprocessor_data)
        {
            event_inj_t event;

            event.value = 0;
            event.fields.vector = 13;
            event.fields.type = 3;
            event.fields.error_code_valid = 1;
            event.fields.valid = 1;
            vprocessor_data->guest_vmcb.control_area.event_inj = event.value;
        }

        void invalid_opcode_exception(pvcpu_t vprocessor_data)
        {
            event_inj_t event;

            event.value = 0;
            event.fields.vector = 6;
            event.fields.type = 3;
            event.fields.error_code_valid = 1;
            event.fields.valid = 1;
            vprocessor_data->guest_vmcb.control_area.event_inj = event.value;
        }
    }
}