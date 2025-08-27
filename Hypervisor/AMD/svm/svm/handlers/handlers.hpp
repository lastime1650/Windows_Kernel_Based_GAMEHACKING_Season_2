#pragma once
#include "../../common-includes.hpp"
#include "../def/cpu.hpp"
#include "../def/cpu.hpp"
#include "../def/descriptors-info.hpp"
#include "../def/vmexit.hpp"
#include "../def/virtual-memory.hpp"
#include "../def/vprocessor-data.hpp"
#include "../util/util.hpp"

#pragma warning (disable : 4244)
#pragma warning (disable : 4293)
#pragma warning (disable : 26451)

#define next_instruction vcpu->guest_vmcb.state_save_area.rip = vcpu->guest_vmcb.control_area.next_rip

namespace svm
{
	namespace handle
	{

        struct hook_info
        {
            void* target_gva;     // 후킹 대상 함수의 GVA
            uint64_t            target_gpa;     // 후킹 대상 함수의 GPA
            pd_entry_4kb_t* npt_entry;      // 이 GPA를 관리하는 NPT PD 엔트리의 포인터
            uint64_t            original_value; // NPT 엔트리의 원래 값 (권한 복구용)
        };
        extern hook_info g_zw_create_file_hook;

        bool initialize_hooks(pshared_vcpu_t shared_vcpu);
        void enable_hook(hook_info* hook);
        void disable_hook(hook_info* hook);
        void is_hook_matched(pvcpu_t vcpu, pguest_registers_t guest_regs, PVOID API_NAME);





        void cpuid(pvcpu_t vprocessor_data, pguest_ctx_t guest_ctx);

        void msr(pvcpu_t vprocessor_data, pguest_ctx_t guest_ctx);

        void rdtsc(pvcpu_t vcpu, pguest_ctx_t guest_ctx);

        extern "C" bool __stdcall handle_vmexit(pvcpu_t vprocessor_data, pguest_registers_t guest_registers);


        // DR6 - Debug Status Register
        typedef union _DR6
        {
            uint64_t value;
            struct
            {
                uint64_t b0 : 1; // Breakpoint condition detected for DR0
                uint64_t b1 : 1; // Breakpoint condition detected for DR1
                uint64_t b2 : 1; // Breakpoint condition detected for DR2
                uint64_t b3 : 1; // Breakpoint condition detected for DR3
                uint64_t reserved1 : 9;
                uint64_t bd : 1; // Debug register access detected (when DR7.GD=1)
                uint64_t bs : 1; // Single-step (TF flag in RFLAGS)
                uint64_t bt : 1; // Task switch
                uint64_t reserved2 : 48;
            } fields;
        } dr6_t;

        typedef union _DR7
        {
            uint64_t value;
            struct
            {
                /**
                 * @brief Local/Global breakpoint enable flags
                 * L (Local): 해당 브레이크포인트를 현재 코어(로컬)에서만 활성화합니다.
                 * G (Global): 해당 브레이크포인트를 모든 코어(글로벌)에서 활성화합니다.
                 * (참고: Global 플래그는 태스크 스위치 시 초기화되지 않도록 하며, 더 복잡한 제어가 필요합니다.
                 *  일반적으로 커널 디버깅에서는 Local 플래그를 사용합니다.)
                 */
                uint64_t l0 : 1;
                uint64_t g0 : 1;
                uint64_t l1 : 1;
                uint64_t g1 : 1;
                uint64_t l2 : 1;
                uint64_t g2 : 1;
                uint64_t l3 : 1;
                uint64_t g3 : 1;

                uint64_t le : 1; // Local Exact breakpoint enable (성능 관련, 보통 0)
                uint64_t ge : 1; // Global Exact breakpoint enable (성능 관련, 보통 0)

                uint64_t reserved1 : 3;

                uint64_t gd : 1; // General Detect enable. 디버그 레지스터 접근 시 #DB 발생 활성화.

                uint64_t reserved2 : 1;
                uint64_t reserved3 : 1; // AMD APM에서는 RTM 비트로 사용되기도 함

                /**
                 * @brief Read/Write condition flags for each breakpoint
                 * 00: 실행 (Instruction execution only)
                 * 01: 쓰기 (Data writes only)
                 * 10: I/O 읽기/쓰기 (I/O port access, 사용되지 않음)
                 * 11: 읽기 또는 쓰기 (Data reads or writes)
                 */
                uint64_t rw0 : 2;
                /**
                 * @brief Length of the breakpoint field
                 * 00: 1-byte
                 * 01: 2-bytes
                 * 10: 8-bytes (지원되지 않을 수 있음, 보통 4-bytes)
                 * 11: 4-bytes
                 */
                uint64_t len0 : 2;

                uint64_t rw1 : 2;
                uint64_t len1 : 2;

                uint64_t rw2 : 2;
                uint64_t len2 : 2;

                uint64_t rw3 : 2;
                uint64_t len3 : 2;

                uint64_t reserved4 : 32; // 상위 32비트는 예약됨
            } fields;
        } dr7_t;
	}
}