#ifndef REAL_USERPROCESS_H
#define REAL_USERPROCESS_H

#include <ntifs.h>
#include <intrin.h>

/*
	By EPROCESS
*/
#define CR3_64BIT_ADDRESS_OFFSET 0x28
#define SECTION_BASE_ADDRESS_OFFSET 0x520

typedef struct UserProcessInfo {
	HANDLE ProcessId;          // Process ID

	UINT64 CR3;         // CR3 value (Page Directory Base)
	PUCHAR ProcessBaseAddress; // Base address of the section (Virtual) 
}UserProcessInfo, *PUserProcessInfo;



UINT64 Get_CR3_by_BruteForce(PEPROCESS process);// search CR3 in Brute-Force
PUCHAR Get_BaseAddress(PEPROCESS process);




// 가상 주소를 인덱스로 분해하기 위한 구조체
typedef union _VIRTUAL_ADDRESS {
    PVOID   Address;
    UINT64  Value;
    struct _VIRTUAL_ADDRESS_BITS {
        UINT64 Offset : 12;
        UINT64 PtIndex : 9;
        UINT64 PdIndex : 9;
        UINT64 PdptIndex : 9;
        UINT64 Pml4Index : 9;
        UINT64 Reserved : 16;
    }BITS;
} VIRTUAL_ADDRESS, * PVIRTUAL_ADDRESS;

// 64Bit PTE struct
typedef struct _MMPTE_HARDWARE {
    union {
        ULONG64 Long;
        struct {
            ULONG64 Valid : 1;               // 0: 페이지 유효 여부
            ULONG64 Dirty1 : 1;              // 1: 더티 비트 (첫 번째)
            ULONG64 Owner : 1;               // 2: 소유자 (커널/유저)
            ULONG64 WriteThrough : 1;        // 3: 쓰기 스루
            ULONG64 CacheDisable : 1;        // 4: 캐시 비활성화
            ULONG64 Accessed : 1;            // 5: 액세스 여부
            ULONG64 Dirty : 1;               // 6: 페이지 수정 여부
            ULONG64 LargePage : 1;            // 7: 대형 페이지 여부
            ULONG64 Global : 1;              // 8: 글로벌 페이지
            ULONG64 CopyOnWrite : 1;         // 9: 쓰기 시 복사
            ULONG64 Unused : 1;              // 10: 사용 안 함
            ULONG64 Write : 1;               // 11: 쓰기 가능
            ULONG64 PageFrameNumber : 40;    // 12-51: 물리 페이지 프레임 번호
            ULONG64 ReservedForSoftware : 4; // 52-55: 소프트웨어용 예약
            ULONG64 WsleAge : 4;             // 56-59: 작업 집합 리스트 나이
            ULONG64 WsleProtection : 3;      // 60-62: 작업 집합 보호 속성
            ULONG64 NoExecute : 1;           // 63: 실행 방지
        } Bits;
    } u;
} MMPTE_HARDWARE, * PMMPTE_HARDWARE;
typedef MMPTE_HARDWARE PTE;
typedef PMMPTE_HARDWARE PPTE;

/*
*  CR3가 변조된 경우를 대비하기 위한 함수 유틸리티
* 
* 
    찾은 PML4 주소값을 통해서 자체적인 메모리 처리 API를 선언
    * 가상주소 -> 물리주소 알아내고 가져와야함
*/
NTSTATUS Own__MemoryCopyUser(UINT64 PML4_Address, PUCHAR Target_UserVirtual, PUCHAR SourceData, SIZE_T data_size); // 유저모드에 쓰기
NTSTATUS Own__MemoryReadUser(UINT64 PML4_Address, PUCHAR Target_UserVirtual, SIZE_T read_size); // 유저모드로부터 읽기 ( 커널로 카피 )
NTSTATUS Own__MemoryPageReadUser(UINT64 PML4_Address, _Inout_ PUCHAR* Target_UserVirtual, SIZE_T read_size, PUCHAR* ReadData); // 유저모드 메모리 페이지 정보 추출

/*
	==== EPROCESS and KPROCESS and PTE struct 
*/
/*
1: kd> dt nt!_EPROCESS
   +0x000 Pcb              : _KPROCESS
   +0x438 ProcessLock      : _EX_PUSH_LOCK
   +0x440 UniqueProcessId  : Ptr64 Void
   +0x448 ActiveProcessLinks : _LIST_ENTRY
   +0x458 RundownProtect   : _EX_RUNDOWN_REF
   +0x460 Flags2           : Uint4B
   +0x460 JobNotReallyActive : Pos 0, 1 Bit
   +0x460 AccountingFolded : Pos 1, 1 Bit
   +0x460 NewProcessReported : Pos 2, 1 Bit
   +0x460 ExitProcessReported : Pos 3, 1 Bit
   +0x460 ReportCommitChanges : Pos 4, 1 Bit
   +0x460 LastReportMemory : Pos 5, 1 Bit
   +0x460 ForceWakeCharge  : Pos 6, 1 Bit
   +0x460 CrossSessionCreate : Pos 7, 1 Bit
   +0x460 NeedsHandleRundown : Pos 8, 1 Bit
   +0x460 RefTraceEnabled  : Pos 9, 1 Bit
   +0x460 PicoCreated      : Pos 10, 1 Bit
   +0x460 EmptyJobEvaluated : Pos 11, 1 Bit
   +0x460 DefaultPagePriority : Pos 12, 3 Bits
   +0x460 PrimaryTokenFrozen : Pos 15, 1 Bit
   +0x460 ProcessVerifierTarget : Pos 16, 1 Bit
   +0x460 RestrictSetThreadContext : Pos 17, 1 Bit
   +0x460 AffinityPermanent : Pos 18, 1 Bit
   +0x460 AffinityUpdateEnable : Pos 19, 1 Bit
   +0x460 PropagateNode    : Pos 20, 1 Bit
   +0x460 ExplicitAffinity : Pos 21, 1 Bit
   +0x460 ProcessExecutionState : Pos 22, 2 Bits
   +0x460 EnableReadVmLogging : Pos 24, 1 Bit
   +0x460 EnableWriteVmLogging : Pos 25, 1 Bit
   +0x460 FatalAccessTerminationRequested : Pos 26, 1 Bit
   +0x460 DisableSystemAllowedCpuSet : Pos 27, 1 Bit
   +0x460 ProcessStateChangeRequest : Pos 28, 2 Bits
   +0x460 ProcessStateChangeInProgress : Pos 30, 1 Bit
   +0x460 InPrivate        : Pos 31, 1 Bit
   +0x464 Flags            : Uint4B
   +0x464 CreateReported   : Pos 0, 1 Bit
   +0x464 NoDebugInherit   : Pos 1, 1 Bit
   +0x464 ProcessExiting   : Pos 2, 1 Bit
   +0x464 ProcessDelete    : Pos 3, 1 Bit
   +0x464 ManageExecutableMemoryWrites : Pos 4, 1 Bit
   +0x464 VmDeleted        : Pos 5, 1 Bit
   +0x464 OutswapEnabled   : Pos 6, 1 Bit
   +0x464 Outswapped       : Pos 7, 1 Bit
   +0x464 FailFastOnCommitFail : Pos 8, 1 Bit
   +0x464 Wow64VaSpace4Gb  : Pos 9, 1 Bit
   +0x464 AddressSpaceInitialized : Pos 10, 2 Bits
   +0x464 SetTimerResolution : Pos 12, 1 Bit
   +0x464 BreakOnTermination : Pos 13, 1 Bit
   +0x464 DeprioritizeViews : Pos 14, 1 Bit
   +0x464 WriteWatch       : Pos 15, 1 Bit
   +0x464 ProcessInSession : Pos 16, 1 Bit
   +0x464 OverrideAddressSpace : Pos 17, 1 Bit
   +0x464 HasAddressSpace  : Pos 18, 1 Bit
   +0x464 LaunchPrefetched : Pos 19, 1 Bit
   +0x464 Reserved         : Pos 20, 1 Bit
   +0x464 VmTopDown        : Pos 21, 1 Bit
   +0x464 ImageNotifyDone  : Pos 22, 1 Bit
   +0x464 PdeUpdateNeeded  : Pos 23, 1 Bit
   +0x464 VdmAllowed       : Pos 24, 1 Bit
   +0x464 ProcessRundown   : Pos 25, 1 Bit
   +0x464 ProcessInserted  : Pos 26, 1 Bit
   +0x464 DefaultIoPriority : Pos 27, 3 Bits
   +0x464 ProcessSelfDelete : Pos 30, 1 Bit
   +0x464 SetTimerResolutionLink : Pos 31, 1 Bit
   +0x468 CreateTime       : _LARGE_INTEGER
   +0x470 ProcessQuotaUsage : [2] Uint8B
   +0x480 ProcessQuotaPeak : [2] Uint8B
   +0x490 PeakVirtualSize  : Uint8B
   +0x498 VirtualSize      : Uint8B
   +0x4a0 SessionProcessLinks : _LIST_ENTRY
   +0x4b0 ExceptionPortData : Ptr64 Void
   +0x4b0 ExceptionPortValue : Uint8B
   +0x4b0 ExceptionPortState : Pos 0, 3 Bits
   +0x4b8 Token            : _EX_FAST_REF
   +0x4c0 MmReserved       : Uint8B
   +0x4c8 AddressCreationLock : _EX_PUSH_LOCK
   +0x4d0 PageTableCommitmentLock : _EX_PUSH_LOCK
   +0x4d8 RotateInProgress : Ptr64 _ETHREAD
   +0x4e0 ForkInProgress   : Ptr64 _ETHREAD
   +0x4e8 CommitChargeJob  : Ptr64 _EJOB
   +0x4f0 CloneRoot        : _RTL_AVL_TREE
   +0x4f8 NumberOfPrivatePages : Uint8B
   +0x500 NumberOfLockedPages : Uint8B
   +0x508 Win32Process     : Ptr64 Void
   +0x510 Job              : Ptr64 _EJOB
   +0x518 SectionObject    : Ptr64 Void
   +0x520 SectionBaseAddress : Ptr64 Void
   +0x528 Cookie           : Uint4B
   +0x530 WorkingSetWatch  : Ptr64 _PAGEFAULT_HISTORY
   +0x538 Win32WindowStation : Ptr64 Void
   +0x540 InheritedFromUniqueProcessId : Ptr64 Void
   +0x548 OwnerProcessId   : Uint8B
   +0x550 Peb              : Ptr64 _PEB
   +0x558 Session          : Ptr64 _MM_SESSION_SPACE
   +0x560 Spare1           : Ptr64 Void
   +0x568 QuotaBlock       : Ptr64 _EPROCESS_QUOTA_BLOCK
   +0x570 ObjectTable      : Ptr64 _HANDLE_TABLE
   +0x578 DebugPort        : Ptr64 Void
   +0x580 WoW64Process     : Ptr64 _EWOW64PROCESS
   +0x588 DeviceMap        : _EX_FAST_REF
   +0x590 EtwDataSource    : Ptr64 Void
   +0x598 PageDirectoryPte : Uint8B
   +0x5a0 ImageFilePointer : Ptr64 _FILE_OBJECT
   +0x5a8 ImageFileName    : [15] UChar
   +0x5b7 PriorityClass    : UChar
   +0x5b8 SecurityPort     : Ptr64 Void
   +0x5c0 SeAuditProcessCreationInfo : _SE_AUDIT_PROCESS_CREATION_INFO
   +0x5c8 JobLinks         : _LIST_ENTRY
   +0x5d8 HighestUserAddress : Ptr64 Void
   +0x5e0 ThreadListHead   : _LIST_ENTRY
   +0x5f0 ActiveThreads    : Uint4B
   +0x5f4 ImagePathHash    : Uint4B
   +0x5f8 DefaultHardErrorProcessing : Uint4B
   +0x5fc LastThreadExitStatus : Int4B
   +0x600 PrefetchTrace    : _EX_FAST_REF
   +0x608 LockedPagesList  : Ptr64 Void
   +0x610 ReadOperationCount : _LARGE_INTEGER
   +0x618 WriteOperationCount : _LARGE_INTEGER
   +0x620 OtherOperationCount : _LARGE_INTEGER
   +0x628 ReadTransferCount : _LARGE_INTEGER
   +0x630 WriteTransferCount : _LARGE_INTEGER
   +0x638 OtherTransferCount : _LARGE_INTEGER
   +0x640 CommitChargeLimit : Uint8B
   +0x648 CommitCharge     : Uint8B
   +0x650 CommitChargePeak : Uint8B
   +0x680 Vm               : _MMSUPPORT_FULL
   +0x7c0 MmProcessLinks   : _LIST_ENTRY
   +0x7d0 ModifiedPageCount : Uint4B
   +0x7d4 ExitStatus       : Int4B
   +0x7d8 VadRoot          : _RTL_AVL_TREE
   +0x7e0 VadHint          : Ptr64 Void
   +0x7e8 VadCount         : Uint8B
   +0x7f0 VadPhysicalPages : Uint8B
   +0x7f8 VadPhysicalPagesLimit : Uint8B
   +0x800 AlpcContext      : _ALPC_PROCESS_CONTEXT
   +0x820 TimerResolutionLink : _LIST_ENTRY
   +0x830 TimerResolutionStackRecord : Ptr64 _PO_DIAG_STACK_RECORD
   +0x838 RequestedTimerResolution : Uint4B
   +0x83c SmallestTimerResolution : Uint4B
   +0x840 ExitTime         : _LARGE_INTEGER
   +0x848 InvertedFunctionTable : Ptr64 _INVERTED_FUNCTION_TABLE_KERNEL_MODE
   +0x850 InvertedFunctionTableLock : _EX_PUSH_LOCK
   +0x858 ActiveThreadsHighWatermark : Uint4B
   +0x85c LargePrivateVadCount : Uint4B
   +0x860 ThreadListLock   : _EX_PUSH_LOCK
   +0x868 WnfContext       : Ptr64 Void
   +0x870 ServerSilo       : Ptr64 _EJOB
   +0x878 SignatureLevel   : UChar
   +0x879 SectionSignatureLevel : UChar
   +0x87a Protection       : _PS_PROTECTION
   +0x87b HangCount        : Pos 0, 3 Bits
   +0x87b GhostCount       : Pos 3, 3 Bits
   +0x87b PrefilterException : Pos 6, 1 Bit
   +0x87c Flags3           : Uint4B
   +0x87c Minimal          : Pos 0, 1 Bit
   +0x87c ReplacingPageRoot : Pos 1, 1 Bit
   +0x87c Crashed          : Pos 2, 1 Bit
   +0x87c JobVadsAreTracked : Pos 3, 1 Bit
   +0x87c VadTrackingDisabled : Pos 4, 1 Bit
   +0x87c AuxiliaryProcess : Pos 5, 1 Bit
   +0x87c SubsystemProcess : Pos 6, 1 Bit
   +0x87c IndirectCpuSets  : Pos 7, 1 Bit
   +0x87c RelinquishedCommit : Pos 8, 1 Bit
   +0x87c HighGraphicsPriority : Pos 9, 1 Bit
   +0x87c CommitFailLogged : Pos 10, 1 Bit
   +0x87c ReserveFailLogged : Pos 11, 1 Bit
   +0x87c SystemProcess    : Pos 12, 1 Bit
   +0x87c HideImageBaseAddresses : Pos 13, 1 Bit
   +0x87c AddressPolicyFrozen : Pos 14, 1 Bit
   +0x87c ProcessFirstResume : Pos 15, 1 Bit
   +0x87c ForegroundExternal : Pos 16, 1 Bit
   +0x87c ForegroundSystem : Pos 17, 1 Bit
   +0x87c HighMemoryPriority : Pos 18, 1 Bit
   +0x87c EnableProcessSuspendResumeLogging : Pos 19, 1 Bit
   +0x87c EnableThreadSuspendResumeLogging : Pos 20, 1 Bit
   +0x87c SecurityDomainChanged : Pos 21, 1 Bit
   +0x87c SecurityFreezeComplete : Pos 22, 1 Bit
   +0x87c VmProcessorHost  : Pos 23, 1 Bit
   +0x87c VmProcessorHostTransition : Pos 24, 1 Bit
   +0x87c AltSyscall       : Pos 25, 1 Bit
   +0x87c TimerResolutionIgnore : Pos 26, 1 Bit
   +0x87c DisallowUserTerminate : Pos 27, 1 Bit
   +0x87c EnableProcessRemoteExecProtectVmLogging : Pos 28, 1 Bit
   +0x87c EnableProcessLocalExecProtectVmLogging : Pos 29, 1 Bit
   +0x87c MemoryCompressionProcess : Pos 30, 1 Bit
   +0x880 DeviceAsid       : Int4B
   +0x888 SvmData          : Ptr64 Void
   +0x890 SvmProcessLock   : _EX_PUSH_LOCK
   +0x898 SvmLock          : Uint8B
   +0x8a0 SvmProcessDeviceListHead : _LIST_ENTRY
   +0x8b0 LastFreezeInterruptTime : Uint8B
   +0x8b8 DiskCounters     : Ptr64 _PROCESS_DISK_COUNTERS
   +0x8c0 PicoContext      : Ptr64 Void
   +0x8c8 EnclaveTable     : Ptr64 Void
   +0x8d0 EnclaveNumber    : Uint8B
   +0x8d8 EnclaveLock      : _EX_PUSH_LOCK
   +0x8e0 HighPriorityFaultsAllowed : Uint4B
   +0x8e8 EnergyContext    : Ptr64 _PO_PROCESS_ENERGY_CONTEXT
   +0x8f0 VmContext        : Ptr64 Void
   +0x8f8 SequenceNumber   : Uint8B
   +0x900 CreateInterruptTime : Uint8B
   +0x908 CreateUnbiasedInterruptTime : Uint8B
   +0x910 TotalUnbiasedFrozenTime : Uint8B
   +0x918 LastAppStateUpdateTime : Uint8B
   +0x920 LastAppStateUptime : Pos 0, 61 Bits
   +0x920 LastAppState     : Pos 61, 3 Bits
   +0x928 SharedCommitCharge : Uint8B
   +0x930 SharedCommitLock : _EX_PUSH_LOCK
   +0x938 SharedCommitLinks : _LIST_ENTRY
   +0x948 AllowedCpuSets   : Uint8B
   +0x950 DefaultCpuSets   : Uint8B
   +0x948 AllowedCpuSetsIndirect : Ptr64 Uint8B
   +0x950 DefaultCpuSetsIndirect : Ptr64 Uint8B
   +0x958 DiskIoAttribution : Ptr64 Void
   +0x960 DxgProcess       : Ptr64 Void
   +0x968 Win32KFilterSet  : Uint4B
   +0x96c Machine          : Uint2B
   +0x96e Spare0           : Uint2B
   +0x970 ProcessTimerDelay : _PS_INTERLOCKED_TIMER_DELAY_VALUES
   +0x978 KTimerSets       : Uint4B
   +0x97c KTimer2Sets      : Uint4B
   +0x980 ThreadTimerSets  : Uint4B
   +0x988 VirtualTimerListLock : Uint8B
   +0x990 VirtualTimerListHead : _LIST_ENTRY
   +0x9a0 WakeChannel      : _WNF_STATE_NAME
   +0x9a0 WakeInfo         : _PS_PROCESS_WAKE_INFORMATION
   +0x9d0 MitigationFlags  : Uint4B
   +0x9d0 MitigationFlagsValues : <unnamed-tag>
   +0x9d4 MitigationFlags2 : Uint4B
   +0x9d4 MitigationFlags2Values : <unnamed-tag>
   +0x9d8 PartitionObject  : Ptr64 Void
   +0x9e0 SecurityDomain   : Uint8B
   +0x9e8 ParentSecurityDomain : Uint8B
   +0x9f0 CoverageSamplerContext : Ptr64 Void
   +0x9f8 MmHotPatchContext : Ptr64 Void
   +0xa00 IdealProcessorAssignmentBlock : _KE_IDEAL_PROCESSOR_ASSIGNMENT_BLOCK
   +0xb18 DynamicEHContinuationTargetsTree : _RTL_AVL_TREE
   +0xb20 DynamicEHContinuationTargetsLock : _EX_PUSH_LOCK
   +0xb28 DynamicEnforcedCetCompatibleRanges : _PS_DYNAMIC_ENFORCED_ADDRESS_RANGES
   +0xb38 DisabledComponentFlags : Uint4B
   +0xb3c PageCombineSequence : Int4B
   +0xb40 EnableOptionalXStateFeaturesLock : _EX_PUSH_LOCK
   +0xb48 PathRedirectionHashes : Ptr64 Uint4B
   +0xb50 SyscallProvider  : Ptr64 _PS_SYSCALL_PROVIDER
   +0xb58 SyscallProviderProcessLinks : _LIST_ENTRY
   +0xb68 SyscallProviderDispatchContext : _PSP_SYSCALL_PROVIDER_DISPATCH_CONTEXT
   +0xb70 MitigationFlags3 : Uint4B
   +0xb70 MitigationFlags3Values : <unnamed-tag>



















1: kd> dt nt!_KPROCESS
   +0x000 Header           : _DISPATCHER_HEADER
   +0x018 ProfileListHead  : _LIST_ENTRY
   +0x028 DirectoryTableBase : Uint8B
   +0x030 ThreadListHead   : _LIST_ENTRY
   +0x040 ProcessLock      : Uint4B
   +0x044 ProcessTimerDelay : Uint4B
   +0x048 DeepFreezeStartTime : Uint8B
   +0x050 Affinity         : _KAFFINITY_EX
   +0x158 ReadyListHead    : _LIST_ENTRY
   +0x168 SwapListEntry    : _SINGLE_LIST_ENTRY
   +0x170 ActiveProcessors : _KAFFINITY_EX
   +0x278 AutoAlignment    : Pos 0, 1 Bit
   +0x278 DisableBoost     : Pos 1, 1 Bit
   +0x278 DisableQuantum   : Pos 2, 1 Bit
   +0x278 DeepFreeze       : Pos 3, 1 Bit
   +0x278 TimerVirtualization : Pos 4, 1 Bit
   +0x278 CheckStackExtents : Pos 5, 1 Bit
   +0x278 CacheIsolationEnabled : Pos 6, 1 Bit
   +0x278 PpmPolicy        : Pos 7, 4 Bits
   +0x278 VaSpaceDeleted   : Pos 11, 1 Bit
   +0x278 MultiGroup       : Pos 12, 1 Bit
   +0x278 ReservedFlags    : Pos 13, 19 Bits
   +0x278 ProcessFlags     : Int4B
   +0x27c ActiveGroupsMask : Uint4B
   +0x280 BasePriority     : Char
   +0x281 QuantumReset     : Char
   +0x282 Visited          : Char
   +0x283 Flags            : _KEXECUTE_OPTIONS
   +0x284 ThreadSeed       : [32] Uint2B
   +0x2c4 IdealProcessor   : [32] Uint2B
   +0x304 IdealNode        : [32] Uint2B
   +0x344 IdealGlobalNode  : Uint2B
   +0x346 Spare1           : Uint2B
   +0x348 StackCount       : _KSTACK_COUNT
   +0x350 ProcessListEntry : _LIST_ENTRY
   +0x360 CycleTime        : Uint8B
   +0x368 ContextSwitches  : Uint8B
   +0x370 SchedulingGroup  : Ptr64 _KSCHEDULING_GROUP
   +0x378 FreezeCount      : Uint4B
   +0x37c KernelTime       : Uint4B
   +0x380 UserTime         : Uint4B
   +0x384 ReadyTime        : Uint4B
   +0x388 UserDirectoryTableBase : Uint8B
   +0x390 AddressPolicy    : UChar
   +0x391 Spare2           : [71] UChar
   +0x3d8 InstrumentationCallback : Ptr64 Void
   +0x3e0 SecureState      : <unnamed-tag>
   +0x3e8 KernelWaitTime   : Uint8B
   +0x3f0 UserWaitTime     : Uint8B
   +0x3f8 LastRebalanceQpc : Uint8B
   +0x400 PerProcessorCycleTimes : Ptr64 Void
   +0x408 ExtendedFeatureDisableMask : Uint8B
   +0x410 PrimaryGroup     : Uint2B
   +0x412 Spare3           : [3] Uint2B
   +0x418 UserCetLogging   : Ptr64 Void
   +0x420 CpuPartitionList : _LIST_ENTRY
   +0x430 EndPadding       : [1] Uint8B








   1: kd> dt nt!_MMPTE_HARDWARE
   +0x000 Valid            : Pos 0, 1 Bit
   +0x000 Dirty1           : Pos 1, 1 Bit
   +0x000 Owner            : Pos 2, 1 Bit
   +0x000 WriteThrough     : Pos 3, 1 Bit
   +0x000 CacheDisable     : Pos 4, 1 Bit
   +0x000 Accessed         : Pos 5, 1 Bit
   +0x000 Dirty            : Pos 6, 1 Bit
   +0x000 LargePage        : Pos 7, 1 Bit
   +0x000 Global           : Pos 8, 1 Bit
   +0x000 CopyOnWrite      : Pos 9, 1 Bit
   +0x000 Unused           : Pos 10, 1 Bit
   +0x000 Write            : Pos 11, 1 Bit
   +0x000 PageFrameNumber  : Pos 12, 40 Bits
   +0x000 ReservedForSoftware : Pos 52, 4 Bits
   +0x000 WsleAge          : Pos 56, 4 Bits
   +0x000 WsleProtection   : Pos 60, 3 Bits
   +0x000 NoExecute        : Pos 63, 1 Bit
*/
#endif