
.const

KTRAP_FRAME_SIZE            equ     190h
MACHINE_FRAME_SIZE          equ     28h

.code

extern handle_vmexit : proc

PUSHAQ macro
        push    rax
        push    rcx
        push    rdx
        push    rbx
        push    -1      
        push    rbp
        push    rsi
        push    rdi
        push    r8
        push    r9
        push    r10
        push    r11
        push    r12
        push    r13
        push    r14
        push    r15
        endm

POPAQ macro
        pop     r15
        pop     r14
        pop     r13
        pop     r12
        pop     r11
        pop     r10
        pop     r9
        pop     r8
        pop     rdi
        pop     rsi
        pop     rbp
        pop     rbx  
        pop     rbx
        pop     rdx
        pop     rcx
        pop     rax
        endm

; __stdcall uses RCX, RDX, R8, R9 in this order
vmenter proc frame
        ; update the current stack pointer with the host RSP. this protects
        ; values stored on stack for the hypervisor from being overwritten by
        ; the guest due to a use of the same stack memory.
        mov rsp, rcx    

svm_loop: 
        ; run the loop to executed the guest and handle vmexit. 
        ; below is the current stack layout.

        ; rsp          -> 0x...fd0 guest_vmcb_pa       
        ;                 0x...fd8 host_vmcb_pa    
        ;                 0x...fe0 self           
        ;                 0x...fe8 shared_vcpu_data     
        ;                 0x...ff0 padding1       
        ;                 0x...ff8 reserved1       

        ; load previously saved guest state passed as a parameter from VMCB
        mov rax, [rsp]  ; physical address of the guest vmcb
        vmload rax      

        ; execute guest utill vmexit gets called
        vmrun rax       ; switch to guest

        ; when vmexit does occur, save guest state to the vmcb
        ; make sure this is saved because host code will destroy it
        vmsave rax      

        ; optionally, allocate the trap frame so that windbg can display a stack trace of the guest 
        .pushframe
        sub     rsp, KTRAP_FRAME_SIZE
        .allocstack KTRAP_FRAME_SIZE - MACHINE_FRAME_SIZE + 100h

        ; push all guest's GPRs since those are not saved anywhere by the
        ; processor on vmexit and will thereby otherwise be lost
        PUSHAQ          ; stack pointer decreased 8 * 16

        ; prepare parameters for handle_vmexit. 
        mov rdx, rsp                                ; rdx <= guest registers
        mov rcx, [rsp + 8 * 18 + KTRAP_FRAME_SIZE]  ; rcx <= virtual processor data

        ; allocate stack for homing space (0x20) 
        ; and volatile XMM registers(0x60)
        sub rsp, 80h

        ; save those registers because host code may destroy
        ; any of those registers. 
        ; XMM6-15 are not saved because those should be
        ; preserved (those are non volatile registers). 
        movaps xmmword ptr [rsp + 20h], xmm0
        movaps xmmword ptr [rsp + 30h], xmm1
        movaps xmmword ptr [rsp + 40h], xmm2
        movaps xmmword ptr [rsp + 50h], xmm3
        movaps xmmword ptr [rsp + 60h], xmm4
        movaps xmmword ptr [rsp + 70h], xmm5
        .endprolog

        ; call our vmexit handler with the args we prepared
        call handle_vmexit

        ; restore all xmm registers we saved
        movaps xmm5, xmmword ptr [rsp + 70h]
        movaps xmm4, xmmword ptr [rsp + 60h]
        movaps xmm3, xmmword ptr [rsp + 50h]
        movaps xmm2, xmmword ptr [rsp + 40h]
        movaps xmm1, xmmword ptr [rsp + 30h]
        movaps xmm0, xmmword ptr [rsp + 20h]
        add rsp, 80h

       
        ; check if handle_vmexit was successfull
        test al, al
        ; restore all gpr's we saved
        POPAQ

        ; If guest_ctx.ExitVm is true, this function exits the loop
        ; otherwise we continue the loop and resume the guest
        jnz vmexit                  ; if (ExitVm) jmp SvLV20
                                    ; else { restore rsp and go back into loop }
        add rsp, KTRAP_FRAME_SIZE   
        jmp svm_loop                

vmexit: 
        ; an exit has been requested
        ; restore the original stack ptr and return to the next instruction of cpuid
        ;   RBX     : address to return
        ;   RCX     : original stack pointer to restore
        ;   EDX:EAX : address of per processor data for this processor
        mov rsp, rcx

        ; update RCX with the magic value 
        mov ecx, 'svm'

        ; return to the next instruction of CPUID 
        jmp rbx
vmenter endp

end