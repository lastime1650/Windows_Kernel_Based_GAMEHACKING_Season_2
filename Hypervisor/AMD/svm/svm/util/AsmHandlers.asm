.CODE
PUBLIC AsmSyscallHookHandler

AsmSyscallHookHandler PROC
    push rax

    mov eax, 1655h
    
    cpuid

    pop rax
    
    ret

AsmSyscallHookHandler ENDP

END