
.code

PUBLIC Hypercall 

Hypercall proc
    mov rax, rcx    
    mov rcx, rdx   
    mov rdx, r8    
    mov r8, r9      

    vmcall
    
    ret

Hypercall endp

END