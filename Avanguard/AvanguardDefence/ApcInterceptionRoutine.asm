EXTERN ApcHandler: PROC
EXTERN OrgnlKiUserApcDispatcher: PROC

PUBLIC KiUserApcHandler

.CODE
    KiUserApcHandler PROC
        push rax
        push rcx
        mov rcx, rsp
        add rcx, 16
        call ApcHandler
        test rax, rax
        pop rcx
        pop rax
        jz Exit
        mov rax, OrgnlKiUserApcDispatcher
        mov rax, [rax]
        jmp rax
Exit:
        ret
    KiUserApcHandler ENDP

END