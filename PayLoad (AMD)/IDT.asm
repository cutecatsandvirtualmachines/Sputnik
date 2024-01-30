
.code _text

EXTERN seh_handler_vm : proc
EXTERN seh_handler_ecode_vm : proc

; #DE has no error code...
generic_interrupt_handler_vm PROC
__de_handler_vm proc
	push rax
	push rbx
	push rcx
	push rdx
	push rsi
	push rdi
	push rbp
	push r8
	push r9
	push r10
	push r11
	push r12
	push r13
	push r14
	push r15

	mov rcx, rsp
	sub rsp, 20h
	call seh_handler_vm
	add rsp, 20h

	pop r15
	pop r14
	pop r13
	pop r12
	pop r11
	pop r10
	pop r9
	pop r8
	pop rbp 
	pop rdi
	pop rsi
	pop rdx
	pop rcx
	pop rbx
	pop rax

	iretq
__de_handler_vm endp
generic_interrupt_handler_vm ENDP

; PF and GP have error code...
generic_interrupt_handler_ecode_vm PROC
__pf_handler_vm proc
__gp_handler_vm proc
	push rax
	push rbx
	push rcx
	push rdx
	push rsi
	push rdi
	push rbp
	push r8
	push r9
	push r10
	push r11
	push r12
	push r13
	push r14
	push r15

	mov rcx, rsp
	sub rsp, 20h
	call seh_handler_ecode_vm
	add rsp, 20h

	pop r15
	pop r14
	pop r13
	pop r12
	pop r11
	pop r10
	pop r9
	pop r8
	pop rbp 
	pop rdi
	pop rsi
	pop rdx
	pop rcx
	pop rbx
	pop rax
	add rsp, 8	; remove error code on the stack...

	iretq
__gp_handler_vm endp
__pf_handler_vm endp
generic_interrupt_handler_ecode_vm ENDP

__db_handler proc
	push rax
	pushfq
	pop rax

	btr rax, 8
	
	push rax
	popfq
	pop rax
	iretq
__db_handler endp

END