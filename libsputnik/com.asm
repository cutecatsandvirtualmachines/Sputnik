_text segment
hypercall proc
	push rbx
	mov rax, r9
	mov rbx, 0babab00eh
	xor r9, rbx
	cpuid
	pop rbx
	ret
hypercall endp
_text ends
end