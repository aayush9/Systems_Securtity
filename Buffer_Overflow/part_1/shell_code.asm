section .text
    global _start

_start:
    jmp end
    begin:
        mov al,0x1
        mov dl,0x1
        pop rsi
        mov dl,0xe
        syscall
        mov al,0x3c
        xor rdi,rdi
        syscall
end:
    call begin
	db  "Hello World!   "
