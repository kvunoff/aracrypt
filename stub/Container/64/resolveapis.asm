; Resolve all required APIs from kernel32.dll via PEB walking and djb2 hashing.
; No plain-text API names in the binary.

macro createStringLoading64 location {
    mov [location+0],'L'
    mov [location+1],'o'
    mov [location+2],'a'
    mov [location+3],'d'
    mov [location+4],'i'
    mov [location+5],'n'
    mov [location+6],'g'
    mov [location+7],' '
    mov [location+8],'A'
    mov [location+9],'P'
    mov [location+10],'I'
    mov [location+11],'s'
    mov [location+12],':'
    mov [location+13],0
}

macro createStringKernel3264 location {
    mov [location+00],'k'
    mov [location+01],'e'
    mov [location+02],'r'
    mov [location+03],'n'
    mov [location+04],'e'
    mov [location+05],'l'
    mov [location+06],'3'
    mov [location+07],'2'
    mov [location+08],'.'
    mov [location+09],'d'
    mov [location+10],'l'
    mov [location+11],'l'
    mov [location+12],0
}

; Returns 1 in rax on success, 0 on failure.
proc resolveAllAPIs
    local kernel_base:QWORD, str1[256]:BYTE

    ; Get kernel32.dll base via PEB walking
    writeWithNewLine createStringLoading64, str1, ra_exit_error

    mov rax, [gs:0x60]        ; PEB
    mov rax, [rax + 0x18]     ; PEB->Ldr
    mov rax, [rax + 0x10]     ; InLoadOrderModuleList.Flink (first module)
    mov rax, [rax]            ; -> ntdll.dll (second module)
    mov rax, [rax + 0x30]     ; third module = kernel32.dll DllBase
    mov [kernel_base], rax

    writeWithNewLine createStringKernel3264, str1, ra_exit_error
    writeRegisterToLog rax, ra_exit_error

    ; Resolve each API by hash
    sub r12, r12
ra_next:
    cmp r12, API_COUNT
    jae ra_exit_success

    ; Get target hash from api_hashes array
    lea rbx, [api_hashes]
    mov edx, [rbx + r12 * 4]

    fastcall resolveByHash, [kernel_base], rdx
    test rax, rax
    jz ra_exit_error

    ; Store in api_table
    lea rbx, [api_table]
    mov [rbx + r12 * 8], rax

    inc r12
    jmp ra_next

ra_exit_success:
    mov rax, 1
    jmp ra_exit_ret

ra_exit_error:
    sub rax, rax

ra_exit_ret:
    ret
endp

; Resolve a function by its djb2 hash from a given module base.
; rcx = module base
; rdx = target djb2 hash
; Returns: function address in rax (0 if not found)
proc resolveByHash uses rbx rsi rdi r12, module_base:QWORD, target_hash:QWORD
    local str1[256]:BYTE

    mov [module_base], rcx
    mov [target_hash], rdx

    ; Get PE signature
    mov rax, [module_base]
    mov eax, [rax + 0x3c]          ; e_lfanew
    add rax, [module_base]          ; PE signature

    ; DataDirectory[0] (Export) is at PE_sig + 0x88 for PE64
    mov ebx, [rax + 0x88]          ; Export.VirtualAddress (RVA)
    test ebx, ebx
    jz rbh_exit_error
    add rbx, [module_base]          ; Export directory VA

    ; IMAGE_EXPORT_DIRECTORY
    mov ecx, [rbx + 24]            ; NumberOfNames
    mov esi, [rbx + 32]            ; AddressOfNames (RVA)
    add rsi, [module_base]         ; -> names array

    mov r8d, [rbx + 36]            ; AddressOfNameOrdinals (RVA)
    add r8, [module_base]          ; -> ordinals array

    mov r9d, [rbx + 28]            ; AddressOfFunctions (RVA)
    add r9, [module_base]          ; -> functions array

    sub rdi, rdi                   ; index
rbh_loop:
    cmp edi, ecx
    jae rbh_exit_error

    ; Get pointer to function name from AddressOfNames[index]
    mov eax, [rsi + rdi * 4]
    add rax, [module_base]

    ; Compute djb2 hash of this name
    fastcall djb2hash, rax

    cmp eax, dword [target_hash]
    je rbh_found

    inc edi
    jmp rbh_loop

rbh_found:
    ; Get ordinal from AddressOfNameOrdinals[index]
    movzx eax, word [r8 + rdi * 2]
    ; Get function RVA from AddressOfFunctions[ordinal]
    mov eax, [r9 + rax * 4]
    add rax, [module_base]
    jmp rbh_exit_ret

rbh_exit_error:
    sub rax, rax

rbh_exit_ret:
    ret
endp

; djb2 hash: rax = pointer to null-terminated string
; Returns: hash in eax
proc djb2hash
    push rcx
    mov eax, 5381
    mov rcx, rax                   ; save string pointer (passed in rax)
.loop:
    movzx edx, byte [rcx]
    test dl, dl
    jz .done
    ; hash = hash * 33 + char
    mov ebx, eax
    shl eax, 5
    add eax, ebx
    add eax, edx
    inc ecx
    jmp .loop
.done:
    pop rcx
    ret
endp

;
