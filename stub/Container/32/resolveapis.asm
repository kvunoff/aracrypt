; Resolve all required APIs from kernel32.dll via PEB walking and djb2 hashing.
; 32-bit version — no plaintext API names in the binary.

; entry: APITable = pointer to function pointer array
; returns: eax=1 on success, 0 on failure
proc resolveAllAPIs32 stdcall APITable:DWORD

local str1[256]:BYTE, kernel_base:DWORD

	pushad

	; Get kernel32.dll base via PEB walking
	writeWithNewLine createStringLoading, str1, ra32_exit_error

	mov eax, [fs:0x30]       ; PEB
	mov eax, [eax + 0x0C]    ; PEB->Ldr
	mov eax, [eax + 0x0C]    ; InLoadOrderModuleList.Flink (first module = exe)
	mov eax, [eax]           ; -> ntdll.dll
	mov eax, [eax + 0x18]    ; third module = kernel32.dll DllBase
	mov [kernel_base], eax

	writeNewLineToLog ra32_exit_error
	writeWithNewLine createStringKernel32, str1, ra32_exit_error

	; Resolve each API by hash
	xor ecx, ecx
ra32_next:
	cmp ecx, API_COUNT
	jae ra32_exit_success

	; Get target hash
	lea ebx, [api_hashes]
	mov edx, [ebx + ecx * 4]

	stdcall resolveByHash32, [kernel_base], edx
	test eax, eax
	jz ra32_exit_error

	; Store in APITable
	mov edx, [APITable]
	mov [edx + ecx * 4], eax

	inc ecx
	jmp ra32_next

ra32_exit_success:
	popad
	mov eax, 1
	jmp ra32_exit_ret

ra32_exit_error:
	popad
	xor eax, eax

ra32_exit_ret:
	ret
endp

; Resolve a function by its djb2 hash from a given module base.
; arg1 = module_base, arg2 = target_hash
; Returns: function address in eax (0 if not found)
proc resolveByHash32 uses ebx esi edi, module_base:DWORD, target_hash:DWORD

local str1[256]:BYTE

	; Get PE signature
	mov eax, [module_base]
	mov eax, [eax + 0x3C]          ; e_lfanew
	add eax, [module_base]          ; PE signature

	; DataDirectory[0] (Export) is at PE_sig + 0x78 for PE32
	mov ebx, [eax + 0x78]          ; Export.VirtualAddress (RVA)
	test ebx, ebx
	jz rbh32_exit_error
	add ebx, [module_base]         ; Export directory VA

	; IMAGE_EXPORT_DIRECTORY offsets:
	mov ecx, [ebx + 24]            ; NumberOfNames
	mov esi, [ebx + 32]            ; AddressOfNames RVA
	add esi, [module_base]

	mov edi, [ebx + 36]            ; AddressOfNameOrdinals RVA
	add edi, [module_base]

	push ebx                       ; save export dir base
	mov ebx, [ebx + 28]            ; AddressOfFunctions RVA
	add ebx, [module_base]

	xor eax, eax                   ; index
rbh32_loop:
	cmp eax, ecx
	jae rbh32_exit_error_pop

	; Get pointer to function name
	mov edx, [esi + eax * 4]
	add edx, [module_base]

	; Compute djb2 hash
	call djb2hash32
	cmp eax, [target_hash]
	je rbh32_found

	inc eax
	jmp rbh32_loop

rbh32_found:
	; Get ordinal from AddressOfNameOrdinals[index]
	movzx edx, word [edi + eax * 2]
	; Get function RVA from AddressOfFunctions[ordinal]
	mov eax, [ebx + edx * 4]
	add eax, [module_base]
	pop ebx                        ; clean saved export dir
	jmp rbh32_exit_ret

rbh32_exit_error_pop:
	pop ebx
rbh32_exit_error:
	xor eax, eax

rbh32_exit_ret:
	ret
endp

; djb2 hash: eax = pointer to null-terminated string
; Returns: hash in eax
djb2hash32:
	push ecx
	push edx
	mov ecx, eax                   ; string pointer
	mov eax, 5381
.loop:
	movzx edx, byte [ecx]
	test dl, dl
	jz .done
	imul eax, 33
	add eax, edx
	inc ecx
	jmp .loop
.done:
	pop edx
	pop ecx
	ret

; string macros for logging
macro createStringLoading location {
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

macro createStringKernel32 location {
    mov [location+0],'k'
    mov [location+1],'e'
    mov [location+2],'r'
    mov [location+3],'n'
    mov [location+4],'e'
    mov [location+5],'l'
    mov [location+6],'3'
    mov [location+7],'2'
    mov [location+8],'.'
    mov [location+9],'d'
    mov [location+10],'l'
    mov [location+11],'l'
    mov [location+12],0
}
