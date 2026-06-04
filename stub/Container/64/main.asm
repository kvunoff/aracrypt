; AraCrypt 64-Bit container.exe

include 'image_base.inc'
include 'main_prolog.inc' ;format PE64 ...
entry start

include '../../FASM_INCLUDE/win64a.inc'
include 'pe.inc'
include 'key_size.inc'
include 'infile_size.inc'
include 'image_size.inc'

SIZE_DATA_SECTION_NAME	equ 5
SIZE_CHECKSUM		equ 4

;this contains the decrypted and loaded executable
section '.bss' data readable writeable

	 decrypted_infile: db IMAGE_SIZE dup (?)

;--------------------------------------------------

;this contains the encrypted exe + API hashes + table
section '.data' data readable writeable

	 encrypted_infile: include 'infile_array.inc'
	 include 'api_hashes.inc'

;--------------------------------------------------

section '.text' code readable executable

include 'logfile_select.asm'
include 'decryption_includes.asm'
;resolver + pe loader
include 'resolveapis.asm'
include 'loadexecutable.asm'

start:
	 sub rsp,8
	 fastcall MainMethod
	 test rax,rax
	 jz the_end_my_friend
	 ;file was loaded, execute it
	 add rsp,8
	 jmp rax
the_end_my_friend:
	 xor ecx,ecx
	 call qword [api_table + API_ExitProcess * 8]

proc MainMethod uses rbx
	 local str1[256]:BYTE

	 ;resolve all APIs via PEB/hash (no plaintext API names)
	 fastcall resolveAllAPIs
	 test rax,rax
	 jz main_exiterror

	 ;create logfile and write initial message into it
	 initLogFile main_exit

	 ;decrypt exe in data section
	 fastcall decryptExecutable, encrypted_infile
	 test rax,rax
	 jz main_exiterror

	 ;load the executable at its image base
	 ;(this will overwrite current MZ header and bss section)
	 fastcall loadExecutable, encrypted_infile
	 test rax,rax
	 jz main_exiterror

	 ;start program execution
	 mov rdx,IMAGE_BASE
	 xor rax,rax
	 mov eax,[rdx+IMAGE_DOS_HEADER.e_lfanew]
	 add rax,rdx
	 add rax,4
	 ;image file header now in eax
	 add rax,sizeof.IMAGE_FILE_HEADER
	 xor rdx,rdx
	 mov edx,[rax+IMAGE_OPTIONAL_HEADER64.AddressOfEntryPoint]
	 mov rax,IMAGE_BASE
	 add rdx,rax
	 ;entry point of original exe is now in rbx
	 mov rbx,rdx

;finished without errors
main_exitsuccess:
	 writeNewLineToLog main_exit
	 createStringDone str1
	 writeLog rax, main_exit
	 mov rax,rbx
	 jmp main_exit

;finished with errors after logfile API loading
main_exiterror:
	 writeNewLineToLog main_exit
	 createStringError str1
	 writeLog rax, main_exit
	 sub rax,rax

main_exit:
	 ret

endp

include 'resource_select.asm'
