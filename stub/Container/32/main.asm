; AraCrypt 32-Bit container.exe

include 'image_base.inc'
include 'main_prolog.inc' ;format PE ...
entry start

include '../../FASM_INCLUDE/win32a.inc'
include 'createstrings.inc'
include 'pe.inc'
include 'key_size.inc'
include 'infile_size.inc'
include 'image_size.inc'

;this contains the decrypted and loaded executable
section '.bss' data readable writeable

decrypted_infile: db IMAGE_SIZE dup (?)

;--------------------------------------------------

;this contains the encrypted exe + API table + hashes
section '.data' data readable writeable

encrypted_infile: include 'infile_array.inc'
include 'api_hashes.inc'

;--------------------------------------------------

section '.text' code readable executable

include 'logfile_select.asm'
include 'resolveapis.asm'
include 'loadexecutable.asm'
include 'decryption_includes.asm'

start:	 call MainMethod
	 push 0
	 call dword [api_table + ExitProcess * 4]

proc MainMethod
	 local str1[256]:BYTE
	 local APITable:DWORD

	 lea eax, [api_table]
	 mov [APITable], eax
	 push eax
	 call resolveAllAPIs32
	 test eax,eax
	 jz main_exiterrornolog

	 ;create logfile and write initial message into it
	 initLogFile APITable
	 test eax,eax
	 jz main_exiterrornolog

	 writeNewLineToLog APITable
	 test eax,eax
	 jz main_exiterror

	 ;decrypt exe in data section
	 push encrypted_infile
	 push [APITable]
	 call decryptExecutable
	 test eax,eax
	 jz main_exiterror

	 ;load the executable at its image base
	 ;(this will overwrite current MZ header and bss section)
	 push encrypted_infile
	 push [APITable]
	 call loadExecutable
	 test eax,eax
	 jz main_exiterror

	 ;start program execution
	 mov edx,IMAGE_BASE
	 mov eax,[edx+IMAGE_DOS_HEADER.e_lfanew]
	 add eax,edx
	 add eax,4
	 ;image file header now in eax
	 add eax,sizeof.IMAGE_FILE_HEADER
	 mov eax,[eax+IMAGE_OPTIONAL_HEADER32.AddressOfEntryPoint]
	 add eax,IMAGE_BASE
	 ;entry point of original exe is now in eax
	 jmp eax

;finished without errors
main_exitsuccess:
	 writeNewLineToLog APITable
	 createStringDone str1
	 lea eax,[str1]
	 writeLog APITable, eax
	 ret

;finished with errors after logfile API loading
main_exiterror:
	 writeNewLineToLog APITable
	 createStringError str1
	 lea eax,[str1]
	 writeLog APITable, eax
	 ret

;finished with errors before logfile API loading
main_exiterrornolog:
	 ret

endp

include 'resource_select.asm'
