;============================================
; HelperProcs.asm file
;============================================
.486
.model flat, C
option casemap :none

.code

; Most of this procedure was code-generated from Visual C++
; Needs stepping through to ensure that the module base address being fetched is correct
Entry PROC
	ASSUME FS:NOTHING
	CALL CURRENTADDR
	CURRENTADDR: POP DWORD PTR SS:[EBP-0Ch] ; Store current address into stack segment
	MOV EAX, DWORD PTR FS:[30h] ; Get PEB pointer from general-purpose FS register
	MOV DWORD PTR SS:[EBP-24h], EAX ; Store PEB pointer in stack segment
	MOV EAX, DWORD PTR SS:[EBP-24h]
	MOV ECX, DWORD PTR DS:[EAX+0Ch]
	MOV EDX, DWORD PTR DS:[ECX+0Ch]
	MOV DWORD PTR SS:[EBP-24h], EDX
	SEARCHPEB: 
		MOV EAX, DWORD PTR SS:[EBP-24h]
		CMP DWORD PTR DS:[EAX+18h], 0h
			JE SHORT FINISH
		MOV EAX, DWORD PTR SS:[EBP-24h]
		MOV ECX, DWORD PTR DS:[EAX+18h]
		MOV DWORD PTR SS:[EBP-30h], ECX
		MOV EAX, DWORD PTR SS:[EBP-0Ch]
		SUB EAX, DWORD PTR SS:[EBP-30h]
		MOV DWORD PTR SS:[EBP-3Ch], EAX
		MOV EAX, DWORD PTR SS:[EBP-30h]
		ADD EAX, DWORD PTR SS:[EBP-3Ch]
		CMP EAX, DWORD PTR SS:[EBP-0Ch]
			JNE SHORT CHECK
		MOV EAX, DWORD PTR SS:[EBP-30h]
		MOV DWORD PTR SS:[EBP-18h], EAX
		JMP SHORT FINISH
	CHECK: 
		MOV EAX, DWORD PTR SS:[EBP-24h]
		MOV ECX, DWORD PTR DS:[EAX]
		MOV DWORD PTR SS:[EBP-24h], ECX
		JMP SHORT SEARCHPEB
	FINISH:
		MOV EDX, DWORD PTR SS:[EBP-18h]	; Get base address
		MOV EAX, 0C1C2C3C4h ; Get original entry point
		OR EDX, EAX ; Bitwise or them together
		JMP EDX ; Jump to the entry point
	ASSUME FS:ERROR
Entry ENDP

; Act as an indicator for where the Entry procedure will end
EntryEnd PROC
	RET
EntryEnd ENDP

END